// SPDX-License-Identifier: GPL-2.0
/*
 * linux/fs/ecfs/ioctl.c
 *
 * Copyright (C) 1993, 1994, 1995
 * Remy Card (card@masi.ibp.fr)
 * Laboratoire MASI - Institut Blaise Pascal
 * Universite Pierre et Marie Curie (Paris VI)
 */

#include <linux/fs.h>
#include <linux/capability.h>
#include <linux/time.h>
#include <linux/compat.h>
#include <linux/mount.h>
#include <linux/file.h>
#include <linux/quotaops.h>
#include <linux/random.h>
#include <linux/uaccess.h>
#include <linux/delay.h>
#include <linux/iversion.h>
#include <linux/fileattr.h>
#include <linux/uuid.h>
#include "ecfs_jbd2.h"
#include "ecfs.h"
#include <linux/fsmap.h>
#include "fsmap.h"
#include <trace/events/ecfs.h>

typedef void ecfs_update_sb_callback(struct ecfs_super_block *es,
				       const void *arg);

/*
 * Superblock modification callback function for changing file system
 * label
 */
static void ecfs_sb_setlabel(struct ecfs_super_block *es, const void *arg)
{
	/* Sanity check, this should never happen */
	BUILD_BUG_ON(sizeof(es->s_volume_name) < ECFS_LABEL_MAX);

	memcpy(es->s_volume_name, (char *)arg, ECFS_LABEL_MAX);
}

/*
 * Superblock modification callback function for changing file system
 * UUID.
 */
static void ecfs_sb_setuuid(struct ecfs_super_block *es, const void *arg)
{
	memcpy(es->s_uuid, (__u8 *)arg, UUID_SIZE);
}

static
int ecfs_update_primary_sb(struct super_block *sb, handle_t *handle,
			   ecfs_update_sb_callback func,
			   const void *arg)
{
	int err = 0;
	struct ecfs_sb_info *sbi = ECFS_SB(sb);
	struct buffer_head *bh = sbi->s_sbh;
	struct ecfs_super_block *es = sbi->s_es;

	trace_ecfs_update_sb(sb, bh->b_blocknr, 1);

	BUFFER_TRACE(bh, "get_write_access");
	err = ecfs_journal_get_write_access(handle, sb,
					    bh,
					    ECFS_JTR_NONE);
	if (err)
		goto out_err;

	lock_buffer(bh);
	func(es, arg);
	ecfs_superblock_csum_set(sb);
	unlock_buffer(bh);

	if (buffer_write_io_error(bh) || !buffer_uptodate(bh)) {
		ecfs_msg(sbi->s_sb, KERN_ERR, "previous I/O error to "
			 "superblock detected");
		clear_buffer_write_io_error(bh);
		set_buffer_uptodate(bh);
	}

	err = ecfs_handle_dirty_metadata(handle, NULL, bh);
	if (err)
		goto out_err;
	err = sync_dirty_buffer(bh);
out_err:
	ecfs_std_error(sb, err);
	return err;
}

/*
 * Update one backup superblock in the group 'grp' using the callback
 * function 'func' and argument 'arg'. If the handle is NULL the
 * modification is not journalled.
 *
 * Returns: 0 when no modification was done (no superblock in the group)
 *	    1 when the modification was successful
 *	   <0 on error
 */
static int ecfs_update_backup_sb(struct super_block *sb,
				 handle_t *handle, ecfs_group_t grp,
				 ecfs_update_sb_callback func, const void *arg)
{
	int err = 0;
	ecfs_fsblk_t sb_block;
	struct buffer_head *bh;
	unsigned long offset = 0;
	struct ecfs_super_block *es;

	if (!ecfs_bg_has_super(sb, grp))
		return 0;

	/*
	 * For the group 0 there is always 1k padding, so we have
	 * either adjust offset, or sb_block depending on blocksize
	 */
	if (grp == 0) {
		sb_block = 1 * ECFS_MIN_BLOCK_SIZE;
		offset = do_div(sb_block, sb->s_blocksize);
	} else {
		sb_block = ecfs_group_first_block_no(sb, grp);
		offset = 0;
	}

	trace_ecfs_update_sb(sb, sb_block, handle ? 1 : 0);

	bh = ecfs_sb_bread(sb, sb_block, 0);
	if (IS_ERR(bh))
		return PTR_ERR(bh);

	if (handle) {
		BUFFER_TRACE(bh, "get_write_access");
		err = ecfs_journal_get_write_access(handle, sb,
						    bh,
						    ECFS_JTR_NONE);
		if (err)
			goto out_bh;
	}

	es = (struct ecfs_super_block *) (bh->b_data + offset);
	lock_buffer(bh);
	if (ecfs_has_feature_metadata_csum(sb) &&
	    es->s_checksum != ecfs_superblock_csum(es)) {
		ecfs_msg(sb, KERN_ERR, "Invalid checksum for backup "
		"superblock %llu", sb_block);
		unlock_buffer(bh);
		goto out_bh;
	}
	func(es, arg);
	if (ecfs_has_feature_metadata_csum(sb))
		es->s_checksum = ecfs_superblock_csum(es);
	set_buffer_uptodate(bh);
	unlock_buffer(bh);

	if (handle) {
		err = ecfs_handle_dirty_metadata(handle, NULL, bh);
		if (err)
			goto out_bh;
	} else {
		BUFFER_TRACE(bh, "marking dirty");
		mark_buffer_dirty(bh);
	}
	err = sync_dirty_buffer(bh);

out_bh:
	brelse(bh);
	ecfs_std_error(sb, err);
	return (err) ? err : 1;
}

/*
 * Update primary and backup superblocks using the provided function
 * func and argument arg.
 *
 * Only the primary superblock and at most two backup superblock
 * modifications are journalled; the rest is modified without journal.
 * This is safe because e2fsck will re-write them if there is a problem,
 * and we're very unlikely to ever need more than two backups.
 */
static
int ecfs_update_superblocks_fn(struct super_block *sb,
			       ecfs_update_sb_callback func,
			       const void *arg)
{
	handle_t *handle;
	ecfs_group_t ngroups;
	unsigned int three = 1;
	unsigned int five = 5;
	unsigned int seven = 7;
	int err = 0, ret, i;
	ecfs_group_t grp, primary_grp;
	struct ecfs_sb_info *sbi = ECFS_SB(sb);

	/*
	 * We can't update superblocks while the online resize is running
	 */
	if (test_and_set_bit_lock(ECFS_FLAGS_RESIZING,
				  &sbi->s_ecfs_flags)) {
		ecfs_msg(sb, KERN_ERR, "Can't modify superblock while"
			 "performing online resize");
		return -EBUSY;
	}

	/*
	 * We're only going to update primary superblock and two
	 * backup superblocks in this transaction.
	 */
	handle = ecfs_journal_start_sb(sb, ECFS_HT_MISC, 3);
	if (IS_ERR(handle)) {
		err = PTR_ERR(handle);
		goto out;
	}

	/* Update primary superblock */
	err = ecfs_update_primary_sb(sb, handle, func, arg);
	if (err) {
		ecfs_msg(sb, KERN_ERR, "Failed to update primary "
			 "superblock");
		goto out_journal;
	}

	primary_grp = ecfs_get_group_number(sb, sbi->s_sbh->b_blocknr);
	ngroups = ecfs_get_groups_count(sb);

	/*
	 * Update backup superblocks. We have to start from group 0
	 * because it might not be where the primary superblock is
	 * if the fs is mounted with -o sb=<backup_sb_block>
	 */
	i = 0;
	grp = 0;
	while (grp < ngroups) {
		/* Skip primary superblock */
		if (grp == primary_grp)
			goto next_grp;

		ret = ecfs_update_backup_sb(sb, handle, grp, func, arg);
		if (ret < 0) {
			/* Ignore bad checksum; try to update next sb */
			if (ret == -EFSBADCRC)
				goto next_grp;
			err = ret;
			goto out_journal;
		}

		i += ret;
		if (handle && i > 1) {
			/*
			 * We're only journalling primary superblock and
			 * two backup superblocks; the rest is not
			 * journalled.
			 */
			err = ecfs_journal_stop(handle);
			if (err)
				goto out;
			handle = NULL;
		}
next_grp:
		grp = ecfs_list_backups(sb, &three, &five, &seven);
	}

out_journal:
	if (handle) {
		ret = ecfs_journal_stop(handle);
		if (ret && !err)
			err = ret;
	}
out:
	clear_bit_unlock(ECFS_FLAGS_RESIZING, &sbi->s_ecfs_flags);
	smp_mb__after_atomic();
	return err ? err : 0;
}

/*
 * Swap memory between @a and @b for @len bytes.
 *
 * @a:          pointer to first memory area
 * @b:          pointer to second memory area
 * @len:        number of bytes to swap
 *
 */
static void memswap(void *a, void *b, size_t len)
{
	unsigned char *ap, *bp;

	ap = (unsigned char *)a;
	bp = (unsigned char *)b;
	while (len-- > 0) {
		swap(*ap, *bp);
		ap++;
		bp++;
	}
}

/*
 * Swap i_data and associated attributes between @inode1 and @inode2.
 * This function is used for the primary swap between inode1 and inode2
 * and also to revert this primary swap in case of errors.
 *
 * Therefore you have to make sure, that calling this method twice
 * will revert all changes.
 *
 * @inode1:     pointer to first inode
 * @inode2:     pointer to second inode
 */
static void swap_inode_data(struct inode *inode1, struct inode *inode2)
{
	loff_t isize;
	struct ecfs_inode_info *ei1;
	struct ecfs_inode_info *ei2;
	unsigned long tmp;
	struct timespec64 ts1, ts2;

	ei1 = ECFS_I(inode1);
	ei2 = ECFS_I(inode2);

	swap(inode1->i_version, inode2->i_version);

	ts1 = inode_get_atime(inode1);
	ts2 = inode_get_atime(inode2);
	inode_set_atime_to_ts(inode1, ts2);
	inode_set_atime_to_ts(inode2, ts1);

	ts1 = inode_get_mtime(inode1);
	ts2 = inode_get_mtime(inode2);
	inode_set_mtime_to_ts(inode1, ts2);
	inode_set_mtime_to_ts(inode2, ts1);

	memswap(ei1->i_data, ei2->i_data, sizeof(ei1->i_data));
	tmp = ei1->i_flags & ECFS_FL_SHOULD_SWAP;
	ei1->i_flags = (ei2->i_flags & ECFS_FL_SHOULD_SWAP) |
		(ei1->i_flags & ~ECFS_FL_SHOULD_SWAP);
	ei2->i_flags = tmp | (ei2->i_flags & ~ECFS_FL_SHOULD_SWAP);
	swap(ei1->i_disksize, ei2->i_disksize);
	ecfs_es_remove_extent(inode1, 0, EXT_MAX_BLOCKS);
	ecfs_es_remove_extent(inode2, 0, EXT_MAX_BLOCKS);

	isize = i_size_read(inode1);
	i_size_write(inode1, i_size_read(inode2));
	i_size_write(inode2, isize);
}

void ecfs_reset_inode_seed(struct inode *inode)
{
	struct ecfs_inode_info *ei = ECFS_I(inode);
	struct ecfs_sb_info *sbi = ECFS_SB(inode->i_sb);
	__le64 inum = cpu_to_le64(inode->i_ino);
	__le32 gen = cpu_to_le32(inode->i_generation);
	__u32 csum;

	if (!ecfs_has_feature_metadata_csum(inode->i_sb))
		return;

	csum = ecfs_chksum(sbi->s_csum_seed, (__u8 *)&inum, sizeof(inum));
	ei->i_csum_seed = ecfs_chksum(csum, (__u8 *)&gen, sizeof(gen));
}

/*
 * Swap the information from the given @inode and the inode
 * ECFS_BOOT_LOADER_INO. It will basically swap i_data and all other
 * important fields of the inodes.
 *
 * @sb:         the super block of the filesystem
 * @idmap:	idmap of the mount the inode was found from
 * @inode:      the inode to swap with ECFS_BOOT_LOADER_INO
 *
 */
static long swap_inode_boot_loader(struct super_block *sb,
				struct mnt_idmap *idmap,
				struct inode *inode)
{
	handle_t *handle;
	int err;
	struct inode *inode_bl;
	struct ecfs_inode_info *ei_bl;
	qsize_t size, size_bl, diff;
	blkcnt_t blocks;
	unsigned short bytes;

	inode_bl = ecfs_iget(sb, make_fid_sbi(ECFS_SB(sb), ECFS_BOOT_LOADER_INO),
			ECFS_IGET_SPECIAL | ECFS_IGET_BAD);
	if (IS_ERR(inode_bl))
		return PTR_ERR(inode_bl);
	ei_bl = ECFS_I(inode_bl);

	/* Protect orig inodes against a truncate and make sure,
	 * that only 1 swap_inode_boot_loader is running. */
	lock_two_nondirectories(inode, inode_bl);

	if (inode->i_nlink != 1 || !S_ISREG(inode->i_mode) ||
	    IS_SWAPFILE(inode) || IS_ENCRYPTED(inode) ||
	    (ECFS_I(inode)->i_flags & ECFS_JOURNAL_DATA_FL) ||
	    ecfs_has_inline_data(inode)) {
		err = -EINVAL;
		goto journal_err_out;
	}

	if (IS_RDONLY(inode) || IS_APPEND(inode) || IS_IMMUTABLE(inode) ||
	    !inode_owner_or_capable(idmap, inode) ||
	    !capable(CAP_SYS_ADMIN)) {
		err = -EPERM;
		goto journal_err_out;
	}

	filemap_invalidate_lock(inode->i_mapping);
	err = filemap_write_and_wait(inode->i_mapping);
	if (err)
		goto err_out;

	err = filemap_write_and_wait(inode_bl->i_mapping);
	if (err)
		goto err_out;

	/* Wait for all existing dio workers */
	inode_dio_wait(inode);
	inode_dio_wait(inode_bl);

	truncate_inode_pages(&inode->i_data, 0);
	truncate_inode_pages(&inode_bl->i_data, 0);

	handle = ecfs_journal_start(inode_bl, ECFS_HT_MOVE_EXTENTS, 2);
	if (IS_ERR(handle)) {
		err = -EINVAL;
		goto err_out;
	}
	ecfs_fc_mark_ineligible(sb, ECFS_FC_REASON_SWAP_BOOT, handle);

	/* Protect extent tree against block allocations via delalloc */
	ecfs_double_down_write_data_sem(inode, inode_bl);

	if (is_bad_inode(inode_bl) || !S_ISREG(inode_bl->i_mode)) {
		/* this inode has never been used as a BOOT_LOADER */
		set_nlink(inode_bl, 1);
		i_uid_write(inode_bl, 0);
		i_gid_write(inode_bl, 0);
		inode_bl->i_flags = 0;
		ei_bl->i_flags = 0;
		inode_set_iversion(inode_bl, 1);
		i_size_write(inode_bl, 0);
		ECFS_I(inode_bl)->i_disksize = inode_bl->i_size;
		inode_bl->i_mode = S_IFREG;
		if (ecfs_has_feature_extents(sb)) {
			ecfs_set_inode_flag(inode_bl, ECFS_INODE_EXTENTS);
			ecfs_ext_tree_init(handle, inode_bl);
		} else
			memset(ei_bl->i_data, 0, sizeof(ei_bl->i_data));
	}

	err = dquot_initialize(inode);
	if (err)
		goto err_out1;

	size = (qsize_t)(inode->i_blocks) * (1 << 9) + inode->i_bytes;
	size_bl = (qsize_t)(inode_bl->i_blocks) * (1 << 9) + inode_bl->i_bytes;
	diff = size - size_bl;
	swap_inode_data(inode, inode_bl);

	inode_set_ctime_current(inode);
	inode_set_ctime_current(inode_bl);
	inode_inc_iversion(inode);

	inode->i_generation = get_random_u32();
	inode_bl->i_generation = get_random_u32();
	ecfs_reset_inode_seed(inode);
	ecfs_reset_inode_seed(inode_bl);

	ecfs_discard_preallocations(inode);

	err = ecfs_mark_inode_dirty(handle, inode);
	if (err < 0) {
		/* No need to update quota information. */
		ecfs_warning(inode->i_sb,
			"couldn't mark inode #%lu dirty (err %d)",
			inode->i_ino, err);
		/* Revert all changes: */
		swap_inode_data(inode, inode_bl);
		ecfs_mark_inode_dirty(handle, inode);
		goto err_out1;
	}

	blocks = inode_bl->i_blocks;
	bytes = inode_bl->i_bytes;
	inode_bl->i_blocks = inode->i_blocks;
	inode_bl->i_bytes = inode->i_bytes;
	err = ecfs_mark_inode_dirty(handle, inode_bl);
	if (err < 0) {
		/* No need to update quota information. */
		ecfs_warning(inode_bl->i_sb,
			"couldn't mark inode #%lu dirty (err %d)",
			inode_bl->i_ino, err);
		goto revert;
	}

	/* Bootloader inode should not be counted into quota information. */
	if (diff > 0)
		dquot_free_space(inode, diff);
	else
		err = dquot_alloc_space(inode, -1 * diff);

	if (err < 0) {
revert:
		/* Revert all changes: */
		inode_bl->i_blocks = blocks;
		inode_bl->i_bytes = bytes;
		swap_inode_data(inode, inode_bl);
		ecfs_mark_inode_dirty(handle, inode);
		ecfs_mark_inode_dirty(handle, inode_bl);
	}

err_out1:
	ecfs_journal_stop(handle);
	ecfs_double_up_write_data_sem(inode, inode_bl);

err_out:
	filemap_invalidate_unlock(inode->i_mapping);
journal_err_out:
	unlock_two_nondirectories(inode, inode_bl);
	iput(inode_bl);
	return err;
}

/*
 * If immutable is set and we are not clearing it, we're not allowed to change
 * anything else in the inode.  Don't error out if we're only trying to set
 * immutable on an immutable file.
 */
static int ecfs_ioctl_check_immutable(struct inode *inode, __u32 new_projid,
				      unsigned int flags)
{
	struct ecfs_inode_info *ei = ECFS_I(inode);
	unsigned int oldflags = ei->i_flags;

	if (!(oldflags & ECFS_IMMUTABLE_FL) || !(flags & ECFS_IMMUTABLE_FL))
		return 0;

	if ((oldflags & ~ECFS_IMMUTABLE_FL) != (flags & ~ECFS_IMMUTABLE_FL))
		return -EPERM;
	if (ecfs_has_feature_project(inode->i_sb) &&
	    __kprojid_val(ei->i_projid) != new_projid)
		return -EPERM;

	return 0;
}

static void ecfs_dax_dontcache(struct inode *inode, unsigned int flags)
{
	struct ecfs_inode_info *ei = ECFS_I(inode);

	if (S_ISDIR(inode->i_mode))
		return;

	if (test_opt2(inode->i_sb, DAX_NEVER) ||
	    test_opt(inode->i_sb, DAX_ALWAYS))
		return;

	if ((ei->i_flags ^ flags) & ECFS_DAX_FL)
		d_mark_dontcache(inode);
}

static bool dax_compatible(struct inode *inode, unsigned int oldflags,
			   unsigned int flags)
{
	/* Allow the DAX flag to be changed on inline directories */
	if (S_ISDIR(inode->i_mode)) {
		flags &= ~ECFS_INLINE_DATA_FL;
		oldflags &= ~ECFS_INLINE_DATA_FL;
	}

	if (flags & ECFS_DAX_FL) {
		if ((oldflags & ECFS_DAX_MUT_EXCL) ||
		     ecfs_test_inode_state(inode,
					  ECFS_STATE_VERITY_IN_PROGRESS)) {
			return false;
		}
	}

	if ((flags & ECFS_DAX_MUT_EXCL) && (oldflags & ECFS_DAX_FL))
			return false;

	return true;
}

static int ecfs_ioctl_setflags(struct inode *inode,
			       unsigned int flags)
{
	struct ecfs_inode_info *ei = ECFS_I(inode);
	handle_t *handle = NULL;
	int err = -EPERM, migrate = 0;
	struct ecfs_iloc iloc;
	unsigned int oldflags, mask, i;
	struct super_block *sb = inode->i_sb;

	/* Is it quota file? Do not allow user to mess with it */
	if (ecfs_is_quota_file(inode))
		goto flags_out;

	oldflags = ei->i_flags;
	/*
	 * The JOURNAL_DATA flag can only be changed by
	 * the relevant capability.
	 */
	if ((flags ^ oldflags) & (ECFS_JOURNAL_DATA_FL)) {
		if (!capable(CAP_SYS_RESOURCE))
			goto flags_out;
	}

	if (!dax_compatible(inode, oldflags, flags)) {
		err = -EOPNOTSUPP;
		goto flags_out;
	}

	if ((flags ^ oldflags) & ECFS_EXTENTS_FL)
		migrate = 1;

	if ((flags ^ oldflags) & ECFS_CASEFOLD_FL) {
		if (!ecfs_has_feature_casefold(sb)) {
			err = -EOPNOTSUPP;
			goto flags_out;
		}

		if (!S_ISDIR(inode->i_mode)) {
			err = -ENOTDIR;
			goto flags_out;
		}

		if (!ecfs_empty_dir(inode)) {
			err = -ENOTEMPTY;
			goto flags_out;
		}
	}

	/*
	 * Wait for all pending directio and then flush all the dirty pages
	 * for this file.  The flush marks all the pages readonly, so any
	 * subsequent attempt to write to the file (particularly mmap pages)
	 * will come through the filesystem and fail.
	 */
	if (S_ISREG(inode->i_mode) && !IS_IMMUTABLE(inode) &&
	    (flags & ECFS_IMMUTABLE_FL)) {
		inode_dio_wait(inode);
		err = filemap_write_and_wait(inode->i_mapping);
		if (err)
			goto flags_out;
	}

	handle = ecfs_journal_start(inode, ECFS_HT_INODE, 1);
	if (IS_ERR(handle)) {
		err = PTR_ERR(handle);
		goto flags_out;
	}
	if (IS_SYNC(inode))
		ecfs_handle_sync(handle);
	err = ecfs_reserve_inode_write(handle, inode, &iloc);
	if (err)
		goto flags_err;

	ecfs_dax_dontcache(inode, flags);

	for (i = 0, mask = 1; i < 32; i++, mask <<= 1) {
		if (!(mask & ECFS_FL_USER_MODIFIABLE))
			continue;
		/* These flags get special treatment later */
		if (mask == ECFS_JOURNAL_DATA_FL || mask == ECFS_EXTENTS_FL)
			continue;
		if (mask & flags)
			ecfs_set_inode_flag(inode, i);
		else
			ecfs_clear_inode_flag(inode, i);
	}

	ecfs_set_inode_flags(inode, false);

	inode_set_ctime_current(inode);
	inode_inc_iversion(inode);

	err = ecfs_mark_iloc_dirty(handle, inode, &iloc);
flags_err:
	ecfs_journal_stop(handle);
	if (err)
		goto flags_out;

	if ((flags ^ oldflags) & (ECFS_JOURNAL_DATA_FL)) {
		/*
		 * Changes to the journaling mode can cause unsafe changes to
		 * S_DAX if the inode is DAX
		 */
		if (IS_DAX(inode)) {
			err = -EBUSY;
			goto flags_out;
		}

		err = ecfs_change_inode_journal_flag(inode,
						     flags & ECFS_JOURNAL_DATA_FL);
		if (err)
			goto flags_out;
	}
	if (migrate) {
		if (flags & ECFS_EXTENTS_FL)
			err = ecfs_ext_migrate(inode);
		else
			err = ecfs_ind_migrate(inode);
	}

flags_out:
	return err;
}

#ifdef CONFIG_QUOTA
static int ecfs_ioctl_setproject(struct inode *inode, __u32 projid)
{
	struct super_block *sb = inode->i_sb;
	struct ecfs_inode_info *ei = ECFS_I(inode);
	int err, rc;
	handle_t *handle;
	kprojid_t kprojid;
	struct ecfs_iloc iloc;
	struct ecfs_inode *raw_inode;
	struct dquot *transfer_to[MAXQUOTAS] = { };

	if (!ecfs_has_feature_project(sb)) {
		if (projid != ECFS_DEF_PROJID)
			return -EOPNOTSUPP;
		else
			return 0;
	}

	if (ECFS_INODE_SIZE(sb) <= ECFS_GOOD_OLD_INODE_SIZE)
		return -EOPNOTSUPP;

	kprojid = make_kprojid(&init_user_ns, (projid_t)projid);

	if (projid_eq(kprojid, ECFS_I(inode)->i_projid))
		return 0;

	err = -EPERM;
	/* Is it quota file? Do not allow user to mess with it */
	if (ecfs_is_quota_file(inode))
		return err;

	err = dquot_initialize(inode);
	if (err)
		return err;

	err = ecfs_get_inode_loc(inode, &iloc);
	if (err)
		return err;

	raw_inode = ecfs_raw_inode(&iloc);
	if (!ECFS_FITS_IN_INODE(raw_inode, ei, i_projid)) {
		err = ecfs_expand_extra_isize(inode,
					      ECFS_SB(sb)->s_want_extra_isize,
					      &iloc);
		if (err)
			return err;
	} else {
		brelse(iloc.bh);
	}

	handle = ecfs_journal_start(inode, ECFS_HT_QUOTA,
		ECFS_QUOTA_INIT_BLOCKS(sb) +
		ECFS_QUOTA_DEL_BLOCKS(sb) + 3);
	if (IS_ERR(handle))
		return PTR_ERR(handle);

	err = ecfs_reserve_inode_write(handle, inode, &iloc);
	if (err)
		goto out_stop;

	transfer_to[PRJQUOTA] = dqget(sb, make_kqid_projid(kprojid));
	if (!IS_ERR(transfer_to[PRJQUOTA])) {

		/* __dquot_transfer() calls back ecfs_get_inode_usage() which
		 * counts xattr inode references.
		 */
		down_read(&ECFS_I(inode)->xattr_sem);
		err = __dquot_transfer(inode, transfer_to);
		up_read(&ECFS_I(inode)->xattr_sem);
		dqput(transfer_to[PRJQUOTA]);
		if (err)
			goto out_dirty;
	}

	ECFS_I(inode)->i_projid = kprojid;
	inode_set_ctime_current(inode);
	inode_inc_iversion(inode);
out_dirty:
	rc = ecfs_mark_iloc_dirty(handle, inode, &iloc);
	if (!err)
		err = rc;
out_stop:
	ecfs_journal_stop(handle);
	return err;
}
#else
static int ecfs_ioctl_setproject(struct inode *inode, __u32 projid)
{
	if (projid != ECFS_DEF_PROJID)
		return -EOPNOTSUPP;
	return 0;
}
#endif

int ecfs_force_shutdown(struct super_block *sb, u32 flags)
{
	struct ecfs_sb_info *sbi = ECFS_SB(sb);
	int ret;

	if (flags > ECFS_GOING_FLAGS_NOLOGFLUSH)
		return -EINVAL;

	if (ecfs_forced_shutdown(sb))
		return 0;

	ecfs_msg(sb, KERN_ALERT, "shut down requested (%d)", flags);
	trace_ecfs_shutdown(sb, flags);

	switch (flags) {
	case ECFS_GOING_FLAGS_DEFAULT:
		ret = bdev_freeze(sb->s_bdev);
		if (ret)
			return ret;
		set_bit(ECFS_FLAGS_SHUTDOWN, &sbi->s_ecfs_flags);
		bdev_thaw(sb->s_bdev);
		break;
	case ECFS_GOING_FLAGS_LOGFLUSH:
		set_bit(ECFS_FLAGS_SHUTDOWN, &sbi->s_ecfs_flags);
		if (sbi->s_journal && !is_journal_aborted(sbi->s_journal)) {
			(void) ecfs_force_commit(sb);
			jbd2_journal_abort(sbi->s_journal, -ESHUTDOWN);
		}
		break;
	case ECFS_GOING_FLAGS_NOLOGFLUSH:
		set_bit(ECFS_FLAGS_SHUTDOWN, &sbi->s_ecfs_flags);
		if (sbi->s_journal && !is_journal_aborted(sbi->s_journal))
			jbd2_journal_abort(sbi->s_journal, -ESHUTDOWN);
		break;
	default:
		return -EINVAL;
	}
	clear_opt(sb, DISCARD);
	return 0;
}

static int ecfs_ioctl_shutdown(struct super_block *sb, unsigned long arg)
{
	u32 flags;

	if (!capable(CAP_SYS_ADMIN))
		return -EPERM;

	if (get_user(flags, (__u32 __user *)arg))
		return -EFAULT;

	return ecfs_force_shutdown(sb, flags);
}

struct getfsmap_info {
	struct super_block	*gi_sb;
	struct fsmap_head __user *gi_data;
	unsigned int		gi_idx;
	__u32			gi_last_flags;
};

static int ecfs_getfsmap_format(struct ecfs_fsmap *xfm, void *priv)
{
	struct getfsmap_info *info = priv;
	struct fsmap fm;

	trace_ecfs_getfsmap_mapping(info->gi_sb, xfm);

	info->gi_last_flags = xfm->fmr_flags;
	ecfs_fsmap_from_internal(info->gi_sb, &fm, xfm);
	if (copy_to_user(&info->gi_data->fmh_recs[info->gi_idx++], &fm,
			sizeof(struct fsmap)))
		return -EFAULT;

	return 0;
}

static int ecfs_ioc_getfsmap(struct super_block *sb,
			     struct fsmap_head __user *arg)
{
	struct getfsmap_info info = { NULL };
	struct ecfs_fsmap_head xhead = {0};
	struct fsmap_head head;
	bool aborted = false;
	int error;

	if (copy_from_user(&head, arg, sizeof(struct fsmap_head)))
		return -EFAULT;
	if (memchr_inv(head.fmh_reserved, 0, sizeof(head.fmh_reserved)) ||
	    memchr_inv(head.fmh_keys[0].fmr_reserved, 0,
		       sizeof(head.fmh_keys[0].fmr_reserved)) ||
	    memchr_inv(head.fmh_keys[1].fmr_reserved, 0,
		       sizeof(head.fmh_keys[1].fmr_reserved)))
		return -EINVAL;
	/*
	 * ecfs doesn't report file extents at all, so the only valid
	 * file offsets are the magic ones (all zeroes or all ones).
	 */
	if (head.fmh_keys[0].fmr_offset ||
	    (head.fmh_keys[1].fmr_offset != 0 &&
	     head.fmh_keys[1].fmr_offset != -1ULL))
		return -EINVAL;

	xhead.fmh_iflags = head.fmh_iflags;
	xhead.fmh_count = head.fmh_count;
	ecfs_fsmap_to_internal(sb, &xhead.fmh_keys[0], &head.fmh_keys[0]);
	ecfs_fsmap_to_internal(sb, &xhead.fmh_keys[1], &head.fmh_keys[1]);

	trace_ecfs_getfsmap_low_key(sb, &xhead.fmh_keys[0]);
	trace_ecfs_getfsmap_high_key(sb, &xhead.fmh_keys[1]);

	info.gi_sb = sb;
	info.gi_data = arg;
	error = ecfs_getfsmap(sb, &xhead, ecfs_getfsmap_format, &info);
	if (error == ECFS_QUERY_RANGE_ABORT)
		aborted = true;
	else if (error)
		return error;

	/* If we didn't abort, set the "last" flag in the last fmx */
	if (!aborted && info.gi_idx) {
		info.gi_last_flags |= FMR_OF_LAST;
		if (copy_to_user(&info.gi_data->fmh_recs[info.gi_idx - 1].fmr_flags,
				 &info.gi_last_flags,
				 sizeof(info.gi_last_flags)))
			return -EFAULT;
	}

	/* copy back header */
	head.fmh_entries = xhead.fmh_entries;
	head.fmh_oflags = xhead.fmh_oflags;
	if (copy_to_user(arg, &head, sizeof(struct fsmap_head)))
		return -EFAULT;

	return 0;
}

static long ecfs_ioctl_group_add(struct file *file,
				 struct ecfs_new_group_data *input)
{
	struct super_block *sb = file_inode(file)->i_sb;
	int err, err2=0;

	err = ecfs_resize_begin(sb);
	if (err)
		return err;

	if (ecfs_has_feature_bigalloc(sb)) {
		ecfs_msg(sb, KERN_ERR,
			 "Online resizing not supported with bigalloc");
		err = -EOPNOTSUPP;
		goto group_add_out;
	}

	err = mnt_want_write_file(file);
	if (err)
		goto group_add_out;

	err = ecfs_group_add(sb, input);
	if (ECFS_SB(sb)->s_journal) {
		jbd2_journal_lock_updates(ECFS_SB(sb)->s_journal);
		err2 = jbd2_journal_flush(ECFS_SB(sb)->s_journal, 0);
		jbd2_journal_unlock_updates(ECFS_SB(sb)->s_journal);
	}
	if (err == 0)
		err = err2;
	mnt_drop_write_file(file);
	if (!err && ecfs_has_group_desc_csum(sb) &&
	    test_opt(sb, INIT_INODE_TABLE))
		err = ecfs_register_li_request(sb, input->group);
group_add_out:
	err2 = ecfs_resize_end(sb, false);
	if (err == 0)
		err = err2;
	return err;
}

int ecfs_fileattr_get(struct dentry *dentry, struct file_kattr *fa)
{
	struct inode *inode = d_inode(dentry);
	struct ecfs_inode_info *ei = ECFS_I(inode);
	u32 flags = ei->i_flags & ECFS_FL_USER_VISIBLE;

	if (S_ISREG(inode->i_mode))
		flags &= ~FS_PROJINHERIT_FL;

	fileattr_fill_flags(fa, flags);
	if (ecfs_has_feature_project(inode->i_sb))
		fa->fsx_projid = from_kprojid(&init_user_ns, ei->i_projid);

	return 0;
}

int ecfs_fileattr_set(struct mnt_idmap *idmap,
		      struct dentry *dentry, struct file_kattr *fa)
{
	struct inode *inode = d_inode(dentry);
	u32 flags = fa->flags;
	int err = -EOPNOTSUPP;

	if (flags & ~ECFS_FL_USER_VISIBLE)
		goto out;

	/*
	 * chattr(1) grabs flags via GETFLAGS, modifies the result and
	 * passes that to SETFLAGS. So we cannot easily make SETFLAGS
	 * more restrictive than just silently masking off visible but
	 * not settable flags as we always did.
	 */
	flags &= ECFS_FL_USER_MODIFIABLE;
	if (ecfs_mask_flags(inode->i_mode, flags) != flags)
		goto out;
	err = ecfs_ioctl_check_immutable(inode, fa->fsx_projid, flags);
	if (err)
		goto out;
	err = ecfs_ioctl_setflags(inode, flags);
	if (err)
		goto out;
	err = ecfs_ioctl_setproject(inode, fa->fsx_projid);
out:
	return err;
}

/* So that the fiemap access checks can't overflow on 32 bit machines. */
#define FIEMAP_MAX_EXTENTS	(UINT_MAX / sizeof(struct fiemap_extent))

static int ecfs_ioctl_get_es_cache(struct file *filp, unsigned long arg)
{
	struct fiemap fiemap;
	struct fiemap __user *ufiemap = (struct fiemap __user *) arg;
	struct fiemap_extent_info fieinfo = { 0, };
	struct inode *inode = file_inode(filp);
	int error;

	if (copy_from_user(&fiemap, ufiemap, sizeof(fiemap)))
		return -EFAULT;

	if (fiemap.fm_extent_count > FIEMAP_MAX_EXTENTS)
		return -EINVAL;

	fieinfo.fi_flags = fiemap.fm_flags;
	fieinfo.fi_extents_max = fiemap.fm_extent_count;
	fieinfo.fi_extents_start = ufiemap->fm_extents;

	error = ecfs_get_es_cache(inode, &fieinfo, fiemap.fm_start,
			fiemap.fm_length);
	fiemap.fm_flags = fieinfo.fi_flags;
	fiemap.fm_mapped_extents = fieinfo.fi_extents_mapped;
	if (copy_to_user(ufiemap, &fiemap, sizeof(fiemap)))
		error = -EFAULT;

	return error;
}

static int ecfs_ioctl_checkpoint(struct file *filp, unsigned long arg)
{
	int err = 0;
	__u32 flags = 0;
	unsigned int flush_flags = 0;
	struct super_block *sb = file_inode(filp)->i_sb;

	if (copy_from_user(&flags, (__u32 __user *)arg,
				sizeof(__u32)))
		return -EFAULT;

	if (!capable(CAP_SYS_ADMIN))
		return -EPERM;

	/* check for invalid bits set */
	if ((flags & ~ECFS_IOC_CHECKPOINT_FLAG_VALID) ||
				((flags & JBD2_JOURNAL_FLUSH_DISCARD) &&
				(flags & JBD2_JOURNAL_FLUSH_ZEROOUT)))
		return -EINVAL;

	if (!ECFS_SB(sb)->s_journal)
		return -ENODEV;

	if ((flags & JBD2_JOURNAL_FLUSH_DISCARD) &&
	    !bdev_max_discard_sectors(ECFS_SB(sb)->s_journal->j_dev))
		return -EOPNOTSUPP;

	if (flags & ECFS_IOC_CHECKPOINT_FLAG_DRY_RUN)
		return 0;

	if (flags & ECFS_IOC_CHECKPOINT_FLAG_DISCARD)
		flush_flags |= JBD2_JOURNAL_FLUSH_DISCARD;

	if (flags & ECFS_IOC_CHECKPOINT_FLAG_ZEROOUT) {
		flush_flags |= JBD2_JOURNAL_FLUSH_ZEROOUT;
		pr_info_ratelimited("warning: checkpointing journal with ECFS_IOC_CHECKPOINT_FLAG_ZEROOUT can be slow");
	}

	jbd2_journal_lock_updates(ECFS_SB(sb)->s_journal);
	err = jbd2_journal_flush(ECFS_SB(sb)->s_journal, flush_flags);
	jbd2_journal_unlock_updates(ECFS_SB(sb)->s_journal);

	return err;
}

static int ecfs_ioctl_setlabel(struct file *filp, const char __user *user_label)
{
	size_t len;
	int ret = 0;
	char new_label[ECFS_LABEL_MAX + 1];
	struct super_block *sb = file_inode(filp)->i_sb;

	if (!capable(CAP_SYS_ADMIN))
		return -EPERM;

	/*
	 * Copy the maximum length allowed for ecfs label with one more to
	 * find the required terminating null byte in order to test the
	 * label length. The on disk label doesn't need to be null terminated.
	 */
	if (copy_from_user(new_label, user_label, ECFS_LABEL_MAX + 1))
		return -EFAULT;

	len = strnlen(new_label, ECFS_LABEL_MAX + 1);
	if (len > ECFS_LABEL_MAX)
		return -EINVAL;

	/*
	 * Clear the buffer after the new label
	 */
	memset(new_label + len, 0, ECFS_LABEL_MAX - len);

	ret = mnt_want_write_file(filp);
	if (ret)
		return ret;

	ret = ecfs_update_superblocks_fn(sb, ecfs_sb_setlabel, new_label);

	mnt_drop_write_file(filp);
	return ret;
}

static int ecfs_ioctl_getlabel(struct ecfs_sb_info *sbi, char __user *user_label)
{
	char label[ECFS_LABEL_MAX + 1];

	/*
	 * ECFS_LABEL_MAX must always be smaller than FSLABEL_MAX because
	 * FSLABEL_MAX must include terminating null byte, while s_volume_name
	 * does not have to.
	 */
	BUILD_BUG_ON(ECFS_LABEL_MAX >= FSLABEL_MAX);

	lock_buffer(sbi->s_sbh);
	memtostr_pad(label, sbi->s_es->s_volume_name);
	unlock_buffer(sbi->s_sbh);

	if (copy_to_user(user_label, label, sizeof(label)))
		return -EFAULT;
	return 0;
}

static int ecfs_ioctl_getuuid(struct ecfs_sb_info *sbi,
			struct fsuuid __user *ufsuuid)
{
	struct fsuuid fsuuid;
	__u8 uuid[UUID_SIZE];

	if (copy_from_user(&fsuuid, ufsuuid, sizeof(fsuuid)))
		return -EFAULT;

	if (fsuuid.fsu_len == 0) {
		fsuuid.fsu_len = UUID_SIZE;
		if (copy_to_user(&ufsuuid->fsu_len, &fsuuid.fsu_len,
					sizeof(fsuuid.fsu_len)))
			return -EFAULT;
		return 0;
	}

	if (fsuuid.fsu_len < UUID_SIZE || fsuuid.fsu_flags != 0)
		return -EINVAL;

	lock_buffer(sbi->s_sbh);
	memcpy(uuid, sbi->s_es->s_uuid, UUID_SIZE);
	unlock_buffer(sbi->s_sbh);

	fsuuid.fsu_len = UUID_SIZE;
	if (copy_to_user(ufsuuid, &fsuuid, sizeof(fsuuid)) ||
	    copy_to_user(&ufsuuid->fsu_uuid[0], uuid, UUID_SIZE))
		return -EFAULT;
	return 0;
}

static int ecfs_ioctl_setuuid(struct file *filp,
			const struct fsuuid __user *ufsuuid)
{
	int ret = 0;
	struct super_block *sb = file_inode(filp)->i_sb;
	struct fsuuid fsuuid;
	__u8 uuid[UUID_SIZE];

	if (!capable(CAP_SYS_ADMIN))
		return -EPERM;

	/*
	 * If any checksums (group descriptors or metadata) are being used
	 * then the checksum seed feature is required to change the UUID.
	 */
	if (((ecfs_has_feature_gdt_csum(sb) ||
	      ecfs_has_feature_metadata_csum(sb))
			&& !ecfs_has_feature_csum_seed(sb))
		|| ecfs_has_feature_stable_inodes(sb))
		return -EOPNOTSUPP;

	if (copy_from_user(&fsuuid, ufsuuid, sizeof(fsuuid)))
		return -EFAULT;

	if (fsuuid.fsu_len != UUID_SIZE || fsuuid.fsu_flags != 0)
		return -EINVAL;

	if (copy_from_user(uuid, &ufsuuid->fsu_uuid[0], UUID_SIZE))
		return -EFAULT;

	ret = mnt_want_write_file(filp);
	if (ret)
		return ret;

	ret = ecfs_update_superblocks_fn(sb, ecfs_sb_setuuid, &uuid);
	mnt_drop_write_file(filp);

	return ret;
}

static long __ecfs_ioctl(struct file *filp, unsigned int cmd, unsigned long arg)
{
	struct inode *inode = file_inode(filp);
	struct super_block *sb = inode->i_sb;
	struct mnt_idmap *idmap = file_mnt_idmap(filp);

	ecfs_debug("cmd = %u, arg = %lu\n", cmd, arg);

	switch (cmd) {
	case FS_IOC_GETFSMAP:
		return ecfs_ioc_getfsmap(sb, (void __user *)arg);
	case ECFS_IOC_GETVERSION:
	case ECFS_IOC_GETVERSION_OLD:
		return put_user(inode->i_generation, (int __user *) arg);
	case ECFS_IOC_SETVERSION:
	case ECFS_IOC_SETVERSION_OLD: {
		handle_t *handle;
		struct ecfs_iloc iloc;
		__u32 generation;
		int err;

		if (!inode_owner_or_capable(idmap, inode))
			return -EPERM;

		if (ecfs_has_feature_metadata_csum(inode->i_sb)) {
			ecfs_warning(sb, "Setting inode version is not "
				     "supported with metadata_csum enabled.");
			return -ENOTTY;
		}

		err = mnt_want_write_file(filp);
		if (err)
			return err;
		if (get_user(generation, (int __user *) arg)) {
			err = -EFAULT;
			goto setversion_out;
		}

		inode_lock(inode);
		handle = ecfs_journal_start(inode, ECFS_HT_INODE, 1);
		if (IS_ERR(handle)) {
			err = PTR_ERR(handle);
			goto unlock_out;
		}
		err = ecfs_reserve_inode_write(handle, inode, &iloc);
		if (err == 0) {
			inode_set_ctime_current(inode);
			inode_inc_iversion(inode);
			inode->i_generation = generation;
			err = ecfs_mark_iloc_dirty(handle, inode, &iloc);
		}
		ecfs_journal_stop(handle);

unlock_out:
		inode_unlock(inode);
setversion_out:
		mnt_drop_write_file(filp);
		return err;
	}
	case ECFS_IOC_GROUP_EXTEND: {
		ecfs_fsblk_t n_blocks_count;
		int err, err2=0;

		err = ecfs_resize_begin(sb);
		if (err)
			return err;

		if (get_user(n_blocks_count, (__u32 __user *)arg)) {
			err = -EFAULT;
			goto group_extend_out;
		}

		if (ecfs_has_feature_bigalloc(sb)) {
			ecfs_msg(sb, KERN_ERR,
				 "Online resizing not supported with bigalloc");
			err = -EOPNOTSUPP;
			goto group_extend_out;
		}

		err = mnt_want_write_file(filp);
		if (err)
			goto group_extend_out;

		err = ecfs_group_extend(sb, ECFS_SB(sb)->s_es, n_blocks_count);
		if (ECFS_SB(sb)->s_journal) {
			jbd2_journal_lock_updates(ECFS_SB(sb)->s_journal);
			err2 = jbd2_journal_flush(ECFS_SB(sb)->s_journal, 0);
			jbd2_journal_unlock_updates(ECFS_SB(sb)->s_journal);
		}
		if (err == 0)
			err = err2;
		mnt_drop_write_file(filp);
group_extend_out:
		err2 = ecfs_resize_end(sb, false);
		if (err == 0)
			err = err2;
		return err;
	}

	case ECFS_IOC_MOVE_EXT: {
		struct move_extent me;
		int err;

		if (!(filp->f_mode & FMODE_READ) ||
		    !(filp->f_mode & FMODE_WRITE))
			return -EBADF;

		if (copy_from_user(&me,
			(struct move_extent __user *)arg, sizeof(me)))
			return -EFAULT;
		me.moved_len = 0;

		CLASS(fd, donor)(me.donor_fd);
		if (fd_empty(donor))
			return -EBADF;

		if (!(fd_file(donor)->f_mode & FMODE_WRITE))
			return -EBADF;

		if (ecfs_has_feature_bigalloc(sb)) {
			ecfs_msg(sb, KERN_ERR,
				 "Online defrag not supported with bigalloc");
			return -EOPNOTSUPP;
		} else if (IS_DAX(inode)) {
			ecfs_msg(sb, KERN_ERR,
				 "Online defrag not supported with DAX");
			return -EOPNOTSUPP;
		}

		err = mnt_want_write_file(filp);
		if (err)
			return err;

		err = ecfs_move_extents(filp, fd_file(donor), me.orig_start,
					me.donor_start, me.len, &me.moved_len);
		mnt_drop_write_file(filp);

		if (copy_to_user((struct move_extent __user *)arg,
				 &me, sizeof(me)))
			err = -EFAULT;
		return err;
	}

	case ECFS_IOC_GROUP_ADD: {
		struct ecfs_new_group_data input;

		if (copy_from_user(&input, (struct ecfs_new_group_input __user *)arg,
				sizeof(input)))
			return -EFAULT;

		return ecfs_ioctl_group_add(filp, &input);
	}

	case ECFS_IOC_MIGRATE:
	{
		int err;
		if (!inode_owner_or_capable(idmap, inode))
			return -EACCES;

		err = mnt_want_write_file(filp);
		if (err)
			return err;
		/*
		 * inode_mutex prevent write and truncate on the file.
		 * Read still goes through. We take i_data_sem in
		 * ecfs_ext_swap_inode_data before we switch the
		 * inode format to prevent read.
		 */
		inode_lock((inode));
		err = ecfs_ext_migrate(inode);
		inode_unlock((inode));
		mnt_drop_write_file(filp);
		return err;
	}

	case ECFS_IOC_ALLOC_DA_BLKS:
	{
		int err;
		if (!inode_owner_or_capable(idmap, inode))
			return -EACCES;

		err = mnt_want_write_file(filp);
		if (err)
			return err;
		err = ecfs_alloc_da_blocks(inode);
		mnt_drop_write_file(filp);
		return err;
	}

	case ECFS_IOC_SWAP_BOOT:
	{
		int err;
		if (!(filp->f_mode & FMODE_WRITE))
			return -EBADF;
		err = mnt_want_write_file(filp);
		if (err)
			return err;
		err = swap_inode_boot_loader(sb, idmap, inode);
		mnt_drop_write_file(filp);
		return err;
	}

	case ECFS_IOC_RESIZE_FS: {
		ecfs_fsblk_t n_blocks_count;
		int err = 0, err2 = 0;
		ecfs_group_t o_group = ECFS_SB(sb)->s_groups_count;

		if (copy_from_user(&n_blocks_count, (__u64 __user *)arg,
				   sizeof(__u64))) {
			return -EFAULT;
		}

		err = ecfs_resize_begin(sb);
		if (err)
			return err;

		err = mnt_want_write_file(filp);
		if (err)
			goto resizefs_out;

		err = ecfs_resize_fs(sb, n_blocks_count);
		if (ECFS_SB(sb)->s_journal) {
			ecfs_fc_mark_ineligible(sb, ECFS_FC_REASON_RESIZE, NULL);
			jbd2_journal_lock_updates(ECFS_SB(sb)->s_journal);
			err2 = jbd2_journal_flush(ECFS_SB(sb)->s_journal, 0);
			jbd2_journal_unlock_updates(ECFS_SB(sb)->s_journal);
		}
		if (err == 0)
			err = err2;
		mnt_drop_write_file(filp);
		if (!err && (o_group < ECFS_SB(sb)->s_groups_count) &&
		    ecfs_has_group_desc_csum(sb) &&
		    test_opt(sb, INIT_INODE_TABLE))
			err = ecfs_register_li_request(sb, o_group);

resizefs_out:
		err2 = ecfs_resize_end(sb, true);
		if (err == 0)
			err = err2;
		return err;
	}

	case FITRIM:
	{
		struct fstrim_range range;
		int ret = 0;

		if (!capable(CAP_SYS_ADMIN))
			return -EPERM;

		if (!bdev_max_discard_sectors(sb->s_bdev))
			return -EOPNOTSUPP;

		/*
		 * We haven't replayed the journal, so we cannot use our
		 * block-bitmap-guided storage zapping commands.
		 */
		if (test_opt(sb, NOLOAD) && ecfs_has_feature_journal(sb))
			return -EROFS;

		if (copy_from_user(&range, (struct fstrim_range __user *)arg,
		    sizeof(range)))
			return -EFAULT;

		ret = ecfs_trim_fs(sb, &range);
		if (ret < 0)
			return ret;

		if (copy_to_user((struct fstrim_range __user *)arg, &range,
		    sizeof(range)))
			return -EFAULT;

		return 0;
	}
	case ECFS_IOC_PRECACHE_EXTENTS:
	{
		int ret;

		inode_lock_shared(inode);
		ret = ecfs_ext_precache(inode);
		inode_unlock_shared(inode);
		return ret;
	}
	case FS_IOC_SET_ENCRYPTION_POLICY:
		if (!ecfs_has_feature_encrypt(sb))
			return -EOPNOTSUPP;
		return fscrypt_ioctl_set_policy(filp, (const void __user *)arg);

	case FS_IOC_GET_ENCRYPTION_PWSALT:
		return ecfs_ioctl_get_encryption_pwsalt(filp, (void __user *)arg);

	case FS_IOC_GET_ENCRYPTION_POLICY:
		if (!ecfs_has_feature_encrypt(sb))
			return -EOPNOTSUPP;
		return fscrypt_ioctl_get_policy(filp, (void __user *)arg);

	case FS_IOC_GET_ENCRYPTION_POLICY_EX:
		if (!ecfs_has_feature_encrypt(sb))
			return -EOPNOTSUPP;
		return fscrypt_ioctl_get_policy_ex(filp, (void __user *)arg);

	case FS_IOC_ADD_ENCRYPTION_KEY:
		if (!ecfs_has_feature_encrypt(sb))
			return -EOPNOTSUPP;
		return fscrypt_ioctl_add_key(filp, (void __user *)arg);

	case FS_IOC_REMOVE_ENCRYPTION_KEY:
		if (!ecfs_has_feature_encrypt(sb))
			return -EOPNOTSUPP;
		return fscrypt_ioctl_remove_key(filp, (void __user *)arg);

	case FS_IOC_REMOVE_ENCRYPTION_KEY_ALL_USERS:
		if (!ecfs_has_feature_encrypt(sb))
			return -EOPNOTSUPP;
		return fscrypt_ioctl_remove_key_all_users(filp,
							  (void __user *)arg);
	case FS_IOC_GET_ENCRYPTION_KEY_STATUS:
		if (!ecfs_has_feature_encrypt(sb))
			return -EOPNOTSUPP;
		return fscrypt_ioctl_get_key_status(filp, (void __user *)arg);

	case FS_IOC_GET_ENCRYPTION_NONCE:
		if (!ecfs_has_feature_encrypt(sb))
			return -EOPNOTSUPP;
		return fscrypt_ioctl_get_nonce(filp, (void __user *)arg);

	case ECFS_IOC_CLEAR_ES_CACHE:
	{
		if (!inode_owner_or_capable(idmap, inode))
			return -EACCES;
		ecfs_clear_inode_es(inode);
		return 0;
	}

	case ECFS_IOC_GETSTATE:
	{
		__u32	state = 0;

		if (ecfs_test_inode_state(inode, ECFS_STATE_EXT_PRECACHED))
			state |= ECFS_STATE_FLAG_EXT_PRECACHED;
		if (ecfs_test_inode_state(inode, ECFS_STATE_NEW))
			state |= ECFS_STATE_FLAG_NEW;
		if (ecfs_test_inode_state(inode, ECFS_STATE_NEWENTRY))
			state |= ECFS_STATE_FLAG_NEWENTRY;
		if (ecfs_test_inode_state(inode, ECFS_STATE_DA_ALLOC_CLOSE))
			state |= ECFS_STATE_FLAG_DA_ALLOC_CLOSE;

		return put_user(state, (__u32 __user *) arg);
	}

	case ECFS_IOC_GET_ES_CACHE:
		return ecfs_ioctl_get_es_cache(filp, arg);

	case ECFS_IOC_SHUTDOWN:
		return ecfs_ioctl_shutdown(sb, arg);

	case FS_IOC_ENABLE_VERITY:
		if (!ecfs_has_feature_verity(sb))
			return -EOPNOTSUPP;
		return fsverity_ioctl_enable(filp, (const void __user *)arg);

	case FS_IOC_MEASURE_VERITY:
		if (!ecfs_has_feature_verity(sb))
			return -EOPNOTSUPP;
		return fsverity_ioctl_measure(filp, (void __user *)arg);

	case FS_IOC_READ_VERITY_METADATA:
		if (!ecfs_has_feature_verity(sb))
			return -EOPNOTSUPP;
		return fsverity_ioctl_read_metadata(filp,
						    (const void __user *)arg);

	case ECFS_IOC_CHECKPOINT:
		return ecfs_ioctl_checkpoint(filp, arg);

	case FS_IOC_GETFSLABEL:
		return ecfs_ioctl_getlabel(ECFS_SB(sb), (void __user *)arg);

	case FS_IOC_SETFSLABEL:
		return ecfs_ioctl_setlabel(filp,
					   (const void __user *)arg);

	case ECFS_IOC_GETFSUUID:
		return ecfs_ioctl_getuuid(ECFS_SB(sb), (void __user *)arg);
	case ECFS_IOC_SETFSUUID:
		return ecfs_ioctl_setuuid(filp, (const void __user *)arg);
	default:
		return -ENOTTY;
	}
}

long ecfs_ioctl(struct file *filp, unsigned int cmd, unsigned long arg)
{
	return __ecfs_ioctl(filp, cmd, arg);
}

#ifdef CONFIG_COMPAT
long ecfs_compat_ioctl(struct file *file, unsigned int cmd, unsigned long arg)
{
	/* These are just misnamed, they actually get/put from/to user an int */
	switch (cmd) {
	case ECFS_IOC32_GETVERSION:
		cmd = ECFS_IOC_GETVERSION;
		break;
	case ECFS_IOC32_SETVERSION:
		cmd = ECFS_IOC_SETVERSION;
		break;
	case ECFS_IOC32_GROUP_EXTEND:
		cmd = ECFS_IOC_GROUP_EXTEND;
		break;
	case ECFS_IOC32_GETVERSION_OLD:
		cmd = ECFS_IOC_GETVERSION_OLD;
		break;
	case ECFS_IOC32_SETVERSION_OLD:
		cmd = ECFS_IOC_SETVERSION_OLD;
		break;
	case ECFS_IOC32_GETRSVSZ:
		cmd = ECFS_IOC_GETRSVSZ;
		break;
	case ECFS_IOC32_SETRSVSZ:
		cmd = ECFS_IOC_SETRSVSZ;
		break;
	case ECFS_IOC32_GROUP_ADD: {
		struct compat_ecfs_new_group_input __user *uinput;
		struct ecfs_new_group_data input;
		int err;

		uinput = compat_ptr(arg);
		err = get_user(input.group, &uinput->group);
		err |= get_user(input.block_bitmap, &uinput->block_bitmap);
		err |= get_user(input.inode_bitmap, &uinput->inode_bitmap);
		err |= get_user(input.inode_table, &uinput->inode_table);
		err |= get_user(input.blocks_count, &uinput->blocks_count);
		err |= get_user(input.reserved_blocks,
				&uinput->reserved_blocks);
		if (err)
			return -EFAULT;
		return ecfs_ioctl_group_add(file, &input);
	}
	case ECFS_IOC_MOVE_EXT:
	case ECFS_IOC_RESIZE_FS:
	case FITRIM:
	case ECFS_IOC_PRECACHE_EXTENTS:
	case FS_IOC_SET_ENCRYPTION_POLICY:
	case FS_IOC_GET_ENCRYPTION_PWSALT:
	case FS_IOC_GET_ENCRYPTION_POLICY:
	case FS_IOC_GET_ENCRYPTION_POLICY_EX:
	case FS_IOC_ADD_ENCRYPTION_KEY:
	case FS_IOC_REMOVE_ENCRYPTION_KEY:
	case FS_IOC_REMOVE_ENCRYPTION_KEY_ALL_USERS:
	case FS_IOC_GET_ENCRYPTION_KEY_STATUS:
	case FS_IOC_GET_ENCRYPTION_NONCE:
	case ECFS_IOC_SHUTDOWN:
	case FS_IOC_GETFSMAP:
	case FS_IOC_ENABLE_VERITY:
	case FS_IOC_MEASURE_VERITY:
	case FS_IOC_READ_VERITY_METADATA:
	case ECFS_IOC_CLEAR_ES_CACHE:
	case ECFS_IOC_GETSTATE:
	case ECFS_IOC_GET_ES_CACHE:
	case ECFS_IOC_CHECKPOINT:
	case FS_IOC_GETFSLABEL:
	case FS_IOC_SETFSLABEL:
	case ECFS_IOC_GETFSUUID:
	case ECFS_IOC_SETFSUUID:
		break;
	default:
		return -ENOIOCTLCMD;
	}
	return ecfs_ioctl(file, cmd, (unsigned long) compat_ptr(arg));
}
#endif

static void set_overhead(struct ecfs_super_block *es, const void *arg)
{
	es->s_overhead_clusters = cpu_to_le32(*((unsigned long *) arg));
}

int ecfs_update_overhead(struct super_block *sb, bool force)
{
	struct ecfs_sb_info *sbi = ECFS_SB(sb);

	if (ecfs_emergency_state(sb) || sb_rdonly(sb))
		return 0;
	if (!force &&
	    (sbi->s_overhead == 0 ||
	     sbi->s_overhead == le32_to_cpu(sbi->s_es->s_overhead_clusters)))
		return 0;
	return ecfs_update_superblocks_fn(sb, set_overhead, &sbi->s_overhead);
}
