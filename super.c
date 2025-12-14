// SPDX-License-Identifier: GPL-2.0
/*
 *  linux/fs/ecfs/super.c
 *
 * Copyright (C) 1992, 1993, 1994, 1995
 * Remy Card (card@masi.ibp.fr)
 * Laboratoire MASI - Institut Blaise Pascal
 * Universite Pierre et Marie Curie (Paris VI)
 *
 *  from
 *
 *  linux/fs/minix/inode.c
 *
 *  Copyright (C) 1991, 1992  Linus Torvalds
 *
 *  Big-endian to little-endian byte-swapping/bitmaps by
 *        David S. Miller (davem@caip.rutgers.edu), 1995
 */

#include <linux/module.h>
#include <linux/string.h>
#include <linux/fs.h>
#include <linux/time.h>
#include <linux/vmalloc.h>
#include <linux/slab.h>
#include <linux/init.h>
#include <linux/blkdev.h>
#include <linux/backing-dev.h>
#include <linux/parser.h>
#include <linux/buffer_head.h>
#include <linux/exportfs.h>
#include <linux/vfs.h>
#include <linux/random.h>
#include <linux/mount.h>
#include <linux/namei.h>
#include <linux/quotaops.h>
#include <linux/seq_file.h>
#include <linux/ctype.h>
#include <linux/log2.h>
#include <linux/crc16.h>
#include <linux/dax.h>
#include <linux/uaccess.h>
#include <linux/iversion.h>
#include <linux/unicode.h>
#include <linux/part_stat.h>
#include <linux/kthread.h>
#include <linux/freezer.h>
#include <linux/fsnotify.h>
#include <linux/fs_context.h>
#include <linux/fs_parser.h>

#include "ecfs.h"
#include "ecfs_extents.h"	/* Needed for trace points definition */
#include "ecfs_jbd2.h"
#include "xattr.h"
#include "acl.h"
#include "mballoc.h"
#include "fsmap.h"

#define ECFS_SUPER_MAGIC	0xECF3

#define CREATE_TRACE_POINTS
#include <trace/events/ecfs.h>

static struct ecfs_lazy_init *ecfs_li_info;
static DEFINE_MUTEX(ecfs_li_mtx);
static struct ratelimit_state ecfs_mount_msg_ratelimit;

static int ecfs_load_journal(struct super_block *, struct ecfs_super_block *,
			     unsigned long journal_devnum);
static int ecfs_show_options(struct seq_file *seq, struct dentry *root);
static void ecfs_update_super(struct super_block *sb);
static int ecfs_commit_super(struct super_block *sb);
static int ecfs_mark_recovery_complete(struct super_block *sb,
					struct ecfs_super_block *es);
static int ecfs_clear_journal_err(struct super_block *sb,
				  struct ecfs_super_block *es);
static int ecfs_sync_fs(struct super_block *sb, int wait);
static int ecfs_statfs(struct dentry *dentry, struct kstatfs *buf);
static int ecfs_unfreeze(struct super_block *sb);
static int ecfs_freeze(struct super_block *sb);

static void ecfs_unregister_li_request(struct super_block *sb);
static void ecfs_clear_request_list(void);
static struct inode *ecfs_get_journal_inode(struct super_block *sb,
					    unsigned int journal_inum);
static int ecfs_validate_options(struct fs_context *fc);
static int ecfs_check_opt_consistency(struct fs_context *fc,
				      struct super_block *sb);
static void ecfs_apply_options(struct fs_context *fc, struct super_block *sb);
static int ecfs_parse_param(struct fs_context *fc, struct fs_parameter *param);
static int ecfs_get_tree(struct fs_context *fc);
static int ecfs_reconfigure(struct fs_context *fc);
static void ecfs_fc_free(struct fs_context *fc);
static int ecfs_init_fs_context(struct fs_context *fc);
static void ecfs_kill_sb(struct super_block *sb);
static const struct fs_parameter_spec ecfs_param_specs[];

/*
 * Lock ordering
 *
 * page fault path:
 * mmap_lock -> sb_start_pagefault -> invalidate_lock (r) -> transaction start
 *   -> page lock -> i_data_sem (rw)
 *
 * buffered write path:
 * sb_start_write -> i_mutex -> mmap_lock
 * sb_start_write -> i_mutex -> transaction start -> page lock ->
 *   i_data_sem (rw)
 *
 * truncate:
 * sb_start_write -> i_mutex -> invalidate_lock (w) -> i_mmap_rwsem (w) ->
 *   page lock
 * sb_start_write -> i_mutex -> invalidate_lock (w) -> transaction start ->
 *   i_data_sem (rw)
 *
 * direct IO:
 * sb_start_write -> i_mutex -> mmap_lock
 * sb_start_write -> i_mutex -> transaction start -> i_data_sem (rw)
 *
 * writepages:
 * transaction start -> page lock(s) -> i_data_sem (rw)
 */

static const struct fs_context_operations ecfs_context_ops = {
	.parse_param	= ecfs_parse_param,
	.get_tree	= ecfs_get_tree,
	.reconfigure	= ecfs_reconfigure,
	.free		= ecfs_fc_free,
};


static inline void __ecfs_read_bh(struct buffer_head *bh, blk_opf_t op_flags,
				  bh_end_io_t *end_io, bool simu_fail)
{
	if (simu_fail) {
		clear_buffer_uptodate(bh);
		unlock_buffer(bh);
		return;
	}

	/*
	 * buffer's verified bit is no longer valid after reading from
	 * disk again due to write out error, clear it to make sure we
	 * recheck the buffer contents.
	 */
	clear_buffer_verified(bh);

	bh->b_end_io = end_io ? end_io : end_buffer_read_sync;
	get_bh(bh);
	submit_bh(REQ_OP_READ | op_flags, bh);
}

void ecfs_read_bh_nowait(struct buffer_head *bh, blk_opf_t op_flags,
			 bh_end_io_t *end_io, bool simu_fail)
{
	BUG_ON(!buffer_locked(bh));

	if (ecfs_buffer_uptodate(bh)) {
		unlock_buffer(bh);
		return;
	}
	__ecfs_read_bh(bh, op_flags, end_io, simu_fail);
}

int ecfs_read_bh(struct buffer_head *bh, blk_opf_t op_flags,
		 bh_end_io_t *end_io, bool simu_fail)
{
	BUG_ON(!buffer_locked(bh));

	if (ecfs_buffer_uptodate(bh)) {
		unlock_buffer(bh);
		return 0;
	}

	__ecfs_read_bh(bh, op_flags, end_io, simu_fail);

	wait_on_buffer(bh);
	if (buffer_uptodate(bh))
		return 0;
	return -EIO;
}

int ecfs_read_bh_lock(struct buffer_head *bh, blk_opf_t op_flags, bool wait)
{
	lock_buffer(bh);
	if (!wait) {
		ecfs_read_bh_nowait(bh, op_flags, NULL, false);
		return 0;
	}
	return ecfs_read_bh(bh, op_flags, NULL, false);
}

/*
 * This works like __bread_gfp() except it uses ERR_PTR for error
 * returns.  Currently with sb_bread it's impossible to distinguish
 * between ENOMEM and EIO situations (since both result in a NULL
 * return.
 */
static struct buffer_head *__ecfs_sb_bread_gfp(struct super_block *sb,
					       sector_t block,
					       blk_opf_t op_flags, gfp_t gfp)
{
	struct buffer_head *bh;
	int ret;

	bh = sb_getblk_gfp(sb, block, gfp);
	if (bh == NULL)
		return ERR_PTR(-ENOMEM);
	if (ecfs_buffer_uptodate(bh))
		return bh;

	ret = ecfs_read_bh_lock(bh, REQ_META | op_flags, true);
	if (ret) {
		put_bh(bh);
		return ERR_PTR(ret);
	}
	return bh;
}

struct buffer_head *ecfs_sb_bread(struct super_block *sb, sector_t block,
				   blk_opf_t op_flags)
{
	gfp_t gfp = mapping_gfp_constraint(sb->s_bdev->bd_mapping,
			~__GFP_FS) | __GFP_MOVABLE;

	return __ecfs_sb_bread_gfp(sb, block, op_flags, gfp);
}

struct buffer_head *ecfs_sb_bread_unmovable(struct super_block *sb,
					    sector_t block)
{
	gfp_t gfp = mapping_gfp_constraint(sb->s_bdev->bd_mapping,
			~__GFP_FS);

	return __ecfs_sb_bread_gfp(sb, block, 0, gfp);
}

void ecfs_sb_breadahead_unmovable(struct super_block *sb, sector_t block)
{
	struct buffer_head *bh = bdev_getblk(sb->s_bdev, block,
			sb->s_blocksize, GFP_NOWAIT);

	if (likely(bh)) {
		if (trylock_buffer(bh))
			ecfs_read_bh_nowait(bh, REQ_RAHEAD, NULL, false);
		brelse(bh);
	}
}

static int ecfs_verify_csum_type(struct super_block *sb,
				 struct ecfs_super_block *es)
{
	if (!ecfs_has_feature_metadata_csum(sb))
		return 1;

	return es->s_checksum_type == ECFS_CRC32C_CHKSUM;
}

__le32 ecfs_superblock_csum(struct ecfs_super_block *es)
{
	int offset = offsetof(struct ecfs_super_block, s_checksum);
	__u32 csum;

	csum = ecfs_chksum(~0, (char *)es, offset);

	return cpu_to_le32(csum);
}

static int ecfs_superblock_csum_verify(struct super_block *sb,
				       struct ecfs_super_block *es)
{
	if (!ecfs_has_feature_metadata_csum(sb))
		return 1;

	return es->s_checksum == ecfs_superblock_csum(es);
}

void ecfs_superblock_csum_set(struct super_block *sb)
{
	struct ecfs_super_block *es = ECFS_SB(sb)->s_es;

	if (!ecfs_has_feature_metadata_csum(sb))
		return;

	es->s_checksum = ecfs_superblock_csum(es);
}

ecfs_fsblk_t ecfs_block_bitmap(struct super_block *sb,
			       struct ecfs_group_desc *bg)
{
	return le32_to_cpu(bg->bg_block_bitmap_lo) |
		(ECFS_DESC_SIZE(sb) >= ECFS_MIN_DESC_SIZE_64BIT ?
		 (ecfs_fsblk_t)le32_to_cpu(bg->bg_block_bitmap_hi) << 32 : 0);
}

ecfs_fsblk_t ecfs_inode_bitmap(struct super_block *sb,
			       struct ecfs_group_desc *bg)
{
	return le32_to_cpu(bg->bg_inode_bitmap_lo) |
		(ECFS_DESC_SIZE(sb) >= ECFS_MIN_DESC_SIZE_64BIT ?
		 (ecfs_fsblk_t)le32_to_cpu(bg->bg_inode_bitmap_hi) << 32 : 0);
}

ecfs_fsblk_t ecfs_inode_table(struct super_block *sb,
			      struct ecfs_group_desc *bg)
{
	return le32_to_cpu(bg->bg_inode_table_lo) |
		(ECFS_DESC_SIZE(sb) >= ECFS_MIN_DESC_SIZE_64BIT ?
		 (ecfs_fsblk_t)le32_to_cpu(bg->bg_inode_table_hi) << 32 : 0);
}

__u32 ecfs_free_group_clusters(struct super_block *sb,
			       struct ecfs_group_desc *bg)
{
	return le16_to_cpu(bg->bg_free_blocks_count_lo) |
		(ECFS_DESC_SIZE(sb) >= ECFS_MIN_DESC_SIZE_64BIT ?
		 (__u32)le16_to_cpu(bg->bg_free_blocks_count_hi) << 16 : 0);
}

__u32 ecfs_free_inodes_count(struct super_block *sb,
			      struct ecfs_group_desc *bg)
{
	return le16_to_cpu(READ_ONCE(bg->bg_free_inodes_count_lo)) |
		(ECFS_DESC_SIZE(sb) >= ECFS_MIN_DESC_SIZE_64BIT ?
		 (__u32)le16_to_cpu(READ_ONCE(bg->bg_free_inodes_count_hi)) << 16 : 0);
}

__u32 ecfs_used_dirs_count(struct super_block *sb,
			      struct ecfs_group_desc *bg)
{
	return le16_to_cpu(bg->bg_used_dirs_count_lo) |
		(ECFS_DESC_SIZE(sb) >= ECFS_MIN_DESC_SIZE_64BIT ?
		 (__u32)le16_to_cpu(bg->bg_used_dirs_count_hi) << 16 : 0);
}

__u32 ecfs_itable_unused_count(struct super_block *sb,
			      struct ecfs_group_desc *bg)
{
	return le16_to_cpu(bg->bg_itable_unused_lo) |
		(ECFS_DESC_SIZE(sb) >= ECFS_MIN_DESC_SIZE_64BIT ?
		 (__u32)le16_to_cpu(bg->bg_itable_unused_hi) << 16 : 0);
}

void ecfs_block_bitmap_set(struct super_block *sb,
			   struct ecfs_group_desc *bg, ecfs_fsblk_t blk)
{
	bg->bg_block_bitmap_lo = cpu_to_le32((u32)blk);
	if (ECFS_DESC_SIZE(sb) >= ECFS_MIN_DESC_SIZE_64BIT)
		bg->bg_block_bitmap_hi = cpu_to_le32(blk >> 32);
}

void ecfs_inode_bitmap_set(struct super_block *sb,
			   struct ecfs_group_desc *bg, ecfs_fsblk_t blk)
{
	bg->bg_inode_bitmap_lo  = cpu_to_le32((u32)blk);
	if (ECFS_DESC_SIZE(sb) >= ECFS_MIN_DESC_SIZE_64BIT)
		bg->bg_inode_bitmap_hi = cpu_to_le32(blk >> 32);
}

void ecfs_inode_table_set(struct super_block *sb,
			  struct ecfs_group_desc *bg, ecfs_fsblk_t blk)
{
	bg->bg_inode_table_lo = cpu_to_le32((u32)blk);
	if (ECFS_DESC_SIZE(sb) >= ECFS_MIN_DESC_SIZE_64BIT)
		bg->bg_inode_table_hi = cpu_to_le32(blk >> 32);
}

void ecfs_free_group_clusters_set(struct super_block *sb,
				  struct ecfs_group_desc *bg, __u32 count)
{
	bg->bg_free_blocks_count_lo = cpu_to_le16((__u16)count);
	if (ECFS_DESC_SIZE(sb) >= ECFS_MIN_DESC_SIZE_64BIT)
		bg->bg_free_blocks_count_hi = cpu_to_le16(count >> 16);
}

void ecfs_free_inodes_set(struct super_block *sb,
			  struct ecfs_group_desc *bg, __u32 count)
{
	WRITE_ONCE(bg->bg_free_inodes_count_lo, cpu_to_le16((__u16)count));
	if (ECFS_DESC_SIZE(sb) >= ECFS_MIN_DESC_SIZE_64BIT)
		WRITE_ONCE(bg->bg_free_inodes_count_hi, cpu_to_le16(count >> 16));
}

void ecfs_used_dirs_set(struct super_block *sb,
			  struct ecfs_group_desc *bg, __u32 count)
{
	bg->bg_used_dirs_count_lo = cpu_to_le16((__u16)count);
	if (ECFS_DESC_SIZE(sb) >= ECFS_MIN_DESC_SIZE_64BIT)
		bg->bg_used_dirs_count_hi = cpu_to_le16(count >> 16);
}

void ecfs_itable_unused_set(struct super_block *sb,
			  struct ecfs_group_desc *bg, __u32 count)
{
	bg->bg_itable_unused_lo = cpu_to_le16((__u16)count);
	if (ECFS_DESC_SIZE(sb) >= ECFS_MIN_DESC_SIZE_64BIT)
		bg->bg_itable_unused_hi = cpu_to_le16(count >> 16);
}

static void __ecfs_update_tstamp(__le32 *lo, __u8 *hi, time64_t now)
{
	now = clamp_val(now, 0, (1ull << 40) - 1);

	*lo = cpu_to_le32(lower_32_bits(now));
	*hi = upper_32_bits(now);
}

static time64_t __ecfs_get_tstamp(__le32 *lo, __u8 *hi)
{
	return ((time64_t)(*hi) << 32) + le32_to_cpu(*lo);
}
#define ecfs_update_tstamp(es, tstamp) \
	__ecfs_update_tstamp(&(es)->tstamp, &(es)->tstamp ## _hi, \
			     ktime_get_real_seconds())
#define ecfs_get_tstamp(es, tstamp) \
	__ecfs_get_tstamp(&(es)->tstamp, &(es)->tstamp ## _hi)

/*
 * The ecfs_maybe_update_superblock() function checks and updates the
 * superblock if needed.
 *
 * This function is designed to update the on-disk superblock only under
 * certain conditions to prevent excessive disk writes and unnecessary
 * waking of the disk from sleep. The superblock will be updated if:
 * 1. More than sbi->s_sb_update_sec (def: 1 hour) has passed since the last
 *    superblock update
 * 2. More than sbi->s_sb_update_kb (def: 16MB) kbs have been written since the
 *    last superblock update.
 *
 * @sb: The superblock
 */
static void ecfs_maybe_update_superblock(struct super_block *sb)
{
	struct ecfs_sb_info *sbi = ECFS_SB(sb);
	struct ecfs_super_block *es = sbi->s_es;
	journal_t *journal = sbi->s_journal;
	time64_t now;
	__u64 last_update;
	__u64 lifetime_write_kbytes;
	__u64 diff_size;

	if (ecfs_emergency_state(sb) || sb_rdonly(sb) ||
	    !(sb->s_flags & SB_ACTIVE) || !journal ||
	    journal->j_flags & JBD2_UNMOUNT)
		return;

	now = ktime_get_real_seconds();
	last_update = ecfs_get_tstamp(es, s_wtime);

	if (likely(now - last_update < sbi->s_sb_update_sec))
		return;

	lifetime_write_kbytes = sbi->s_kbytes_written +
		((part_stat_read(sb->s_bdev, sectors[STAT_WRITE]) -
		  sbi->s_sectors_written_start) >> 1);

	/* Get the number of kilobytes not written to disk to account
	 * for statistics and compare with a multiple of 16 MB. This
	 * is used to determine when the next superblock commit should
	 * occur (i.e. not more often than once per 16MB if there was
	 * less written in an hour).
	 */
	diff_size = lifetime_write_kbytes - le64_to_cpu(es->s_kbytes_written);

	if (diff_size > sbi->s_sb_update_kb)
		schedule_work(&ECFS_SB(sb)->s_sb_upd_work);
}

static void ecfs_journal_commit_callback(journal_t *journal, transaction_t *txn)
{
	struct super_block		*sb = journal->j_private;

	BUG_ON(txn->t_state == T_FINISHED);

	ecfs_process_freed_data(sb, txn->t_tid);
	ecfs_maybe_update_superblock(sb);
}

static bool ecfs_journalled_writepage_needs_redirty(struct jbd2_inode *jinode,
		struct folio *folio)
{
	struct buffer_head *bh, *head;
	struct journal_head *jh;

	bh = head = folio_buffers(folio);
	do {
		/*
		 * We have to redirty a page in these cases:
		 * 1) If buffer is dirty, it means the page was dirty because it
		 * contains a buffer that needs checkpointing. So the dirty bit
		 * needs to be preserved so that checkpointing writes the buffer
		 * properly.
		 * 2) If buffer is not part of the committing transaction
		 * (we may have just accidentally come across this buffer because
		 * inode range tracking is not exact) or if the currently running
		 * transaction already contains this buffer as well, dirty bit
		 * needs to be preserved so that the buffer gets writeprotected
		 * properly on running transaction's commit.
		 */
		jh = bh2jh(bh);
		if (buffer_dirty(bh) ||
		    (jh && (jh->b_transaction != jinode->i_transaction ||
			    jh->b_next_transaction)))
			return true;
	} while ((bh = bh->b_this_page) != head);

	return false;
}

static int ecfs_journalled_submit_inode_data_buffers(struct jbd2_inode *jinode)
{
	struct address_space *mapping = jinode->i_vfs_inode->i_mapping;
	struct writeback_control wbc = {
		.sync_mode =  WB_SYNC_ALL,
		.nr_to_write = LONG_MAX,
		.range_start = jinode->i_dirty_start,
		.range_end = jinode->i_dirty_end,
        };
	struct folio *folio = NULL;
	int error;

	/*
	 * writeback_iter() already checks for dirty pages and calls
	 * folio_clear_dirty_for_io(), which we want to write protect the
	 * folios.
	 *
	 * However, we may have to redirty a folio sometimes.
	 */
	while ((folio = writeback_iter(mapping, &wbc, folio, &error))) {
		if (ecfs_journalled_writepage_needs_redirty(jinode, folio))
			folio_redirty_for_writepage(&wbc, folio);
		folio_unlock(folio);
	}

	return error;
}

static int ecfs_journal_submit_inode_data_buffers(struct jbd2_inode *jinode)
{
	int ret;

	if (ecfs_should_journal_data(jinode->i_vfs_inode))
		ret = ecfs_journalled_submit_inode_data_buffers(jinode);
	else
		ret = ecfs_normal_submit_inode_data_buffers(jinode);
	return ret;
}

static int ecfs_journal_finish_inode_data_buffers(struct jbd2_inode *jinode)
{
	int ret = 0;

	if (!ecfs_should_journal_data(jinode->i_vfs_inode))
		ret = jbd2_journal_finish_inode_data_buffers(jinode);

	return ret;
}

static bool system_going_down(void)
{
	return system_state == SYSTEM_HALT || system_state == SYSTEM_POWER_OFF
		|| system_state == SYSTEM_RESTART;
}

struct ecfs_err_translation {
	int code;
	int errno;
};

#define ECFS_ERR_TRANSLATE(err) { .code = ECFS_ERR_##err, .errno = err }

static struct ecfs_err_translation err_translation[] = {
	ECFS_ERR_TRANSLATE(EIO),
	ECFS_ERR_TRANSLATE(ENOMEM),
	ECFS_ERR_TRANSLATE(EFSBADCRC),
	ECFS_ERR_TRANSLATE(EFSCORRUPTED),
	ECFS_ERR_TRANSLATE(ENOSPC),
	ECFS_ERR_TRANSLATE(ENOKEY),
	ECFS_ERR_TRANSLATE(EROFS),
	ECFS_ERR_TRANSLATE(EFBIG),
	ECFS_ERR_TRANSLATE(EEXIST),
	ECFS_ERR_TRANSLATE(ERANGE),
	ECFS_ERR_TRANSLATE(EOVERFLOW),
	ECFS_ERR_TRANSLATE(EBUSY),
	ECFS_ERR_TRANSLATE(ENOTDIR),
	ECFS_ERR_TRANSLATE(ENOTEMPTY),
	ECFS_ERR_TRANSLATE(ESHUTDOWN),
	ECFS_ERR_TRANSLATE(EFAULT),
};

static int ecfs_errno_to_code(int errno)
{
	int i;

	for (i = 0; i < ARRAY_SIZE(err_translation); i++)
		if (err_translation[i].errno == errno)
			return err_translation[i].code;
	return ECFS_ERR_UNKNOWN;
}

static void save_error_info(struct super_block *sb, int error,
			    __u32 ino, __u64 block,
			    const char *func, unsigned int line)
{
	struct ecfs_sb_info *sbi = ECFS_SB(sb);

	/* We default to EFSCORRUPTED error... */
	if (error == 0)
		error = EFSCORRUPTED;

	spin_lock(&sbi->s_error_lock);
	sbi->s_add_error_count++;
	sbi->s_last_error_code = error;
	sbi->s_last_error_line = line;
	sbi->s_last_error_ino = ino;
	sbi->s_last_error_block = block;
	sbi->s_last_error_func = func;
	sbi->s_last_error_time = ktime_get_real_seconds();
	if (!sbi->s_first_error_time) {
		sbi->s_first_error_code = error;
		sbi->s_first_error_line = line;
		sbi->s_first_error_ino = ino;
		sbi->s_first_error_block = block;
		sbi->s_first_error_func = func;
		sbi->s_first_error_time = sbi->s_last_error_time;
	}
	spin_unlock(&sbi->s_error_lock);
}

/* Deal with the reporting of failure conditions on a filesystem such as
 * inconsistencies detected or read IO failures.
 *
 * On ext2, we can store the error state of the filesystem in the
 * superblock.  That is not possible on ecfs, because we may have other
 * write ordering constraints on the superblock which prevent us from
 * writing it out straight away; and given that the journal is about to
 * be aborted, we can't rely on the current, or future, transactions to
 * write out the superblock safely.
 *
 * We'll just use the jbd2_journal_abort() error code to record an error in
 * the journal instead.  On recovery, the journal will complain about
 * that error until we've noted it down and cleared it.
 *
 * If force_ro is set, we unconditionally force the filesystem into an
 * ABORT|READONLY state, unless the error response on the fs has been set to
 * panic in which case we take the easy way out and panic immediately. This is
 * used to deal with unrecoverable failures such as journal IO errors or ENOMEM
 * at a critical moment in log management.
 */
static void ecfs_handle_error(struct super_block *sb, bool force_ro, int error,
			      __u32 ino, __u64 block,
			      const char *func, unsigned int line)
{
	journal_t *journal = ECFS_SB(sb)->s_journal;
	bool continue_fs = !force_ro && test_opt(sb, ERRORS_CONT);

	ECFS_SB(sb)->s_mount_state |= ECFS_ERROR_FS;
	if (test_opt(sb, WARN_ON_ERROR))
		WARN_ON_ONCE(1);

	if (!continue_fs && !ecfs_emergency_ro(sb) && journal)
		jbd2_journal_abort(journal, -EIO);

	if (!bdev_read_only(sb->s_bdev)) {
		save_error_info(sb, error, ino, block, func, line);
		/*
		 * In case the fs should keep running, we need to writeout
		 * superblock through the journal. Due to lock ordering
		 * constraints, it may not be safe to do it right here so we
		 * defer superblock flushing to a workqueue. We just need to be
		 * careful when the journal is already shutting down. If we get
		 * here in that case, just update the sb directly as the last
		 * transaction won't commit anyway.
		 */
		if (continue_fs && journal &&
		    !ecfs_test_mount_flag(sb, ECFS_MF_JOURNAL_DESTROY))
			schedule_work(&ECFS_SB(sb)->s_sb_upd_work);
		else
			ecfs_commit_super(sb);
	}

	/*
	 * We force ERRORS_RO behavior when system is rebooting. Otherwise we
	 * could panic during 'reboot -f' as the underlying device got already
	 * disabled.
	 */
	if (test_opt(sb, ERRORS_PANIC) && !system_going_down()) {
		panic("ECFS-fs (device %s): panic forced after error\n",
			sb->s_id);
	}

	if (ecfs_emergency_ro(sb) || continue_fs)
		return;

	ecfs_msg(sb, KERN_CRIT, "Remounting filesystem read-only");
	/*
	 * We don't set SB_RDONLY because that requires sb->s_umount
	 * semaphore and setting it without proper remount procedure is
	 * confusing code such as freeze_super() leading to deadlocks
	 * and other problems.
	 */
	set_bit(ECFS_FLAGS_EMERGENCY_RO, &ECFS_SB(sb)->s_ecfs_flags);
}

static void update_super_work(struct work_struct *work)
{
	struct ecfs_sb_info *sbi = container_of(work, struct ecfs_sb_info,
						s_sb_upd_work);
	journal_t *journal = sbi->s_journal;
	handle_t *handle;

	/*
	 * If the journal is still running, we have to write out superblock
	 * through the journal to avoid collisions of other journalled sb
	 * updates.
	 *
	 * We use directly jbd2 functions here to avoid recursing back into
	 * ecfs error handling code during handling of previous errors.
	 */
	if (!ecfs_emergency_state(sbi->s_sb) &&
	    !sb_rdonly(sbi->s_sb) && journal) {
		struct buffer_head *sbh = sbi->s_sbh;
		bool call_notify_err = false;

		handle = jbd2_journal_start(journal, 1);
		if (IS_ERR(handle))
			goto write_directly;
		if (jbd2_journal_get_write_access(handle, sbh)) {
			jbd2_journal_stop(handle);
			goto write_directly;
		}

		if (sbi->s_add_error_count > 0)
			call_notify_err = true;

		ecfs_update_super(sbi->s_sb);
		if (buffer_write_io_error(sbh) || !buffer_uptodate(sbh)) {
			ecfs_msg(sbi->s_sb, KERN_ERR, "previous I/O error to "
				 "superblock detected");
			clear_buffer_write_io_error(sbh);
			set_buffer_uptodate(sbh);
		}

		if (jbd2_journal_dirty_metadata(handle, sbh)) {
			jbd2_journal_stop(handle);
			goto write_directly;
		}
		jbd2_journal_stop(handle);

		if (call_notify_err)
			ecfs_notify_error_sysfs(sbi);

		return;
	}
write_directly:
	/*
	 * Write through journal failed. Write sb directly to get error info
	 * out and hope for the best.
	 */
	ecfs_commit_super(sbi->s_sb);
	ecfs_notify_error_sysfs(sbi);
}

#define ecfs_error_ratelimit(sb)					\
		___ratelimit(&(ECFS_SB(sb)->s_err_ratelimit_state),	\
			     "ECFS-fs error")

void __ecfs_error(struct super_block *sb, const char *function,
		  unsigned int line, bool force_ro, int error, __u64 block,
		  const char *fmt, ...)
{
	struct va_format vaf;
	va_list args;

	if (unlikely(ecfs_emergency_state(sb)))
		return;

	trace_ecfs_error(sb, function, line);
	if (ecfs_error_ratelimit(sb)) {
		va_start(args, fmt);
		vaf.fmt = fmt;
		vaf.va = &args;
		printk(KERN_CRIT
		       "ECFS-fs error (device %s): %s:%d: comm %s: %pV\n",
		       sb->s_id, function, line, current->comm, &vaf);
		va_end(args);
	}
	fsnotify_sb_error(sb, NULL, error ? error : EFSCORRUPTED);

	ecfs_handle_error(sb, force_ro, error, 0, block, function, line);
}

void __ecfs_error_inode(struct inode *inode, const char *function,
			unsigned int line, ecfs_fsblk_t block, int error,
			const char *fmt, ...)
{
	va_list args;
	struct va_format vaf;

	if (unlikely(ecfs_emergency_state(inode->i_sb)))
		return;

	trace_ecfs_error(inode->i_sb, function, line);
	if (ecfs_error_ratelimit(inode->i_sb)) {
		va_start(args, fmt);
		vaf.fmt = fmt;
		vaf.va = &args;
		if (block)
			printk(KERN_CRIT "ECFS-fs error (device %s): %s:%d: "
			       "inode #%lu: block %llu: comm %s: %pV\n",
			       inode->i_sb->s_id, function, line, inode->i_ino,
			       block, current->comm, &vaf);
		else
			printk(KERN_CRIT "ECFS-fs error (device %s): %s:%d: "
			       "inode #%lu: comm %s: %pV\n",
			       inode->i_sb->s_id, function, line, inode->i_ino,
			       current->comm, &vaf);
		va_end(args);
	}
	fsnotify_sb_error(inode->i_sb, inode, error ? error : EFSCORRUPTED);

	ecfs_handle_error(inode->i_sb, false, error, inode->i_ino, block,
			  function, line);
}

void __ecfs_error_file(struct file *file, const char *function,
		       unsigned int line, ecfs_fsblk_t block,
		       const char *fmt, ...)
{
	va_list args;
	struct va_format vaf;
	struct inode *inode = file_inode(file);
	char pathname[80], *path;

	if (unlikely(ecfs_emergency_state(inode->i_sb)))
		return;

	trace_ecfs_error(inode->i_sb, function, line);
	if (ecfs_error_ratelimit(inode->i_sb)) {
		path = file_path(file, pathname, sizeof(pathname));
		if (IS_ERR(path))
			path = "(unknown)";
		va_start(args, fmt);
		vaf.fmt = fmt;
		vaf.va = &args;
		if (block)
			printk(KERN_CRIT
			       "ECFS-fs error (device %s): %s:%d: inode #%lu: "
			       "block %llu: comm %s: path %s: %pV\n",
			       inode->i_sb->s_id, function, line, inode->i_ino,
			       block, current->comm, path, &vaf);
		else
			printk(KERN_CRIT
			       "ECFS-fs error (device %s): %s:%d: inode #%lu: "
			       "comm %s: path %s: %pV\n",
			       inode->i_sb->s_id, function, line, inode->i_ino,
			       current->comm, path, &vaf);
		va_end(args);
	}
	fsnotify_sb_error(inode->i_sb, inode, EFSCORRUPTED);

	ecfs_handle_error(inode->i_sb, false, EFSCORRUPTED, inode->i_ino, block,
			  function, line);
}

const char *ecfs_decode_error(struct super_block *sb, int errno,
			      char nbuf[16])
{
	char *errstr = NULL;

	switch (errno) {
	case -EFSCORRUPTED:
		errstr = "Corrupt filesystem";
		break;
	case -EFSBADCRC:
		errstr = "Filesystem failed CRC";
		break;
	case -EIO:
		errstr = "IO failure";
		break;
	case -ENOMEM:
		errstr = "Out of memory";
		break;
	case -EROFS:
		if (!sb || (ECFS_SB(sb)->s_journal &&
			    ECFS_SB(sb)->s_journal->j_flags & JBD2_ABORT))
			errstr = "Journal has aborted";
		else
			errstr = "Readonly filesystem";
		break;
	default:
		/* If the caller passed in an extra buffer for unknown
		 * errors, textualise them now.  Else we just return
		 * NULL. */
		if (nbuf) {
			/* Check for truncated error codes... */
			if (snprintf(nbuf, 16, "error %d", -errno) >= 0)
				errstr = nbuf;
		}
		break;
	}

	return errstr;
}

/* __ecfs_std_error decodes expected errors from journaling functions
 * automatically and invokes the appropriate error response.  */

void __ecfs_std_error(struct super_block *sb, const char *function,
		      unsigned int line, int errno)
{
	char nbuf[16];
	const char *errstr;

	if (unlikely(ecfs_emergency_state(sb)))
		return;

	/* Special case: if the error is EROFS, and we're not already
	 * inside a transaction, then there's really no point in logging
	 * an error. */
	if (errno == -EROFS && journal_current_handle() == NULL && sb_rdonly(sb))
		return;

	if (ecfs_error_ratelimit(sb)) {
		errstr = ecfs_decode_error(sb, errno, nbuf);
		printk(KERN_CRIT "ECFS-fs error (device %s) in %s:%d: %s\n",
		       sb->s_id, function, line, errstr);
	}
	fsnotify_sb_error(sb, NULL, errno ? errno : EFSCORRUPTED);

	ecfs_handle_error(sb, false, -errno, 0, 0, function, line);
}

void __ecfs_msg(struct super_block *sb,
		const char *prefix, const char *fmt, ...)
{
	struct va_format vaf;
	va_list args;

	if (sb) {
		atomic_inc(&ECFS_SB(sb)->s_msg_count);
		if (!___ratelimit(&(ECFS_SB(sb)->s_msg_ratelimit_state),
				  "ECFS-fs"))
			return;
	}

	va_start(args, fmt);
	vaf.fmt = fmt;
	vaf.va = &args;
	if (sb)
		printk("%sECFS-fs (%s): %pV\n", prefix, sb->s_id, &vaf);
	else
		printk("%sECFS-fs: %pV\n", prefix, &vaf);
	va_end(args);
}

static int ecfs_warning_ratelimit(struct super_block *sb)
{
	atomic_inc(&ECFS_SB(sb)->s_warning_count);
	return ___ratelimit(&(ECFS_SB(sb)->s_warning_ratelimit_state),
			    "ECFS-fs warning");
}

void __ecfs_warning(struct super_block *sb, const char *function,
		    unsigned int line, const char *fmt, ...)
{
	struct va_format vaf;
	va_list args;

	if (!ecfs_warning_ratelimit(sb))
		return;

	va_start(args, fmt);
	vaf.fmt = fmt;
	vaf.va = &args;
	printk(KERN_WARNING "ECFS-fs warning (device %s): %s:%d: %pV\n",
	       sb->s_id, function, line, &vaf);
	va_end(args);
}

void __ecfs_warning_inode(const struct inode *inode, const char *function,
			  unsigned int line, const char *fmt, ...)
{
	struct va_format vaf;
	va_list args;

	if (!ecfs_warning_ratelimit(inode->i_sb))
		return;

	va_start(args, fmt);
	vaf.fmt = fmt;
	vaf.va = &args;
	printk(KERN_WARNING "ECFS-fs warning (device %s): %s:%d: "
	       "inode #%lu: comm %s: %pV\n", inode->i_sb->s_id,
	       function, line, inode->i_ino, current->comm, &vaf);
	va_end(args);
}

void __ecfs_grp_locked_error(const char *function, unsigned int line,
			     struct super_block *sb, ecfs_group_t grp,
			     unsigned long ino, ecfs_fsblk_t block,
			     const char *fmt, ...)
__releases(bitlock)
__acquires(bitlock)
{
	struct va_format vaf;
	va_list args;

	if (unlikely(ecfs_emergency_state(sb)))
		return;

	trace_ecfs_error(sb, function, line);
	if (ecfs_error_ratelimit(sb)) {
		va_start(args, fmt);
		vaf.fmt = fmt;
		vaf.va = &args;
		printk(KERN_CRIT "ECFS-fs error (device %s): %s:%d: group %u, ",
		       sb->s_id, function, line, grp);
		if (ino)
			printk(KERN_CONT "inode %lu: ", ino);
		if (block)
			printk(KERN_CONT "block %llu:",
			       (unsigned long long) block);
		printk(KERN_CONT "%pV\n", &vaf);
		va_end(args);
	}

	if (test_opt(sb, ERRORS_CONT)) {
		if (test_opt(sb, WARN_ON_ERROR))
			WARN_ON_ONCE(1);
		ECFS_SB(sb)->s_mount_state |= ECFS_ERROR_FS;
		if (!bdev_read_only(sb->s_bdev)) {
			save_error_info(sb, EFSCORRUPTED, ino, block, function,
					line);
			schedule_work(&ECFS_SB(sb)->s_sb_upd_work);
		}
		return;
	}
	ecfs_unlock_group(sb, grp);
	ecfs_handle_error(sb, false, EFSCORRUPTED, ino, block, function, line);
	/*
	 * We only get here in the ERRORS_RO case; relocking the group
	 * may be dangerous, but nothing bad will happen since the
	 * filesystem will have already been marked read/only and the
	 * journal has been aborted.  We return 1 as a hint to callers
	 * who might what to use the return value from
	 * ecfs_grp_locked_error() to distinguish between the
	 * ERRORS_CONT and ERRORS_RO case, and perhaps return more
	 * aggressively from the ecfs function in question, with a
	 * more appropriate error code.
	 */
	ecfs_lock_group(sb, grp);
	return;
}

void ecfs_mark_group_bitmap_corrupted(struct super_block *sb,
				     ecfs_group_t group,
				     unsigned int flags)
{
	struct ecfs_sb_info *sbi = ECFS_SB(sb);
	struct ecfs_group_info *grp = ecfs_get_group_info(sb, group);
	struct ecfs_group_desc *gdp = ecfs_get_group_desc(sb, group, NULL);
	int ret;

	if (!grp || !gdp)
		return;
	if (flags & ECFS_GROUP_INFO_BBITMAP_CORRUPT) {
		ret = ecfs_test_and_set_bit(ECFS_GROUP_INFO_BBITMAP_CORRUPT_BIT,
					    &grp->bb_state);
		if (!ret)
			percpu_counter_sub(&sbi->s_freeclusters_counter,
					   grp->bb_free);
	}

	if (flags & ECFS_GROUP_INFO_IBITMAP_CORRUPT) {
		ret = ecfs_test_and_set_bit(ECFS_GROUP_INFO_IBITMAP_CORRUPT_BIT,
					    &grp->bb_state);
		if (!ret && gdp) {
			int count;

			count = ecfs_free_inodes_count(sb, gdp);
			percpu_counter_sub(&sbi->s_freeinodes_counter,
					   count);
		}
	}
}

void ecfs_update_dynamic_rev(struct super_block *sb)
{
	struct ecfs_super_block *es = ECFS_SB(sb)->s_es;

	if (le32_to_cpu(es->s_rev_level) > ECFS_GOOD_OLD_REV)
		return;

	ecfs_warning(sb,
		     "updating to rev %d because of new feature flag, "
		     "running e2fsck is recommended",
		     ECFS_DYNAMIC_REV);

	es->s_first_ino = cpu_to_le32(ECFS_GOOD_OLD_FIRST_INO);
	es->s_inode_size = cpu_to_le16(ECFS_GOOD_OLD_INODE_SIZE);
	es->s_rev_level = cpu_to_le32(ECFS_DYNAMIC_REV);
	/* leave es->s_feature_*compat flags alone */
	/* es->s_uuid will be set by e2fsck if empty */

	/*
	 * The rest of the superblock fields should be zero, and if not it
	 * means they are likely already in use, so leave them alone.  We
	 * can leave it up to e2fsck to clean up any inconsistencies there.
	 */
}

static inline struct inode *orphan_list_entry(struct list_head *l)
{
	return &list_entry(l, struct ecfs_inode_info, i_orphan)->vfs_inode;
}

static void dump_orphan_list(struct super_block *sb, struct ecfs_sb_info *sbi)
{
	struct list_head *l;

	ecfs_msg(sb, KERN_ERR, "sb orphan head is %d",
		 le32_to_cpu(sbi->s_es->s_last_orphan));

	printk(KERN_ERR "sb_info orphan list:\n");
	list_for_each(l, &sbi->s_orphan) {
		struct inode *inode = orphan_list_entry(l);
		printk(KERN_ERR "  "
		       "inode %s:%lu at %p: mode %o, nlink %d, next %d\n",
		       inode->i_sb->s_id, inode->i_ino, inode,
		       inode->i_mode, inode->i_nlink,
		       NEXT_ORPHAN(inode));
	}
}

#ifdef CONFIG_QUOTA
static int ecfs_quota_off(struct super_block *sb, int type);

static inline void ecfs_quotas_off(struct super_block *sb, int type)
{
	BUG_ON(type > ECFS_MAXQUOTAS);

	/* Use our quota_off function to clear inode flags etc. */
	for (type--; type >= 0; type--)
		ecfs_quota_off(sb, type);
}

/*
 * This is a helper function which is used in the mount/remount
 * codepaths (which holds s_umount) to fetch the quota file name.
 */
static inline char *get_qf_name(struct super_block *sb,
				struct ecfs_sb_info *sbi,
				int type)
{
	return rcu_dereference_protected(sbi->s_qf_names[type],
					 lockdep_is_held(&sb->s_umount));
}
#else
static inline void ecfs_quotas_off(struct super_block *sb, int type)
{
}
#endif

static int ecfs_percpu_param_init(struct ecfs_sb_info *sbi)
{
	ecfs_fsblk_t block;
	int err;

	block = ecfs_count_free_clusters(sbi->s_sb);
	ecfs_free_blocks_count_set(sbi->s_es, ECFS_C2B(sbi, block));
	err = percpu_counter_init(&sbi->s_freeclusters_counter, block,
				  GFP_KERNEL);
	if (!err) {
		unsigned long freei = ecfs_count_free_inodes(sbi->s_sb);
		sbi->s_es->s_free_inodes_count = cpu_to_le32(freei);
		err = percpu_counter_init(&sbi->s_freeinodes_counter, freei,
					  GFP_KERNEL);
	}
	if (!err)
		err = percpu_counter_init(&sbi->s_dirs_counter,
					  ecfs_count_dirs(sbi->s_sb), GFP_KERNEL);
	if (!err)
		err = percpu_counter_init(&sbi->s_dirtyclusters_counter, 0,
					  GFP_KERNEL);
	if (!err)
		err = percpu_counter_init(&sbi->s_sra_exceeded_retry_limit, 0,
					  GFP_KERNEL);
	if (!err)
		err = percpu_init_rwsem(&sbi->s_writepages_rwsem);

	if (err)
		ecfs_msg(sbi->s_sb, KERN_ERR, "insufficient memory");

	return err;
}

static void ecfs_percpu_param_destroy(struct ecfs_sb_info *sbi)
{
	percpu_counter_destroy(&sbi->s_freeclusters_counter);
	percpu_counter_destroy(&sbi->s_freeinodes_counter);
	percpu_counter_destroy(&sbi->s_dirs_counter);
	percpu_counter_destroy(&sbi->s_dirtyclusters_counter);
	percpu_counter_destroy(&sbi->s_sra_exceeded_retry_limit);
	percpu_free_rwsem(&sbi->s_writepages_rwsem);
}

static void ecfs_group_desc_free(struct ecfs_sb_info *sbi)
{
	struct buffer_head **group_desc;
	int i;

	rcu_read_lock();
	group_desc = rcu_dereference(sbi->s_group_desc);
	for (i = 0; i < sbi->s_gdb_count; i++)
		brelse(group_desc[i]);
	kvfree(group_desc);
	rcu_read_unlock();
}

static void ecfs_flex_groups_free(struct ecfs_sb_info *sbi)
{
	struct flex_groups **flex_groups;
	int i;

	rcu_read_lock();
	flex_groups = rcu_dereference(sbi->s_flex_groups);
	if (flex_groups) {
		for (i = 0; i < sbi->s_flex_groups_allocated; i++)
			kvfree(flex_groups[i]);
		kvfree(flex_groups);
	}
	rcu_read_unlock();
}

static void ecfs_put_super(struct super_block *sb)
{
	struct ecfs_sb_info *sbi = ECFS_SB(sb);
	struct ecfs_super_block *es = sbi->s_es;
	int aborted = 0;
	int err;

	/*
	 * Unregister sysfs before destroying jbd2 journal.
	 * Since we could still access attr_journal_task attribute via sysfs
	 * path which could have sbi->s_journal->j_task as NULL
	 * Unregister sysfs before flush sbi->s_sb_upd_work.
	 * Since user may read /proc/fs/ecfs/xx/mb_groups during umount, If
	 * read metadata verify failed then will queue error work.
	 * update_super_work will call start_this_handle may trigger
	 * BUG_ON.
	 */
	ecfs_unregister_sysfs(sb);

	if (___ratelimit(&ecfs_mount_msg_ratelimit, "ECFS-fs unmount"))
		ecfs_msg(sb, KERN_INFO, "unmounting filesystem %pU.",
			 &sb->s_uuid);

	ecfs_unregister_li_request(sb);
	ecfs_quotas_off(sb, ECFS_MAXQUOTAS);

	destroy_workqueue(sbi->rsv_conversion_wq);
	ecfs_release_orphan_info(sb);

	if (sbi->s_journal) {
		aborted = is_journal_aborted(sbi->s_journal);
		err = ecfs_journal_destroy(sbi, sbi->s_journal);
		if ((err < 0) && !aborted) {
			ecfs_abort(sb, -err, "Couldn't clean up the journal");
		}
	} else
		flush_work(&sbi->s_sb_upd_work);

	ecfs_es_unregister_shrinker(sbi);
	timer_shutdown_sync(&sbi->s_err_report);
	ecfs_release_system_zone(sb);
	ecfs_mb_release(sb);
	ecfs_ext_release(sb);

	if (!ecfs_emergency_state(sb) && !sb_rdonly(sb)) {
		if (!aborted) {
			ecfs_clear_feature_journal_needs_recovery(sb);
			ecfs_clear_feature_orphan_present(sb);
			es->s_state = cpu_to_le16(sbi->s_mount_state);
		}
		ecfs_commit_super(sb);
	}

	ecfs_group_desc_free(sbi);
	ecfs_flex_groups_free(sbi);

	WARN_ON_ONCE(!(sbi->s_mount_state & ECFS_ERROR_FS) &&
		     percpu_counter_sum(&sbi->s_dirtyclusters_counter));
	ecfs_percpu_param_destroy(sbi);
#ifdef CONFIG_QUOTA
	for (int i = 0; i < ECFS_MAXQUOTAS; i++)
		kfree(get_qf_name(sb, sbi, i));
#endif

	/* Debugging code just in case the in-memory inode orphan list
	 * isn't empty.  The on-disk one can be non-empty if we've
	 * detected an error and taken the fs readonly, but the
	 * in-memory list had better be clean by this point. */
	if (!list_empty(&sbi->s_orphan))
		dump_orphan_list(sb, sbi);
	ASSERT(list_empty(&sbi->s_orphan));

	sync_blockdev(sb->s_bdev);
	invalidate_bdev(sb->s_bdev);
	if (sbi->s_journal_bdev_file) {
		/*
		 * Invalidate the journal device's buffers.  We don't want them
		 * floating about in memory - the physical journal device may
		 * hotswapped, and it breaks the `ro-after' testing code.
		 */
		sync_blockdev(file_bdev(sbi->s_journal_bdev_file));
		invalidate_bdev(file_bdev(sbi->s_journal_bdev_file));
	}

	ecfs_xattr_destroy_cache(sbi->s_ea_inode_cache);
	sbi->s_ea_inode_cache = NULL;

	ecfs_xattr_destroy_cache(sbi->s_ea_block_cache);
	sbi->s_ea_block_cache = NULL;

	ecfs_stop_mmpd(sbi);

	brelse(sbi->s_sbh);
	sb->s_fs_info = NULL;
	/*
	 * Now that we are completely done shutting down the
	 * superblock, we need to actually destroy the kobject.
	 */
	kobject_put(&sbi->s_kobj);
	wait_for_completion(&sbi->s_kobj_unregister);
	kfree(sbi->s_blockgroup_lock);
	fs_put_dax(sbi->s_daxdev, NULL);
	fscrypt_free_dummy_policy(&sbi->s_dummy_enc_policy);
#if IS_ENABLED(CONFIG_UNICODE)
	utf8_unload(sb->s_encoding);
#endif
	kfree(sbi);
}

static struct kmem_cache *ecfs_inode_cachep;

/*
 * Called inside transaction, so use GFP_NOFS
 */
static struct inode *ecfs_alloc_inode(struct super_block *sb)
{
	struct ecfs_inode_info *ei;

	ei = alloc_inode_sb(sb, ecfs_inode_cachep, GFP_NOFS);
	if (!ei)
		return NULL;

	inode_set_iversion(&ei->vfs_inode, 1);
	ei->i_flags = 0;
	spin_lock_init(&ei->i_raw_lock);
	ei->i_prealloc_node = RB_ROOT;
	atomic_set(&ei->i_prealloc_active, 0);
	rwlock_init(&ei->i_prealloc_lock);
	ecfs_es_init_tree(&ei->i_es_tree);
	rwlock_init(&ei->i_es_lock);
	INIT_LIST_HEAD(&ei->i_es_list);
	ei->i_es_all_nr = 0;
	ei->i_es_shk_nr = 0;
	ei->i_es_shrink_lblk = 0;
	ei->i_reserved_data_blocks = 0;
	spin_lock_init(&(ei->i_block_reservation_lock));
	ecfs_init_pending_tree(&ei->i_pending_tree);
#ifdef CONFIG_QUOTA
	ei->i_reserved_quota = 0;
	memset(&ei->i_dquot, 0, sizeof(ei->i_dquot));
#endif
	ei->jinode = NULL;
	INIT_LIST_HEAD(&ei->i_rsv_conversion_list);
	spin_lock_init(&ei->i_completed_io_lock);
	ei->i_sync_tid = 0;
	ei->i_datasync_tid = 0;
	INIT_WORK(&ei->i_rsv_conversion_work, ecfs_end_io_rsv_work);
	ecfs_fc_init_inode(&ei->vfs_inode);
	spin_lock_init(&ei->i_fc_lock);
	return &ei->vfs_inode;
}

static int ecfs_drop_inode(struct inode *inode)
{
	int drop = generic_drop_inode(inode);

	if (!drop)
		drop = fscrypt_drop_inode(inode);

	trace_ecfs_drop_inode(inode, drop);
	return drop;
}

static void ecfs_free_in_core_inode(struct inode *inode)
{
	fscrypt_free_inode(inode);
	if (!list_empty(&(ECFS_I(inode)->i_fc_list))) {
		pr_warn("%s: inode %ld still in fc list",
			__func__, inode->i_ino);
	}
	kmem_cache_free(ecfs_inode_cachep, ECFS_I(inode));
}

static void ecfs_destroy_inode(struct inode *inode)
{
	if (!list_empty(&(ECFS_I(inode)->i_orphan))) {
		ecfs_msg(inode->i_sb, KERN_ERR,
			 "Inode %lu (%p): orphan list check failed!",
			 inode->i_ino, ECFS_I(inode));
		print_hex_dump(KERN_INFO, "", DUMP_PREFIX_ADDRESS, 16, 4,
				ECFS_I(inode), sizeof(struct ecfs_inode_info),
				true);
		dump_stack();
	}

	if (!(ECFS_SB(inode->i_sb)->s_mount_state & ECFS_ERROR_FS) &&
	    WARN_ON_ONCE(ECFS_I(inode)->i_reserved_data_blocks))
		ecfs_msg(inode->i_sb, KERN_ERR,
			 "Inode %lu (%p): i_reserved_data_blocks (%u) not cleared!",
			 inode->i_ino, ECFS_I(inode),
			 ECFS_I(inode)->i_reserved_data_blocks);
}

static void ecfs_shutdown(struct super_block *sb)
{
       ecfs_force_shutdown(sb, ECFS_GOING_FLAGS_NOLOGFLUSH);
}

static void init_once(void *foo)
{
	struct ecfs_inode_info *ei = foo;

	INIT_LIST_HEAD(&ei->i_orphan);
	init_rwsem(&ei->xattr_sem);
	init_rwsem(&ei->i_data_sem);
	inode_init_once(&ei->vfs_inode);
	ecfs_fc_init_inode(&ei->vfs_inode);
}

static int __init init_inodecache(void)
{
	ecfs_inode_cachep = kmem_cache_create_usercopy("ecfs_inode_cache",
				sizeof(struct ecfs_inode_info), 0,
				SLAB_RECLAIM_ACCOUNT | SLAB_ACCOUNT,
				offsetof(struct ecfs_inode_info, i_data),
				sizeof_field(struct ecfs_inode_info, i_data),
				init_once);
	if (ecfs_inode_cachep == NULL)
		return -ENOMEM;
	return 0;
}

static void destroy_inodecache(void)
{
	/*
	 * Make sure all delayed rcu free inodes are flushed before we
	 * destroy cache.
	 */
	rcu_barrier();
	kmem_cache_destroy(ecfs_inode_cachep);
}

void ecfs_clear_inode(struct inode *inode)
{
	ecfs_fc_del(inode);
	invalidate_inode_buffers(inode);
	clear_inode(inode);
	ecfs_discard_preallocations(inode);
	ecfs_es_remove_extent(inode, 0, EXT_MAX_BLOCKS);
	dquot_drop(inode);
	if (ECFS_I(inode)->jinode) {
		jbd2_journal_release_jbd_inode(ECFS_JOURNAL(inode),
					       ECFS_I(inode)->jinode);
		jbd2_free_inode(ECFS_I(inode)->jinode);
		ECFS_I(inode)->jinode = NULL;
	}
	fscrypt_put_encryption_info(inode);
	fsverity_cleanup_inode(inode);
}

static struct inode *ecfs_nfs_get_inode(struct super_block *sb,
					u64 ino, u32 generation)
{
	struct inode *inode;

	/*
	 * Currently we don't know the generation for parent directory, so
	 * a generation of 0 means "accept any"
	 */
	inode = ecfs_iget(sb, ino, ECFS_IGET_HANDLE);
	if (IS_ERR(inode))
		return ERR_CAST(inode);
	if (generation && inode->i_generation != generation) {
		iput(inode);
		return ERR_PTR(-ESTALE);
	}

	return inode;
}

static struct dentry *ecfs_fh_to_dentry(struct super_block *sb, struct fid *fid,
					int fh_len, int fh_type)
{
	return generic_fh_to_dentry(sb, fid, fh_len, fh_type,
				    ecfs_nfs_get_inode);
}

static struct dentry *ecfs_fh_to_parent(struct super_block *sb, struct fid *fid,
					int fh_len, int fh_type)
{
	return generic_fh_to_parent(sb, fid, fh_len, fh_type,
				    ecfs_nfs_get_inode);
}

static int ecfs_nfs_commit_metadata(struct inode *inode)
{
	struct writeback_control wbc = {
		.sync_mode = WB_SYNC_ALL
	};

	trace_ecfs_nfs_commit_metadata(inode);
	return ecfs_write_inode(inode, &wbc);
}

#ifdef CONFIG_QUOTA
static const char * const quotatypes[] = INITQFNAMES;
#define QTYPE2NAME(t) (quotatypes[t])

static int ecfs_write_dquot(struct dquot *dquot);
static int ecfs_acquire_dquot(struct dquot *dquot);
static int ecfs_release_dquot(struct dquot *dquot);
static int ecfs_mark_dquot_dirty(struct dquot *dquot);
static int ecfs_write_info(struct super_block *sb, int type);
static int ecfs_quota_on(struct super_block *sb, int type, int format_id,
			 const struct path *path);
static ssize_t ecfs_quota_read(struct super_block *sb, int type, char *data,
			       size_t len, loff_t off);
static ssize_t ecfs_quota_write(struct super_block *sb, int type,
				const char *data, size_t len, loff_t off);
static int ecfs_quota_enable(struct super_block *sb, int type, int format_id,
			     unsigned int flags);

static struct dquot __rcu **ecfs_get_dquots(struct inode *inode)
{
	return ECFS_I(inode)->i_dquot;
}

static const struct dquot_operations ecfs_quota_operations = {
	.get_reserved_space	= ecfs_get_reserved_space,
	.write_dquot		= ecfs_write_dquot,
	.acquire_dquot		= ecfs_acquire_dquot,
	.release_dquot		= ecfs_release_dquot,
	.mark_dirty		= ecfs_mark_dquot_dirty,
	.write_info		= ecfs_write_info,
	.alloc_dquot		= dquot_alloc,
	.destroy_dquot		= dquot_destroy,
	.get_projid		= ecfs_get_projid,
	.get_inode_usage	= ecfs_get_inode_usage,
	.get_next_id		= dquot_get_next_id,
};

static const struct quotactl_ops ecfs_qctl_operations = {
	.quota_on	= ecfs_quota_on,
	.quota_off	= ecfs_quota_off,
	.quota_sync	= dquot_quota_sync,
	.get_state	= dquot_get_state,
	.set_info	= dquot_set_dqinfo,
	.get_dqblk	= dquot_get_dqblk,
	.set_dqblk	= dquot_set_dqblk,
	.get_nextdqblk	= dquot_get_next_dqblk,
};
#endif

static const struct super_operations ecfs_sops = {
	.alloc_inode	= ecfs_alloc_inode,
	.free_inode	= ecfs_free_in_core_inode,
	.destroy_inode	= ecfs_destroy_inode,
	.write_inode	= ecfs_write_inode,
	.dirty_inode	= ecfs_dirty_inode,
	.drop_inode	= ecfs_drop_inode,
	.evict_inode	= ecfs_evict_inode,
	.put_super	= ecfs_put_super,
	.sync_fs	= ecfs_sync_fs,
	.freeze_fs	= ecfs_freeze,
	.unfreeze_fs	= ecfs_unfreeze,
	.statfs		= ecfs_statfs,
	.show_options	= ecfs_show_options,
	.shutdown	= ecfs_shutdown,
#ifdef CONFIG_QUOTA
	.quota_read	= ecfs_quota_read,
	.quota_write	= ecfs_quota_write,
	.get_dquots	= ecfs_get_dquots,
#endif
};

static const struct export_operations ecfs_export_ops = {
	.encode_fh = generic_encode_ino32_fh,
	.fh_to_dentry = ecfs_fh_to_dentry,
	.fh_to_parent = ecfs_fh_to_parent,
	.get_parent = ecfs_get_parent,
	.commit_metadata = ecfs_nfs_commit_metadata,
};

enum {
	Opt_bsd_df, Opt_minix_df, Opt_grpid, Opt_nogrpid,
	Opt_resgid, Opt_resuid, Opt_sb,
	Opt_nouid32, Opt_debug, Opt_removed,
	Opt_user_xattr, Opt_acl,
	Opt_auto_da_alloc, Opt_noauto_da_alloc, Opt_noload,
	Opt_commit, Opt_min_batch_time, Opt_max_batch_time, Opt_journal_dev,
	Opt_journal_path, Opt_journal_checksum, Opt_journal_async_commit,
	Opt_abort, Opt_data_journal, Opt_data_ordered, Opt_data_writeback,
	Opt_data_err_abort, Opt_data_err_ignore, Opt_test_dummy_encryption,
	Opt_inlinecrypt,
	Opt_usrjquota, Opt_grpjquota, Opt_quota,
	Opt_noquota, Opt_barrier, Opt_nobarrier, Opt_err,
	Opt_usrquota, Opt_grpquota, Opt_prjquota,
	Opt_dax, Opt_dax_always, Opt_dax_inode, Opt_dax_never,
	Opt_stripe, Opt_delalloc, Opt_nodelalloc, Opt_warn_on_error,
	Opt_nowarn_on_error, Opt_mblk_io_submit, Opt_debug_want_extra_isize,
	Opt_nomblk_io_submit, Opt_block_validity, Opt_noblock_validity,
	Opt_inode_readahead_blks, Opt_journal_ioprio,
	Opt_dioread_nolock, Opt_dioread_lock,
	Opt_discard, Opt_nodiscard, Opt_init_itable, Opt_noinit_itable,
	Opt_max_dir_size_kb, Opt_nojournal_checksum, Opt_nombcache,
	Opt_no_prefetch_block_bitmaps, Opt_mb_optimize_scan,
	Opt_errors, Opt_data, Opt_data_err, Opt_jqfmt, Opt_dax_type,
#ifdef CONFIG_ECFS_DEBUG
	Opt_fc_debug_max_replay, Opt_fc_debug_force
#endif
};

static const struct constant_table ecfs_param_errors[] = {
	{"continue",	ECFS_MOUNT_ERRORS_CONT},
	{"panic",	ECFS_MOUNT_ERRORS_PANIC},
	{"remount-ro",	ECFS_MOUNT_ERRORS_RO},
	{}
};

static const struct constant_table ecfs_param_data[] = {
	{"journal",	ECFS_MOUNT_JOURNAL_DATA},
	{"ordered",	ECFS_MOUNT_ORDERED_DATA},
	{"writeback",	ECFS_MOUNT_WRITEBACK_DATA},
	{}
};

static const struct constant_table ecfs_param_data_err[] = {
	{"abort",	Opt_data_err_abort},
	{"ignore",	Opt_data_err_ignore},
	{}
};

static const struct constant_table ecfs_param_jqfmt[] = {
	{"vfsold",	QFMT_VFS_OLD},
	{"vfsv0",	QFMT_VFS_V0},
	{"vfsv1",	QFMT_VFS_V1},
	{}
};

static const struct constant_table ecfs_param_dax[] = {
	{"always",	Opt_dax_always},
	{"inode",	Opt_dax_inode},
	{"never",	Opt_dax_never},
	{}
};

/*
 * Mount option specification
 * We don't use fsparam_flag_no because of the way we set the
 * options and the way we show them in _ecfs_show_options(). To
 * keep the changes to a minimum, let's keep the negative options
 * separate for now.
 */
static const struct fs_parameter_spec ecfs_param_specs[] = {
	fsparam_flag	("bsddf",		Opt_bsd_df),
	fsparam_flag	("minixdf",		Opt_minix_df),
	fsparam_flag	("grpid",		Opt_grpid),
	fsparam_flag	("bsdgroups",		Opt_grpid),
	fsparam_flag	("nogrpid",		Opt_nogrpid),
	fsparam_flag	("sysvgroups",		Opt_nogrpid),
	fsparam_gid	("resgid",		Opt_resgid),
	fsparam_uid	("resuid",		Opt_resuid),
	fsparam_u32	("sb",			Opt_sb),
	fsparam_enum	("errors",		Opt_errors, ecfs_param_errors),
	fsparam_flag	("nouid32",		Opt_nouid32),
	fsparam_flag	("debug",		Opt_debug),
	fsparam_flag	("oldalloc",		Opt_removed),
	fsparam_flag	("orlov",		Opt_removed),
	fsparam_flag	("user_xattr",		Opt_user_xattr),
	fsparam_flag	("acl",			Opt_acl),
	fsparam_flag	("norecovery",		Opt_noload),
	fsparam_flag	("noload",		Opt_noload),
	fsparam_flag	("bh",			Opt_removed),
	fsparam_flag	("nobh",		Opt_removed),
	fsparam_u32	("commit",		Opt_commit),
	fsparam_u32	("min_batch_time",	Opt_min_batch_time),
	fsparam_u32	("max_batch_time",	Opt_max_batch_time),
	fsparam_u32	("journal_dev",		Opt_journal_dev),
	fsparam_bdev	("journal_path",	Opt_journal_path),
	fsparam_flag	("journal_checksum",	Opt_journal_checksum),
	fsparam_flag	("nojournal_checksum",	Opt_nojournal_checksum),
	fsparam_flag	("journal_async_commit",Opt_journal_async_commit),
	fsparam_flag	("abort",		Opt_abort),
	fsparam_enum	("data",		Opt_data, ecfs_param_data),
	fsparam_enum	("data_err",		Opt_data_err,
						ecfs_param_data_err),
	fsparam_string_empty
			("usrjquota",		Opt_usrjquota),
	fsparam_string_empty
			("grpjquota",		Opt_grpjquota),
	fsparam_enum	("jqfmt",		Opt_jqfmt, ecfs_param_jqfmt),
	fsparam_flag	("grpquota",		Opt_grpquota),
	fsparam_flag	("quota",		Opt_quota),
	fsparam_flag	("noquota",		Opt_noquota),
	fsparam_flag	("usrquota",		Opt_usrquota),
	fsparam_flag	("prjquota",		Opt_prjquota),
	fsparam_flag	("barrier",		Opt_barrier),
	fsparam_u32	("barrier",		Opt_barrier),
	fsparam_flag	("nobarrier",		Opt_nobarrier),
	fsparam_flag	("i_version",		Opt_removed),
	fsparam_flag	("dax",			Opt_dax),
	fsparam_enum	("dax",			Opt_dax_type, ecfs_param_dax),
	fsparam_u32	("stripe",		Opt_stripe),
	fsparam_flag	("delalloc",		Opt_delalloc),
	fsparam_flag	("nodelalloc",		Opt_nodelalloc),
	fsparam_flag	("warn_on_error",	Opt_warn_on_error),
	fsparam_flag	("nowarn_on_error",	Opt_nowarn_on_error),
	fsparam_u32	("debug_want_extra_isize",
						Opt_debug_want_extra_isize),
	fsparam_flag	("mblk_io_submit",	Opt_removed),
	fsparam_flag	("nomblk_io_submit",	Opt_removed),
	fsparam_flag	("block_validity",	Opt_block_validity),
	fsparam_flag	("noblock_validity",	Opt_noblock_validity),
	fsparam_u32	("inode_readahead_blks",
						Opt_inode_readahead_blks),
	fsparam_u32	("journal_ioprio",	Opt_journal_ioprio),
	fsparam_u32	("auto_da_alloc",	Opt_auto_da_alloc),
	fsparam_flag	("auto_da_alloc",	Opt_auto_da_alloc),
	fsparam_flag	("noauto_da_alloc",	Opt_noauto_da_alloc),
	fsparam_flag	("dioread_nolock",	Opt_dioread_nolock),
	fsparam_flag	("nodioread_nolock",	Opt_dioread_lock),
	fsparam_flag	("dioread_lock",	Opt_dioread_lock),
	fsparam_flag	("discard",		Opt_discard),
	fsparam_flag	("nodiscard",		Opt_nodiscard),
	fsparam_u32	("init_itable",		Opt_init_itable),
	fsparam_flag	("init_itable",		Opt_init_itable),
	fsparam_flag	("noinit_itable",	Opt_noinit_itable),
#ifdef CONFIG_ECFS_DEBUG
	fsparam_flag	("fc_debug_force",	Opt_fc_debug_force),
	fsparam_u32	("fc_debug_max_replay",	Opt_fc_debug_max_replay),
#endif
	fsparam_u32	("max_dir_size_kb",	Opt_max_dir_size_kb),
	fsparam_flag	("test_dummy_encryption",
						Opt_test_dummy_encryption),
	fsparam_string	("test_dummy_encryption",
						Opt_test_dummy_encryption),
	fsparam_flag	("inlinecrypt",		Opt_inlinecrypt),
	fsparam_flag	("nombcache",		Opt_nombcache),
	fsparam_flag	("no_mbcache",		Opt_nombcache),	/* for backward compatibility */
	fsparam_flag	("prefetch_block_bitmaps",
						Opt_removed),
	fsparam_flag	("no_prefetch_block_bitmaps",
						Opt_no_prefetch_block_bitmaps),
	fsparam_s32	("mb_optimize_scan",	Opt_mb_optimize_scan),
	{}
};


#define MOPT_SET	0x0001
#define MOPT_CLEAR	0x0002
#define MOPT_NOSUPPORT	0x0004
#define MOPT_EXPLICIT	0x0008
#ifdef CONFIG_QUOTA
#define MOPT_Q		0
#define MOPT_QFMT	0x0010
#else
#define MOPT_Q		MOPT_NOSUPPORT
#define MOPT_QFMT	MOPT_NOSUPPORT
#endif
#define MOPT_NO_EXT2	0x0020
#define MOPT_NO_EXT3	0x0040
#define MOPT_ECFS_ONLY	(MOPT_NO_EXT2 | MOPT_NO_EXT3)
#define MOPT_SKIP	0x0080
#define	MOPT_2		0x0100

static const struct mount_opts {
	int	token;
	int	mount_opt;
	int	flags;
} ecfs_mount_opts[] = {
	{Opt_minix_df, ECFS_MOUNT_MINIX_DF, MOPT_SET},
	{Opt_bsd_df, ECFS_MOUNT_MINIX_DF, MOPT_CLEAR},
	{Opt_grpid, ECFS_MOUNT_GRPID, MOPT_SET},
	{Opt_nogrpid, ECFS_MOUNT_GRPID, MOPT_CLEAR},
	{Opt_block_validity, ECFS_MOUNT_BLOCK_VALIDITY, MOPT_SET},
	{Opt_noblock_validity, ECFS_MOUNT_BLOCK_VALIDITY, MOPT_CLEAR},
	{Opt_dioread_nolock, ECFS_MOUNT_DIOREAD_NOLOCK,
	 MOPT_ECFS_ONLY | MOPT_SET},
	{Opt_dioread_lock, ECFS_MOUNT_DIOREAD_NOLOCK,
	 MOPT_ECFS_ONLY | MOPT_CLEAR},
	{Opt_discard, ECFS_MOUNT_DISCARD, MOPT_SET},
	{Opt_nodiscard, ECFS_MOUNT_DISCARD, MOPT_CLEAR},
	{Opt_delalloc, ECFS_MOUNT_DELALLOC,
	 MOPT_ECFS_ONLY | MOPT_SET | MOPT_EXPLICIT},
	{Opt_nodelalloc, ECFS_MOUNT_DELALLOC,
	 MOPT_ECFS_ONLY | MOPT_CLEAR},
	{Opt_warn_on_error, ECFS_MOUNT_WARN_ON_ERROR, MOPT_SET},
	{Opt_nowarn_on_error, ECFS_MOUNT_WARN_ON_ERROR, MOPT_CLEAR},
	{Opt_commit, 0, MOPT_NO_EXT2},
	{Opt_nojournal_checksum, ECFS_MOUNT_JOURNAL_CHECKSUM,
	 MOPT_ECFS_ONLY | MOPT_CLEAR},
	{Opt_journal_checksum, ECFS_MOUNT_JOURNAL_CHECKSUM,
	 MOPT_ECFS_ONLY | MOPT_SET | MOPT_EXPLICIT},
	{Opt_journal_async_commit, (ECFS_MOUNT_JOURNAL_ASYNC_COMMIT |
				    ECFS_MOUNT_JOURNAL_CHECKSUM),
	 MOPT_ECFS_ONLY | MOPT_SET | MOPT_EXPLICIT},
	{Opt_noload, ECFS_MOUNT_NOLOAD, MOPT_NO_EXT2 | MOPT_SET},
	{Opt_data_err, ECFS_MOUNT_DATA_ERR_ABORT, MOPT_NO_EXT2},
	{Opt_barrier, ECFS_MOUNT_BARRIER, MOPT_SET},
	{Opt_nobarrier, ECFS_MOUNT_BARRIER, MOPT_CLEAR},
	{Opt_noauto_da_alloc, ECFS_MOUNT_NO_AUTO_DA_ALLOC, MOPT_SET},
	{Opt_auto_da_alloc, ECFS_MOUNT_NO_AUTO_DA_ALLOC, MOPT_CLEAR},
	{Opt_noinit_itable, ECFS_MOUNT_INIT_INODE_TABLE, MOPT_CLEAR},
	{Opt_dax_type, 0, MOPT_ECFS_ONLY},
	{Opt_journal_dev, 0, MOPT_NO_EXT2},
	{Opt_journal_path, 0, MOPT_NO_EXT2},
	{Opt_journal_ioprio, 0, MOPT_NO_EXT2},
	{Opt_data, 0, MOPT_NO_EXT2},
	{Opt_user_xattr, ECFS_MOUNT_XATTR_USER, MOPT_SET},
#ifdef CONFIG_ECFS_FS_POSIX_ACL
	{Opt_acl, ECFS_MOUNT_POSIX_ACL, MOPT_SET},
#else
	{Opt_acl, 0, MOPT_NOSUPPORT},
#endif
	{Opt_nouid32, ECFS_MOUNT_NO_UID32, MOPT_SET},
	{Opt_debug, ECFS_MOUNT_DEBUG, MOPT_SET},
	{Opt_quota, ECFS_MOUNT_QUOTA | ECFS_MOUNT_USRQUOTA, MOPT_SET | MOPT_Q},
	{Opt_usrquota, ECFS_MOUNT_QUOTA | ECFS_MOUNT_USRQUOTA,
							MOPT_SET | MOPT_Q},
	{Opt_grpquota, ECFS_MOUNT_QUOTA | ECFS_MOUNT_GRPQUOTA,
							MOPT_SET | MOPT_Q},
	{Opt_prjquota, ECFS_MOUNT_QUOTA | ECFS_MOUNT_PRJQUOTA,
							MOPT_SET | MOPT_Q},
	{Opt_noquota, (ECFS_MOUNT_QUOTA | ECFS_MOUNT_USRQUOTA |
		       ECFS_MOUNT_GRPQUOTA | ECFS_MOUNT_PRJQUOTA),
							MOPT_CLEAR | MOPT_Q},
	{Opt_usrjquota, 0, MOPT_Q},
	{Opt_grpjquota, 0, MOPT_Q},
	{Opt_jqfmt, 0, MOPT_QFMT},
	{Opt_nombcache, ECFS_MOUNT_NO_MBCACHE, MOPT_SET},
	{Opt_no_prefetch_block_bitmaps, ECFS_MOUNT_NO_PREFETCH_BLOCK_BITMAPS,
	 MOPT_SET},
#ifdef CONFIG_ECFS_DEBUG
	{Opt_fc_debug_force, ECFS_MOUNT2_JOURNAL_FAST_COMMIT,
	 MOPT_SET | MOPT_2 | MOPT_ECFS_ONLY},
#endif
	{Opt_abort, ECFS_MOUNT2_ABORT, MOPT_SET | MOPT_2},
	{Opt_err, 0, 0}
};

#if IS_ENABLED(CONFIG_UNICODE)
static const struct ecfs_sb_encodings {
	__u16 magic;
	char *name;
	unsigned int version;
} ecfs_sb_encoding_map[] = {
	{ECFS_ENC_UTF8_12_1, "utf8", UNICODE_AGE(12, 1, 0)},
};

static const struct ecfs_sb_encodings *
ecfs_sb_read_encoding(const struct ecfs_super_block *es)
{
	__u16 magic = le16_to_cpu(es->s_encoding);
	int i;

	for (i = 0; i < ARRAY_SIZE(ecfs_sb_encoding_map); i++)
		if (magic == ecfs_sb_encoding_map[i].magic)
			return &ecfs_sb_encoding_map[i];

	return NULL;
}
#endif

#define ECFS_SPEC_JQUOTA			(1 <<  0)
#define ECFS_SPEC_JQFMT				(1 <<  1)
#define ECFS_SPEC_DATAJ				(1 <<  2)
#define ECFS_SPEC_SB_BLOCK			(1 <<  3)
#define ECFS_SPEC_JOURNAL_DEV			(1 <<  4)
#define ECFS_SPEC_JOURNAL_IOPRIO		(1 <<  5)
#define ECFS_SPEC_s_want_extra_isize		(1 <<  7)
#define ECFS_SPEC_s_max_batch_time		(1 <<  8)
#define ECFS_SPEC_s_min_batch_time		(1 <<  9)
#define ECFS_SPEC_s_inode_readahead_blks	(1 << 10)
#define ECFS_SPEC_s_li_wait_mult		(1 << 11)
#define ECFS_SPEC_s_max_dir_size_kb		(1 << 12)
#define ECFS_SPEC_s_stripe			(1 << 13)
#define ECFS_SPEC_s_resuid			(1 << 14)
#define ECFS_SPEC_s_resgid			(1 << 15)
#define ECFS_SPEC_s_commit_interval		(1 << 16)
#define ECFS_SPEC_s_fc_debug_max_replay		(1 << 17)
#define ECFS_SPEC_s_sb_block			(1 << 18)
#define ECFS_SPEC_mb_optimize_scan		(1 << 19)

struct ecfs_fs_context {
	char		*s_qf_names[ECFS_MAXQUOTAS];
	struct fscrypt_dummy_policy dummy_enc_policy;
	int		s_jquota_fmt;	/* Format of quota to use */
#ifdef CONFIG_ECFS_DEBUG
	int s_fc_debug_max_replay;
#endif
	unsigned short	qname_spec;
	unsigned long	vals_s_flags;	/* Bits to set in s_flags */
	unsigned long	mask_s_flags;	/* Bits changed in s_flags */
	unsigned long	journal_devnum;
	unsigned long	s_commit_interval;
	unsigned long	s_stripe;
	unsigned int	s_inode_readahead_blks;
	unsigned int	s_want_extra_isize;
	unsigned int	s_li_wait_mult;
	unsigned int	s_max_dir_size_kb;
	unsigned int	journal_ioprio;
	unsigned int	vals_s_mount_opt;
	unsigned int	mask_s_mount_opt;
	unsigned int	vals_s_mount_opt2;
	unsigned int	mask_s_mount_opt2;
	unsigned int	opt_flags;	/* MOPT flags */
	unsigned int	spec;
	u32		s_max_batch_time;
	u32		s_min_batch_time;
	kuid_t		s_resuid;
	kgid_t		s_resgid;
	ecfs_fsblk_t	s_sb_block;
};

static void ecfs_fc_free(struct fs_context *fc)
{
	struct ecfs_fs_context *ctx = fc->fs_private;
	int i;

	if (!ctx)
		return;

	for (i = 0; i < ECFS_MAXQUOTAS; i++)
		kfree(ctx->s_qf_names[i]);

	fscrypt_free_dummy_policy(&ctx->dummy_enc_policy);
	kfree(ctx);
}

int ecfs_init_fs_context(struct fs_context *fc)
{
	struct ecfs_fs_context *ctx;

	ctx = kzalloc(sizeof(struct ecfs_fs_context), GFP_KERNEL);
	if (!ctx)
		return -ENOMEM;

	fc->fs_private = ctx;
	fc->ops = &ecfs_context_ops;

	/* i_version is always enabled now */
	fc->sb_flags |= SB_I_VERSION;

	return 0;
}

#ifdef CONFIG_QUOTA
/*
 * Note the name of the specified quota file.
 */
static int note_qf_name(struct fs_context *fc, int qtype,
		       struct fs_parameter *param)
{
	struct ecfs_fs_context *ctx = fc->fs_private;
	char *qname;

	if (param->size < 1) {
		ecfs_msg(NULL, KERN_ERR, "Missing quota name");
		return -EINVAL;
	}
	if (strchr(param->string, '/')) {
		ecfs_msg(NULL, KERN_ERR,
			 "quotafile must be on filesystem root");
		return -EINVAL;
	}
	if (ctx->s_qf_names[qtype]) {
		if (strcmp(ctx->s_qf_names[qtype], param->string) != 0) {
			ecfs_msg(NULL, KERN_ERR,
				 "%s quota file already specified",
				 QTYPE2NAME(qtype));
			return -EINVAL;
		}
		return 0;
	}

	qname = kmemdup_nul(param->string, param->size, GFP_KERNEL);
	if (!qname) {
		ecfs_msg(NULL, KERN_ERR,
			 "Not enough memory for storing quotafile name");
		return -ENOMEM;
	}
	ctx->s_qf_names[qtype] = qname;
	ctx->qname_spec |= 1 << qtype;
	ctx->spec |= ECFS_SPEC_JQUOTA;
	return 0;
}

/*
 * Clear the name of the specified quota file.
 */
static int unnote_qf_name(struct fs_context *fc, int qtype)
{
	struct ecfs_fs_context *ctx = fc->fs_private;

	kfree(ctx->s_qf_names[qtype]);

	ctx->s_qf_names[qtype] = NULL;
	ctx->qname_spec |= 1 << qtype;
	ctx->spec |= ECFS_SPEC_JQUOTA;
	return 0;
}
#endif

static int ecfs_parse_test_dummy_encryption(const struct fs_parameter *param,
					    struct ecfs_fs_context *ctx)
{
	int err;

	if (!IS_ENABLED(CONFIG_FS_ENCRYPTION)) {
		ecfs_msg(NULL, KERN_WARNING,
			 "test_dummy_encryption option not supported");
		return -EINVAL;
	}
	err = fscrypt_parse_test_dummy_encryption(param,
						  &ctx->dummy_enc_policy);
	if (err == -EINVAL) {
		ecfs_msg(NULL, KERN_WARNING,
			 "Value of option \"%s\" is unrecognized", param->key);
	} else if (err == -EEXIST) {
		ecfs_msg(NULL, KERN_WARNING,
			 "Conflicting test_dummy_encryption options");
		return -EINVAL;
	}
	return err;
}

#define ECFS_SET_CTX(name)						\
static inline __maybe_unused						\
void ctx_set_##name(struct ecfs_fs_context *ctx, unsigned long flag)	\
{									\
	ctx->mask_s_##name |= flag;					\
	ctx->vals_s_##name |= flag;					\
}

#define ECFS_CLEAR_CTX(name)						\
static inline __maybe_unused						\
void ctx_clear_##name(struct ecfs_fs_context *ctx, unsigned long flag)	\
{									\
	ctx->mask_s_##name |= flag;					\
	ctx->vals_s_##name &= ~flag;					\
}

#define ECFS_TEST_CTX(name)						\
static inline unsigned long						\
ctx_test_##name(struct ecfs_fs_context *ctx, unsigned long flag)	\
{									\
	return (ctx->vals_s_##name & flag);				\
}

ECFS_SET_CTX(flags); /* set only */
ECFS_SET_CTX(mount_opt);
ECFS_CLEAR_CTX(mount_opt);
ECFS_TEST_CTX(mount_opt);
ECFS_SET_CTX(mount_opt2);
ECFS_CLEAR_CTX(mount_opt2);
ECFS_TEST_CTX(mount_opt2);

static int ecfs_parse_param(struct fs_context *fc, struct fs_parameter *param)
{
	struct ecfs_fs_context *ctx = fc->fs_private;
	struct fs_parse_result result;
	const struct mount_opts *m;
	int is_remount;
	int token;

	token = fs_parse(fc, ecfs_param_specs, param, &result);
	if (token < 0)
		return token;
	is_remount = fc->purpose == FS_CONTEXT_FOR_RECONFIGURE;

	for (m = ecfs_mount_opts; m->token != Opt_err; m++)
		if (token == m->token)
			break;

	ctx->opt_flags |= m->flags;

	if (m->flags & MOPT_EXPLICIT) {
		if (m->mount_opt & ECFS_MOUNT_DELALLOC) {
			ctx_set_mount_opt2(ctx, ECFS_MOUNT2_EXPLICIT_DELALLOC);
		} else if (m->mount_opt & ECFS_MOUNT_JOURNAL_CHECKSUM) {
			ctx_set_mount_opt2(ctx,
				       ECFS_MOUNT2_EXPLICIT_JOURNAL_CHECKSUM);
		} else
			return -EINVAL;
	}

	if (m->flags & MOPT_NOSUPPORT) {
		ecfs_msg(NULL, KERN_ERR, "%s option not supported",
			 param->key);
		return 0;
	}

	switch (token) {
#ifdef CONFIG_QUOTA
	case Opt_usrjquota:
		if (!*param->string)
			return unnote_qf_name(fc, USRQUOTA);
		else
			return note_qf_name(fc, USRQUOTA, param);
	case Opt_grpjquota:
		if (!*param->string)
			return unnote_qf_name(fc, GRPQUOTA);
		else
			return note_qf_name(fc, GRPQUOTA, param);
#endif
	case Opt_sb:
		if (fc->purpose == FS_CONTEXT_FOR_RECONFIGURE) {
			ecfs_msg(NULL, KERN_WARNING,
				 "Ignoring %s option on remount", param->key);
		} else {
			ctx->s_sb_block = result.uint_32;
			ctx->spec |= ECFS_SPEC_s_sb_block;
		}
		return 0;
	case Opt_removed:
		ecfs_msg(NULL, KERN_WARNING, "Ignoring removed %s option",
			 param->key);
		return 0;
	case Opt_inlinecrypt:
#ifdef CONFIG_FS_ENCRYPTION_INLINE_CRYPT
		ctx_set_flags(ctx, SB_INLINECRYPT);
#else
		ecfs_msg(NULL, KERN_ERR, "inline encryption not supported");
#endif
		return 0;
	case Opt_errors:
		ctx_clear_mount_opt(ctx, ECFS_MOUNT_ERRORS_MASK);
		ctx_set_mount_opt(ctx, result.uint_32);
		return 0;
#ifdef CONFIG_QUOTA
	case Opt_jqfmt:
		ctx->s_jquota_fmt = result.uint_32;
		ctx->spec |= ECFS_SPEC_JQFMT;
		return 0;
#endif
	case Opt_data:
		ctx_clear_mount_opt(ctx, ECFS_MOUNT_DATA_FLAGS);
		ctx_set_mount_opt(ctx, result.uint_32);
		ctx->spec |= ECFS_SPEC_DATAJ;
		return 0;
	case Opt_commit:
		if (result.uint_32 == 0)
			result.uint_32 = JBD2_DEFAULT_MAX_COMMIT_AGE;
		else if (result.uint_32 > INT_MAX / HZ) {
			ecfs_msg(NULL, KERN_ERR,
				 "Invalid commit interval %d, "
				 "must be smaller than %d",
				 result.uint_32, INT_MAX / HZ);
			return -EINVAL;
		}
		ctx->s_commit_interval = HZ * result.uint_32;
		ctx->spec |= ECFS_SPEC_s_commit_interval;
		return 0;
	case Opt_debug_want_extra_isize:
		if ((result.uint_32 & 1) || (result.uint_32 < 4)) {
			ecfs_msg(NULL, KERN_ERR,
				 "Invalid want_extra_isize %d", result.uint_32);
			return -EINVAL;
		}
		ctx->s_want_extra_isize = result.uint_32;
		ctx->spec |= ECFS_SPEC_s_want_extra_isize;
		return 0;
	case Opt_max_batch_time:
		ctx->s_max_batch_time = result.uint_32;
		ctx->spec |= ECFS_SPEC_s_max_batch_time;
		return 0;
	case Opt_min_batch_time:
		ctx->s_min_batch_time = result.uint_32;
		ctx->spec |= ECFS_SPEC_s_min_batch_time;
		return 0;
	case Opt_inode_readahead_blks:
		if (result.uint_32 &&
		    (result.uint_32 > (1 << 30) ||
		     !is_power_of_2(result.uint_32))) {
			ecfs_msg(NULL, KERN_ERR,
				 "ECFS-fs: inode_readahead_blks must be "
				 "0 or a power of 2 smaller than 2^31");
			return -EINVAL;
		}
		ctx->s_inode_readahead_blks = result.uint_32;
		ctx->spec |= ECFS_SPEC_s_inode_readahead_blks;
		return 0;
	case Opt_init_itable:
		ctx_set_mount_opt(ctx, ECFS_MOUNT_INIT_INODE_TABLE);
		ctx->s_li_wait_mult = ECFS_DEF_LI_WAIT_MULT;
		if (param->type == fs_value_is_string)
			ctx->s_li_wait_mult = result.uint_32;
		ctx->spec |= ECFS_SPEC_s_li_wait_mult;
		return 0;
	case Opt_max_dir_size_kb:
		ctx->s_max_dir_size_kb = result.uint_32;
		ctx->spec |= ECFS_SPEC_s_max_dir_size_kb;
		return 0;
#ifdef CONFIG_ECFS_DEBUG
	case Opt_fc_debug_max_replay:
		ctx->s_fc_debug_max_replay = result.uint_32;
		ctx->spec |= ECFS_SPEC_s_fc_debug_max_replay;
		return 0;
#endif
	case Opt_stripe:
		ctx->s_stripe = result.uint_32;
		ctx->spec |= ECFS_SPEC_s_stripe;
		return 0;
	case Opt_resuid:
		ctx->s_resuid = result.uid;
		ctx->spec |= ECFS_SPEC_s_resuid;
		return 0;
	case Opt_resgid:
		ctx->s_resgid = result.gid;
		ctx->spec |= ECFS_SPEC_s_resgid;
		return 0;
	case Opt_journal_dev:
		if (is_remount) {
			ecfs_msg(NULL, KERN_ERR,
				 "Cannot specify journal on remount");
			return -EINVAL;
		}
		ctx->journal_devnum = result.uint_32;
		ctx->spec |= ECFS_SPEC_JOURNAL_DEV;
		return 0;
	case Opt_journal_path:
	{
		struct inode *journal_inode;
		struct path path;
		int error;

		if (is_remount) {
			ecfs_msg(NULL, KERN_ERR,
				 "Cannot specify journal on remount");
			return -EINVAL;
		}

		error = fs_lookup_param(fc, param, 1, LOOKUP_FOLLOW, &path);
		if (error) {
			ecfs_msg(NULL, KERN_ERR, "error: could not find "
				 "journal device path");
			return -EINVAL;
		}

		journal_inode = d_inode(path.dentry);
		ctx->journal_devnum = new_encode_dev(journal_inode->i_rdev);
		ctx->spec |= ECFS_SPEC_JOURNAL_DEV;
		path_put(&path);
		return 0;
	}
	case Opt_journal_ioprio:
		if (result.uint_32 > 7) {
			ecfs_msg(NULL, KERN_ERR, "Invalid journal IO priority"
				 " (must be 0-7)");
			return -EINVAL;
		}
		ctx->journal_ioprio =
			IOPRIO_PRIO_VALUE(IOPRIO_CLASS_BE, result.uint_32);
		ctx->spec |= ECFS_SPEC_JOURNAL_IOPRIO;
		return 0;
	case Opt_test_dummy_encryption:
		return ecfs_parse_test_dummy_encryption(param, ctx);
	case Opt_dax:
	case Opt_dax_type:
#ifdef CONFIG_FS_DAX
	{
		int type = (token == Opt_dax) ?
			   Opt_dax : result.uint_32;

		switch (type) {
		case Opt_dax:
		case Opt_dax_always:
			ctx_set_mount_opt(ctx, ECFS_MOUNT_DAX_ALWAYS);
			ctx_clear_mount_opt2(ctx, ECFS_MOUNT2_DAX_NEVER);
			break;
		case Opt_dax_never:
			ctx_set_mount_opt2(ctx, ECFS_MOUNT2_DAX_NEVER);
			ctx_clear_mount_opt(ctx, ECFS_MOUNT_DAX_ALWAYS);
			break;
		case Opt_dax_inode:
			ctx_clear_mount_opt(ctx, ECFS_MOUNT_DAX_ALWAYS);
			ctx_clear_mount_opt2(ctx, ECFS_MOUNT2_DAX_NEVER);
			/* Strictly for printing options */
			ctx_set_mount_opt2(ctx, ECFS_MOUNT2_DAX_INODE);
			break;
		}
		return 0;
	}
#else
		ecfs_msg(NULL, KERN_INFO, "dax option not supported");
		return -EINVAL;
#endif
	case Opt_data_err:
		if (result.uint_32 == Opt_data_err_abort)
			ctx_set_mount_opt(ctx, m->mount_opt);
		else if (result.uint_32 == Opt_data_err_ignore)
			ctx_clear_mount_opt(ctx, m->mount_opt);
		return 0;
	case Opt_mb_optimize_scan:
		if (result.int_32 == 1) {
			ctx_set_mount_opt2(ctx, ECFS_MOUNT2_MB_OPTIMIZE_SCAN);
			ctx->spec |= ECFS_SPEC_mb_optimize_scan;
		} else if (result.int_32 == 0) {
			ctx_clear_mount_opt2(ctx, ECFS_MOUNT2_MB_OPTIMIZE_SCAN);
			ctx->spec |= ECFS_SPEC_mb_optimize_scan;
		} else {
			ecfs_msg(NULL, KERN_WARNING,
				 "mb_optimize_scan should be set to 0 or 1.");
			return -EINVAL;
		}
		return 0;
	}

	/*
	 * At this point we should only be getting options requiring MOPT_SET,
	 * or MOPT_CLEAR. Anything else is a bug
	 */
	if (m->token == Opt_err) {
		ecfs_msg(NULL, KERN_WARNING, "buggy handling of option %s",
			 param->key);
		WARN_ON(1);
		return -EINVAL;
	}

	else {
		unsigned int set = 0;

		if ((param->type == fs_value_is_flag) ||
		    result.uint_32 > 0)
			set = 1;

		if (m->flags & MOPT_CLEAR)
			set = !set;
		else if (unlikely(!(m->flags & MOPT_SET))) {
			ecfs_msg(NULL, KERN_WARNING,
				 "buggy handling of option %s",
				 param->key);
			WARN_ON(1);
			return -EINVAL;
		}
		if (m->flags & MOPT_2) {
			if (set != 0)
				ctx_set_mount_opt2(ctx, m->mount_opt);
			else
				ctx_clear_mount_opt2(ctx, m->mount_opt);
		} else {
			if (set != 0)
				ctx_set_mount_opt(ctx, m->mount_opt);
			else
				ctx_clear_mount_opt(ctx, m->mount_opt);
		}
	}

	return 0;
}

static int parse_options(struct fs_context *fc, char *options)
{
	struct fs_parameter param;
	int ret;
	char *key;

	if (!options)
		return 0;

	while ((key = strsep(&options, ",")) != NULL) {
		if (*key) {
			size_t v_len = 0;
			char *value = strchr(key, '=');

			param.type = fs_value_is_flag;
			param.string = NULL;

			if (value) {
				if (value == key)
					continue;

				*value++ = 0;
				v_len = strlen(value);
				param.string = kmemdup_nul(value, v_len,
							   GFP_KERNEL);
				if (!param.string)
					return -ENOMEM;
				param.type = fs_value_is_string;
			}

			param.key = key;
			param.size = v_len;

			ret = ecfs_parse_param(fc, &param);
			kfree(param.string);
			if (ret < 0)
				return ret;
		}
	}

	ret = ecfs_validate_options(fc);
	if (ret < 0)
		return ret;

	return 0;
}

static int parse_apply_sb_mount_options(struct super_block *sb,
					struct ecfs_fs_context *m_ctx)
{
	struct ecfs_sb_info *sbi = ECFS_SB(sb);
	char *s_mount_opts = NULL;
	struct ecfs_fs_context *s_ctx = NULL;
	struct fs_context *fc = NULL;
	int ret = -ENOMEM;

	if (!sbi->s_es->s_mount_opts[0])
		return 0;

	s_mount_opts = kstrndup(sbi->s_es->s_mount_opts,
				sizeof(sbi->s_es->s_mount_opts),
				GFP_KERNEL);
	if (!s_mount_opts)
		return ret;

	fc = kzalloc(sizeof(struct fs_context), GFP_KERNEL);
	if (!fc)
		goto out_free;

	s_ctx = kzalloc(sizeof(struct ecfs_fs_context), GFP_KERNEL);
	if (!s_ctx)
		goto out_free;

	fc->fs_private = s_ctx;
	fc->s_fs_info = sbi;

	ret = parse_options(fc, s_mount_opts);
	if (ret < 0)
		goto parse_failed;

	ret = ecfs_check_opt_consistency(fc, sb);
	if (ret < 0) {
parse_failed:
		ecfs_msg(sb, KERN_WARNING,
			 "failed to parse options in superblock: %s",
			 s_mount_opts);
		ret = 0;
		goto out_free;
	}

	if (s_ctx->spec & ECFS_SPEC_JOURNAL_DEV)
		m_ctx->journal_devnum = s_ctx->journal_devnum;
	if (s_ctx->spec & ECFS_SPEC_JOURNAL_IOPRIO)
		m_ctx->journal_ioprio = s_ctx->journal_ioprio;

	ecfs_apply_options(fc, sb);
	ret = 0;

out_free:
	if (fc) {
		ecfs_fc_free(fc);
		kfree(fc);
	}
	kfree(s_mount_opts);
	return ret;
}

static void ecfs_apply_quota_options(struct fs_context *fc,
				     struct super_block *sb)
{
#ifdef CONFIG_QUOTA
	bool quota_feature = ecfs_has_feature_quota(sb);
	struct ecfs_fs_context *ctx = fc->fs_private;
	struct ecfs_sb_info *sbi = ECFS_SB(sb);
	char *qname;
	int i;

	if (quota_feature)
		return;

	if (ctx->spec & ECFS_SPEC_JQUOTA) {
		for (i = 0; i < ECFS_MAXQUOTAS; i++) {
			if (!(ctx->qname_spec & (1 << i)))
				continue;

			qname = ctx->s_qf_names[i]; /* May be NULL */
			if (qname)
				set_opt(sb, QUOTA);
			ctx->s_qf_names[i] = NULL;
			qname = rcu_replace_pointer(sbi->s_qf_names[i], qname,
						lockdep_is_held(&sb->s_umount));
			if (qname)
				kfree_rcu_mightsleep(qname);
		}
	}

	if (ctx->spec & ECFS_SPEC_JQFMT)
		sbi->s_jquota_fmt = ctx->s_jquota_fmt;
#endif
}

/*
 * Check quota settings consistency.
 */
static int ecfs_check_quota_consistency(struct fs_context *fc,
					struct super_block *sb)
{
#ifdef CONFIG_QUOTA
	struct ecfs_fs_context *ctx = fc->fs_private;
	struct ecfs_sb_info *sbi = ECFS_SB(sb);
	bool quota_feature = ecfs_has_feature_quota(sb);
	bool quota_loaded = sb_any_quota_loaded(sb);
	bool usr_qf_name, grp_qf_name, usrquota, grpquota;
	int quota_flags, i;

	/*
	 * We do the test below only for project quotas. 'usrquota' and
	 * 'grpquota' mount options are allowed even without quota feature
	 * to support legacy quotas in quota files.
	 */
	if (ctx_test_mount_opt(ctx, ECFS_MOUNT_PRJQUOTA) &&
	    !ecfs_has_feature_project(sb)) {
		ecfs_msg(NULL, KERN_ERR, "Project quota feature not enabled. "
			 "Cannot enable project quota enforcement.");
		return -EINVAL;
	}

	quota_flags = ECFS_MOUNT_QUOTA | ECFS_MOUNT_USRQUOTA |
		      ECFS_MOUNT_GRPQUOTA | ECFS_MOUNT_PRJQUOTA;
	if (quota_loaded &&
	    ctx->mask_s_mount_opt & quota_flags &&
	    !ctx_test_mount_opt(ctx, quota_flags))
		goto err_quota_change;

	if (ctx->spec & ECFS_SPEC_JQUOTA) {

		for (i = 0; i < ECFS_MAXQUOTAS; i++) {
			if (!(ctx->qname_spec & (1 << i)))
				continue;

			if (quota_loaded &&
			    !!sbi->s_qf_names[i] != !!ctx->s_qf_names[i])
				goto err_jquota_change;

			if (sbi->s_qf_names[i] && ctx->s_qf_names[i] &&
			    strcmp(get_qf_name(sb, sbi, i),
				   ctx->s_qf_names[i]) != 0)
				goto err_jquota_specified;
		}

		if (quota_feature) {
			ecfs_msg(NULL, KERN_INFO,
				 "Journaled quota options ignored when "
				 "QUOTA feature is enabled");
			return 0;
		}
	}

	if (ctx->spec & ECFS_SPEC_JQFMT) {
		if (sbi->s_jquota_fmt != ctx->s_jquota_fmt && quota_loaded)
			goto err_jquota_change;
		if (quota_feature) {
			ecfs_msg(NULL, KERN_INFO, "Quota format mount options "
				 "ignored when QUOTA feature is enabled");
			return 0;
		}
	}

	/* Make sure we don't mix old and new quota format */
	usr_qf_name = (get_qf_name(sb, sbi, USRQUOTA) ||
		       ctx->s_qf_names[USRQUOTA]);
	grp_qf_name = (get_qf_name(sb, sbi, GRPQUOTA) ||
		       ctx->s_qf_names[GRPQUOTA]);

	usrquota = (ctx_test_mount_opt(ctx, ECFS_MOUNT_USRQUOTA) ||
		    test_opt(sb, USRQUOTA));

	grpquota = (ctx_test_mount_opt(ctx, ECFS_MOUNT_GRPQUOTA) ||
		    test_opt(sb, GRPQUOTA));

	if (usr_qf_name) {
		ctx_clear_mount_opt(ctx, ECFS_MOUNT_USRQUOTA);
		usrquota = false;
	}
	if (grp_qf_name) {
		ctx_clear_mount_opt(ctx, ECFS_MOUNT_GRPQUOTA);
		grpquota = false;
	}

	if (usr_qf_name || grp_qf_name) {
		if (usrquota || grpquota) {
			ecfs_msg(NULL, KERN_ERR, "old and new quota "
				 "format mixing");
			return -EINVAL;
		}

		if (!(ctx->spec & ECFS_SPEC_JQFMT || sbi->s_jquota_fmt)) {
			ecfs_msg(NULL, KERN_ERR, "journaled quota format "
				 "not specified");
			return -EINVAL;
		}
	}

	return 0;

err_quota_change:
	ecfs_msg(NULL, KERN_ERR,
		 "Cannot change quota options when quota turned on");
	return -EINVAL;
err_jquota_change:
	ecfs_msg(NULL, KERN_ERR, "Cannot change journaled quota "
		 "options when quota turned on");
	return -EINVAL;
err_jquota_specified:
	ecfs_msg(NULL, KERN_ERR, "%s quota file already specified",
		 QTYPE2NAME(i));
	return -EINVAL;
#else
	return 0;
#endif
}

static int ecfs_check_test_dummy_encryption(const struct fs_context *fc,
					    struct super_block *sb)
{
	const struct ecfs_fs_context *ctx = fc->fs_private;
	const struct ecfs_sb_info *sbi = ECFS_SB(sb);

	if (!fscrypt_is_dummy_policy_set(&ctx->dummy_enc_policy))
		return 0;

	if (!ecfs_has_feature_encrypt(sb)) {
		ecfs_msg(NULL, KERN_WARNING,
			 "test_dummy_encryption requires encrypt feature");
		return -EINVAL;
	}
	/*
	 * This mount option is just for testing, and it's not worthwhile to
	 * implement the extra complexity (e.g. RCU protection) that would be
	 * needed to allow it to be set or changed during remount.  We do allow
	 * it to be specified during remount, but only if there is no change.
	 */
	if (fc->purpose == FS_CONTEXT_FOR_RECONFIGURE) {
		if (fscrypt_dummy_policies_equal(&sbi->s_dummy_enc_policy,
						 &ctx->dummy_enc_policy))
			return 0;
		ecfs_msg(NULL, KERN_WARNING,
			 "Can't set or change test_dummy_encryption on remount");
		return -EINVAL;
	}
	/* Also make sure s_mount_opts didn't contain a conflicting value. */
	if (fscrypt_is_dummy_policy_set(&sbi->s_dummy_enc_policy)) {
		if (fscrypt_dummy_policies_equal(&sbi->s_dummy_enc_policy,
						 &ctx->dummy_enc_policy))
			return 0;
		ecfs_msg(NULL, KERN_WARNING,
			 "Conflicting test_dummy_encryption options");
		return -EINVAL;
	}
	return 0;
}

static void ecfs_apply_test_dummy_encryption(struct ecfs_fs_context *ctx,
					     struct super_block *sb)
{
	if (!fscrypt_is_dummy_policy_set(&ctx->dummy_enc_policy) ||
	    /* if already set, it was already verified to be the same */
	    fscrypt_is_dummy_policy_set(&ECFS_SB(sb)->s_dummy_enc_policy))
		return;
	ECFS_SB(sb)->s_dummy_enc_policy = ctx->dummy_enc_policy;
	memset(&ctx->dummy_enc_policy, 0, sizeof(ctx->dummy_enc_policy));
	ecfs_msg(sb, KERN_WARNING, "Test dummy encryption mode enabled");
}

static int ecfs_check_opt_consistency(struct fs_context *fc,
				      struct super_block *sb)
{
	struct ecfs_fs_context *ctx = fc->fs_private;
	struct ecfs_sb_info *sbi = fc->s_fs_info;
	int is_remount = fc->purpose == FS_CONTEXT_FOR_RECONFIGURE;
	int err;

	if (ctx->s_want_extra_isize >
	    (sbi->s_inode_size - ECFS_GOOD_OLD_INODE_SIZE)) {
		ecfs_msg(NULL, KERN_ERR,
			 "Invalid want_extra_isize %d",
			 ctx->s_want_extra_isize);
		return -EINVAL;
	}

	err = ecfs_check_test_dummy_encryption(fc, sb);
	if (err)
		return err;

	if ((ctx->spec & ECFS_SPEC_DATAJ) && is_remount) {
		if (!sbi->s_journal) {
			ecfs_msg(NULL, KERN_WARNING,
				 "Remounting file system with no journal "
				 "so ignoring journalled data option");
			ctx_clear_mount_opt(ctx, ECFS_MOUNT_DATA_FLAGS);
		} else if (ctx_test_mount_opt(ctx, ECFS_MOUNT_DATA_FLAGS) !=
			   test_opt(sb, DATA_FLAGS)) {
			ecfs_msg(NULL, KERN_ERR, "Cannot change data mode "
				 "on remount");
			return -EINVAL;
		}
	}

	if (is_remount) {
		if (!sbi->s_journal &&
		    ctx_test_mount_opt(ctx, ECFS_MOUNT_DATA_ERR_ABORT)) {
			ecfs_msg(NULL, KERN_WARNING,
				 "Remounting fs w/o journal so ignoring data_err option");
			ctx_clear_mount_opt(ctx, ECFS_MOUNT_DATA_ERR_ABORT);
		}

		if (ctx_test_mount_opt(ctx, ECFS_MOUNT_DAX_ALWAYS) &&
		    (test_opt(sb, DATA_FLAGS) == ECFS_MOUNT_JOURNAL_DATA)) {
			ecfs_msg(NULL, KERN_ERR, "can't mount with "
				 "both data=journal and dax");
			return -EINVAL;
		}

		if (ctx_test_mount_opt(ctx, ECFS_MOUNT_DAX_ALWAYS) &&
		    (!(sbi->s_mount_opt & ECFS_MOUNT_DAX_ALWAYS) ||
		     (sbi->s_mount_opt2 & ECFS_MOUNT2_DAX_NEVER))) {
fail_dax_change_remount:
			ecfs_msg(NULL, KERN_ERR, "can't change "
				 "dax mount option while remounting");
			return -EINVAL;
		} else if (ctx_test_mount_opt2(ctx, ECFS_MOUNT2_DAX_NEVER) &&
			 (!(sbi->s_mount_opt2 & ECFS_MOUNT2_DAX_NEVER) ||
			  (sbi->s_mount_opt & ECFS_MOUNT_DAX_ALWAYS))) {
			goto fail_dax_change_remount;
		} else if (ctx_test_mount_opt2(ctx, ECFS_MOUNT2_DAX_INODE) &&
			   ((sbi->s_mount_opt & ECFS_MOUNT_DAX_ALWAYS) ||
			    (sbi->s_mount_opt2 & ECFS_MOUNT2_DAX_NEVER) ||
			    !(sbi->s_mount_opt2 & ECFS_MOUNT2_DAX_INODE))) {
			goto fail_dax_change_remount;
		}
	}

	return ecfs_check_quota_consistency(fc, sb);
}

static void ecfs_apply_options(struct fs_context *fc, struct super_block *sb)
{
	struct ecfs_fs_context *ctx = fc->fs_private;
	struct ecfs_sb_info *sbi = fc->s_fs_info;

	sbi->s_mount_opt &= ~ctx->mask_s_mount_opt;
	sbi->s_mount_opt |= ctx->vals_s_mount_opt;
	sbi->s_mount_opt2 &= ~ctx->mask_s_mount_opt2;
	sbi->s_mount_opt2 |= ctx->vals_s_mount_opt2;
	sb->s_flags &= ~ctx->mask_s_flags;
	sb->s_flags |= ctx->vals_s_flags;

#define APPLY(X) ({ if (ctx->spec & ECFS_SPEC_##X) sbi->X = ctx->X; })
	APPLY(s_commit_interval);
	APPLY(s_stripe);
	APPLY(s_max_batch_time);
	APPLY(s_min_batch_time);
	APPLY(s_want_extra_isize);
	APPLY(s_inode_readahead_blks);
	APPLY(s_max_dir_size_kb);
	APPLY(s_li_wait_mult);
	APPLY(s_resgid);
	APPLY(s_resuid);

#ifdef CONFIG_ECFS_DEBUG
	APPLY(s_fc_debug_max_replay);
#endif

	ecfs_apply_quota_options(fc, sb);
	ecfs_apply_test_dummy_encryption(ctx, sb);
}


static int ecfs_validate_options(struct fs_context *fc)
{
#ifdef CONFIG_QUOTA
	struct ecfs_fs_context *ctx = fc->fs_private;
	char *usr_qf_name, *grp_qf_name;

	usr_qf_name = ctx->s_qf_names[USRQUOTA];
	grp_qf_name = ctx->s_qf_names[GRPQUOTA];

	if (usr_qf_name || grp_qf_name) {
		if (ctx_test_mount_opt(ctx, ECFS_MOUNT_USRQUOTA) && usr_qf_name)
			ctx_clear_mount_opt(ctx, ECFS_MOUNT_USRQUOTA);

		if (ctx_test_mount_opt(ctx, ECFS_MOUNT_GRPQUOTA) && grp_qf_name)
			ctx_clear_mount_opt(ctx, ECFS_MOUNT_GRPQUOTA);

		if (ctx_test_mount_opt(ctx, ECFS_MOUNT_USRQUOTA) ||
		    ctx_test_mount_opt(ctx, ECFS_MOUNT_GRPQUOTA)) {
			ecfs_msg(NULL, KERN_ERR, "old and new quota "
				 "format mixing");
			return -EINVAL;
		}
	}
#endif
	return 1;
}

static inline void ecfs_show_quota_options(struct seq_file *seq,
					   struct super_block *sb)
{
#if defined(CONFIG_QUOTA)
	struct ecfs_sb_info *sbi = ECFS_SB(sb);
	char *usr_qf_name, *grp_qf_name;

	if (sbi->s_jquota_fmt) {
		char *fmtname = "";

		switch (sbi->s_jquota_fmt) {
		case QFMT_VFS_OLD:
			fmtname = "vfsold";
			break;
		case QFMT_VFS_V0:
			fmtname = "vfsv0";
			break;
		case QFMT_VFS_V1:
			fmtname = "vfsv1";
			break;
		}
		seq_printf(seq, ",jqfmt=%s", fmtname);
	}

	rcu_read_lock();
	usr_qf_name = rcu_dereference(sbi->s_qf_names[USRQUOTA]);
	grp_qf_name = rcu_dereference(sbi->s_qf_names[GRPQUOTA]);
	if (usr_qf_name)
		seq_show_option(seq, "usrjquota", usr_qf_name);
	if (grp_qf_name)
		seq_show_option(seq, "grpjquota", grp_qf_name);
	rcu_read_unlock();
#endif
}

static const char *token2str(int token)
{
	const struct fs_parameter_spec *spec;

	for (spec = ecfs_param_specs; spec->name != NULL; spec++)
		if (spec->opt == token && !spec->type)
			break;
	return spec->name;
}

/*
 * Show an option if
 *  - it's set to a non-default value OR
 *  - if the per-sb default is different from the global default
 */
static int _ecfs_show_options(struct seq_file *seq, struct super_block *sb,
			      int nodefs)
{
	struct ecfs_sb_info *sbi = ECFS_SB(sb);
	struct ecfs_super_block *es = sbi->s_es;
	int def_errors;
	const struct mount_opts *m;
	char sep = nodefs ? '\n' : ',';

#define SEQ_OPTS_PUTS(str) seq_printf(seq, "%c" str, sep)
#define SEQ_OPTS_PRINT(str, arg) seq_printf(seq, "%c" str, sep, arg)

	if (sbi->s_sb_block != 1)
		SEQ_OPTS_PRINT("sb=%llu", sbi->s_sb_block);

	for (m = ecfs_mount_opts; m->token != Opt_err; m++) {
		int want_set = m->flags & MOPT_SET;
		int opt_2 = m->flags & MOPT_2;
		unsigned int mount_opt, def_mount_opt;

		if (((m->flags & (MOPT_SET|MOPT_CLEAR)) == 0) ||
		    m->flags & MOPT_SKIP)
			continue;

		if (opt_2) {
			mount_opt = sbi->s_mount_opt2;
			def_mount_opt = sbi->s_def_mount_opt2;
		} else {
			mount_opt = sbi->s_mount_opt;
			def_mount_opt = sbi->s_def_mount_opt;
		}
		/* skip if same as the default */
		if (!nodefs && !(m->mount_opt & (mount_opt ^ def_mount_opt)))
			continue;
		/* select Opt_noFoo vs Opt_Foo */
		if ((want_set &&
		     (mount_opt & m->mount_opt) != m->mount_opt) ||
		    (!want_set && (mount_opt & m->mount_opt)))
			continue;
		SEQ_OPTS_PRINT("%s", token2str(m->token));
	}

	if (nodefs || !uid_eq(sbi->s_resuid, make_kuid(&init_user_ns, ECFS_DEF_RESUID)) ||
	    le16_to_cpu(es->s_def_resuid) != ECFS_DEF_RESUID)
		SEQ_OPTS_PRINT("resuid=%u",
				from_kuid_munged(&init_user_ns, sbi->s_resuid));
	if (nodefs || !gid_eq(sbi->s_resgid, make_kgid(&init_user_ns, ECFS_DEF_RESGID)) ||
	    le16_to_cpu(es->s_def_resgid) != ECFS_DEF_RESGID)
		SEQ_OPTS_PRINT("resgid=%u",
				from_kgid_munged(&init_user_ns, sbi->s_resgid));
	def_errors = nodefs ? -1 : le16_to_cpu(es->s_errors);
	if (test_opt(sb, ERRORS_RO) && def_errors != ECFS_ERRORS_RO)
		SEQ_OPTS_PUTS("errors=remount-ro");
	if (test_opt(sb, ERRORS_CONT) && def_errors != ECFS_ERRORS_CONTINUE)
		SEQ_OPTS_PUTS("errors=continue");
	if (test_opt(sb, ERRORS_PANIC) && def_errors != ECFS_ERRORS_PANIC)
		SEQ_OPTS_PUTS("errors=panic");
	if (nodefs || sbi->s_commit_interval != JBD2_DEFAULT_MAX_COMMIT_AGE*HZ)
		SEQ_OPTS_PRINT("commit=%lu", sbi->s_commit_interval / HZ);
	if (nodefs || sbi->s_min_batch_time != ECFS_DEF_MIN_BATCH_TIME)
		SEQ_OPTS_PRINT("min_batch_time=%u", sbi->s_min_batch_time);
	if (nodefs || sbi->s_max_batch_time != ECFS_DEF_MAX_BATCH_TIME)
		SEQ_OPTS_PRINT("max_batch_time=%u", sbi->s_max_batch_time);
	if (nodefs && sb->s_flags & SB_I_VERSION)
		SEQ_OPTS_PUTS("i_version");
	if (nodefs || sbi->s_stripe)
		SEQ_OPTS_PRINT("stripe=%lu", sbi->s_stripe);
	if (nodefs || ECFS_MOUNT_DATA_FLAGS &
			(sbi->s_mount_opt ^ sbi->s_def_mount_opt)) {
		if (test_opt(sb, DATA_FLAGS) == ECFS_MOUNT_JOURNAL_DATA)
			SEQ_OPTS_PUTS("data=journal");
		else if (test_opt(sb, DATA_FLAGS) == ECFS_MOUNT_ORDERED_DATA)
			SEQ_OPTS_PUTS("data=ordered");
		else if (test_opt(sb, DATA_FLAGS) == ECFS_MOUNT_WRITEBACK_DATA)
			SEQ_OPTS_PUTS("data=writeback");
	}
	if (nodefs ||
	    sbi->s_inode_readahead_blks != ECFS_DEF_INODE_READAHEAD_BLKS)
		SEQ_OPTS_PRINT("inode_readahead_blks=%u",
			       sbi->s_inode_readahead_blks);

	if (test_opt(sb, INIT_INODE_TABLE) && (nodefs ||
		       (sbi->s_li_wait_mult != ECFS_DEF_LI_WAIT_MULT)))
		SEQ_OPTS_PRINT("init_itable=%u", sbi->s_li_wait_mult);
	if (nodefs || sbi->s_max_dir_size_kb)
		SEQ_OPTS_PRINT("max_dir_size_kb=%u", sbi->s_max_dir_size_kb);
	if (test_opt(sb, DATA_ERR_ABORT))
		SEQ_OPTS_PUTS("data_err=abort");

	fscrypt_show_test_dummy_encryption(seq, sep, sb);

	if (sb->s_flags & SB_INLINECRYPT)
		SEQ_OPTS_PUTS("inlinecrypt");

	if (test_opt(sb, DAX_ALWAYS)) {
		SEQ_OPTS_PUTS("dax=always");
	} else if (test_opt2(sb, DAX_NEVER)) {
		SEQ_OPTS_PUTS("dax=never");
	} else if (test_opt2(sb, DAX_INODE)) {
		SEQ_OPTS_PUTS("dax=inode");
	}

	if (sbi->s_groups_count >= MB_DEFAULT_LINEAR_SCAN_THRESHOLD &&
			!test_opt2(sb, MB_OPTIMIZE_SCAN)) {
		SEQ_OPTS_PUTS("mb_optimize_scan=0");
	} else if (sbi->s_groups_count < MB_DEFAULT_LINEAR_SCAN_THRESHOLD &&
			test_opt2(sb, MB_OPTIMIZE_SCAN)) {
		SEQ_OPTS_PUTS("mb_optimize_scan=1");
	}

	if (nodefs && !test_opt(sb, NO_PREFETCH_BLOCK_BITMAPS))
		SEQ_OPTS_PUTS("prefetch_block_bitmaps");

	if (ecfs_emergency_ro(sb))
		SEQ_OPTS_PUTS("emergency_ro");

	if (ecfs_forced_shutdown(sb))
		SEQ_OPTS_PUTS("shutdown");

	ecfs_show_quota_options(seq, sb);
	return 0;
}

static int ecfs_show_options(struct seq_file *seq, struct dentry *root)
{
	return _ecfs_show_options(seq, root->d_sb, 0);
}

int ecfs_seq_options_show(struct seq_file *seq, void *offset)
{
	struct super_block *sb = seq->private;
	int rc;

	seq_puts(seq, sb_rdonly(sb) ? "ro" : "rw");
	rc = _ecfs_show_options(seq, sb, 1);
	seq_putc(seq, '\n');
	return rc;
}

static int ecfs_setup_super(struct super_block *sb, struct ecfs_super_block *es,
			    int read_only)
{
	struct ecfs_sb_info *sbi = ECFS_SB(sb);
	int err = 0;

	if (le32_to_cpu(es->s_rev_level) > ECFS_MAX_SUPP_REV) {
		ecfs_msg(sb, KERN_ERR, "revision level too high, "
			 "forcing read-only mode");
		err = -EROFS;
		goto done;
	}
	if (read_only)
		goto done;
	if (!(sbi->s_mount_state & ECFS_VALID_FS))
		ecfs_msg(sb, KERN_WARNING, "warning: mounting unchecked fs, "
			 "running e2fsck is recommended");
	else if (sbi->s_mount_state & ECFS_ERROR_FS)
		ecfs_msg(sb, KERN_WARNING,
			 "warning: mounting fs with errors, "
			 "running e2fsck is recommended");
	else if ((__s16) le16_to_cpu(es->s_max_mnt_count) > 0 &&
		 le16_to_cpu(es->s_mnt_count) >=
		 (unsigned short) (__s16) le16_to_cpu(es->s_max_mnt_count))
		ecfs_msg(sb, KERN_WARNING,
			 "warning: maximal mount count reached, "
			 "running e2fsck is recommended");
	else if (le32_to_cpu(es->s_checkinterval) &&
		 (ecfs_get_tstamp(es, s_lastcheck) +
		  le32_to_cpu(es->s_checkinterval) <= ktime_get_real_seconds()))
		ecfs_msg(sb, KERN_WARNING,
			 "warning: checktime reached, "
			 "running e2fsck is recommended");
	if (!sbi->s_journal)
		es->s_state &= cpu_to_le16(~ECFS_VALID_FS);
	if (!(__s16) le16_to_cpu(es->s_max_mnt_count))
		es->s_max_mnt_count = cpu_to_le16(ECFS_DFL_MAX_MNT_COUNT);
	le16_add_cpu(&es->s_mnt_count, 1);
	ecfs_update_tstamp(es, s_mtime);
	if (sbi->s_journal) {
		ecfs_set_feature_journal_needs_recovery(sb);
		if (ecfs_has_feature_orphan_file(sb))
			ecfs_set_feature_orphan_present(sb);
	}

	err = ecfs_commit_super(sb);
done:
	if (test_opt(sb, DEBUG))
		printk(KERN_INFO "[ECFS FS bs=%lu, gc=%u, "
				"bpg=%lu, ipg=%lu, mo=%04x, mo2=%04x]\n",
			sb->s_blocksize,
			sbi->s_groups_count,
			ECFS_BLOCKS_PER_GROUP(sb),
			ECFS_INODES_PER_GROUP(sb),
			sbi->s_mount_opt, sbi->s_mount_opt2);
	return err;
}

int ecfs_alloc_flex_bg_array(struct super_block *sb, ecfs_group_t ngroup)
{
	struct ecfs_sb_info *sbi = ECFS_SB(sb);
	struct flex_groups **old_groups, **new_groups;
	int size, i, j;

	if (!sbi->s_log_groups_per_flex)
		return 0;

	size = ecfs_flex_group(sbi, ngroup - 1) + 1;
	if (size <= sbi->s_flex_groups_allocated)
		return 0;

	new_groups = kvzalloc(roundup_pow_of_two(size *
			      sizeof(*sbi->s_flex_groups)), GFP_KERNEL);
	if (!new_groups) {
		ecfs_msg(sb, KERN_ERR,
			 "not enough memory for %d flex group pointers", size);
		return -ENOMEM;
	}
	for (i = sbi->s_flex_groups_allocated; i < size; i++) {
		new_groups[i] = kvzalloc(roundup_pow_of_two(
					 sizeof(struct flex_groups)),
					 GFP_KERNEL);
		if (!new_groups[i]) {
			for (j = sbi->s_flex_groups_allocated; j < i; j++)
				kvfree(new_groups[j]);
			kvfree(new_groups);
			ecfs_msg(sb, KERN_ERR,
				 "not enough memory for %d flex groups", size);
			return -ENOMEM;
		}
	}
	rcu_read_lock();
	old_groups = rcu_dereference(sbi->s_flex_groups);
	if (old_groups)
		memcpy(new_groups, old_groups,
		       (sbi->s_flex_groups_allocated *
			sizeof(struct flex_groups *)));
	rcu_read_unlock();
	rcu_assign_pointer(sbi->s_flex_groups, new_groups);
	sbi->s_flex_groups_allocated = size;
	if (old_groups)
		ecfs_kvfree_array_rcu(old_groups);
	return 0;
}

static int ecfs_fill_flex_info(struct super_block *sb)
{
	struct ecfs_sb_info *sbi = ECFS_SB(sb);
	struct ecfs_group_desc *gdp = NULL;
	struct flex_groups *fg;
	ecfs_group_t flex_group;
	int i, err;

	sbi->s_log_groups_per_flex = sbi->s_es->s_log_groups_per_flex;
	if (sbi->s_log_groups_per_flex < 1 || sbi->s_log_groups_per_flex > 31) {
		sbi->s_log_groups_per_flex = 0;
		return 1;
	}

	err = ecfs_alloc_flex_bg_array(sb, sbi->s_groups_count);
	if (err)
		goto failed;

	for (i = 0; i < sbi->s_groups_count; i++) {
		gdp = ecfs_get_group_desc(sb, i, NULL);

		flex_group = ecfs_flex_group(sbi, i);
		fg = sbi_array_rcu_deref(sbi, s_flex_groups, flex_group);
		atomic_add(ecfs_free_inodes_count(sb, gdp), &fg->free_inodes);
		atomic64_add(ecfs_free_group_clusters(sb, gdp),
			     &fg->free_clusters);
		atomic_add(ecfs_used_dirs_count(sb, gdp), &fg->used_dirs);
	}

	return 1;
failed:
	return 0;
}

static __le16 ecfs_group_desc_csum(struct super_block *sb, __u32 block_group,
				   struct ecfs_group_desc *gdp)
{
	int offset = offsetof(struct ecfs_group_desc, bg_checksum);
	__u16 crc = 0;
	__le32 le_group = cpu_to_le32(block_group);
	struct ecfs_sb_info *sbi = ECFS_SB(sb);

	if (ecfs_has_feature_metadata_csum(sbi->s_sb)) {
		/* Use new metadata_csum algorithm */
		__u32 csum32;
		__u16 dummy_csum = 0;

		csum32 = ecfs_chksum(sbi->s_csum_seed, (__u8 *)&le_group,
				     sizeof(le_group));
		csum32 = ecfs_chksum(csum32, (__u8 *)gdp, offset);
		csum32 = ecfs_chksum(csum32, (__u8 *)&dummy_csum,
				     sizeof(dummy_csum));
		offset += sizeof(dummy_csum);
		if (offset < sbi->s_desc_size)
			csum32 = ecfs_chksum(csum32, (__u8 *)gdp + offset,
					     sbi->s_desc_size - offset);

		crc = csum32 & 0xFFFF;
		goto out;
	}

	/* old crc16 code */
	if (!ecfs_has_feature_gdt_csum(sb))
		return 0;

	crc = crc16(~0, sbi->s_es->s_uuid, sizeof(sbi->s_es->s_uuid));
	crc = crc16(crc, (__u8 *)&le_group, sizeof(le_group));
	crc = crc16(crc, (__u8 *)gdp, offset);
	offset += sizeof(gdp->bg_checksum); /* skip checksum */
	/* for checksum of struct ecfs_group_desc do the rest...*/
	if (ecfs_has_feature_64bit(sb) && offset < sbi->s_desc_size)
		crc = crc16(crc, (__u8 *)gdp + offset,
			    sbi->s_desc_size - offset);

out:
	return cpu_to_le16(crc);
}

int ecfs_group_desc_csum_verify(struct super_block *sb, __u32 block_group,
				struct ecfs_group_desc *gdp)
{
	if (ecfs_has_group_desc_csum(sb) &&
	    (gdp->bg_checksum != ecfs_group_desc_csum(sb, block_group, gdp)))
		return 0;

	return 1;
}

void ecfs_group_desc_csum_set(struct super_block *sb, __u32 block_group,
			      struct ecfs_group_desc *gdp)
{
	if (!ecfs_has_group_desc_csum(sb))
		return;
	gdp->bg_checksum = ecfs_group_desc_csum(sb, block_group, gdp);
}

/* Called at mount-time, super-block is locked */
static int ecfs_check_descriptors(struct super_block *sb,
				  ecfs_fsblk_t sb_block,
				  ecfs_group_t *first_not_zeroed)
{
	struct ecfs_sb_info *sbi = ECFS_SB(sb);
	ecfs_fsblk_t first_block = le32_to_cpu(sbi->s_es->s_first_data_block);
	ecfs_fsblk_t last_block;
	ecfs_fsblk_t last_bg_block = sb_block + ecfs_bg_num_gdb(sb, 0);
	ecfs_fsblk_t block_bitmap;
	ecfs_fsblk_t inode_bitmap;
	ecfs_fsblk_t inode_table;
	int flexbg_flag = 0;
	ecfs_group_t i, grp = sbi->s_groups_count;

	if (ecfs_has_feature_flex_bg(sb))
		flexbg_flag = 1;

	ecfs_debug("Checking group descriptors");

	for (i = 0; i < sbi->s_groups_count; i++) {
		struct ecfs_group_desc *gdp = ecfs_get_group_desc(sb, i, NULL);

		if (i == sbi->s_groups_count - 1 || flexbg_flag)
			last_block = ecfs_blocks_count(sbi->s_es) - 1;
		else
			last_block = first_block +
				(ECFS_BLOCKS_PER_GROUP(sb) - 1);

		if ((grp == sbi->s_groups_count) &&
		   !(gdp->bg_flags & cpu_to_le16(ECFS_BG_INODE_ZEROED)))
			grp = i;

		block_bitmap = ecfs_block_bitmap(sb, gdp);
		if (block_bitmap == sb_block) {
			ecfs_msg(sb, KERN_ERR, "ecfs_check_descriptors: "
				 "Block bitmap for group %u overlaps "
				 "superblock", i);
			if (!sb_rdonly(sb))
				return 0;
		}
		if (block_bitmap >= sb_block + 1 &&
		    block_bitmap <= last_bg_block) {
			ecfs_msg(sb, KERN_ERR, "ecfs_check_descriptors: "
				 "Block bitmap for group %u overlaps "
				 "block group descriptors", i);
			if (!sb_rdonly(sb))
				return 0;
		}
		if (block_bitmap < first_block || block_bitmap > last_block) {
			ecfs_msg(sb, KERN_ERR, "ecfs_check_descriptors: "
			       "Block bitmap for group %u not in group "
			       "(block %llu)!", i, block_bitmap);
			return 0;
		}
		inode_bitmap = ecfs_inode_bitmap(sb, gdp);
		if (inode_bitmap == sb_block) {
			ecfs_msg(sb, KERN_ERR, "ecfs_check_descriptors: "
				 "Inode bitmap for group %u overlaps "
				 "superblock", i);
			if (!sb_rdonly(sb))
				return 0;
		}
		if (inode_bitmap >= sb_block + 1 &&
		    inode_bitmap <= last_bg_block) {
			ecfs_msg(sb, KERN_ERR, "ecfs_check_descriptors: "
				 "Inode bitmap for group %u overlaps "
				 "block group descriptors", i);
			if (!sb_rdonly(sb))
				return 0;
		}
		if (inode_bitmap < first_block || inode_bitmap > last_block) {
			ecfs_msg(sb, KERN_ERR, "ecfs_check_descriptors: "
			       "Inode bitmap for group %u not in group "
			       "(block %llu)!", i, inode_bitmap);
			return 0;
		}
		inode_table = ecfs_inode_table(sb, gdp);
		if (inode_table == sb_block) {
			ecfs_msg(sb, KERN_ERR, "ecfs_check_descriptors: "
				 "Inode table for group %u overlaps "
				 "superblock", i);
			if (!sb_rdonly(sb))
				return 0;
		}
		if (inode_table >= sb_block + 1 &&
		    inode_table <= last_bg_block) {
			ecfs_msg(sb, KERN_ERR, "ecfs_check_descriptors: "
				 "Inode table for group %u overlaps "
				 "block group descriptors", i);
			if (!sb_rdonly(sb))
				return 0;
		}
		if (inode_table < first_block ||
		    inode_table + sbi->s_itb_per_group - 1 > last_block) {
			ecfs_msg(sb, KERN_ERR, "ecfs_check_descriptors: "
			       "Inode table for group %u not in group "
			       "(block %llu)!", i, inode_table);
			return 0;
		}
		ecfs_lock_group(sb, i);
		if (!ecfs_group_desc_csum_verify(sb, i, gdp)) {
			ecfs_msg(sb, KERN_ERR, "ecfs_check_descriptors: "
				 "Checksum for group %u failed (%u!=%u)",
				 i, le16_to_cpu(ecfs_group_desc_csum(sb, i,
				     gdp)), le16_to_cpu(gdp->bg_checksum));
			if (!sb_rdonly(sb)) {
				ecfs_unlock_group(sb, i);
				return 0;
			}
		}
		ecfs_unlock_group(sb, i);
		if (!flexbg_flag)
			first_block += ECFS_BLOCKS_PER_GROUP(sb);
	}
	if (NULL != first_not_zeroed)
		*first_not_zeroed = grp;
	return 1;
}

/*
 * Maximal extent format file size.
 * Resulting logical blkno at s_maxbytes must fit in our on-disk
 * extent format containers, within a sector_t, and within i_blocks
 * in the vfs.  ecfs inode has 48 bits of i_block in fsblock units,
 * so that won't be a limiting factor.
 *
 * However there is other limiting factor. We do store extents in the form
 * of starting block and length, hence the resulting length of the extent
 * covering maximum file size must fit into on-disk format containers as
 * well. Given that length is always by 1 unit bigger than max unit (because
 * we count 0 as well) we have to lower the s_maxbytes by one fs block.
 *
 * Note, this does *not* consider any metadata overhead for vfs i_blocks.
 */
static loff_t ecfs_max_size(int blkbits, int has_huge_files)
{
	loff_t res;
	loff_t upper_limit = MAX_LFS_FILESIZE;

	BUILD_BUG_ON(sizeof(blkcnt_t) < sizeof(u64));

	if (!has_huge_files) {
		upper_limit = (1LL << 32) - 1;

		/* total blocks in file system block size */
		upper_limit >>= (blkbits - 9);
		upper_limit <<= blkbits;
	}

	/*
	 * 32-bit extent-start container, ee_block. We lower the maxbytes
	 * by one fs block, so ee_len can cover the extent of maximum file
	 * size
	 */
	res = (1LL << 32) - 1;
	res <<= blkbits;

	/* Sanity check against vm- & vfs- imposed limits */
	if (res > upper_limit)
		res = upper_limit;

	return res;
}

/*
 * Maximal bitmap file size.  There is a direct, and {,double-,triple-}indirect
 * block limit, and also a limit of (2^48 - 1) 512-byte sectors in i_blocks.
 * We need to be 1 filesystem block less than the 2^48 sector limit.
 */
static loff_t ecfs_max_bitmap_size(int bits, int has_huge_files)
{
	loff_t upper_limit, res = ECFS_NDIR_BLOCKS;
	int meta_blocks;
	unsigned int ppb = 1 << (bits - 2);

	/*
	 * This is calculated to be the largest file size for a dense, block
	 * mapped file such that the file's total number of 512-byte sectors,
	 * including data and all indirect blocks, does not exceed (2^48 - 1).
	 *
	 * __u32 i_blocks_lo and _u16 i_blocks_high represent the total
	 * number of 512-byte sectors of the file.
	 */
	if (!has_huge_files) {
		/*
		 * !has_huge_files or implies that the inode i_block field
		 * represents total file blocks in 2^32 512-byte sectors ==
		 * size of vfs inode i_blocks * 8
		 */
		upper_limit = (1LL << 32) - 1;

		/* total blocks in file system block size */
		upper_limit >>= (bits - 9);

	} else {
		/*
		 * We use 48 bit ecfs_inode i_blocks
		 * With ECFS_HUGE_FILE_FL set the i_blocks
		 * represent total number of blocks in
		 * file system block size
		 */
		upper_limit = (1LL << 48) - 1;

	}

	/* Compute how many blocks we can address by block tree */
	res += ppb;
	res += ppb * ppb;
	res += ((loff_t)ppb) * ppb * ppb;
	/* Compute how many metadata blocks are needed */
	meta_blocks = 1;
	meta_blocks += 1 + ppb;
	meta_blocks += 1 + ppb + ppb * ppb;
	/* Does block tree limit file size? */
	if (res + meta_blocks <= upper_limit)
		goto check_lfs;

	res = upper_limit;
	/* How many metadata blocks are needed for addressing upper_limit? */
	upper_limit -= ECFS_NDIR_BLOCKS;
	/* indirect blocks */
	meta_blocks = 1;
	upper_limit -= ppb;
	/* double indirect blocks */
	if (upper_limit < ppb * ppb) {
		meta_blocks += 1 + DIV_ROUND_UP_ULL(upper_limit, ppb);
		res -= meta_blocks;
		goto check_lfs;
	}
	meta_blocks += 1 + ppb;
	upper_limit -= ppb * ppb;
	/* tripple indirect blocks for the rest */
	meta_blocks += 1 + DIV_ROUND_UP_ULL(upper_limit, ppb) +
		DIV_ROUND_UP_ULL(upper_limit, ppb*ppb);
	res -= meta_blocks;
check_lfs:
	res <<= bits;
	if (res > MAX_LFS_FILESIZE)
		res = MAX_LFS_FILESIZE;

	return res;
}

static ecfs_fsblk_t descriptor_loc(struct super_block *sb,
				   ecfs_fsblk_t logical_sb_block, int nr)
{
	struct ecfs_sb_info *sbi = ECFS_SB(sb);
	ecfs_group_t bg, first_meta_bg;
	int has_super = 0;

	first_meta_bg = le32_to_cpu(sbi->s_es->s_first_meta_bg);

	if (!ecfs_has_feature_meta_bg(sb) || nr < first_meta_bg)
		return logical_sb_block + nr + 1;
	bg = sbi->s_desc_per_block * nr;
	if (ecfs_bg_has_super(sb, bg))
		has_super = 1;

	/*
	 * If we have a meta_bg fs with 1k blocks, group 0's GDT is at
	 * block 2, not 1.  If s_first_data_block == 0 (bigalloc is enabled
	 * on modern mke2fs or blksize > 1k on older mke2fs) then we must
	 * compensate.
	 */
	if (sb->s_blocksize == 1024 && nr == 0 &&
	    le32_to_cpu(sbi->s_es->s_first_data_block) == 0)
		has_super++;

	return (has_super + ecfs_group_first_block_no(sb, bg));
}

/**
 * ecfs_get_stripe_size: Get the stripe size.
 * @sbi: In memory super block info
 *
 * If we have specified it via mount option, then
 * use the mount option value. If the value specified at mount time is
 * greater than the blocks per group use the super block value.
 * If the super block value is greater than blocks per group return 0.
 * Allocator needs it be less than blocks per group.
 *
 */
static unsigned long ecfs_get_stripe_size(struct ecfs_sb_info *sbi)
{
	unsigned long stride = le16_to_cpu(sbi->s_es->s_raid_stride);
	unsigned long stripe_width =
			le32_to_cpu(sbi->s_es->s_raid_stripe_width);
	int ret;

	if (sbi->s_stripe && sbi->s_stripe <= sbi->s_blocks_per_group)
		ret = sbi->s_stripe;
	else if (stripe_width && stripe_width <= sbi->s_blocks_per_group)
		ret = stripe_width;
	else if (stride && stride <= sbi->s_blocks_per_group)
		ret = stride;
	else
		ret = 0;

	/*
	 * If the stripe width is 1, this makes no sense and
	 * we set it to 0 to turn off stripe handling code.
	 */
	if (ret <= 1)
		ret = 0;

	return ret;
}

/*
 * Check whether this filesystem can be mounted based on
 * the features present and the RDONLY/RDWR mount requested.
 * Returns 1 if this filesystem can be mounted as requested,
 * 0 if it cannot be.
 */
int ecfs_feature_set_ok(struct super_block *sb, int readonly)
{
	if (ecfs_has_unknown_ecfs_incompat_features(sb)) {
		ecfs_msg(sb, KERN_ERR,
			"Couldn't mount because of "
			"unsupported optional features (%x)",
			(le32_to_cpu(ECFS_SB(sb)->s_es->s_feature_incompat) &
			~ECFS_FEATURE_INCOMPAT_SUPP));
		return 0;
	}

	if (!IS_ENABLED(CONFIG_UNICODE) && ecfs_has_feature_casefold(sb)) {
		ecfs_msg(sb, KERN_ERR,
			 "Filesystem with casefold feature cannot be "
			 "mounted without CONFIG_UNICODE");
		return 0;
	}

	if (readonly)
		return 1;

	if (ecfs_has_feature_readonly(sb)) {
		ecfs_msg(sb, KERN_INFO, "filesystem is read-only");
		sb->s_flags |= SB_RDONLY;
		return 1;
	}

	/* Check that feature set is OK for a read-write mount */
	if (ecfs_has_unknown_ecfs_ro_compat_features(sb)) {
		ecfs_msg(sb, KERN_ERR, "couldn't mount RDWR because of "
			 "unsupported optional features (%x)",
			 (le32_to_cpu(ECFS_SB(sb)->s_es->s_feature_ro_compat) &
				~ECFS_FEATURE_RO_COMPAT_SUPP));
		return 0;
	}
	if (ecfs_has_feature_bigalloc(sb) && !ecfs_has_feature_extents(sb)) {
		ecfs_msg(sb, KERN_ERR,
			 "Can't support bigalloc feature without "
			 "extents feature\n");
		return 0;
	}

#if !IS_ENABLED(CONFIG_QUOTA) || !IS_ENABLED(CONFIG_QFMT_V2)
	if (!readonly && (ecfs_has_feature_quota(sb) ||
			  ecfs_has_feature_project(sb))) {
		ecfs_msg(sb, KERN_ERR,
			 "The kernel was not built with CONFIG_QUOTA and CONFIG_QFMT_V2");
		return 0;
	}
#endif  /* CONFIG_QUOTA */
	return 1;
}

/*
 * This function is called once a day if we have errors logged
 * on the file system
 */
static void print_daily_error_info(struct timer_list *t)
{
	struct ecfs_sb_info *sbi = timer_container_of(sbi, t, s_err_report);
	struct super_block *sb = sbi->s_sb;
	struct ecfs_super_block *es = sbi->s_es;

	if (es->s_error_count)
		/* fsck newer than v1.41.13 is needed to clean this condition. */
		ecfs_msg(sb, KERN_NOTICE, "error count since last fsck: %u",
			 le32_to_cpu(es->s_error_count));
	if (es->s_first_error_time) {
		printk(KERN_NOTICE "ECFS-fs (%s): initial error at time %llu: %.*s:%d",
		       sb->s_id,
		       ecfs_get_tstamp(es, s_first_error_time),
		       (int) sizeof(es->s_first_error_func),
		       es->s_first_error_func,
		       le32_to_cpu(es->s_first_error_line));
		if (es->s_first_error_ino)
			printk(KERN_CONT ": inode %u",
			       le32_to_cpu(es->s_first_error_ino));
		if (es->s_first_error_block)
			printk(KERN_CONT ": block %llu", (unsigned long long)
			       le64_to_cpu(es->s_first_error_block));
		printk(KERN_CONT "\n");
	}
	if (es->s_last_error_time) {
		printk(KERN_NOTICE "ECFS-fs (%s): last error at time %llu: %.*s:%d",
		       sb->s_id,
		       ecfs_get_tstamp(es, s_last_error_time),
		       (int) sizeof(es->s_last_error_func),
		       es->s_last_error_func,
		       le32_to_cpu(es->s_last_error_line));
		if (es->s_last_error_ino)
			printk(KERN_CONT ": inode %u",
			       le32_to_cpu(es->s_last_error_ino));
		if (es->s_last_error_block)
			printk(KERN_CONT ": block %llu", (unsigned long long)
			       le64_to_cpu(es->s_last_error_block));
		printk(KERN_CONT "\n");
	}
	mod_timer(&sbi->s_err_report, jiffies + 24*60*60*HZ);  /* Once a day */
}

/* Find next suitable group and run ecfs_init_inode_table */
static int ecfs_run_li_request(struct ecfs_li_request *elr)
{
	struct ecfs_group_desc *gdp = NULL;
	struct super_block *sb = elr->lr_super;
	ecfs_group_t ngroups = ECFS_SB(sb)->s_groups_count;
	ecfs_group_t group = elr->lr_next_group;
	unsigned int prefetch_ios = 0;
	int ret = 0;
	int nr = ECFS_SB(sb)->s_mb_prefetch;
	u64 start_time;

	if (elr->lr_mode == ECFS_LI_MODE_PREFETCH_BBITMAP) {
		elr->lr_next_group = ecfs_mb_prefetch(sb, group, nr, &prefetch_ios);
		ecfs_mb_prefetch_fini(sb, elr->lr_next_group, nr);
		trace_ecfs_prefetch_bitmaps(sb, group, elr->lr_next_group, nr);
		if (group >= elr->lr_next_group) {
			ret = 1;
			if (elr->lr_first_not_zeroed != ngroups &&
			    !ecfs_emergency_state(sb) && !sb_rdonly(sb) &&
			    test_opt(sb, INIT_INODE_TABLE)) {
				elr->lr_next_group = elr->lr_first_not_zeroed;
				elr->lr_mode = ECFS_LI_MODE_ITABLE;
				ret = 0;
			}
		}
		return ret;
	}

	for (; group < ngroups; group++) {
		gdp = ecfs_get_group_desc(sb, group, NULL);
		if (!gdp) {
			ret = 1;
			break;
		}

		if (!(gdp->bg_flags & cpu_to_le16(ECFS_BG_INODE_ZEROED)))
			break;
	}

	if (group >= ngroups)
		ret = 1;

	if (!ret) {
		start_time = ktime_get_ns();
		ret = ecfs_init_inode_table(sb, group,
					    elr->lr_timeout ? 0 : 1);
		trace_ecfs_lazy_itable_init(sb, group);
		if (elr->lr_timeout == 0) {
			elr->lr_timeout = nsecs_to_jiffies((ktime_get_ns() - start_time) *
				ECFS_SB(elr->lr_super)->s_li_wait_mult);
		}
		elr->lr_next_sched = jiffies + elr->lr_timeout;
		elr->lr_next_group = group + 1;
	}
	return ret;
}

/*
 * Remove lr_request from the list_request and free the
 * request structure. Should be called with li_list_mtx held
 */
static void ecfs_remove_li_request(struct ecfs_li_request *elr)
{
	if (!elr)
		return;

	list_del(&elr->lr_request);
	ECFS_SB(elr->lr_super)->s_li_request = NULL;
	kfree(elr);
}

static void ecfs_unregister_li_request(struct super_block *sb)
{
	mutex_lock(&ecfs_li_mtx);
	if (!ecfs_li_info) {
		mutex_unlock(&ecfs_li_mtx);
		return;
	}

	mutex_lock(&ecfs_li_info->li_list_mtx);
	ecfs_remove_li_request(ECFS_SB(sb)->s_li_request);
	mutex_unlock(&ecfs_li_info->li_list_mtx);
	mutex_unlock(&ecfs_li_mtx);
}

static struct task_struct *ecfs_lazyinit_task;

/*
 * This is the function where ecfslazyinit thread lives. It walks
 * through the request list searching for next scheduled filesystem.
 * When such a fs is found, run the lazy initialization request
 * (ecfs_rn_li_request) and keep track of the time spend in this
 * function. Based on that time we compute next schedule time of
 * the request. When walking through the list is complete, compute
 * next waking time and put itself into sleep.
 */
static int ecfs_lazyinit_thread(void *arg)
{
	struct ecfs_lazy_init *eli = arg;
	struct list_head *pos, *n;
	struct ecfs_li_request *elr;
	unsigned long next_wakeup, cur;

	BUG_ON(NULL == eli);
	set_freezable();

cont_thread:
	while (true) {
		bool next_wakeup_initialized = false;

		next_wakeup = 0;
		mutex_lock(&eli->li_list_mtx);
		if (list_empty(&eli->li_request_list)) {
			mutex_unlock(&eli->li_list_mtx);
			goto exit_thread;
		}
		list_for_each_safe(pos, n, &eli->li_request_list) {
			int err = 0;
			int progress = 0;
			elr = list_entry(pos, struct ecfs_li_request,
					 lr_request);

			if (time_before(jiffies, elr->lr_next_sched)) {
				if (!next_wakeup_initialized ||
				    time_before(elr->lr_next_sched, next_wakeup)) {
					next_wakeup = elr->lr_next_sched;
					next_wakeup_initialized = true;
				}
				continue;
			}
			if (down_read_trylock(&elr->lr_super->s_umount)) {
				if (sb_start_write_trylock(elr->lr_super)) {
					progress = 1;
					/*
					 * We hold sb->s_umount, sb can not
					 * be removed from the list, it is
					 * now safe to drop li_list_mtx
					 */
					mutex_unlock(&eli->li_list_mtx);
					err = ecfs_run_li_request(elr);
					sb_end_write(elr->lr_super);
					mutex_lock(&eli->li_list_mtx);
					n = pos->next;
				}
				up_read((&elr->lr_super->s_umount));
			}
			/* error, remove the lazy_init job */
			if (err) {
				ecfs_remove_li_request(elr);
				continue;
			}
			if (!progress) {
				elr->lr_next_sched = jiffies +
					get_random_u32_below(ECFS_DEF_LI_MAX_START_DELAY * HZ);
			}
			if (!next_wakeup_initialized ||
			    time_before(elr->lr_next_sched, next_wakeup)) {
				next_wakeup = elr->lr_next_sched;
				next_wakeup_initialized = true;
			}
		}
		mutex_unlock(&eli->li_list_mtx);

		try_to_freeze();

		cur = jiffies;
		if (!next_wakeup_initialized || time_after_eq(cur, next_wakeup)) {
			cond_resched();
			continue;
		}

		schedule_timeout_interruptible(next_wakeup - cur);

		if (kthread_should_stop()) {
			ecfs_clear_request_list();
			goto exit_thread;
		}
	}

exit_thread:
	/*
	 * It looks like the request list is empty, but we need
	 * to check it under the li_list_mtx lock, to prevent any
	 * additions into it, and of course we should lock ecfs_li_mtx
	 * to atomically free the list and ecfs_li_info, because at
	 * this point another ecfs filesystem could be registering
	 * new one.
	 */
	mutex_lock(&ecfs_li_mtx);
	mutex_lock(&eli->li_list_mtx);
	if (!list_empty(&eli->li_request_list)) {
		mutex_unlock(&eli->li_list_mtx);
		mutex_unlock(&ecfs_li_mtx);
		goto cont_thread;
	}
	mutex_unlock(&eli->li_list_mtx);
	kfree(ecfs_li_info);
	ecfs_li_info = NULL;
	mutex_unlock(&ecfs_li_mtx);

	return 0;
}

static void ecfs_clear_request_list(void)
{
	struct list_head *pos, *n;
	struct ecfs_li_request *elr;

	mutex_lock(&ecfs_li_info->li_list_mtx);
	list_for_each_safe(pos, n, &ecfs_li_info->li_request_list) {
		elr = list_entry(pos, struct ecfs_li_request,
				 lr_request);
		ecfs_remove_li_request(elr);
	}
	mutex_unlock(&ecfs_li_info->li_list_mtx);
}

static int ecfs_run_lazyinit_thread(void)
{
	ecfs_lazyinit_task = kthread_run(ecfs_lazyinit_thread,
					 ecfs_li_info, "ecfslazyinit");
	if (IS_ERR(ecfs_lazyinit_task)) {
		int err = PTR_ERR(ecfs_lazyinit_task);
		ecfs_clear_request_list();
		kfree(ecfs_li_info);
		ecfs_li_info = NULL;
		printk(KERN_CRIT "ECFS-fs: error %d creating inode table "
				 "initialization thread\n",
				 err);
		return err;
	}
	ecfs_li_info->li_state |= ECFS_LAZYINIT_RUNNING;
	return 0;
}

/*
 * Check whether it make sense to run itable init. thread or not.
 * If there is at least one uninitialized inode table, return
 * corresponding group number, else the loop goes through all
 * groups and return total number of groups.
 */
static ecfs_group_t ecfs_has_uninit_itable(struct super_block *sb)
{
	ecfs_group_t group, ngroups = ECFS_SB(sb)->s_groups_count;
	struct ecfs_group_desc *gdp = NULL;

	if (!ecfs_has_group_desc_csum(sb))
		return ngroups;

	for (group = 0; group < ngroups; group++) {
		gdp = ecfs_get_group_desc(sb, group, NULL);
		if (!gdp)
			continue;

		if (!(gdp->bg_flags & cpu_to_le16(ECFS_BG_INODE_ZEROED)))
			break;
	}

	return group;
}

static int ecfs_li_info_new(void)
{
	struct ecfs_lazy_init *eli = NULL;

	eli = kzalloc(sizeof(*eli), GFP_KERNEL);
	if (!eli)
		return -ENOMEM;

	INIT_LIST_HEAD(&eli->li_request_list);
	mutex_init(&eli->li_list_mtx);

	eli->li_state |= ECFS_LAZYINIT_QUIT;

	ecfs_li_info = eli;

	return 0;
}

static struct ecfs_li_request *ecfs_li_request_new(struct super_block *sb,
					    ecfs_group_t start)
{
	struct ecfs_li_request *elr;

	elr = kzalloc(sizeof(*elr), GFP_KERNEL);
	if (!elr)
		return NULL;

	elr->lr_super = sb;
	elr->lr_first_not_zeroed = start;
	if (test_opt(sb, NO_PREFETCH_BLOCK_BITMAPS)) {
		elr->lr_mode = ECFS_LI_MODE_ITABLE;
		elr->lr_next_group = start;
	} else {
		elr->lr_mode = ECFS_LI_MODE_PREFETCH_BBITMAP;
	}

	/*
	 * Randomize first schedule time of the request to
	 * spread the inode table initialization requests
	 * better.
	 */
	elr->lr_next_sched = jiffies + get_random_u32_below(ECFS_DEF_LI_MAX_START_DELAY * HZ);
	return elr;
}

int ecfs_register_li_request(struct super_block *sb,
			     ecfs_group_t first_not_zeroed)
{
	struct ecfs_sb_info *sbi = ECFS_SB(sb);
	struct ecfs_li_request *elr = NULL;
	ecfs_group_t ngroups = sbi->s_groups_count;
	int ret = 0;

	mutex_lock(&ecfs_li_mtx);
	if (sbi->s_li_request != NULL) {
		/*
		 * Reset timeout so it can be computed again, because
		 * s_li_wait_mult might have changed.
		 */
		sbi->s_li_request->lr_timeout = 0;
		goto out;
	}

	if (ecfs_emergency_state(sb) || sb_rdonly(sb) ||
	    (test_opt(sb, NO_PREFETCH_BLOCK_BITMAPS) &&
	     (first_not_zeroed == ngroups || !test_opt(sb, INIT_INODE_TABLE))))
		goto out;

	elr = ecfs_li_request_new(sb, first_not_zeroed);
	if (!elr) {
		ret = -ENOMEM;
		goto out;
	}

	if (NULL == ecfs_li_info) {
		ret = ecfs_li_info_new();
		if (ret)
			goto out;
	}

	mutex_lock(&ecfs_li_info->li_list_mtx);
	list_add(&elr->lr_request, &ecfs_li_info->li_request_list);
	mutex_unlock(&ecfs_li_info->li_list_mtx);

	sbi->s_li_request = elr;
	/*
	 * set elr to NULL here since it has been inserted to
	 * the request_list and the removal and free of it is
	 * handled by ecfs_clear_request_list from now on.
	 */
	elr = NULL;

	if (!(ecfs_li_info->li_state & ECFS_LAZYINIT_RUNNING)) {
		ret = ecfs_run_lazyinit_thread();
		if (ret)
			goto out;
	}
out:
	mutex_unlock(&ecfs_li_mtx);
	if (ret)
		kfree(elr);
	return ret;
}

/*
 * We do not need to lock anything since this is called on
 * module unload.
 */
static void ecfs_destroy_lazyinit_thread(void)
{
	/*
	 * If thread exited earlier
	 * there's nothing to be done.
	 */
	if (!ecfs_li_info || !ecfs_lazyinit_task)
		return;

	kthread_stop(ecfs_lazyinit_task);
}

static int set_journal_csum_feature_set(struct super_block *sb)
{
	int ret = 1;
	int compat, incompat;
	struct ecfs_sb_info *sbi = ECFS_SB(sb);

	if (ecfs_has_feature_metadata_csum(sb)) {
		/* journal checksum v3 */
		compat = 0;
		incompat = JBD2_FEATURE_INCOMPAT_CSUM_V3;
	} else {
		/* journal checksum v1 */
		compat = JBD2_FEATURE_COMPAT_CHECKSUM;
		incompat = 0;
	}

	jbd2_journal_clear_features(sbi->s_journal,
			JBD2_FEATURE_COMPAT_CHECKSUM, 0,
			JBD2_FEATURE_INCOMPAT_CSUM_V3 |
			JBD2_FEATURE_INCOMPAT_CSUM_V2);
	if (test_opt(sb, JOURNAL_ASYNC_COMMIT)) {
		ret = jbd2_journal_set_features(sbi->s_journal,
				compat, 0,
				JBD2_FEATURE_INCOMPAT_ASYNC_COMMIT |
				incompat);
	} else if (test_opt(sb, JOURNAL_CHECKSUM)) {
		ret = jbd2_journal_set_features(sbi->s_journal,
				compat, 0,
				incompat);
		jbd2_journal_clear_features(sbi->s_journal, 0, 0,
				JBD2_FEATURE_INCOMPAT_ASYNC_COMMIT);
	} else {
		jbd2_journal_clear_features(sbi->s_journal, 0, 0,
				JBD2_FEATURE_INCOMPAT_ASYNC_COMMIT);
	}

	return ret;
}

/*
 * Note: calculating the overhead so we can be compatible with
 * historical BSD practice is quite difficult in the face of
 * clusters/bigalloc.  This is because multiple metadata blocks from
 * different block group can end up in the same allocation cluster.
 * Calculating the exact overhead in the face of clustered allocation
 * requires either O(all block bitmaps) in memory or O(number of block
 * groups**2) in time.  We will still calculate the superblock for
 * older file systems --- and if we come across with a bigalloc file
 * system with zero in s_overhead_clusters the estimate will be close to
 * correct especially for very large cluster sizes --- but for newer
 * file systems, it's better to calculate this figure once at mkfs
 * time, and store it in the superblock.  If the superblock value is
 * present (even for non-bigalloc file systems), we will use it.
 */
static int count_overhead(struct super_block *sb, ecfs_group_t grp,
			  char *buf)
{
	struct ecfs_sb_info	*sbi = ECFS_SB(sb);
	struct ecfs_group_desc	*gdp;
	ecfs_fsblk_t		first_block, last_block, b;
	ecfs_group_t		i, ngroups = ecfs_get_groups_count(sb);
	int			s, j, count = 0;
	int			has_super = ecfs_bg_has_super(sb, grp);

	if (!ecfs_has_feature_bigalloc(sb))
		return (has_super + ecfs_bg_num_gdb(sb, grp) +
			(has_super ? le16_to_cpu(sbi->s_es->s_reserved_gdt_blocks) : 0) +
			sbi->s_itb_per_group + 2);

	first_block = le32_to_cpu(sbi->s_es->s_first_data_block) +
		(grp * ECFS_BLOCKS_PER_GROUP(sb));
	last_block = first_block + ECFS_BLOCKS_PER_GROUP(sb) - 1;
	for (i = 0; i < ngroups; i++) {
		gdp = ecfs_get_group_desc(sb, i, NULL);
		b = ecfs_block_bitmap(sb, gdp);
		if (b >= first_block && b <= last_block) {
			ecfs_set_bit(ECFS_B2C(sbi, b - first_block), buf);
			count++;
		}
		b = ecfs_inode_bitmap(sb, gdp);
		if (b >= first_block && b <= last_block) {
			ecfs_set_bit(ECFS_B2C(sbi, b - first_block), buf);
			count++;
		}
		b = ecfs_inode_table(sb, gdp);
		if (b >= first_block && b + sbi->s_itb_per_group <= last_block)
			for (j = 0; j < sbi->s_itb_per_group; j++, b++) {
				int c = ECFS_B2C(sbi, b - first_block);
				ecfs_set_bit(c, buf);
				count++;
			}
		if (i != grp)
			continue;
		s = 0;
		if (ecfs_bg_has_super(sb, grp)) {
			ecfs_set_bit(s++, buf);
			count++;
		}
		j = ecfs_bg_num_gdb(sb, grp);
		if (s + j > ECFS_BLOCKS_PER_GROUP(sb)) {
			ecfs_error(sb, "Invalid number of block group "
				   "descriptor blocks: %d", j);
			j = ECFS_BLOCKS_PER_GROUP(sb) - s;
		}
		count += j;
		for (; j > 0; j--)
			ecfs_set_bit(ECFS_B2C(sbi, s++), buf);
	}
	if (!count)
		return 0;
	return ECFS_CLUSTERS_PER_GROUP(sb) -
		ecfs_count_free(buf, ECFS_CLUSTERS_PER_GROUP(sb) / 8);
}

/*
 * Compute the overhead and stash it in sbi->s_overhead
 */
int ecfs_calculate_overhead(struct super_block *sb)
{
	struct ecfs_sb_info *sbi = ECFS_SB(sb);
	struct ecfs_super_block *es = sbi->s_es;
	struct inode *j_inode;
	unsigned int j_blocks, j_inum = le32_to_cpu(es->s_journal_inum);
	ecfs_group_t i, ngroups = ecfs_get_groups_count(sb);
	ecfs_fsblk_t overhead = 0;
	char *buf = (char *) get_zeroed_page(GFP_NOFS);

	if (!buf)
		return -ENOMEM;

	/*
	 * Compute the overhead (FS structures).  This is constant
	 * for a given filesystem unless the number of block groups
	 * changes so we cache the previous value until it does.
	 */

	/*
	 * All of the blocks before first_data_block are overhead
	 */
	overhead = ECFS_B2C(sbi, le32_to_cpu(es->s_first_data_block));

	/*
	 * Add the overhead found in each block group
	 */
	for (i = 0; i < ngroups; i++) {
		int blks;

		blks = count_overhead(sb, i, buf);
		overhead += blks;
		if (blks)
			memset(buf, 0, PAGE_SIZE);
		cond_resched();
	}

	/*
	 * Add the internal journal blocks whether the journal has been
	 * loaded or not
	 */
	if (sbi->s_journal && !sbi->s_journal_bdev_file)
		overhead += ECFS_NUM_B2C(sbi, sbi->s_journal->j_total_len);
	else if (ecfs_has_feature_journal(sb) && !sbi->s_journal && j_inum) {
		/* j_inum for internal journal is non-zero */
		j_inode = ecfs_get_journal_inode(sb, j_inum);
		if (!IS_ERR(j_inode)) {
			j_blocks = j_inode->i_size >> sb->s_blocksize_bits;
			overhead += ECFS_NUM_B2C(sbi, j_blocks);
			iput(j_inode);
		} else {
			ecfs_msg(sb, KERN_ERR, "can't get journal size");
		}
	}
	sbi->s_overhead = overhead;
	smp_wmb();
	free_page((unsigned long) buf);
	return 0;
}

static void ecfs_set_resv_clusters(struct super_block *sb)
{
	ecfs_fsblk_t resv_clusters;
	struct ecfs_sb_info *sbi = ECFS_SB(sb);

	/*
	 * There's no need to reserve anything when we aren't using extents.
	 * The space estimates are exact, there are no unwritten extents,
	 * hole punching doesn't need new metadata... This is needed especially
	 * to keep ext2/3 backward compatibility.
	 */
	if (!ecfs_has_feature_extents(sb))
		return;
	/*
	 * By default we reserve 2% or 4096 clusters, whichever is smaller.
	 * This should cover the situations where we can not afford to run
	 * out of space like for example punch hole, or converting
	 * unwritten extents in delalloc path. In most cases such
	 * allocation would require 1, or 2 blocks, higher numbers are
	 * very rare.
	 */
	resv_clusters = (ecfs_blocks_count(sbi->s_es) >>
			 sbi->s_cluster_bits);

	do_div(resv_clusters, 50);
	resv_clusters = min_t(ecfs_fsblk_t, resv_clusters, 4096);

	atomic64_set(&sbi->s_resv_clusters, resv_clusters);
}

static const char *ecfs_quota_mode(struct super_block *sb)
{
#ifdef CONFIG_QUOTA
	if (!ecfs_quota_capable(sb))
		return "none";

	if (ECFS_SB(sb)->s_journal && ecfs_is_quota_journalled(sb))
		return "journalled";
	else
		return "writeback";
#else
	return "disabled";
#endif
}

static void ecfs_setup_csum_trigger(struct super_block *sb,
				    enum ecfs_journal_trigger_type type,
				    void (*trigger)(
					struct jbd2_buffer_trigger_type *type,
					struct buffer_head *bh,
					void *mapped_data,
					size_t size))
{
	struct ecfs_sb_info *sbi = ECFS_SB(sb);

	sbi->s_journal_triggers[type].sb = sb;
	sbi->s_journal_triggers[type].tr_triggers.t_frozen = trigger;
}

static void ecfs_free_sbi(struct ecfs_sb_info *sbi)
{
	if (!sbi)
		return;

	kfree(sbi->s_blockgroup_lock);
	fs_put_dax(sbi->s_daxdev, NULL);
	kfree(sbi);
}

static struct ecfs_sb_info *ecfs_alloc_sbi(struct super_block *sb)
{
	struct ecfs_sb_info *sbi;

	sbi = kzalloc(sizeof(*sbi), GFP_KERNEL);
	if (!sbi)
		return NULL;

	sbi->s_daxdev = fs_dax_get_by_bdev(sb->s_bdev, &sbi->s_dax_part_off,
					   NULL, NULL);

	sbi->s_blockgroup_lock =
		kzalloc(sizeof(struct blockgroup_lock), GFP_KERNEL);

	if (!sbi->s_blockgroup_lock)
		goto err_out;

	sb->s_fs_info = sbi;
	sbi->s_sb = sb;
	return sbi;
err_out:
	fs_put_dax(sbi->s_daxdev, NULL);
	kfree(sbi);
	return NULL;
}

static void ecfs_set_def_opts(struct super_block *sb,
			      struct ecfs_super_block *es)
{
	unsigned long def_mount_opts;

	/* Set defaults before we parse the mount options */
	def_mount_opts = le32_to_cpu(es->s_default_mount_opts);
	set_opt(sb, INIT_INODE_TABLE);
	if (def_mount_opts & ECFS_DEFM_DEBUG)
		set_opt(sb, DEBUG);
	if (def_mount_opts & ECFS_DEFM_BSDGROUPS)
		set_opt(sb, GRPID);
	if (def_mount_opts & ECFS_DEFM_UID16)
		set_opt(sb, NO_UID32);
	/* xattr user namespace & acls are now defaulted on */
	set_opt(sb, XATTR_USER);
#ifdef CONFIG_ECFS_FS_POSIX_ACL
	set_opt(sb, POSIX_ACL);
#endif
	if (ecfs_has_feature_fast_commit(sb))
		set_opt2(sb, JOURNAL_FAST_COMMIT);
	/* don't forget to enable journal_csum when metadata_csum is enabled. */
	if (ecfs_has_feature_metadata_csum(sb))
		set_opt(sb, JOURNAL_CHECKSUM);

	if ((def_mount_opts & ECFS_DEFM_JMODE) == ECFS_DEFM_JMODE_DATA)
		set_opt(sb, JOURNAL_DATA);
	else if ((def_mount_opts & ECFS_DEFM_JMODE) == ECFS_DEFM_JMODE_ORDERED)
		set_opt(sb, ORDERED_DATA);
	else if ((def_mount_opts & ECFS_DEFM_JMODE) == ECFS_DEFM_JMODE_WBACK)
		set_opt(sb, WRITEBACK_DATA);

	if (le16_to_cpu(es->s_errors) == ECFS_ERRORS_PANIC)
		set_opt(sb, ERRORS_PANIC);
	else if (le16_to_cpu(es->s_errors) == ECFS_ERRORS_CONTINUE)
		set_opt(sb, ERRORS_CONT);
	else
		set_opt(sb, ERRORS_RO);
	/* block_validity enabled by default; disable with noblock_validity */
	set_opt(sb, BLOCK_VALIDITY);
	if (def_mount_opts & ECFS_DEFM_DISCARD)
		set_opt(sb, DISCARD);

	if ((def_mount_opts & ECFS_DEFM_NOBARRIER) == 0)
		set_opt(sb, BARRIER);

	/*
	 * enable delayed allocation by default
	 * Use -o nodelalloc to turn it off
	 */
	if ((def_mount_opts & ECFS_DEFM_NODELALLOC) == 0)
		set_opt(sb, DELALLOC);

	if (sb->s_blocksize <= PAGE_SIZE)
		set_opt(sb, DIOREAD_NOLOCK);
}

static int ecfs_handle_clustersize(struct super_block *sb)
{
	struct ecfs_sb_info *sbi = ECFS_SB(sb);
	struct ecfs_super_block *es = sbi->s_es;
	int clustersize;

	/* Handle clustersize */
	clustersize = BLOCK_SIZE << le32_to_cpu(es->s_log_cluster_size);
	if (ecfs_has_feature_bigalloc(sb)) {
		if (clustersize < sb->s_blocksize) {
			ecfs_msg(sb, KERN_ERR,
				 "cluster size (%d) smaller than "
				 "block size (%lu)", clustersize, sb->s_blocksize);
			return -EINVAL;
		}
		sbi->s_cluster_bits = le32_to_cpu(es->s_log_cluster_size) -
			le32_to_cpu(es->s_log_block_size);
	} else {
		if (clustersize != sb->s_blocksize) {
			ecfs_msg(sb, KERN_ERR,
				 "fragment/cluster size (%d) != "
				 "block size (%lu)", clustersize, sb->s_blocksize);
			return -EINVAL;
		}
		if (sbi->s_blocks_per_group > sb->s_blocksize * 8) {
			ecfs_msg(sb, KERN_ERR,
				 "#blocks per group too big: %lu",
				 sbi->s_blocks_per_group);
			return -EINVAL;
		}
		sbi->s_cluster_bits = 0;
	}
	sbi->s_clusters_per_group = le32_to_cpu(es->s_clusters_per_group);
	if (sbi->s_clusters_per_group > sb->s_blocksize * 8) {
		ecfs_msg(sb, KERN_ERR, "#clusters per group too big: %lu",
			 sbi->s_clusters_per_group);
		return -EINVAL;
	}
	if (sbi->s_blocks_per_group !=
	    (sbi->s_clusters_per_group * (clustersize / sb->s_blocksize))) {
		ecfs_msg(sb, KERN_ERR,
			 "blocks per group (%lu) and clusters per group (%lu) inconsistent",
			 sbi->s_blocks_per_group, sbi->s_clusters_per_group);
		return -EINVAL;
	}
	sbi->s_cluster_ratio = clustersize / sb->s_blocksize;

	/* Do we have standard group size of clustersize * 8 blocks ? */
	if (sbi->s_blocks_per_group == clustersize << 3)
		set_opt2(sb, STD_GROUP_SIZE);

	return 0;
}

/*
 * ecfs_atomic_write_init: Initializes filesystem min & max atomic write units.
 * With non-bigalloc filesystem awu will be based upon filesystem blocksize
 * & bdev awu units.
 * With bigalloc it will be based upon bigalloc cluster size & bdev awu units.
 * @sb: super block
 */
static void ecfs_atomic_write_init(struct super_block *sb)
{
	struct ecfs_sb_info *sbi = ECFS_SB(sb);
	struct block_device *bdev = sb->s_bdev;
	unsigned int clustersize = ECFS_CLUSTER_SIZE(sb);

	if (!bdev_can_atomic_write(bdev))
		return;

	if (!ecfs_has_feature_extents(sb))
		return;

	sbi->s_awu_min = max(sb->s_blocksize,
			      bdev_atomic_write_unit_min_bytes(bdev));
	sbi->s_awu_max = min(clustersize,
			      bdev_atomic_write_unit_max_bytes(bdev));
	if (sbi->s_awu_min && sbi->s_awu_max &&
	    sbi->s_awu_min <= sbi->s_awu_max) {
		ecfs_msg(sb, KERN_NOTICE, "Supports (experimental) DIO atomic writes awu_min: %u, awu_max: %u",
			 sbi->s_awu_min, sbi->s_awu_max);
	} else {
		sbi->s_awu_min = 0;
		sbi->s_awu_max = 0;
	}
}

static void ecfs_fast_commit_init(struct super_block *sb)
{
	struct ecfs_sb_info *sbi = ECFS_SB(sb);

	/* Initialize fast commit stuff */
	atomic_set(&sbi->s_fc_subtid, 0);
	INIT_LIST_HEAD(&sbi->s_fc_q[FC_Q_MAIN]);
	INIT_LIST_HEAD(&sbi->s_fc_q[FC_Q_STAGING]);
	INIT_LIST_HEAD(&sbi->s_fc_dentry_q[FC_Q_MAIN]);
	INIT_LIST_HEAD(&sbi->s_fc_dentry_q[FC_Q_STAGING]);
	sbi->s_fc_bytes = 0;
	ecfs_clear_mount_flag(sb, ECFS_MF_FC_INELIGIBLE);
	sbi->s_fc_ineligible_tid = 0;
	mutex_init(&sbi->s_fc_lock);
	memset(&sbi->s_fc_stats, 0, sizeof(sbi->s_fc_stats));
	sbi->s_fc_replay_state.fc_regions = NULL;
	sbi->s_fc_replay_state.fc_regions_size = 0;
	sbi->s_fc_replay_state.fc_regions_used = 0;
	sbi->s_fc_replay_state.fc_regions_valid = 0;
	sbi->s_fc_replay_state.fc_modified_inodes = NULL;
	sbi->s_fc_replay_state.fc_modified_inodes_size = 0;
	sbi->s_fc_replay_state.fc_modified_inodes_used = 0;
}

static int ecfs_inode_info_init(struct super_block *sb,
				struct ecfs_super_block *es)
{
	struct ecfs_sb_info *sbi = ECFS_SB(sb);

	if (le32_to_cpu(es->s_rev_level) == ECFS_GOOD_OLD_REV) {
		sbi->s_inode_size = ECFS_GOOD_OLD_INODE_SIZE;
		sbi->s_first_ino = ECFS_GOOD_OLD_FIRST_INO;
	} else {
		sbi->s_inode_size = le16_to_cpu(es->s_inode_size);
		sbi->s_first_ino = le32_to_cpu(es->s_first_ino);
		if (sbi->s_first_ino < ECFS_GOOD_OLD_FIRST_INO) {
			ecfs_msg(sb, KERN_ERR, "invalid first ino: %u",
				 sbi->s_first_ino);
			return -EINVAL;
		}
		if ((sbi->s_inode_size < ECFS_GOOD_OLD_INODE_SIZE) ||
		    (!is_power_of_2(sbi->s_inode_size)) ||
		    (sbi->s_inode_size > sb->s_blocksize)) {
			ecfs_msg(sb, KERN_ERR,
			       "unsupported inode size: %d",
			       sbi->s_inode_size);
			ecfs_msg(sb, KERN_ERR, "blocksize: %lu", sb->s_blocksize);
			return -EINVAL;
		}
		/*
		 * i_atime_extra is the last extra field available for
		 * [acm]times in struct ecfs_inode. Checking for that
		 * field should suffice to ensure we have extra space
		 * for all three.
		 */
		if (sbi->s_inode_size >= offsetof(struct ecfs_inode, i_atime_extra) +
			sizeof(((struct ecfs_inode *)0)->i_atime_extra)) {
			sb->s_time_gran = 1;
			sb->s_time_max = ECFS_EXTRA_TIMESTAMP_MAX;
		} else {
			sb->s_time_gran = NSEC_PER_SEC;
			sb->s_time_max = ECFS_NON_EXTRA_TIMESTAMP_MAX;
		}
		sb->s_time_min = ECFS_TIMESTAMP_MIN;
	}

	if (sbi->s_inode_size > ECFS_GOOD_OLD_INODE_SIZE) {
		sbi->s_want_extra_isize = sizeof(struct ecfs_inode) -
			ECFS_GOOD_OLD_INODE_SIZE;
		if (ecfs_has_feature_extra_isize(sb)) {
			unsigned v, max = (sbi->s_inode_size -
					   ECFS_GOOD_OLD_INODE_SIZE);

			v = le16_to_cpu(es->s_want_extra_isize);
			if (v > max) {
				ecfs_msg(sb, KERN_ERR,
					 "bad s_want_extra_isize: %d", v);
				return -EINVAL;
			}
			if (sbi->s_want_extra_isize < v)
				sbi->s_want_extra_isize = v;

			v = le16_to_cpu(es->s_min_extra_isize);
			if (v > max) {
				ecfs_msg(sb, KERN_ERR,
					 "bad s_min_extra_isize: %d", v);
				return -EINVAL;
			}
			if (sbi->s_want_extra_isize < v)
				sbi->s_want_extra_isize = v;
		}
	}

	return 0;
}

#if IS_ENABLED(CONFIG_UNICODE)
static int ecfs_encoding_init(struct super_block *sb, struct ecfs_super_block *es)
{
	const struct ecfs_sb_encodings *encoding_info;
	struct unicode_map *encoding;
	__u16 encoding_flags = le16_to_cpu(es->s_encoding_flags);

	if (!ecfs_has_feature_casefold(sb) || sb->s_encoding)
		return 0;

	encoding_info = ecfs_sb_read_encoding(es);
	if (!encoding_info) {
		ecfs_msg(sb, KERN_ERR,
			"Encoding requested by superblock is unknown");
		return -EINVAL;
	}

	encoding = utf8_load(encoding_info->version);
	if (IS_ERR(encoding)) {
		ecfs_msg(sb, KERN_ERR,
			"can't mount with superblock charset: %s-%u.%u.%u "
			"not supported by the kernel. flags: 0x%x.",
			encoding_info->name,
			unicode_major(encoding_info->version),
			unicode_minor(encoding_info->version),
			unicode_rev(encoding_info->version),
			encoding_flags);
		return -EINVAL;
	}
	ecfs_msg(sb, KERN_INFO,"Using encoding defined by superblock: "
		"%s-%u.%u.%u with flags 0x%hx", encoding_info->name,
		unicode_major(encoding_info->version),
		unicode_minor(encoding_info->version),
		unicode_rev(encoding_info->version),
		encoding_flags);

	sb->s_encoding = encoding;
	sb->s_encoding_flags = encoding_flags;

	return 0;
}
#else
static inline int ecfs_encoding_init(struct super_block *sb, struct ecfs_super_block *es)
{
	return 0;
}
#endif

static int ecfs_init_metadata_csum(struct super_block *sb, struct ecfs_super_block *es)
{
	struct ecfs_sb_info *sbi = ECFS_SB(sb);

	/* Warn if metadata_csum and gdt_csum are both set. */
	if (ecfs_has_feature_metadata_csum(sb) &&
	    ecfs_has_feature_gdt_csum(sb))
		ecfs_warning(sb, "metadata_csum and uninit_bg are "
			     "redundant flags; please run fsck.");

	/* Check for a known checksum algorithm */
	if (!ecfs_verify_csum_type(sb, es)) {
		ecfs_msg(sb, KERN_ERR, "VFS: Found ecfs filesystem with "
			 "unknown checksum algorithm.");
		return -EINVAL;
	}
	ecfs_setup_csum_trigger(sb, ECFS_JTR_ORPHAN_FILE,
				ecfs_orphan_file_block_trigger);

	/* Check superblock checksum */
	if (!ecfs_superblock_csum_verify(sb, es)) {
		ecfs_msg(sb, KERN_ERR, "VFS: Found ecfs filesystem with "
			 "invalid superblock checksum.  Run e2fsck?");
		return -EFSBADCRC;
	}

	/* Precompute checksum seed for all metadata */
	if (ecfs_has_feature_csum_seed(sb))
		sbi->s_csum_seed = le32_to_cpu(es->s_checksum_seed);
	else if (ecfs_has_feature_metadata_csum(sb) ||
		 ecfs_has_feature_ea_inode(sb))
		sbi->s_csum_seed = ecfs_chksum(~0, es->s_uuid,
					       sizeof(es->s_uuid));
	return 0;
}

static int ecfs_check_feature_compatibility(struct super_block *sb,
					    struct ecfs_super_block *es,
					    int silent)
{
	struct ecfs_sb_info *sbi = ECFS_SB(sb);

	if (le32_to_cpu(es->s_rev_level) == ECFS_GOOD_OLD_REV &&
	    (ecfs_has_compat_features(sb) ||
	     ecfs_has_ro_compat_features(sb) ||
	     ecfs_has_incompat_features(sb)))
		ecfs_msg(sb, KERN_WARNING,
		       "feature flags set on rev 0 fs, "
		       "running e2fsck is recommended");

	if (es->s_creator_os == cpu_to_le32(ECFS_OS_HURD)) {
		set_opt2(sb, HURD_COMPAT);
		if (ecfs_has_feature_64bit(sb)) {
			ecfs_msg(sb, KERN_ERR,
				 "The Hurd can't support 64-bit file systems");
			return -EINVAL;
		}

		/*
		 * ea_inode feature uses l_i_version field which is not
		 * available in HURD_COMPAT mode.
		 */
		if (ecfs_has_feature_ea_inode(sb)) {
			ecfs_msg(sb, KERN_ERR,
				 "ea_inode feature is not supported for Hurd");
			return -EINVAL;
		}
	}

	/*
	 * Check feature flags regardless of the revision level, since we
	 * previously didn't change the revision level when setting the flags,
	 * so there is a chance incompat flags are set on a rev 0 filesystem.
	 */
	if (!ecfs_feature_set_ok(sb, (sb_rdonly(sb))))
		return -EINVAL;

	if (sbi->s_daxdev) {
		if (sb->s_blocksize == PAGE_SIZE)
			set_bit(ECFS_FLAGS_BDEV_IS_DAX, &sbi->s_ecfs_flags);
		else
			ecfs_msg(sb, KERN_ERR, "unsupported blocksize for DAX\n");
	}

	if (sbi->s_mount_opt & ECFS_MOUNT_DAX_ALWAYS) {
		if (ecfs_has_feature_inline_data(sb)) {
			ecfs_msg(sb, KERN_ERR, "Cannot use DAX on a filesystem"
					" that may contain inline data");
			return -EINVAL;
		}
		if (!test_bit(ECFS_FLAGS_BDEV_IS_DAX, &sbi->s_ecfs_flags)) {
			ecfs_msg(sb, KERN_ERR,
				"DAX unsupported by block device.");
			return -EINVAL;
		}
	}

	if (ecfs_has_feature_encrypt(sb) && es->s_encryption_level) {
		ecfs_msg(sb, KERN_ERR, "Unsupported encryption level %d",
			 es->s_encryption_level);
		return -EINVAL;
	}

	return 0;
}

static int ecfs_check_geometry(struct super_block *sb,
			       struct ecfs_super_block *es)
{
	struct ecfs_sb_info *sbi = ECFS_SB(sb);
	__u64 blocks_count;
	int err;

	if (le16_to_cpu(sbi->s_es->s_reserved_gdt_blocks) > (sb->s_blocksize / 4)) {
		ecfs_msg(sb, KERN_ERR,
			 "Number of reserved GDT blocks insanely large: %d",
			 le16_to_cpu(sbi->s_es->s_reserved_gdt_blocks));
		return -EINVAL;
	}
	/*
	 * Test whether we have more sectors than will fit in sector_t,
	 * and whether the max offset is addressable by the page cache.
	 */
	err = generic_check_addressable(sb->s_blocksize_bits,
					ecfs_blocks_count(es));
	if (err) {
		ecfs_msg(sb, KERN_ERR, "filesystem"
			 " too large to mount safely on this system");
		return err;
	}

	/* check blocks count against device size */
	blocks_count = sb_bdev_nr_blocks(sb);
	if (blocks_count && ecfs_blocks_count(es) > blocks_count) {
		ecfs_msg(sb, KERN_WARNING, "bad geometry: block count %llu "
		       "exceeds size of device (%llu blocks)",
		       ecfs_blocks_count(es), blocks_count);
		return -EINVAL;
	}

	/*
	 * It makes no sense for the first data block to be beyond the end
	 * of the filesystem.
	 */
	if (le32_to_cpu(es->s_first_data_block) >= ecfs_blocks_count(es)) {
		ecfs_msg(sb, KERN_WARNING, "bad geometry: first data "
			 "block %u is beyond end of filesystem (%llu)",
			 le32_to_cpu(es->s_first_data_block),
			 ecfs_blocks_count(es));
		return -EINVAL;
	}
	if ((es->s_first_data_block == 0) && (es->s_log_block_size == 0) &&
	    (sbi->s_cluster_ratio == 1)) {
		ecfs_msg(sb, KERN_WARNING, "bad geometry: first data "
			 "block is 0 with a 1k block and cluster size");
		return -EINVAL;
	}

	blocks_count = (ecfs_blocks_count(es) -
			le32_to_cpu(es->s_first_data_block) +
			ECFS_BLOCKS_PER_GROUP(sb) - 1);
	do_div(blocks_count, ECFS_BLOCKS_PER_GROUP(sb));
	if (blocks_count > ((uint64_t)1<<32) - ECFS_DESC_PER_BLOCK(sb)) {
		ecfs_msg(sb, KERN_WARNING, "groups count too large: %llu "
		       "(block count %llu, first data block %u, "
		       "blocks per group %lu)", blocks_count,
		       ecfs_blocks_count(es),
		       le32_to_cpu(es->s_first_data_block),
		       ECFS_BLOCKS_PER_GROUP(sb));
		return -EINVAL;
	}
	sbi->s_groups_count = blocks_count;
	sbi->s_blockfile_groups = min_t(ecfs_group_t, sbi->s_groups_count,
			(ECFS_MAX_BLOCK_FILE_PHYS / ECFS_BLOCKS_PER_GROUP(sb)));
	if (((u64)sbi->s_groups_count * sbi->s_inodes_per_group) !=
	    le32_to_cpu(es->s_inodes_count)) {
		ecfs_msg(sb, KERN_ERR, "inodes count not valid: %u vs %llu",
			 le32_to_cpu(es->s_inodes_count),
			 ((u64)sbi->s_groups_count * sbi->s_inodes_per_group));
		return -EINVAL;
	}

	return 0;
}

static int ecfs_group_desc_init(struct super_block *sb,
				struct ecfs_super_block *es,
				ecfs_fsblk_t logical_sb_block,
				ecfs_group_t *first_not_zeroed)
{
	struct ecfs_sb_info *sbi = ECFS_SB(sb);
	unsigned int db_count;
	ecfs_fsblk_t block;
	int i;

	db_count = (sbi->s_groups_count + ECFS_DESC_PER_BLOCK(sb) - 1) /
		   ECFS_DESC_PER_BLOCK(sb);
	if (ecfs_has_feature_meta_bg(sb)) {
		if (le32_to_cpu(es->s_first_meta_bg) > db_count) {
			ecfs_msg(sb, KERN_WARNING,
				 "first meta block group too large: %u "
				 "(group descriptor block count %u)",
				 le32_to_cpu(es->s_first_meta_bg), db_count);
			return -EINVAL;
		}
	}
	rcu_assign_pointer(sbi->s_group_desc,
			   kvmalloc_array(db_count,
					  sizeof(struct buffer_head *),
					  GFP_KERNEL));
	if (sbi->s_group_desc == NULL) {
		ecfs_msg(sb, KERN_ERR, "not enough memory");
		return -ENOMEM;
	}

	bgl_lock_init(sbi->s_blockgroup_lock);

	/* Pre-read the descriptors into the buffer cache */
	for (i = 0; i < db_count; i++) {
		block = descriptor_loc(sb, logical_sb_block, i);
		ecfs_sb_breadahead_unmovable(sb, block);
	}

	for (i = 0; i < db_count; i++) {
		struct buffer_head *bh;

		block = descriptor_loc(sb, logical_sb_block, i);
		bh = ecfs_sb_bread_unmovable(sb, block);
		if (IS_ERR(bh)) {
			ecfs_msg(sb, KERN_ERR,
			       "can't read group descriptor %d", i);
			sbi->s_gdb_count = i;
			return PTR_ERR(bh);
		}
		rcu_read_lock();
		rcu_dereference(sbi->s_group_desc)[i] = bh;
		rcu_read_unlock();
	}
	sbi->s_gdb_count = db_count;
	if (!ecfs_check_descriptors(sb, logical_sb_block, first_not_zeroed)) {
		ecfs_msg(sb, KERN_ERR, "group descriptors corrupted!");
		return -EFSCORRUPTED;
	}

	return 0;
}

static int ecfs_load_and_init_journal(struct super_block *sb,
				      struct ecfs_super_block *es,
				      struct ecfs_fs_context *ctx)
{
	struct ecfs_sb_info *sbi = ECFS_SB(sb);
	int err;

	err = ecfs_load_journal(sb, es, ctx->journal_devnum);
	if (err)
		return err;

	if (ecfs_has_feature_64bit(sb) &&
	    !jbd2_journal_set_features(ECFS_SB(sb)->s_journal, 0, 0,
				       JBD2_FEATURE_INCOMPAT_64BIT)) {
		ecfs_msg(sb, KERN_ERR, "Failed to set 64-bit journal feature");
		goto out;
	}

	if (!set_journal_csum_feature_set(sb)) {
		ecfs_msg(sb, KERN_ERR, "Failed to set journal checksum "
			 "feature set");
		goto out;
	}

	if (test_opt2(sb, JOURNAL_FAST_COMMIT) &&
		!jbd2_journal_set_features(ECFS_SB(sb)->s_journal, 0, 0,
					  JBD2_FEATURE_INCOMPAT_FAST_COMMIT)) {
		ecfs_msg(sb, KERN_ERR,
			"Failed to set fast commit journal feature");
		goto out;
	}

	/* We have now updated the journal if required, so we can
	 * validate the data journaling mode. */
	switch (test_opt(sb, DATA_FLAGS)) {
	case 0:
		/* No mode set, assume a default based on the journal
		 * capabilities: ORDERED_DATA if the journal can
		 * cope, else JOURNAL_DATA
		 */
		if (jbd2_journal_check_available_features
		    (sbi->s_journal, 0, 0, JBD2_FEATURE_INCOMPAT_REVOKE)) {
			set_opt(sb, ORDERED_DATA);
			sbi->s_def_mount_opt |= ECFS_MOUNT_ORDERED_DATA;
		} else {
			set_opt(sb, JOURNAL_DATA);
			sbi->s_def_mount_opt |= ECFS_MOUNT_JOURNAL_DATA;
		}
		break;

	case ECFS_MOUNT_ORDERED_DATA:
	case ECFS_MOUNT_WRITEBACK_DATA:
		if (!jbd2_journal_check_available_features
		    (sbi->s_journal, 0, 0, JBD2_FEATURE_INCOMPAT_REVOKE)) {
			ecfs_msg(sb, KERN_ERR, "Journal does not support "
			       "requested data journaling mode");
			goto out;
		}
		break;
	default:
		break;
	}

	if (test_opt(sb, DATA_FLAGS) == ECFS_MOUNT_ORDERED_DATA &&
	    test_opt(sb, JOURNAL_ASYNC_COMMIT)) {
		ecfs_msg(sb, KERN_ERR, "can't mount with "
			"journal_async_commit in data=ordered mode");
		goto out;
	}

	set_task_ioprio(sbi->s_journal->j_task, ctx->journal_ioprio);

	sbi->s_journal->j_submit_inode_data_buffers =
		ecfs_journal_submit_inode_data_buffers;
	sbi->s_journal->j_finish_inode_data_buffers =
		ecfs_journal_finish_inode_data_buffers;

	return 0;

out:
	ecfs_journal_destroy(sbi, sbi->s_journal);
	return -EINVAL;
}

static int ecfs_check_journal_data_mode(struct super_block *sb)
{
	if (test_opt(sb, DATA_FLAGS) == ECFS_MOUNT_JOURNAL_DATA) {
		printk_once(KERN_WARNING "ECFS-fs: Warning: mounting with "
			    "data=journal disables delayed allocation, "
			    "dioread_nolock, O_DIRECT and fast_commit support!\n");
		/* can't mount with both data=journal and dioread_nolock. */
		clear_opt(sb, DIOREAD_NOLOCK);
		clear_opt2(sb, JOURNAL_FAST_COMMIT);
		if (test_opt2(sb, EXPLICIT_DELALLOC)) {
			ecfs_msg(sb, KERN_ERR, "can't mount with "
				 "both data=journal and delalloc");
			return -EINVAL;
		}
		if (test_opt(sb, DAX_ALWAYS)) {
			ecfs_msg(sb, KERN_ERR, "can't mount with "
				 "both data=journal and dax");
			return -EINVAL;
		}
		if (ecfs_has_feature_encrypt(sb)) {
			ecfs_msg(sb, KERN_WARNING,
				 "encrypted files will use data=ordered "
				 "instead of data journaling mode");
		}
		if (test_opt(sb, DELALLOC))
			clear_opt(sb, DELALLOC);
	} else {
		sb->s_iflags |= SB_I_CGROUPWB;
	}

	return 0;
}

static const char *ecfs_has_journal_option(struct super_block *sb)
{
	struct ecfs_sb_info *sbi = ECFS_SB(sb);

	if (test_opt(sb, JOURNAL_ASYNC_COMMIT))
		return "journal_async_commit";
	if (test_opt2(sb, EXPLICIT_JOURNAL_CHECKSUM))
		return "journal_checksum";
	if (sbi->s_commit_interval != JBD2_DEFAULT_MAX_COMMIT_AGE*HZ)
		return "commit=";
	if (ECFS_MOUNT_DATA_FLAGS &
	    (sbi->s_mount_opt ^ sbi->s_def_mount_opt))
		return "data=";
	if (test_opt(sb, DATA_ERR_ABORT))
		return "data_err=abort";
	return NULL;
}

static int ecfs_load_super(struct super_block *sb, ecfs_fsblk_t *lsb,
			   int silent)
{
	struct ecfs_sb_info *sbi = ECFS_SB(sb);
	struct ecfs_super_block *es;
	ecfs_fsblk_t logical_sb_block;
	unsigned long offset = 0;
	struct buffer_head *bh;
	int ret = -EINVAL;
	int blocksize;

	blocksize = sb_min_blocksize(sb, ECFS_MIN_BLOCK_SIZE);
	if (!blocksize) {
		ecfs_msg(sb, KERN_ERR, "unable to set blocksize");
		return -EINVAL;
	}

	/*
	 * The ecfs superblock will not be buffer aligned for other than 1kB
	 * block sizes.  We need to calculate the offset from buffer start.
	 */
	if (blocksize != ECFS_MIN_BLOCK_SIZE) {
		logical_sb_block = sbi->s_sb_block * ECFS_MIN_BLOCK_SIZE;
		offset = do_div(logical_sb_block, blocksize);
	} else {
		logical_sb_block = sbi->s_sb_block;
	}

	bh = ecfs_sb_bread_unmovable(sb, logical_sb_block);
	if (IS_ERR(bh)) {
		ecfs_msg(sb, KERN_ERR, "unable to read superblock");
		return PTR_ERR(bh);
	}
	/*
	 * Note: s_es must be initialized as soon as possible because
	 *       some ecfs macro-instructions depend on its value
	 */
	es = (struct ecfs_super_block *) (bh->b_data + offset);
	sbi->s_es = es;
	sb->s_magic = le16_to_cpu(es->s_magic);
	if (sb->s_magic != ECFS_SUPER_MAGIC) {
		if (!silent)
			ecfs_msg(sb, KERN_ERR, "VFS: Can't find ecfs filesystem");
		goto out;
	}

	if (le32_to_cpu(es->s_log_block_size) >
	    (ECFS_MAX_BLOCK_LOG_SIZE - ECFS_MIN_BLOCK_LOG_SIZE)) {
		ecfs_msg(sb, KERN_ERR,
			 "Invalid log block size: %u",
			 le32_to_cpu(es->s_log_block_size));
		goto out;
	}
	if (le32_to_cpu(es->s_log_cluster_size) >
	    (ECFS_MAX_CLUSTER_LOG_SIZE - ECFS_MIN_BLOCK_LOG_SIZE)) {
		ecfs_msg(sb, KERN_ERR,
			 "Invalid log cluster size: %u",
			 le32_to_cpu(es->s_log_cluster_size));
		goto out;
	}

	blocksize = ECFS_MIN_BLOCK_SIZE << le32_to_cpu(es->s_log_block_size);

	/*
	 * If the default block size is not the same as the real block size,
	 * we need to reload it.
	 */
	if (sb->s_blocksize == blocksize) {
		*lsb = logical_sb_block;
		sbi->s_sbh = bh;
		return 0;
	}

	/*
	 * bh must be released before kill_bdev(), otherwise
	 * it won't be freed and its page also. kill_bdev()
	 * is called by sb_set_blocksize().
	 */
	brelse(bh);
	/* Validate the filesystem blocksize */
	if (!sb_set_blocksize(sb, blocksize)) {
		ecfs_msg(sb, KERN_ERR, "bad block size %d",
				blocksize);
		bh = NULL;
		goto out;
	}

	logical_sb_block = sbi->s_sb_block * ECFS_MIN_BLOCK_SIZE;
	offset = do_div(logical_sb_block, blocksize);
	bh = ecfs_sb_bread_unmovable(sb, logical_sb_block);
	if (IS_ERR(bh)) {
		ecfs_msg(sb, KERN_ERR, "Can't read superblock on 2nd try");
		ret = PTR_ERR(bh);
		bh = NULL;
		goto out;
	}
	es = (struct ecfs_super_block *)(bh->b_data + offset);
	sbi->s_es = es;
	if (es->s_magic != cpu_to_le16(ECFS_SUPER_MAGIC)) {
		ecfs_msg(sb, KERN_ERR, "Magic mismatch, very weird!");
		goto out;
	}
	*lsb = logical_sb_block;
	sbi->s_sbh = bh;
	return 0;
out:
	brelse(bh);
	return ret;
}

static int ecfs_hash_info_init(struct super_block *sb)
{
	struct ecfs_sb_info *sbi = ECFS_SB(sb);
	struct ecfs_super_block *es = sbi->s_es;
	unsigned int i;

	sbi->s_def_hash_version = es->s_def_hash_version;

	if (sbi->s_def_hash_version > DX_HASH_LAST) {
		ecfs_msg(sb, KERN_ERR,
			 "Invalid default hash set in the superblock");
		return -EINVAL;
	} else if (sbi->s_def_hash_version == DX_HASH_SIPHASH) {
		ecfs_msg(sb, KERN_ERR,
			 "SIPHASH is not a valid default hash value");
		return -EINVAL;
	}

	for (i = 0; i < 4; i++)
		sbi->s_hash_seed[i] = le32_to_cpu(es->s_hash_seed[i]);

// 	if (ecfs_has_feature_dir_index(sb)) {
// 		i = le32_to_cpu(es->s_flags);
// 		if (i & EXT2_FLAGS_UNSIGNED_HASH)
// 			sbi->s_hash_unsigned = 3;
// 		else if ((i & EXT2_FLAGS_SIGNED_HASH) == 0) {
// #ifdef __CHAR_UNSIGNED__
// 			if (!sb_rdonly(sb))
// 				es->s_flags |=
// 					cpu_to_le32(EXT2_FLAGS_UNSIGNED_HASH);
// 			sbi->s_hash_unsigned = 3;
// #else
// 			if (!sb_rdonly(sb))
// 				es->s_flags |=
// 					cpu_to_le32(EXT2_FLAGS_SIGNED_HASH);
// #endif
// 		}
// 	}
	return 0;
}

static int ecfs_block_group_meta_init(struct super_block *sb, int silent)
{
	struct ecfs_sb_info *sbi = ECFS_SB(sb);
	struct ecfs_super_block *es = sbi->s_es;
	int has_huge_files;

	has_huge_files = ecfs_has_feature_huge_file(sb);
	sbi->s_bitmap_maxbytes = ecfs_max_bitmap_size(sb->s_blocksize_bits,
						      has_huge_files);
	sb->s_maxbytes = ecfs_max_size(sb->s_blocksize_bits, has_huge_files);

	sbi->s_desc_size = le16_to_cpu(es->s_desc_size);
	if (ecfs_has_feature_64bit(sb)) {
		if (sbi->s_desc_size < ECFS_MIN_DESC_SIZE_64BIT ||
		    sbi->s_desc_size > ECFS_MAX_DESC_SIZE ||
		    !is_power_of_2(sbi->s_desc_size)) {
			ecfs_msg(sb, KERN_ERR,
			       "unsupported descriptor size %lu",
			       sbi->s_desc_size);
			return -EINVAL;
		}
	} else
		sbi->s_desc_size = ECFS_MIN_DESC_SIZE;

	sbi->s_blocks_per_group = le32_to_cpu(es->s_blocks_per_group);
	sbi->s_inodes_per_group = le32_to_cpu(es->s_inodes_per_group);

	sbi->s_inodes_per_block = sb->s_blocksize / ECFS_INODE_SIZE(sb);
	if (sbi->s_inodes_per_block == 0 || sbi->s_blocks_per_group == 0) {
		if (!silent)
			ecfs_msg(sb, KERN_ERR, "VFS: Can't find ecfs filesystem");
		return -EINVAL;
	}
	if (sbi->s_inodes_per_group < sbi->s_inodes_per_block ||
	    sbi->s_inodes_per_group > sb->s_blocksize * 8) {
		ecfs_msg(sb, KERN_ERR, "invalid inodes per group: %lu\n",
			 sbi->s_inodes_per_group);
		return -EINVAL;
	}
	sbi->s_itb_per_group = sbi->s_inodes_per_group /
					sbi->s_inodes_per_block;
	sbi->s_desc_per_block = sb->s_blocksize / ECFS_DESC_SIZE(sb);
	sbi->s_mount_state = le16_to_cpu(es->s_state) & ~ECFS_FC_REPLAY;
	sbi->s_addr_per_block_bits = ilog2(ECFS_ADDR_PER_BLOCK(sb));
	sbi->s_desc_per_block_bits = ilog2(ECFS_DESC_PER_BLOCK(sb));

	return 0;
}

/*
 * It's hard to get stripe aligned blocks if stripe is not aligned with
 * cluster, just disable stripe and alert user to simplify code and avoid
 * stripe aligned allocation which will rarely succeed.
 */
static bool ecfs_is_stripe_incompatible(struct super_block *sb, unsigned long stripe)
{
	struct ecfs_sb_info *sbi = ECFS_SB(sb);
	return (stripe > 0 && sbi->s_cluster_ratio > 1 &&
		stripe % sbi->s_cluster_ratio != 0);
}

static int __ecfs_fill_super(struct fs_context *fc, struct super_block *sb)
{
	struct ecfs_super_block *es = NULL;
	struct ecfs_sb_info *sbi = ECFS_SB(sb);
	ecfs_fsblk_t logical_sb_block;
	struct inode *root;
	int needs_recovery;
	int err;
	ecfs_group_t first_not_zeroed;
	struct ecfs_fs_context *ctx = fc->fs_private;
	int silent = fc->sb_flags & SB_SILENT;

	/* Set defaults for the variables that will be set during parsing */
	if (!(ctx->spec & ECFS_SPEC_JOURNAL_IOPRIO))
		ctx->journal_ioprio = ECFS_DEF_JOURNAL_IOPRIO;

	sbi->s_inode_readahead_blks = ECFS_DEF_INODE_READAHEAD_BLKS;
	sbi->s_sectors_written_start =
		part_stat_read(sb->s_bdev, sectors[STAT_WRITE]);

	err = ecfs_load_super(sb, &logical_sb_block, silent);
	if (err)
		goto out_fail;

	es = sbi->s_es;
	sbi->s_kbytes_written = le64_to_cpu(es->s_kbytes_written);

	sbi->s_node_id = le16_to_cpu(es->s_node_id);
	sbi->s_disk_id = le16_to_cpu(es->s_disk_id);

	err = ecfs_init_metadata_csum(sb, es);
	if (err)
		goto failed_mount;

	ecfs_set_def_opts(sb, es);

	sbi->s_resuid = make_kuid(&init_user_ns, le16_to_cpu(es->s_def_resuid));
	sbi->s_resgid = make_kgid(&init_user_ns, le16_to_cpu(es->s_def_resgid));
	sbi->s_commit_interval = JBD2_DEFAULT_MAX_COMMIT_AGE * HZ;
	sbi->s_min_batch_time = ECFS_DEF_MIN_BATCH_TIME;
	sbi->s_max_batch_time = ECFS_DEF_MAX_BATCH_TIME;
	sbi->s_sb_update_kb = ECFS_DEF_SB_UPDATE_INTERVAL_KB;
	sbi->s_sb_update_sec = ECFS_DEF_SB_UPDATE_INTERVAL_SEC;

	/*
	 * set default s_li_wait_mult for lazyinit, for the case there is
	 * no mount option specified.
	 */
	sbi->s_li_wait_mult = ECFS_DEF_LI_WAIT_MULT;

	err = ecfs_inode_info_init(sb, es);
	if (err)
		goto failed_mount;

	err = parse_apply_sb_mount_options(sb, ctx);
	if (err < 0)
		goto failed_mount;

	sbi->s_def_mount_opt = sbi->s_mount_opt;
	sbi->s_def_mount_opt2 = sbi->s_mount_opt2;

	err = ecfs_check_opt_consistency(fc, sb);
	if (err < 0)
		goto failed_mount;

	ecfs_apply_options(fc, sb);

	err = ecfs_encoding_init(sb, es);
	if (err)
		goto failed_mount;

	err = ecfs_check_journal_data_mode(sb);
	if (err)
		goto failed_mount;

	sb->s_flags = (sb->s_flags & ~SB_POSIXACL) |
		(test_opt(sb, POSIX_ACL) ? SB_POSIXACL : 0);

	/* HSM events are allowed by default. */
	sb->s_iflags |= SB_I_ALLOW_HSM;

	err = ecfs_check_feature_compatibility(sb, es, silent);
	if (err)
		goto failed_mount;

	err = ecfs_block_group_meta_init(sb, silent);
	if (err)
		goto failed_mount;

	err = ecfs_hash_info_init(sb);
	if (err)
		goto failed_mount;

	err = ecfs_handle_clustersize(sb);
	if (err)
		goto failed_mount;

	err = ecfs_check_geometry(sb, es);
	if (err)
		goto failed_mount;

	timer_setup(&sbi->s_err_report, print_daily_error_info, 0);
	spin_lock_init(&sbi->s_error_lock);
	INIT_WORK(&sbi->s_sb_upd_work, update_super_work);

	err = ecfs_group_desc_init(sb, es, logical_sb_block, &first_not_zeroed);
	if (err)
		goto failed_mount3;

	err = ecfs_es_register_shrinker(sbi);
	if (err)
		goto failed_mount3;

	sbi->s_stripe = ecfs_get_stripe_size(sbi);
	if (ecfs_is_stripe_incompatible(sb, sbi->s_stripe)) {
		ecfs_msg(sb, KERN_WARNING,
			 "stripe (%lu) is not aligned with cluster size (%u), "
			 "stripe is disabled",
			 sbi->s_stripe, sbi->s_cluster_ratio);
		sbi->s_stripe = 0;
	}
	sbi->s_extent_max_zeroout_kb = 32;

	/*
	 * set up enough so that it can read an inode
	 */
	sb->s_op = &ecfs_sops;
	sb->s_export_op = &ecfs_export_ops;
	sb->s_xattr = ecfs_xattr_handlers;
#ifdef CONFIG_FS_ENCRYPTION
	sb->s_cop = &ecfs_cryptops;
#endif
#ifdef CONFIG_FS_VERITY
	sb->s_vop = &ecfs_verityops;
#endif
#ifdef CONFIG_QUOTA
	sb->dq_op = &ecfs_quota_operations;
	if (ecfs_has_feature_quota(sb))
		sb->s_qcop = &dquot_quotactl_sysfile_ops;
	else
		sb->s_qcop = &ecfs_qctl_operations;
	sb->s_quota_types = QTYPE_MASK_USR | QTYPE_MASK_GRP | QTYPE_MASK_PRJ;
#endif
	super_set_uuid(sb, es->s_uuid, sizeof(es->s_uuid));
	super_set_sysfs_name_bdev(sb);

	INIT_LIST_HEAD(&sbi->s_orphan); /* unlinked but open files */
	mutex_init(&sbi->s_orphan_lock);

	spin_lock_init(&sbi->s_bdev_wb_lock);

	ecfs_atomic_write_init(sb);
	ecfs_fast_commit_init(sb);

	sb->s_root = NULL;

	needs_recovery = (es->s_last_orphan != 0 ||
			  ecfs_has_feature_orphan_present(sb) ||
			  ecfs_has_feature_journal_needs_recovery(sb));

	if (ecfs_has_feature_mmp(sb) && !sb_rdonly(sb)) {
		err = ecfs_multi_mount_protect(sb, le64_to_cpu(es->s_mmp_block));
		if (err)
			goto failed_mount3a;
	}

	err = -EINVAL;
	/*
	 * The first inode we look at is the journal inode.  Don't try
	 * root first: it may be modified in the journal!
	 */
	if (!test_opt(sb, NOLOAD) && ecfs_has_feature_journal(sb)) {
		err = ecfs_load_and_init_journal(sb, es, ctx);
		if (err)
			goto failed_mount3a;
		if (bdev_read_only(sb->s_bdev))
		    needs_recovery = 0;
	} else if (test_opt(sb, NOLOAD) && !sb_rdonly(sb) &&
		   ecfs_has_feature_journal_needs_recovery(sb)) {
		ecfs_msg(sb, KERN_ERR, "required journal recovery "
		       "suppressed and not mounted read-only");
		goto failed_mount3a;
	} else {
		const char *journal_option;

		/* Nojournal mode, all journal mount options are illegal */
		journal_option = ecfs_has_journal_option(sb);
		if (journal_option != NULL) {
			ecfs_msg(sb, KERN_ERR,
				 "can't mount with %s, fs mounted w/o journal",
				 journal_option);
			goto failed_mount3a;
		}

		sbi->s_def_mount_opt &= ~ECFS_MOUNT_JOURNAL_CHECKSUM;
		clear_opt(sb, JOURNAL_CHECKSUM);
		clear_opt(sb, DATA_FLAGS);
		clear_opt2(sb, JOURNAL_FAST_COMMIT);
		sbi->s_journal = NULL;
		needs_recovery = 0;
	}

	if (!test_opt(sb, NO_MBCACHE)) {
		sbi->s_ea_block_cache = ecfs_xattr_create_cache();
		if (!sbi->s_ea_block_cache) {
			ecfs_msg(sb, KERN_ERR,
				 "Failed to create ea_block_cache");
			err = -EINVAL;
			goto failed_mount_wq;
		}

		if (ecfs_has_feature_ea_inode(sb)) {
			sbi->s_ea_inode_cache = ecfs_xattr_create_cache();
			if (!sbi->s_ea_inode_cache) {
				ecfs_msg(sb, KERN_ERR,
					 "Failed to create ea_inode_cache");
				err = -EINVAL;
				goto failed_mount_wq;
			}
		}
	}

	/*
	 * Get the # of file system overhead blocks from the
	 * superblock if present.
	 */
	sbi->s_overhead = le32_to_cpu(es->s_overhead_clusters);
	/* ignore the precalculated value if it is ridiculous */
	if (sbi->s_overhead > ecfs_blocks_count(es))
		sbi->s_overhead = 0;
	/*
	 * If the bigalloc feature is not enabled recalculating the
	 * overhead doesn't take long, so we might as well just redo
	 * it to make sure we are using the correct value.
	 */
	if (!ecfs_has_feature_bigalloc(sb))
		sbi->s_overhead = 0;
	if (sbi->s_overhead == 0) {
		err = ecfs_calculate_overhead(sb);
		if (err)
			goto failed_mount_wq;
	}

	/*
	 * The maximum number of concurrent works can be high and
	 * concurrency isn't really necessary.  Limit it to 1.
	 */
	ECFS_SB(sb)->rsv_conversion_wq =
		alloc_workqueue("ecfs-rsv-conversion", WQ_MEM_RECLAIM | WQ_UNBOUND, 1);
	if (!ECFS_SB(sb)->rsv_conversion_wq) {
		printk(KERN_ERR "ECFS-fs: failed to create workqueue\n");
		err = -ENOMEM;
		goto failed_mount4;
	}

	/*
	 * The jbd2_journal_load will have done any necessary log recovery,
	 * so we can safely mount the rest of the filesystem now.
	 */

	root = ecfs_iget(sb, make_fid_sbi(sbi, ECFS_ROOT_INO), ECFS_IGET_SPECIAL);
	if (IS_ERR(root)) {
		ecfs_msg(sb, KERN_ERR, "get root inode failed");
		err = PTR_ERR(root);
		root = NULL;
		goto failed_mount4;
	}
	if (!S_ISDIR(root->i_mode) || !root->i_blocks || !root->i_size) {
		ecfs_msg(sb, KERN_ERR, "corrupt root inode, run e2fsck");
		iput(root);
		err = -EFSCORRUPTED;
		goto failed_mount4;
	}

	generic_set_sb_d_ops(sb);
	sb->s_root = d_make_root(root);
	if (!sb->s_root) {
		ecfs_msg(sb, KERN_ERR, "get root dentry failed");
		err = -ENOMEM;
		goto failed_mount4;
	}

	err = ecfs_setup_super(sb, es, sb_rdonly(sb));
	if (err == -EROFS) {
		sb->s_flags |= SB_RDONLY;
	} else if (err)
		goto failed_mount4a;

	ecfs_set_resv_clusters(sb);

	if (test_opt(sb, BLOCK_VALIDITY)) {
		err = ecfs_setup_system_zone(sb);
		if (err) {
			ecfs_msg(sb, KERN_ERR, "failed to initialize system "
				 "zone (%d)", err);
			goto failed_mount4a;
		}
	}
	ecfs_fc_replay_cleanup(sb);

	ecfs_ext_init(sb);

	/*
	 * Enable optimize_scan if number of groups is > threshold. This can be
	 * turned off by passing "mb_optimize_scan=0". This can also be
	 * turned on forcefully by passing "mb_optimize_scan=1".
	 */
	if (!(ctx->spec & ECFS_SPEC_mb_optimize_scan)) {
		if (sbi->s_groups_count >= MB_DEFAULT_LINEAR_SCAN_THRESHOLD)
			set_opt2(sb, MB_OPTIMIZE_SCAN);
		else
			clear_opt2(sb, MB_OPTIMIZE_SCAN);
	}

	err = ecfs_mb_init(sb);
	if (err) {
		ecfs_msg(sb, KERN_ERR, "failed to initialize mballoc (%d)",
			 err);
		goto failed_mount5;
	}

	/*
	 * We can only set up the journal commit callback once
	 * mballoc is initialized
	 */
	if (sbi->s_journal)
		sbi->s_journal->j_commit_callback =
			ecfs_journal_commit_callback;

	err = ecfs_percpu_param_init(sbi);
	if (err)
		goto failed_mount6;

	if (ecfs_has_feature_flex_bg(sb))
		if (!ecfs_fill_flex_info(sb)) {
			ecfs_msg(sb, KERN_ERR,
			       "unable to initialize "
			       "flex_bg meta info!");
			err = -ENOMEM;
			goto failed_mount6;
		}

	err = ecfs_register_li_request(sb, first_not_zeroed);
	if (err)
		goto failed_mount6;

	err = ecfs_init_orphan_info(sb);
	if (err)
		goto failed_mount7;
#ifdef CONFIG_QUOTA
	/* Enable quota usage during mount. */
	if (ecfs_has_feature_quota(sb) && !sb_rdonly(sb)) {
		err = ecfs_enable_quotas(sb);
		if (err)
			goto failed_mount8;
	}
#endif  /* CONFIG_QUOTA */

	/*
	 * Save the original bdev mapping's wb_err value which could be
	 * used to detect the metadata async write error.
	 */
	errseq_check_and_advance(&sb->s_bdev->bd_mapping->wb_err,
				 &sbi->s_bdev_wb_err);
	ECFS_SB(sb)->s_mount_state |= ECFS_ORPHAN_FS;
	ecfs_orphan_cleanup(sb, es);
	ECFS_SB(sb)->s_mount_state &= ~ECFS_ORPHAN_FS;
	/*
	 * Update the checksum after updating free space/inode counters and
	 * ecfs_orphan_cleanup. Otherwise the superblock can have an incorrect
	 * checksum in the buffer cache until it is written out and
	 * e2fsprogs programs trying to open a file system immediately
	 * after it is mounted can fail.
	 */
	ecfs_superblock_csum_set(sb);
	if (needs_recovery) {
		ecfs_msg(sb, KERN_INFO, "recovery complete");
		err = ecfs_mark_recovery_complete(sb, es);
		if (err)
			goto failed_mount9;
	}

	if (test_opt(sb, DISCARD) && !bdev_max_discard_sectors(sb->s_bdev)) {
		ecfs_msg(sb, KERN_WARNING,
			 "mounting with \"discard\" option, but the device does not support discard");
		clear_opt(sb, DISCARD);
	}

	if (es->s_error_count)
		mod_timer(&sbi->s_err_report, jiffies + 300*HZ); /* 5 minutes */

	/* Enable message ratelimiting. Default is 10 messages per 5 secs. */
	ratelimit_state_init(&sbi->s_err_ratelimit_state, 5 * HZ, 10);
	ratelimit_state_init(&sbi->s_warning_ratelimit_state, 5 * HZ, 10);
	ratelimit_state_init(&sbi->s_msg_ratelimit_state, 5 * HZ, 10);
	atomic_set(&sbi->s_warning_count, 0);
	atomic_set(&sbi->s_msg_count, 0);

	/* Register sysfs after all initializations are complete. */
	err = ecfs_register_sysfs(sb);
	if (err)
		goto failed_mount9;

	return 0;

failed_mount9:
	ecfs_quotas_off(sb, ECFS_MAXQUOTAS);
failed_mount8: __maybe_unused
	ecfs_release_orphan_info(sb);
failed_mount7:
	ecfs_unregister_li_request(sb);
failed_mount6:
	ecfs_mb_release(sb);
	ecfs_flex_groups_free(sbi);
	ecfs_percpu_param_destroy(sbi);
failed_mount5:
	ecfs_ext_release(sb);
	ecfs_release_system_zone(sb);
failed_mount4a:
	dput(sb->s_root);
	sb->s_root = NULL;
failed_mount4:
	ecfs_msg(sb, KERN_ERR, "mount failed");
	if (ECFS_SB(sb)->rsv_conversion_wq)
		destroy_workqueue(ECFS_SB(sb)->rsv_conversion_wq);
failed_mount_wq:
	ecfs_xattr_destroy_cache(sbi->s_ea_inode_cache);
	sbi->s_ea_inode_cache = NULL;

	ecfs_xattr_destroy_cache(sbi->s_ea_block_cache);
	sbi->s_ea_block_cache = NULL;

	if (sbi->s_journal) {
		ecfs_journal_destroy(sbi, sbi->s_journal);
	}
failed_mount3a:
	ecfs_es_unregister_shrinker(sbi);
failed_mount3:
	/* flush s_sb_upd_work before sbi destroy */
	flush_work(&sbi->s_sb_upd_work);
	ecfs_stop_mmpd(sbi);
	timer_delete_sync(&sbi->s_err_report);
	ecfs_group_desc_free(sbi);
failed_mount:
#if IS_ENABLED(CONFIG_UNICODE)
	utf8_unload(sb->s_encoding);
#endif

#ifdef CONFIG_QUOTA
	for (unsigned int i = 0; i < ECFS_MAXQUOTAS; i++)
		kfree(get_qf_name(sb, sbi, i));
#endif
	fscrypt_free_dummy_policy(&sbi->s_dummy_enc_policy);
	brelse(sbi->s_sbh);
	if (sbi->s_journal_bdev_file) {
		invalidate_bdev(file_bdev(sbi->s_journal_bdev_file));
		bdev_fput(sbi->s_journal_bdev_file);
	}
out_fail:
	invalidate_bdev(sb->s_bdev);
	sb->s_fs_info = NULL;
	return err;
}

static int ecfs_fill_super(struct super_block *sb, struct fs_context *fc)
{
	struct ecfs_fs_context *ctx = fc->fs_private;
	struct ecfs_sb_info *sbi;
	const char *descr;
	int ret;

	sbi = ecfs_alloc_sbi(sb);
	if (!sbi)
		return -ENOMEM;

	fc->s_fs_info = sbi;

	/* Cleanup superblock name */
	strreplace(sb->s_id, '/', '!');

	sbi->s_sb_block = 1;	/* Default super block location */
	if (ctx->spec & ECFS_SPEC_s_sb_block)
		sbi->s_sb_block = ctx->s_sb_block;

	ret = __ecfs_fill_super(fc, sb);
	if (ret < 0)
		goto free_sbi;

	if (sbi->s_journal) {
		if (test_opt(sb, DATA_FLAGS) == ECFS_MOUNT_JOURNAL_DATA)
			descr = " journalled data mode";
		else if (test_opt(sb, DATA_FLAGS) == ECFS_MOUNT_ORDERED_DATA)
			descr = " ordered data mode";
		else
			descr = " writeback data mode";
	} else
		descr = "out journal";

	if (___ratelimit(&ecfs_mount_msg_ratelimit, "ECFS-fs mount"))
		ecfs_msg(sb, KERN_INFO, "mounted filesystem %pU %s with%s. "
			 "Quota mode: %s.", &sb->s_uuid,
			 sb_rdonly(sb) ? "ro" : "r/w", descr,
			 ecfs_quota_mode(sb));

	/* Update the s_overhead_clusters if necessary */
	ecfs_update_overhead(sb, false);
	return 0;

free_sbi:
	ecfs_free_sbi(sbi);
	fc->s_fs_info = NULL;
	return ret;
}

static int ecfs_get_tree(struct fs_context *fc)
{
	return get_tree_bdev(fc, ecfs_fill_super);
}

/*
 * Setup any per-fs journal parameters now.  We'll do this both on
 * initial mount, once the journal has been initialised but before we've
 * done any recovery; and again on any subsequent remount.
 */
static void ecfs_init_journal_params(struct super_block *sb, journal_t *journal)
{
	struct ecfs_sb_info *sbi = ECFS_SB(sb);

	journal->j_commit_interval = sbi->s_commit_interval;
	journal->j_min_batch_time = sbi->s_min_batch_time;
	journal->j_max_batch_time = sbi->s_max_batch_time;
	ecfs_fc_init(sb, journal);

	write_lock(&journal->j_state_lock);
	if (test_opt(sb, BARRIER))
		journal->j_flags |= JBD2_BARRIER;
	else
		journal->j_flags &= ~JBD2_BARRIER;
	/*
	 * Always enable journal cycle record option, letting the journal
	 * records log transactions continuously between each mount.
	 */
	journal->j_flags |= JBD2_CYCLE_RECORD;
	write_unlock(&journal->j_state_lock);
}

static struct inode *ecfs_get_journal_inode(struct super_block *sb,
					     unsigned int journal_inum)
{
	struct inode *journal_inode;

	/*
	 * Test for the existence of a valid inode on disk.  Bad things
	 * happen if we iget() an unused inode, as the subsequent iput()
	 * will try to delete it.
	 */
	journal_inode = ecfs_iget(sb, journal_inum, ECFS_IGET_SPECIAL);
	if (IS_ERR(journal_inode)) {
		ecfs_msg(sb, KERN_ERR, "no journal found");
		return ERR_CAST(journal_inode);
	}
	if (!journal_inode->i_nlink) {
		make_bad_inode(journal_inode);
		iput(journal_inode);
		ecfs_msg(sb, KERN_ERR, "journal inode is deleted");
		return ERR_PTR(-EFSCORRUPTED);
	}
	if (!S_ISREG(journal_inode->i_mode) || IS_ENCRYPTED(journal_inode)) {
		ecfs_msg(sb, KERN_ERR, "invalid journal inode");
		iput(journal_inode);
		return ERR_PTR(-EFSCORRUPTED);
	}

	ecfs_debug("Journal inode found at %p: %lld bytes\n",
		  journal_inode, journal_inode->i_size);
	return journal_inode;
}

static int ecfs_journal_bmap(journal_t *journal, sector_t *block)
{
	struct ecfs_map_blocks map;
	int ret;

	if (journal->j_inode == NULL)
		return 0;

	map.m_lblk = *block;
	map.m_len = 1;
	ret = ecfs_map_blocks(NULL, journal->j_inode, &map, 0);
	if (ret <= 0) {
		ecfs_msg(journal->j_inode->i_sb, KERN_CRIT,
			 "journal bmap failed: block %llu ret %d\n",
			 *block, ret);
		jbd2_journal_abort(journal, ret ? ret : -EIO);
		return ret;
	}
	*block = map.m_pblk;
	return 0;
}

static journal_t *ecfs_open_inode_journal(struct super_block *sb,
					  unsigned int journal_inum)
{
	struct inode *journal_inode;
	journal_t *journal;

	journal_inode = ecfs_get_journal_inode(sb, journal_inum);
	if (IS_ERR(journal_inode))
		return ERR_CAST(journal_inode);

	journal = jbd2_journal_init_inode(journal_inode);
	if (IS_ERR(journal)) {
		ecfs_msg(sb, KERN_ERR, "Could not load journal inode");
		iput(journal_inode);
		return ERR_CAST(journal);
	}
	journal->j_private = sb;
	journal->j_bmap = ecfs_journal_bmap;
	ecfs_init_journal_params(sb, journal);
	return journal;
}

static struct file *ecfs_get_journal_blkdev(struct super_block *sb,
					dev_t j_dev, ecfs_fsblk_t *j_start,
					ecfs_fsblk_t *j_len)
{
	struct buffer_head *bh;
	struct block_device *bdev;
	struct file *bdev_file;
	int hblock, blocksize;
	ecfs_fsblk_t sb_block;
	unsigned long offset;
	struct ecfs_super_block *es;
	int errno;

	bdev_file = bdev_file_open_by_dev(j_dev,
		BLK_OPEN_READ | BLK_OPEN_WRITE | BLK_OPEN_RESTRICT_WRITES,
		sb, &fs_holder_ops);
	if (IS_ERR(bdev_file)) {
		ecfs_msg(sb, KERN_ERR,
			 "failed to open journal device unknown-block(%u,%u) %ld",
			 MAJOR(j_dev), MINOR(j_dev), PTR_ERR(bdev_file));
		return bdev_file;
	}

	bdev = file_bdev(bdev_file);
	blocksize = sb->s_blocksize;
	hblock = bdev_logical_block_size(bdev);
	if (blocksize < hblock) {
		ecfs_msg(sb, KERN_ERR,
			"blocksize too small for journal device");
		errno = -EINVAL;
		goto out_bdev;
	}

	sb_block = ECFS_MIN_BLOCK_SIZE / blocksize;
	offset = ECFS_MIN_BLOCK_SIZE % blocksize;
	set_blocksize(bdev_file, blocksize);
	bh = __bread(bdev, sb_block, blocksize);
	if (!bh) {
		ecfs_msg(sb, KERN_ERR, "couldn't read superblock of "
		       "external journal");
		errno = -EINVAL;
		goto out_bdev;
	}

	es = (struct ecfs_super_block *) (bh->b_data + offset);
	if ((le16_to_cpu(es->s_magic) != ECFS_SUPER_MAGIC) ||
	    !(le32_to_cpu(es->s_feature_incompat) &
	      ECFS_FEATURE_INCOMPAT_JOURNAL_DEV)) {
		ecfs_msg(sb, KERN_ERR, "external journal has bad superblock");
		errno = -EFSCORRUPTED;
		goto out_bh;
	}

	if ((le32_to_cpu(es->s_feature_ro_compat) &
	     ECFS_FEATURE_RO_COMPAT_METADATA_CSUM) &&
	    es->s_checksum != ecfs_superblock_csum(es)) {
		ecfs_msg(sb, KERN_ERR, "external journal has corrupt superblock");
		errno = -EFSCORRUPTED;
		goto out_bh;
	}

	if (memcmp(ECFS_SB(sb)->s_es->s_journal_uuid, es->s_uuid, 16)) {
		ecfs_msg(sb, KERN_ERR, "journal UUID does not match");
		errno = -EFSCORRUPTED;
		goto out_bh;
	}

	*j_start = sb_block + 1;
	*j_len = ecfs_blocks_count(es);
	brelse(bh);
	return bdev_file;

out_bh:
	brelse(bh);
out_bdev:
	bdev_fput(bdev_file);
	return ERR_PTR(errno);
}

static journal_t *ecfs_open_dev_journal(struct super_block *sb,
					dev_t j_dev)
{
	journal_t *journal;
	ecfs_fsblk_t j_start;
	ecfs_fsblk_t j_len;
	struct file *bdev_file;
	int errno = 0;

	bdev_file = ecfs_get_journal_blkdev(sb, j_dev, &j_start, &j_len);
	if (IS_ERR(bdev_file))
		return ERR_CAST(bdev_file);

	journal = jbd2_journal_init_dev(file_bdev(bdev_file), sb->s_bdev, j_start,
					j_len, sb->s_blocksize);
	if (IS_ERR(journal)) {
		ecfs_msg(sb, KERN_ERR, "failed to create device journal");
		errno = PTR_ERR(journal);
		goto out_bdev;
	}
	if (be32_to_cpu(journal->j_superblock->s_nr_users) != 1) {
		ecfs_msg(sb, KERN_ERR, "External journal has more than one "
					"user (unsupported) - %d",
			be32_to_cpu(journal->j_superblock->s_nr_users));
		errno = -EINVAL;
		goto out_journal;
	}
	journal->j_private = sb;
	ECFS_SB(sb)->s_journal_bdev_file = bdev_file;
	ecfs_init_journal_params(sb, journal);
	return journal;

out_journal:
	ecfs_journal_destroy(ECFS_SB(sb), journal);
out_bdev:
	bdev_fput(bdev_file);
	return ERR_PTR(errno);
}

static int ecfs_load_journal(struct super_block *sb,
			     struct ecfs_super_block *es,
			     unsigned long journal_devnum)
{
	journal_t *journal;
	unsigned int journal_inum = le32_to_cpu(es->s_journal_inum);
	dev_t journal_dev;
	int err = 0;
	int really_read_only;
	int journal_dev_ro;

	if (WARN_ON_ONCE(!ecfs_has_feature_journal(sb)))
		return -EFSCORRUPTED;

	if (journal_devnum &&
	    journal_devnum != le32_to_cpu(es->s_journal_dev)) {
		ecfs_msg(sb, KERN_INFO, "external journal device major/minor "
			"numbers have changed");
		journal_dev = new_decode_dev(journal_devnum);
	} else
		journal_dev = new_decode_dev(le32_to_cpu(es->s_journal_dev));

	if (journal_inum && journal_dev) {
		ecfs_msg(sb, KERN_ERR,
			 "filesystem has both journal inode and journal device!");
		return -EINVAL;
	}

	if (journal_inum) {
		journal = ecfs_open_inode_journal(sb, journal_inum);
		if (IS_ERR(journal))
			return PTR_ERR(journal);
	} else {
		journal = ecfs_open_dev_journal(sb, journal_dev);
		if (IS_ERR(journal))
			return PTR_ERR(journal);
	}

	journal_dev_ro = bdev_read_only(journal->j_dev);
	really_read_only = bdev_read_only(sb->s_bdev) | journal_dev_ro;

	if (journal_dev_ro && !sb_rdonly(sb)) {
		ecfs_msg(sb, KERN_ERR,
			 "journal device read-only, try mounting with '-o ro'");
		err = -EROFS;
		goto err_out;
	}

	/*
	 * Are we loading a blank journal or performing recovery after a
	 * crash?  For recovery, we need to check in advance whether we
	 * can get read-write access to the device.
	 */
	if (ecfs_has_feature_journal_needs_recovery(sb)) {
		if (sb_rdonly(sb)) {
			ecfs_msg(sb, KERN_INFO, "INFO: recovery "
					"required on readonly filesystem");
			if (really_read_only) {
				ecfs_msg(sb, KERN_ERR, "write access "
					"unavailable, cannot proceed "
					"(try mounting with noload)");
				err = -EROFS;
				goto err_out;
			}
			ecfs_msg(sb, KERN_INFO, "write access will "
			       "be enabled during recovery");
		}
	}

	if (!(journal->j_flags & JBD2_BARRIER))
		ecfs_msg(sb, KERN_INFO, "barriers disabled");

	if (!ecfs_has_feature_journal_needs_recovery(sb))
		err = jbd2_journal_wipe(journal, !really_read_only);
	if (!err) {
		char *save = kmalloc(ECFS_S_ERR_LEN, GFP_KERNEL);
		__le16 orig_state;
		bool changed = false;

		if (save)
			memcpy(save, ((char *) es) +
			       ECFS_S_ERR_START, ECFS_S_ERR_LEN);
		err = jbd2_journal_load(journal);
		if (save && memcmp(((char *) es) + ECFS_S_ERR_START,
				   save, ECFS_S_ERR_LEN)) {
			memcpy(((char *) es) + ECFS_S_ERR_START,
			       save, ECFS_S_ERR_LEN);
			changed = true;
		}
		kfree(save);
		orig_state = es->s_state;
		es->s_state |= cpu_to_le16(ECFS_SB(sb)->s_mount_state &
					   ECFS_ERROR_FS);
		if (orig_state != es->s_state)
			changed = true;
		/* Write out restored error information to the superblock */
		if (changed && !really_read_only) {
			int err2;
			err2 = ecfs_commit_super(sb);
			err = err ? : err2;
		}
	}

	if (err) {
		ecfs_msg(sb, KERN_ERR, "error loading journal");
		goto err_out;
	}

	ECFS_SB(sb)->s_journal = journal;
	err = ecfs_clear_journal_err(sb, es);
	if (err) {
		ecfs_journal_destroy(ECFS_SB(sb), journal);
		return err;
	}

	if (!really_read_only && journal_devnum &&
	    journal_devnum != le32_to_cpu(es->s_journal_dev)) {
		es->s_journal_dev = cpu_to_le32(journal_devnum);
		ecfs_commit_super(sb);
	}
	if (!really_read_only && journal_inum &&
	    journal_inum != le32_to_cpu(es->s_journal_inum)) {
		es->s_journal_inum = cpu_to_le32(journal_inum);
		ecfs_commit_super(sb);
	}

	return 0;

err_out:
	ecfs_journal_destroy(ECFS_SB(sb), journal);
	return err;
}

/* Copy state of ECFS_SB(sb) into buffer for on-disk superblock */
static void ecfs_update_super(struct super_block *sb)
{
	struct ecfs_sb_info *sbi = ECFS_SB(sb);
	struct ecfs_super_block *es = sbi->s_es;
	struct buffer_head *sbh = sbi->s_sbh;

	lock_buffer(sbh);
	/*
	 * If the file system is mounted read-only, don't update the
	 * superblock write time.  This avoids updating the superblock
	 * write time when we are mounting the root file system
	 * read/only but we need to replay the journal; at that point,
	 * for people who are east of GMT and who make their clock
	 * tick in localtime for Windows bug-for-bug compatibility,
	 * the clock is set in the future, and this will cause e2fsck
	 * to complain and force a full file system check.
	 */
	if (!sb_rdonly(sb))
		ecfs_update_tstamp(es, s_wtime);
	es->s_kbytes_written =
		cpu_to_le64(sbi->s_kbytes_written +
		    ((part_stat_read(sb->s_bdev, sectors[STAT_WRITE]) -
		      sbi->s_sectors_written_start) >> 1));
	if (percpu_counter_initialized(&sbi->s_freeclusters_counter))
		ecfs_free_blocks_count_set(es,
			ECFS_C2B(sbi, percpu_counter_sum_positive(
				&sbi->s_freeclusters_counter)));
	if (percpu_counter_initialized(&sbi->s_freeinodes_counter))
		es->s_free_inodes_count =
			cpu_to_le32(percpu_counter_sum_positive(
				&sbi->s_freeinodes_counter));
	/* Copy error information to the on-disk superblock */
	spin_lock(&sbi->s_error_lock);
	if (sbi->s_add_error_count > 0) {
		es->s_state |= cpu_to_le16(ECFS_ERROR_FS);
		if (!es->s_first_error_time && !es->s_first_error_time_hi) {
			__ecfs_update_tstamp(&es->s_first_error_time,
					     &es->s_first_error_time_hi,
					     sbi->s_first_error_time);
			strtomem_pad(es->s_first_error_func,
				     sbi->s_first_error_func, 0);
			es->s_first_error_line =
				cpu_to_le32(sbi->s_first_error_line);
			es->s_first_error_ino =
				cpu_to_le32(sbi->s_first_error_ino);
			es->s_first_error_block =
				cpu_to_le64(sbi->s_first_error_block);
			es->s_first_error_errcode =
				ecfs_errno_to_code(sbi->s_first_error_code);
		}
		__ecfs_update_tstamp(&es->s_last_error_time,
				     &es->s_last_error_time_hi,
				     sbi->s_last_error_time);
		strtomem_pad(es->s_last_error_func, sbi->s_last_error_func, 0);
		es->s_last_error_line = cpu_to_le32(sbi->s_last_error_line);
		es->s_last_error_ino = cpu_to_le32(sbi->s_last_error_ino);
		es->s_last_error_block = cpu_to_le64(sbi->s_last_error_block);
		es->s_last_error_errcode =
				ecfs_errno_to_code(sbi->s_last_error_code);
		/*
		 * Start the daily error reporting function if it hasn't been
		 * started already
		 */
		if (!es->s_error_count)
			mod_timer(&sbi->s_err_report, jiffies + 24*60*60*HZ);
		le32_add_cpu(&es->s_error_count, sbi->s_add_error_count);
		sbi->s_add_error_count = 0;
	}
	spin_unlock(&sbi->s_error_lock);

	ecfs_superblock_csum_set(sb);
	unlock_buffer(sbh);
}

static int ecfs_commit_super(struct super_block *sb)
{
	struct buffer_head *sbh = ECFS_SB(sb)->s_sbh;

	if (!sbh)
		return -EINVAL;

	ecfs_update_super(sb);

	lock_buffer(sbh);
	/* Buffer got discarded which means block device got invalidated */
	if (!buffer_mapped(sbh)) {
		unlock_buffer(sbh);
		return -EIO;
	}

	if (buffer_write_io_error(sbh) || !buffer_uptodate(sbh)) {
		/*
		 * Oh, dear.  A previous attempt to write the
		 * superblock failed.  This could happen because the
		 * USB device was yanked out.  Or it could happen to
		 * be a transient write error and maybe the block will
		 * be remapped.  Nothing we can do but to retry the
		 * write and hope for the best.
		 */
		ecfs_msg(sb, KERN_ERR, "previous I/O error to "
		       "superblock detected");
		clear_buffer_write_io_error(sbh);
		set_buffer_uptodate(sbh);
	}
	get_bh(sbh);
	/* Clear potential dirty bit if it was journalled update */
	clear_buffer_dirty(sbh);
	sbh->b_end_io = end_buffer_write_sync;
	submit_bh(REQ_OP_WRITE | REQ_SYNC |
		  (test_opt(sb, BARRIER) ? REQ_FUA : 0), sbh);
	wait_on_buffer(sbh);
	if (buffer_write_io_error(sbh)) {
		ecfs_msg(sb, KERN_ERR, "I/O error while writing "
		       "superblock");
		clear_buffer_write_io_error(sbh);
		set_buffer_uptodate(sbh);
		return -EIO;
	}
	return 0;
}

/*
 * Have we just finished recovery?  If so, and if we are mounting (or
 * remounting) the filesystem readonly, then we will end up with a
 * consistent fs on disk.  Record that fact.
 */
static int ecfs_mark_recovery_complete(struct super_block *sb,
				       struct ecfs_super_block *es)
{
	int err;
	journal_t *journal = ECFS_SB(sb)->s_journal;

	if (!ecfs_has_feature_journal(sb)) {
		if (journal != NULL) {
			ecfs_error(sb, "Journal got removed while the fs was "
				   "mounted!");
			return -EFSCORRUPTED;
		}
		return 0;
	}
	jbd2_journal_lock_updates(journal);
	err = jbd2_journal_flush(journal, 0);
	if (err < 0)
		goto out;

	if (sb_rdonly(sb) && (ecfs_has_feature_journal_needs_recovery(sb) ||
	    ecfs_has_feature_orphan_present(sb))) {
		if (!ecfs_orphan_file_empty(sb)) {
			ecfs_error(sb, "Orphan file not empty on read-only fs.");
			err = -EFSCORRUPTED;
			goto out;
		}
		ecfs_clear_feature_journal_needs_recovery(sb);
		ecfs_clear_feature_orphan_present(sb);
		ecfs_commit_super(sb);
	}
out:
	jbd2_journal_unlock_updates(journal);
	return err;
}

/*
 * If we are mounting (or read-write remounting) a filesystem whose journal
 * has recorded an error from a previous lifetime, move that error to the
 * main filesystem now.
 */
static int ecfs_clear_journal_err(struct super_block *sb,
				   struct ecfs_super_block *es)
{
	journal_t *journal;
	int j_errno;
	const char *errstr;

	if (!ecfs_has_feature_journal(sb)) {
		ecfs_error(sb, "Journal got removed while the fs was mounted!");
		return -EFSCORRUPTED;
	}

	journal = ECFS_SB(sb)->s_journal;

	/*
	 * Now check for any error status which may have been recorded in the
	 * journal by a prior ecfs_error() or ecfs_abort()
	 */

	j_errno = jbd2_journal_errno(journal);
	if (j_errno) {
		char nbuf[16];

		errstr = ecfs_decode_error(sb, j_errno, nbuf);
		ecfs_warning(sb, "Filesystem error recorded "
			     "from previous mount: %s", errstr);

		ECFS_SB(sb)->s_mount_state |= ECFS_ERROR_FS;
		es->s_state |= cpu_to_le16(ECFS_ERROR_FS);
		j_errno = ecfs_commit_super(sb);
		if (j_errno)
			return j_errno;
		ecfs_warning(sb, "Marked fs in need of filesystem check.");

		jbd2_journal_clear_err(journal);
		jbd2_journal_update_sb_errno(journal);
	}
	return 0;
}

/*
 * Force the running and committing transactions to commit,
 * and wait on the commit.
 */
int ecfs_force_commit(struct super_block *sb)
{
	return ecfs_journal_force_commit(ECFS_SB(sb)->s_journal);
}

static int ecfs_sync_fs(struct super_block *sb, int wait)
{
	int ret = 0;
	tid_t target;
	bool needs_barrier = false;
	struct ecfs_sb_info *sbi = ECFS_SB(sb);

	ret = ecfs_emergency_state(sb);
	if (unlikely(ret))
		return ret;

	trace_ecfs_sync_fs(sb, wait);
	flush_workqueue(sbi->rsv_conversion_wq);
	/*
	 * Writeback quota in non-journalled quota case - journalled quota has
	 * no dirty dquots
	 */
	dquot_writeback_dquots(sb, -1);
	/*
	 * Data writeback is possible w/o journal transaction, so barrier must
	 * being sent at the end of the function. But we can skip it if
	 * transaction_commit will do it for us.
	 */
	if (sbi->s_journal) {
		target = jbd2_get_latest_transaction(sbi->s_journal);
		if (wait && sbi->s_journal->j_flags & JBD2_BARRIER &&
		    !jbd2_trans_will_send_data_barrier(sbi->s_journal, target))
			needs_barrier = true;

		if (jbd2_journal_start_commit(sbi->s_journal, &target)) {
			if (wait)
				ret = jbd2_log_wait_commit(sbi->s_journal,
							   target);
		}
	} else if (wait && test_opt(sb, BARRIER))
		needs_barrier = true;
	if (needs_barrier) {
		int err;
		err = blkdev_issue_flush(sb->s_bdev);
		if (!ret)
			ret = err;
	}

	return ret;
}

/*
 * LVM calls this function before a (read-only) snapshot is created.  This
 * gives us a chance to flush the journal completely and mark the fs clean.
 *
 * Note that only this function cannot bring a filesystem to be in a clean
 * state independently. It relies on upper layer to stop all data & metadata
 * modifications.
 */
static int ecfs_freeze(struct super_block *sb)
{
	int error = 0;
	journal_t *journal = ECFS_SB(sb)->s_journal;

	if (journal) {
		/* Now we set up the journal barrier. */
		jbd2_journal_lock_updates(journal);

		/*
		 * Don't clear the needs_recovery flag if we failed to
		 * flush the journal.
		 */
		error = jbd2_journal_flush(journal, 0);
		if (error < 0)
			goto out;

		/* Journal blocked and flushed, clear needs_recovery flag. */
		ecfs_clear_feature_journal_needs_recovery(sb);
		if (ecfs_orphan_file_empty(sb))
			ecfs_clear_feature_orphan_present(sb);
	}

	error = ecfs_commit_super(sb);
out:
	if (journal)
		/* we rely on upper layer to stop further updates */
		jbd2_journal_unlock_updates(journal);
	return error;
}

/*
 * Called by LVM after the snapshot is done.  We need to reset the RECOVER
 * flag here, even though the filesystem is not technically dirty yet.
 */
static int ecfs_unfreeze(struct super_block *sb)
{
	if (ecfs_emergency_state(sb))
		return 0;

	if (ECFS_SB(sb)->s_journal) {
		/* Reset the needs_recovery flag before the fs is unlocked. */
		ecfs_set_feature_journal_needs_recovery(sb);
		if (ecfs_has_feature_orphan_file(sb))
			ecfs_set_feature_orphan_present(sb);
	}

	ecfs_commit_super(sb);
	return 0;
}

/*
 * Structure to save mount options for ecfs_remount's benefit
 */
struct ecfs_mount_options {
	unsigned long s_mount_opt;
	unsigned long s_mount_opt2;
	kuid_t s_resuid;
	kgid_t s_resgid;
	unsigned long s_commit_interval;
	u32 s_min_batch_time, s_max_batch_time;
#ifdef CONFIG_QUOTA
	int s_jquota_fmt;
	char *s_qf_names[ECFS_MAXQUOTAS];
#endif
};

static int __ecfs_remount(struct fs_context *fc, struct super_block *sb)
{
	struct ecfs_fs_context *ctx = fc->fs_private;
	struct ecfs_super_block *es;
	struct ecfs_sb_info *sbi = ECFS_SB(sb);
	unsigned long old_sb_flags;
	struct ecfs_mount_options old_opts;
	ecfs_group_t g;
	int err = 0;
	int alloc_ctx;
#ifdef CONFIG_QUOTA
	int enable_quota = 0;
	int i, j;
	char *to_free[ECFS_MAXQUOTAS];
#endif


	/* Store the original options */
	old_sb_flags = sb->s_flags;
	old_opts.s_mount_opt = sbi->s_mount_opt;
	old_opts.s_mount_opt2 = sbi->s_mount_opt2;
	old_opts.s_resuid = sbi->s_resuid;
	old_opts.s_resgid = sbi->s_resgid;
	old_opts.s_commit_interval = sbi->s_commit_interval;
	old_opts.s_min_batch_time = sbi->s_min_batch_time;
	old_opts.s_max_batch_time = sbi->s_max_batch_time;
#ifdef CONFIG_QUOTA
	old_opts.s_jquota_fmt = sbi->s_jquota_fmt;
	for (i = 0; i < ECFS_MAXQUOTAS; i++)
		if (sbi->s_qf_names[i]) {
			char *qf_name = get_qf_name(sb, sbi, i);

			old_opts.s_qf_names[i] = kstrdup(qf_name, GFP_KERNEL);
			if (!old_opts.s_qf_names[i]) {
				for (j = 0; j < i; j++)
					kfree(old_opts.s_qf_names[j]);
				return -ENOMEM;
			}
		} else
			old_opts.s_qf_names[i] = NULL;
#endif
	if (!(ctx->spec & ECFS_SPEC_JOURNAL_IOPRIO)) {
		if (sbi->s_journal && sbi->s_journal->j_task->io_context)
			ctx->journal_ioprio =
				sbi->s_journal->j_task->io_context->ioprio;
		else
			ctx->journal_ioprio = ECFS_DEF_JOURNAL_IOPRIO;

	}

	if ((ctx->spec & ECFS_SPEC_s_stripe) &&
	    ecfs_is_stripe_incompatible(sb, ctx->s_stripe)) {
		ecfs_msg(sb, KERN_WARNING,
			 "stripe (%lu) is not aligned with cluster size (%u), "
			 "stripe is disabled",
			 ctx->s_stripe, sbi->s_cluster_ratio);
		ctx->s_stripe = 0;
	}

	/*
	 * Changing the DIOREAD_NOLOCK or DELALLOC mount options may cause
	 * two calls to ecfs_should_dioread_nolock() to return inconsistent
	 * values, triggering WARN_ON in ecfs_add_complete_io(). we grab
	 * here s_writepages_rwsem to avoid race between writepages ops and
	 * remount.
	 */
	alloc_ctx = ecfs_writepages_down_write(sb);
	ecfs_apply_options(fc, sb);
	ecfs_writepages_up_write(sb, alloc_ctx);

	if ((old_opts.s_mount_opt & ECFS_MOUNT_JOURNAL_CHECKSUM) ^
	    test_opt(sb, JOURNAL_CHECKSUM)) {
		ecfs_msg(sb, KERN_ERR, "changing journal_checksum "
			 "during remount not supported; ignoring");
		sbi->s_mount_opt ^= ECFS_MOUNT_JOURNAL_CHECKSUM;
	}

	if (test_opt(sb, DATA_FLAGS) == ECFS_MOUNT_JOURNAL_DATA) {
		if (test_opt2(sb, EXPLICIT_DELALLOC)) {
			ecfs_msg(sb, KERN_ERR, "can't mount with "
				 "both data=journal and delalloc");
			err = -EINVAL;
			goto restore_opts;
		}
		if (test_opt(sb, DIOREAD_NOLOCK)) {
			ecfs_msg(sb, KERN_ERR, "can't mount with "
				 "both data=journal and dioread_nolock");
			err = -EINVAL;
			goto restore_opts;
		}
	} else if (test_opt(sb, DATA_FLAGS) == ECFS_MOUNT_ORDERED_DATA) {
		if (test_opt(sb, JOURNAL_ASYNC_COMMIT)) {
			ecfs_msg(sb, KERN_ERR, "can't mount with "
				"journal_async_commit in data=ordered mode");
			err = -EINVAL;
			goto restore_opts;
		}
	}

	if ((sbi->s_mount_opt ^ old_opts.s_mount_opt) & ECFS_MOUNT_NO_MBCACHE) {
		ecfs_msg(sb, KERN_ERR, "can't enable nombcache during remount");
		err = -EINVAL;
		goto restore_opts;
	}

	if ((old_opts.s_mount_opt & ECFS_MOUNT_DELALLOC) &&
	    !test_opt(sb, DELALLOC)) {
		ecfs_msg(sb, KERN_ERR, "can't disable delalloc during remount");
		err = -EINVAL;
		goto restore_opts;
	}

	sb->s_flags = (sb->s_flags & ~SB_POSIXACL) |
		(test_opt(sb, POSIX_ACL) ? SB_POSIXACL : 0);

	es = sbi->s_es;

	if (sbi->s_journal) {
		ecfs_init_journal_params(sb, sbi->s_journal);
		set_task_ioprio(sbi->s_journal->j_task, ctx->journal_ioprio);
	}

	/* Flush outstanding errors before changing fs state */
	flush_work(&sbi->s_sb_upd_work);

	if ((bool)(fc->sb_flags & SB_RDONLY) != sb_rdonly(sb)) {
		if (ecfs_emergency_state(sb)) {
			err = -EROFS;
			goto restore_opts;
		}

		if (fc->sb_flags & SB_RDONLY) {
			err = sync_filesystem(sb);
			if (err < 0)
				goto restore_opts;
			err = dquot_suspend(sb, -1);
			if (err < 0)
				goto restore_opts;

			/*
			 * First of all, the unconditional stuff we have to do
			 * to disable replay of the journal when we next remount
			 */
			sb->s_flags |= SB_RDONLY;

			/*
			 * OK, test if we are remounting a valid rw partition
			 * readonly, and if so set the rdonly flag and then
			 * mark the partition as valid again.
			 */
			if (!(es->s_state & cpu_to_le16(ECFS_VALID_FS)) &&
			    (sbi->s_mount_state & ECFS_VALID_FS))
				es->s_state = cpu_to_le16(sbi->s_mount_state);

			if (sbi->s_journal) {
				/*
				 * We let remount-ro finish even if marking fs
				 * as clean failed...
				 */
				ecfs_mark_recovery_complete(sb, es);
			}
		} else {
			/* Make sure we can mount this feature set readwrite */
			if (ecfs_has_feature_readonly(sb) ||
			    !ecfs_feature_set_ok(sb, 0)) {
				err = -EROFS;
				goto restore_opts;
			}
			/*
			 * Make sure the group descriptor checksums
			 * are sane.  If they aren't, refuse to remount r/w.
			 */
			for (g = 0; g < sbi->s_groups_count; g++) {
				struct ecfs_group_desc *gdp =
					ecfs_get_group_desc(sb, g, NULL);

				if (!ecfs_group_desc_csum_verify(sb, g, gdp)) {
					ecfs_msg(sb, KERN_ERR,
	       "ecfs_remount: Checksum for group %u failed (%u!=%u)",
		g, le16_to_cpu(ecfs_group_desc_csum(sb, g, gdp)),
					       le16_to_cpu(gdp->bg_checksum));
					err = -EFSBADCRC;
					goto restore_opts;
				}
			}

			/*
			 * If we have an unprocessed orphan list hanging
			 * around from a previously readonly bdev mount,
			 * require a full umount/remount for now.
			 */
			if (es->s_last_orphan || !ecfs_orphan_file_empty(sb)) {
				ecfs_msg(sb, KERN_WARNING, "Couldn't "
				       "remount RDWR because of unprocessed "
				       "orphan inode list.  Please "
				       "umount/remount instead");
				err = -EINVAL;
				goto restore_opts;
			}

			/*
			 * Mounting a RDONLY partition read-write, so reread
			 * and store the current valid flag.  (It may have
			 * been changed by e2fsck since we originally mounted
			 * the partition.)
			 */
			if (sbi->s_journal) {
				err = ecfs_clear_journal_err(sb, es);
				if (err)
					goto restore_opts;
			}
			sbi->s_mount_state = (le16_to_cpu(es->s_state) &
					      ~ECFS_FC_REPLAY);

			err = ecfs_setup_super(sb, es, 0);
			if (err)
				goto restore_opts;

			sb->s_flags &= ~SB_RDONLY;
			if (ecfs_has_feature_mmp(sb)) {
				err = ecfs_multi_mount_protect(sb,
						le64_to_cpu(es->s_mmp_block));
				if (err)
					goto restore_opts;
			}
#ifdef CONFIG_QUOTA
			enable_quota = 1;
#endif
		}
	}

	/*
	 * Handle creation of system zone data early because it can fail.
	 * Releasing of existing data is done when we are sure remount will
	 * succeed.
	 */
	if (test_opt(sb, BLOCK_VALIDITY) && !sbi->s_system_blks) {
		err = ecfs_setup_system_zone(sb);
		if (err)
			goto restore_opts;
	}

	if (sbi->s_journal == NULL && !(old_sb_flags & SB_RDONLY)) {
		err = ecfs_commit_super(sb);
		if (err)
			goto restore_opts;
	}

#ifdef CONFIG_QUOTA
	if (enable_quota) {
		if (sb_any_quota_suspended(sb))
			dquot_resume(sb, -1);
		else if (ecfs_has_feature_quota(sb)) {
			err = ecfs_enable_quotas(sb);
			if (err)
				goto restore_opts;
		}
	}
	/* Release old quota file names */
	for (i = 0; i < ECFS_MAXQUOTAS; i++)
		kfree(old_opts.s_qf_names[i]);
#endif
	if (!test_opt(sb, BLOCK_VALIDITY) && sbi->s_system_blks)
		ecfs_release_system_zone(sb);

	/*
	 * Reinitialize lazy itable initialization thread based on
	 * current settings
	 */
	if (sb_rdonly(sb) || !test_opt(sb, INIT_INODE_TABLE))
		ecfs_unregister_li_request(sb);
	else {
		ecfs_group_t first_not_zeroed;
		first_not_zeroed = ecfs_has_uninit_itable(sb);
		ecfs_register_li_request(sb, first_not_zeroed);
	}

	if (!ecfs_has_feature_mmp(sb) || sb_rdonly(sb))
		ecfs_stop_mmpd(sbi);

	/*
	 * Handle aborting the filesystem as the last thing during remount to
	 * avoid obsure errors during remount when some option changes fail to
	 * apply due to shutdown filesystem.
	 */
	if (test_opt2(sb, ABORT))
		ecfs_abort(sb, ESHUTDOWN, "Abort forced by user");

	return 0;

restore_opts:
	/*
	 * If there was a failing r/w to ro transition, we may need to
	 * re-enable quota
	 */
	if (sb_rdonly(sb) && !(old_sb_flags & SB_RDONLY) &&
	    sb_any_quota_suspended(sb))
		dquot_resume(sb, -1);

	alloc_ctx = ecfs_writepages_down_write(sb);
	sb->s_flags = old_sb_flags;
	sbi->s_mount_opt = old_opts.s_mount_opt;
	sbi->s_mount_opt2 = old_opts.s_mount_opt2;
	sbi->s_resuid = old_opts.s_resuid;
	sbi->s_resgid = old_opts.s_resgid;
	sbi->s_commit_interval = old_opts.s_commit_interval;
	sbi->s_min_batch_time = old_opts.s_min_batch_time;
	sbi->s_max_batch_time = old_opts.s_max_batch_time;
	ecfs_writepages_up_write(sb, alloc_ctx);

	if (!test_opt(sb, BLOCK_VALIDITY) && sbi->s_system_blks)
		ecfs_release_system_zone(sb);
#ifdef CONFIG_QUOTA
	sbi->s_jquota_fmt = old_opts.s_jquota_fmt;
	for (i = 0; i < ECFS_MAXQUOTAS; i++) {
		to_free[i] = get_qf_name(sb, sbi, i);
		rcu_assign_pointer(sbi->s_qf_names[i], old_opts.s_qf_names[i]);
	}
	synchronize_rcu();
	for (i = 0; i < ECFS_MAXQUOTAS; i++)
		kfree(to_free[i]);
#endif
	if (!ecfs_has_feature_mmp(sb) || sb_rdonly(sb))
		ecfs_stop_mmpd(sbi);
	return err;
}

static int ecfs_reconfigure(struct fs_context *fc)
{
	struct super_block *sb = fc->root->d_sb;
	int ret;
	bool old_ro = sb_rdonly(sb);

	fc->s_fs_info = ECFS_SB(sb);

	ret = ecfs_check_opt_consistency(fc, sb);
	if (ret < 0)
		return ret;

	ret = __ecfs_remount(fc, sb);
	if (ret < 0)
		return ret;

	ecfs_msg(sb, KERN_INFO, "re-mounted %pU%s.",
		 &sb->s_uuid,
		 (old_ro != sb_rdonly(sb)) ? (sb_rdonly(sb) ? " ro" : " r/w") : "");

	return 0;
}

#ifdef CONFIG_QUOTA
static int ecfs_statfs_project(struct super_block *sb,
			       kprojid_t projid, struct kstatfs *buf)
{
	struct kqid qid;
	struct dquot *dquot;
	u64 limit;
	u64 curblock;

	qid = make_kqid_projid(projid);
	dquot = dqget(sb, qid);
	if (IS_ERR(dquot))
		return PTR_ERR(dquot);
	spin_lock(&dquot->dq_dqb_lock);

	limit = min_not_zero(dquot->dq_dqb.dqb_bsoftlimit,
			     dquot->dq_dqb.dqb_bhardlimit);
	limit >>= sb->s_blocksize_bits;

	if (limit) {
		uint64_t	remaining = 0;

		curblock = (dquot->dq_dqb.dqb_curspace +
			    dquot->dq_dqb.dqb_rsvspace) >> sb->s_blocksize_bits;
		if (limit > curblock)
			remaining = limit - curblock;

		buf->f_blocks = min(buf->f_blocks, limit);
		buf->f_bfree = min(buf->f_bfree, remaining);
		buf->f_bavail = min(buf->f_bavail, remaining);
	}

	limit = min_not_zero(dquot->dq_dqb.dqb_isoftlimit,
			     dquot->dq_dqb.dqb_ihardlimit);
	if (limit) {
		uint64_t	remaining = 0;

		if (limit > dquot->dq_dqb.dqb_curinodes)
			remaining = limit - dquot->dq_dqb.dqb_curinodes;

		buf->f_files = min(buf->f_files, limit);
		buf->f_ffree = min(buf->f_ffree, remaining);
	}

	spin_unlock(&dquot->dq_dqb_lock);
	dqput(dquot);
	return 0;
}
#endif

static int ecfs_statfs(struct dentry *dentry, struct kstatfs *buf)
{
	struct super_block *sb = dentry->d_sb;
	struct ecfs_sb_info *sbi = ECFS_SB(sb);
	struct ecfs_super_block *es = sbi->s_es;
	ecfs_fsblk_t overhead = 0, resv_blocks;
	s64 bfree;
	resv_blocks = ECFS_C2B(sbi, atomic64_read(&sbi->s_resv_clusters));

	if (!test_opt(sb, MINIX_DF))
		overhead = sbi->s_overhead;

	buf->f_type = ECFS_SUPER_MAGIC;
	buf->f_bsize = sb->s_blocksize;
	buf->f_blocks = ecfs_blocks_count(es) - ECFS_C2B(sbi, overhead);
	bfree = percpu_counter_sum_positive(&sbi->s_freeclusters_counter) -
		percpu_counter_sum_positive(&sbi->s_dirtyclusters_counter);
	/* prevent underflow in case that few free space is available */
	buf->f_bfree = ECFS_C2B(sbi, max_t(s64, bfree, 0));
	buf->f_bavail = buf->f_bfree -
			(ecfs_r_blocks_count(es) + resv_blocks);
	if (buf->f_bfree < (ecfs_r_blocks_count(es) + resv_blocks))
		buf->f_bavail = 0;
	buf->f_files = le32_to_cpu(es->s_inodes_count);
	buf->f_ffree = percpu_counter_sum_positive(&sbi->s_freeinodes_counter);
	buf->f_namelen = ECFS_NAME_LEN;
	buf->f_fsid = uuid_to_fsid(es->s_uuid);

#ifdef CONFIG_QUOTA
	if (ecfs_test_inode_flag(dentry->d_inode, ECFS_INODE_PROJINHERIT) &&
	    sb_has_quota_limits_enabled(sb, PRJQUOTA))
		ecfs_statfs_project(sb, ECFS_I(dentry->d_inode)->i_projid, buf);
#endif
	return 0;
}


#ifdef CONFIG_QUOTA

/*
 * Helper functions so that transaction is started before we acquire dqio_sem
 * to keep correct lock ordering of transaction > dqio_sem
 */
static inline struct inode *dquot_to_inode(struct dquot *dquot)
{
	return sb_dqopt(dquot->dq_sb)->files[dquot->dq_id.type];
}

static int ecfs_write_dquot(struct dquot *dquot)
{
	int ret, err;
	handle_t *handle;
	struct inode *inode;

	inode = dquot_to_inode(dquot);
	handle = ecfs_journal_start(inode, ECFS_HT_QUOTA,
				    ECFS_QUOTA_TRANS_BLOCKS(dquot->dq_sb));
	if (IS_ERR(handle))
		return PTR_ERR(handle);
	ret = dquot_commit(dquot);
	if (ret < 0)
		ecfs_error_err(dquot->dq_sb, -ret,
			       "Failed to commit dquot type %d",
			       dquot->dq_id.type);
	err = ecfs_journal_stop(handle);
	if (!ret)
		ret = err;
	return ret;
}

static int ecfs_acquire_dquot(struct dquot *dquot)
{
	int ret, err;
	handle_t *handle;

	handle = ecfs_journal_start(dquot_to_inode(dquot), ECFS_HT_QUOTA,
				    ECFS_QUOTA_INIT_BLOCKS(dquot->dq_sb));
	if (IS_ERR(handle))
		return PTR_ERR(handle);
	ret = dquot_acquire(dquot);
	if (ret < 0)
		ecfs_error_err(dquot->dq_sb, -ret,
			      "Failed to acquire dquot type %d",
			      dquot->dq_id.type);
	err = ecfs_journal_stop(handle);
	if (!ret)
		ret = err;
	return ret;
}

static int ecfs_release_dquot(struct dquot *dquot)
{
	int ret, err;
	handle_t *handle;
	bool freeze_protected = false;

	/*
	 * Trying to sb_start_intwrite() in a running transaction
	 * can result in a deadlock. Further, running transactions
	 * are already protected from freezing.
	 */
	if (!ecfs_journal_current_handle()) {
		sb_start_intwrite(dquot->dq_sb);
		freeze_protected = true;
	}

	handle = ecfs_journal_start(dquot_to_inode(dquot), ECFS_HT_QUOTA,
				    ECFS_QUOTA_DEL_BLOCKS(dquot->dq_sb));
	if (IS_ERR(handle)) {
		/* Release dquot anyway to avoid endless cycle in dqput() */
		dquot_release(dquot);
		if (freeze_protected)
			sb_end_intwrite(dquot->dq_sb);
		return PTR_ERR(handle);
	}
	ret = dquot_release(dquot);
	if (ret < 0)
		ecfs_error_err(dquot->dq_sb, -ret,
			       "Failed to release dquot type %d",
			       dquot->dq_id.type);
	err = ecfs_journal_stop(handle);
	if (!ret)
		ret = err;

	if (freeze_protected)
		sb_end_intwrite(dquot->dq_sb);

	return ret;
}

static int ecfs_mark_dquot_dirty(struct dquot *dquot)
{
	struct super_block *sb = dquot->dq_sb;

	if (ecfs_is_quota_journalled(sb)) {
		dquot_mark_dquot_dirty(dquot);
		return ecfs_write_dquot(dquot);
	} else {
		return dquot_mark_dquot_dirty(dquot);
	}
}

static int ecfs_write_info(struct super_block *sb, int type)
{
	int ret, err;
	handle_t *handle;

	/* Data block + inode block */
	handle = ecfs_journal_start_sb(sb, ECFS_HT_QUOTA, 2);
	if (IS_ERR(handle))
		return PTR_ERR(handle);
	ret = dquot_commit_info(sb, type);
	err = ecfs_journal_stop(handle);
	if (!ret)
		ret = err;
	return ret;
}

static void lockdep_set_quota_inode(struct inode *inode, int subclass)
{
	struct ecfs_inode_info *ei = ECFS_I(inode);

	/* The first argument of lockdep_set_subclass has to be
	 * *exactly* the same as the argument to init_rwsem() --- in
	 * this case, in init_once() --- or lockdep gets unhappy
	 * because the name of the lock is set using the
	 * stringification of the argument to init_rwsem().
	 */
	(void) ei;	/* shut up clang warning if !CONFIG_LOCKDEP */
	lockdep_set_subclass(&ei->i_data_sem, subclass);
}

/*
 * Standard function to be called on quota_on
 */
static int ecfs_quota_on(struct super_block *sb, int type, int format_id,
			 const struct path *path)
{
	int err;

	if (!test_opt(sb, QUOTA))
		return -EINVAL;

	/* Quotafile not on the same filesystem? */
	if (path->dentry->d_sb != sb)
		return -EXDEV;

	/* Quota already enabled for this file? */
	if (IS_NOQUOTA(d_inode(path->dentry)))
		return -EBUSY;

	/* Journaling quota? */
	if (ECFS_SB(sb)->s_qf_names[type]) {
		/* Quotafile not in fs root? */
		if (path->dentry->d_parent != sb->s_root)
			ecfs_msg(sb, KERN_WARNING,
				"Quota file not on filesystem root. "
				"Journaled quota will not work");
		sb_dqopt(sb)->flags |= DQUOT_NOLIST_DIRTY;
	} else {
		/*
		 * Clear the flag just in case mount options changed since
		 * last time.
		 */
		sb_dqopt(sb)->flags &= ~DQUOT_NOLIST_DIRTY;
	}

	lockdep_set_quota_inode(path->dentry->d_inode, I_DATA_SEM_QUOTA);
	err = dquot_quota_on(sb, type, format_id, path);
	if (!err) {
		struct inode *inode = d_inode(path->dentry);
		handle_t *handle;

		/*
		 * Set inode flags to prevent userspace from messing with quota
		 * files. If this fails, we return success anyway since quotas
		 * are already enabled and this is not a hard failure.
		 */
		inode_lock(inode);
		handle = ecfs_journal_start(inode, ECFS_HT_QUOTA, 1);
		if (IS_ERR(handle))
			goto unlock_inode;
		ECFS_I(inode)->i_flags |= ECFS_NOATIME_FL | ECFS_IMMUTABLE_FL;
		inode_set_flags(inode, S_NOATIME | S_IMMUTABLE,
				S_NOATIME | S_IMMUTABLE);
		err = ecfs_mark_inode_dirty(handle, inode);
		ecfs_journal_stop(handle);
	unlock_inode:
		inode_unlock(inode);
		if (err)
			dquot_quota_off(sb, type);
	}
	if (err)
		lockdep_set_quota_inode(path->dentry->d_inode,
					     I_DATA_SEM_NORMAL);
	return err;
}

static inline bool ecfs_check_quota_inum(int type, unsigned long qf_inum)
{
	/* qf_inum is from ECFS_SB(sb)->s_es->s_usr_quota_inum/s_grp_quota_inum/s_prj_quota_inum , it's 32 bit, so only local ino is saved.*/
	switch (type) {
	case USRQUOTA:
		return qf_inum == ECFS_USR_QUOTA_INO;
	case GRPQUOTA:
		return qf_inum == ECFS_GRP_QUOTA_INO;
	case PRJQUOTA:
		return qf_inum >= ECFS_GOOD_OLD_FIRST_INO;
	default:
		BUG();
	}
}

static int ecfs_quota_enable(struct super_block *sb, int type, int format_id,
			     unsigned int flags)
{
	int err;
	struct inode *qf_inode;
	unsigned long qf_inums[ECFS_MAXQUOTAS] = {
		le32_to_cpu(ECFS_SB(sb)->s_es->s_usr_quota_inum),
		le32_to_cpu(ECFS_SB(sb)->s_es->s_grp_quota_inum),
		le32_to_cpu(ECFS_SB(sb)->s_es->s_prj_quota_inum)
	};

	BUG_ON(!ecfs_has_feature_quota(sb));

	if (!qf_inums[type])
		return -EPERM;

	if (!ecfs_check_quota_inum(type, qf_inums[type])) {
		ecfs_error(sb, "Bad quota inum: %lu, type: %d",
				qf_inums[type], type);
		return -EUCLEAN;
	}

	qf_inode = ecfs_iget(sb, qf_inums[type], ECFS_IGET_SPECIAL);
	if (IS_ERR(qf_inode)) {
		ecfs_error(sb, "Bad quota inode: %lu, type: %d",
				qf_inums[type], type);
		return PTR_ERR(qf_inode);
	}

	/* Don't account quota for quota files to avoid recursion */
	qf_inode->i_flags |= S_NOQUOTA;
	lockdep_set_quota_inode(qf_inode, I_DATA_SEM_QUOTA);
	err = dquot_load_quota_inode(qf_inode, type, format_id, flags);
	if (err)
		lockdep_set_quota_inode(qf_inode, I_DATA_SEM_NORMAL);
	iput(qf_inode);

	return err;
}

/* Enable usage tracking for all quota types. */
int ecfs_enable_quotas(struct super_block *sb)
{
	int type, err = 0;
	unsigned long qf_inums[ECFS_MAXQUOTAS] = {
		le32_to_cpu(ECFS_SB(sb)->s_es->s_usr_quota_inum),
		le32_to_cpu(ECFS_SB(sb)->s_es->s_grp_quota_inum),
		le32_to_cpu(ECFS_SB(sb)->s_es->s_prj_quota_inum)
	};
	bool quota_mopt[ECFS_MAXQUOTAS] = {
		test_opt(sb, USRQUOTA),
		test_opt(sb, GRPQUOTA),
		test_opt(sb, PRJQUOTA),
	};

	sb_dqopt(sb)->flags |= DQUOT_QUOTA_SYS_FILE | DQUOT_NOLIST_DIRTY;
	for (type = 0; type < ECFS_MAXQUOTAS; type++) {
		if (qf_inums[type]) {
			err = ecfs_quota_enable(sb, type, QFMT_VFS_V1,
				DQUOT_USAGE_ENABLED |
				(quota_mopt[type] ? DQUOT_LIMITS_ENABLED : 0));
			if (err) {
				ecfs_warning(sb,
					"Failed to enable quota tracking "
					"(type=%d, err=%d, ino=%lu). "
					"Please run e2fsck to fix.", type,
					err, qf_inums[type]);

				ecfs_quotas_off(sb, type);
				return err;
			}
		}
	}
	return 0;
}

static int ecfs_quota_off(struct super_block *sb, int type)
{
	struct inode *inode = sb_dqopt(sb)->files[type];
	handle_t *handle;
	int err;

	/* Force all delayed allocation blocks to be allocated.
	 * Caller already holds s_umount sem */
	if (test_opt(sb, DELALLOC))
		sync_filesystem(sb);

	if (!inode || !igrab(inode))
		goto out;

	err = dquot_quota_off(sb, type);
	if (err || ecfs_has_feature_quota(sb))
		goto out_put;
	/*
	 * When the filesystem was remounted read-only first, we cannot cleanup
	 * inode flags here. Bad luck but people should be using QUOTA feature
	 * these days anyway.
	 */
	if (sb_rdonly(sb))
		goto out_put;

	inode_lock(inode);
	/*
	 * Update modification times of quota files when userspace can
	 * start looking at them. If we fail, we return success anyway since
	 * this is not a hard failure and quotas are already disabled.
	 */
	handle = ecfs_journal_start(inode, ECFS_HT_QUOTA, 1);
	if (IS_ERR(handle)) {
		err = PTR_ERR(handle);
		goto out_unlock;
	}
	ECFS_I(inode)->i_flags &= ~(ECFS_NOATIME_FL | ECFS_IMMUTABLE_FL);
	inode_set_flags(inode, 0, S_NOATIME | S_IMMUTABLE);
	inode_set_mtime_to_ts(inode, inode_set_ctime_current(inode));
	err = ecfs_mark_inode_dirty(handle, inode);
	ecfs_journal_stop(handle);
out_unlock:
	inode_unlock(inode);
out_put:
	lockdep_set_quota_inode(inode, I_DATA_SEM_NORMAL);
	iput(inode);
	return err;
out:
	return dquot_quota_off(sb, type);
}

/* Read data from quotafile - avoid pagecache and such because we cannot afford
 * acquiring the locks... As quota files are never truncated and quota code
 * itself serializes the operations (and no one else should touch the files)
 * we don't have to be afraid of races */
static ssize_t ecfs_quota_read(struct super_block *sb, int type, char *data,
			       size_t len, loff_t off)
{
	struct inode *inode = sb_dqopt(sb)->files[type];
	ecfs_lblk_t blk = off >> ECFS_BLOCK_SIZE_BITS(sb);
	int offset = off & (sb->s_blocksize - 1);
	int tocopy;
	size_t toread;
	struct buffer_head *bh;
	loff_t i_size = i_size_read(inode);

	if (off > i_size)
		return 0;
	if (off+len > i_size)
		len = i_size-off;
	toread = len;
	while (toread > 0) {
		tocopy = min_t(unsigned long, sb->s_blocksize - offset, toread);
		bh = ecfs_bread(NULL, inode, blk, 0);
		if (IS_ERR(bh))
			return PTR_ERR(bh);
		if (!bh)	/* A hole? */
			memset(data, 0, tocopy);
		else
			memcpy(data, bh->b_data+offset, tocopy);
		brelse(bh);
		offset = 0;
		toread -= tocopy;
		data += tocopy;
		blk++;
	}
	return len;
}

/* Write to quotafile (we know the transaction is already started and has
 * enough credits) */
static ssize_t ecfs_quota_write(struct super_block *sb, int type,
				const char *data, size_t len, loff_t off)
{
	struct inode *inode = sb_dqopt(sb)->files[type];
	ecfs_lblk_t blk = off >> ECFS_BLOCK_SIZE_BITS(sb);
	int err = 0, err2 = 0, offset = off & (sb->s_blocksize - 1);
	int retries = 0;
	struct buffer_head *bh;
	handle_t *handle = journal_current_handle();

	if (!handle) {
		ecfs_msg(sb, KERN_WARNING, "Quota write (off=%llu, len=%llu)"
			" cancelled because transaction is not started",
			(unsigned long long)off, (unsigned long long)len);
		return -EIO;
	}
	/*
	 * Since we account only one data block in transaction credits,
	 * then it is impossible to cross a block boundary.
	 */
	if (sb->s_blocksize - offset < len) {
		ecfs_msg(sb, KERN_WARNING, "Quota write (off=%llu, len=%llu)"
			" cancelled because not block aligned",
			(unsigned long long)off, (unsigned long long)len);
		return -EIO;
	}

	do {
		bh = ecfs_bread(handle, inode, blk,
				ECFS_GET_BLOCKS_CREATE |
				ECFS_GET_BLOCKS_METADATA_NOFAIL);
	} while (PTR_ERR(bh) == -ENOSPC &&
		 ecfs_should_retry_alloc(inode->i_sb, &retries));
	if (IS_ERR(bh))
		return PTR_ERR(bh);
	if (!bh)
		goto out;
	BUFFER_TRACE(bh, "get write access");
	err = ecfs_journal_get_write_access(handle, sb, bh, ECFS_JTR_NONE);
	if (err) {
		brelse(bh);
		return err;
	}
	lock_buffer(bh);
	memcpy(bh->b_data+offset, data, len);
	flush_dcache_folio(bh->b_folio);
	unlock_buffer(bh);
	err = ecfs_handle_dirty_metadata(handle, NULL, bh);
	brelse(bh);
out:
	if (inode->i_size < off + len) {
		i_size_write(inode, off + len);
		ECFS_I(inode)->i_disksize = inode->i_size;
		err2 = ecfs_mark_inode_dirty(handle, inode);
		if (unlikely(err2 && !err))
			err = err2;
	}
	return err ? err : len;
}
#endif


static void ecfs_kill_sb(struct super_block *sb)
{
	struct ecfs_sb_info *sbi = ECFS_SB(sb);
	struct file *bdev_file = sbi ? sbi->s_journal_bdev_file : NULL;

	kill_block_super(sb);

	if (bdev_file)
		bdev_fput(bdev_file);
}

static struct file_system_type ecfs_fs_type = {
	.owner			= THIS_MODULE,
	.name			= "ecfs",
	.init_fs_context	= ecfs_init_fs_context,
	.parameters		= ecfs_param_specs,
	.kill_sb		= ecfs_kill_sb,
	.fs_flags		= FS_REQUIRES_DEV | FS_ALLOW_IDMAP | FS_MGTIME,
};
MODULE_ALIAS_FS("ecfs");

static int __init ecfs_init_fs(void)
{
	int err;

	ratelimit_state_init(&ecfs_mount_msg_ratelimit, 30 * HZ, 64);
	ecfs_li_info = NULL;

	/* Build-time check for flags consistency */
	ecfs_check_flag_values();

	err = ecfs_init_es();
	if (err)
		return err;

	err = ecfs_init_pending();
	if (err)
		goto out7;

	err = ecfs_init_post_read_processing();
	if (err)
		goto out6;

	err = ecfs_init_pageio();
	if (err)
		goto out5;

	err = ecfs_init_system_zone();
	if (err)
		goto out4;

	err = ecfs_init_sysfs();
	if (err)
		goto out3;

	err = ecfs_init_mballoc();
	if (err)
		goto out2;
	err = init_inodecache();
	if (err)
		goto out1;

	err = ecfs_fc_init_dentry_cache();
	if (err)
		goto out05;


	err = register_filesystem(&ecfs_fs_type);
	if (err)
		goto out;

	return 0;
out:

	ecfs_fc_destroy_dentry_cache();
out05:
	destroy_inodecache();
out1:
	ecfs_exit_mballoc();
out2:
	ecfs_exit_sysfs();
out3:
	ecfs_exit_system_zone();
out4:
	ecfs_exit_pageio();
out5:
	ecfs_exit_post_read_processing();
out6:
	ecfs_exit_pending();
out7:
	ecfs_exit_es();

	return err;
}

static void __exit ecfs_exit_fs(void)
{
	ecfs_destroy_lazyinit_thread();

	unregister_filesystem(&ecfs_fs_type);
	ecfs_fc_destroy_dentry_cache();
	destroy_inodecache();
	ecfs_exit_mballoc();
	ecfs_exit_sysfs();
	ecfs_exit_system_zone();
	ecfs_exit_pageio();
	ecfs_exit_post_read_processing();
	ecfs_exit_es();
	ecfs_exit_pending();
}

MODULE_AUTHOR("Remy Card, Stephen Tweedie, Andrew Morton, Andreas Dilger, Theodore Ts'o and others");
MODULE_DESCRIPTION("Fourth Extended Filesystem");
MODULE_LICENSE("GPL");
module_init(ecfs_init_fs)
module_exit(ecfs_exit_fs)
