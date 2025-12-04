// SPDX-License-Identifier: GPL-2.0
/*
 *  linux/fs/ecfs/ialloc.c
 *
 * Copyright (C) 1992, 1993, 1994, 1995
 * Remy Card (card@masi.ibp.fr)
 * Laboratoire MASI - Institut Blaise Pascal
 * Universite Pierre et Marie Curie (Paris VI)
 *
 *  BSD ufs-inspired inode and directory allocation by
 *  Stephen Tweedie (sct@redhat.com), 1993
 *  Big-endian to little-endian byte-swapping/bitmaps by
 *        David S. Miller (davem@caip.rutgers.edu), 1995
 */

#include <linux/time.h>
#include <linux/fs.h>
#include <linux/stat.h>
#include <linux/string.h>
#include <linux/quotaops.h>
#include <linux/buffer_head.h>
#include <linux/random.h>
#include <linux/bitops.h>
#include <linux/blkdev.h>
#include <linux/cred.h>

#include <asm/byteorder.h>

#include "ecfs.h"
#include "ecfs_jbd2.h"
#include "xattr.h"
#include "acl.h"

#include <trace/events/ecfs.h>

/*
 * ialloc.c contains the inodes allocation and deallocation routines
 */

/*
 * The free inodes are managed by bitmaps.  A file system contains several
 * blocks groups.  Each group contains 1 bitmap block for blocks, 1 bitmap
 * block for inodes, N blocks for the inode table and data blocks.
 *
 * The file system contains group descriptors which are located after the
 * super block.  Each descriptor contains the number of the bitmap block and
 * the free blocks count in the block.
 */

/*
 * To avoid calling the atomic setbit hundreds or thousands of times, we only
 * need to use it within a single byte (to ensure we get endianness right).
 * We can use memset for the rest of the bitmap as there are no other users.
 */
void ecfs_mark_bitmap_end(int start_bit, int end_bit, char *bitmap)
{
	int i;

	if (start_bit >= end_bit)
		return;

	ecfs_debug("mark end bits +%d through +%d used\n", start_bit, end_bit);
	for (i = start_bit; i < ((start_bit + 7) & ~7UL); i++)
		ecfs_set_bit(i, bitmap);
	if (i < end_bit)
		memset(bitmap + (i >> 3), 0xff, (end_bit - i) >> 3);
}

void ecfs_end_bitmap_read(struct buffer_head *bh, int uptodate)
{
	if (uptodate) {
		set_buffer_uptodate(bh);
		set_bitmap_uptodate(bh);
	}
	unlock_buffer(bh);
	put_bh(bh);
}

static int ecfs_validate_inode_bitmap(struct super_block *sb,
				      struct ecfs_group_desc *desc,
				      ecfs_group_t block_group,
				      struct buffer_head *bh)
{
	ecfs_fsblk_t	blk;
	struct ecfs_group_info *grp;

	if (ECFS_SB(sb)->s_mount_state & ECFS_FC_REPLAY)
		return 0;

	if (buffer_verified(bh))
		return 0;

	grp = ecfs_get_group_info(sb, block_group);
	if (!grp || ECFS_MB_GRP_IBITMAP_CORRUPT(grp))
		return -EFSCORRUPTED;

	ecfs_lock_group(sb, block_group);
	if (buffer_verified(bh))
		goto verified;
	blk = ecfs_inode_bitmap(sb, desc);
	if (!ecfs_inode_bitmap_csum_verify(sb, desc, bh) ||
	    ecfs_simulate_fail(sb, ECFS_SIM_IBITMAP_CRC)) {
		ecfs_unlock_group(sb, block_group);
		ecfs_error(sb, "Corrupt inode bitmap - block_group = %u, "
			   "inode_bitmap = %llu", block_group, blk);
		ecfs_mark_group_bitmap_corrupted(sb, block_group,
					ECFS_GROUP_INFO_IBITMAP_CORRUPT);
		return -EFSBADCRC;
	}
	set_buffer_verified(bh);
verified:
	ecfs_unlock_group(sb, block_group);
	return 0;
}

/*
 * Read the inode allocation bitmap for a given block_group, reading
 * into the specified slot in the superblock's bitmap cache.
 *
 * Return buffer_head of bitmap on success, or an ERR_PTR on error.
 */
static struct buffer_head *
ecfs_read_inode_bitmap(struct super_block *sb, ecfs_group_t block_group)
{
	struct ecfs_group_desc *desc;
	struct ecfs_sb_info *sbi = ECFS_SB(sb);
	struct buffer_head *bh = NULL;
	ecfs_fsblk_t bitmap_blk;
	int err;

	desc = ecfs_get_group_desc(sb, block_group, NULL);
	if (!desc)
		return ERR_PTR(-EFSCORRUPTED);

	bitmap_blk = ecfs_inode_bitmap(sb, desc);
	if ((bitmap_blk <= le32_to_cpu(sbi->s_es->s_first_data_block)) ||
	    (bitmap_blk >= ecfs_blocks_count(sbi->s_es))) {
		ecfs_error(sb, "Invalid inode bitmap blk %llu in "
			   "block_group %u", bitmap_blk, block_group);
		ecfs_mark_group_bitmap_corrupted(sb, block_group,
					ECFS_GROUP_INFO_IBITMAP_CORRUPT);
		return ERR_PTR(-EFSCORRUPTED);
	}
	bh = sb_getblk(sb, bitmap_blk);
	if (unlikely(!bh)) {
		ecfs_warning(sb, "Cannot read inode bitmap - "
			     "block_group = %u, inode_bitmap = %llu",
			     block_group, bitmap_blk);
		return ERR_PTR(-ENOMEM);
	}
	if (bitmap_uptodate(bh))
		goto verify;

	lock_buffer(bh);
	if (bitmap_uptodate(bh)) {
		unlock_buffer(bh);
		goto verify;
	}

	ecfs_lock_group(sb, block_group);
	if (ecfs_has_group_desc_csum(sb) &&
	    (desc->bg_flags & cpu_to_le16(ECFS_BG_INODE_UNINIT))) {
		if (block_group == 0) {
			ecfs_unlock_group(sb, block_group);
			unlock_buffer(bh);
			ecfs_error(sb, "Inode bitmap for bg 0 marked "
				   "uninitialized");
			err = -EFSCORRUPTED;
			goto out;
		}
		memset(bh->b_data, 0, (ECFS_INODES_PER_GROUP(sb) + 7) / 8);
		ecfs_mark_bitmap_end(ECFS_INODES_PER_GROUP(sb),
				     sb->s_blocksize * 8, bh->b_data);
		set_bitmap_uptodate(bh);
		set_buffer_uptodate(bh);
		set_buffer_verified(bh);
		ecfs_unlock_group(sb, block_group);
		unlock_buffer(bh);
		return bh;
	}
	ecfs_unlock_group(sb, block_group);

	if (buffer_uptodate(bh)) {
		/*
		 * if not uninit if bh is uptodate,
		 * bitmap is also uptodate
		 */
		set_bitmap_uptodate(bh);
		unlock_buffer(bh);
		goto verify;
	}
	/*
	 * submit the buffer_head for reading
	 */
	trace_ecfs_load_inode_bitmap(sb, block_group);
	ecfs_read_bh(bh, REQ_META | REQ_PRIO,
		     ecfs_end_bitmap_read,
		     ecfs_simulate_fail(sb, ECFS_SIM_IBITMAP_EIO));
	if (!buffer_uptodate(bh)) {
		put_bh(bh);
		ecfs_error_err(sb, EIO, "Cannot read inode bitmap - "
			       "block_group = %u, inode_bitmap = %llu",
			       block_group, bitmap_blk);
		ecfs_mark_group_bitmap_corrupted(sb, block_group,
				ECFS_GROUP_INFO_IBITMAP_CORRUPT);
		return ERR_PTR(-EIO);
	}

verify:
	err = ecfs_validate_inode_bitmap(sb, desc, block_group, bh);
	if (err)
		goto out;
	return bh;
out:
	put_bh(bh);
	return ERR_PTR(err);
}

/*
 * NOTE! When we get the inode, we're the only people
 * that have access to it, and as such there are no
 * race conditions we have to worry about. The inode
 * is not on the hash-lists, and it cannot be reached
 * through the filesystem because the directory entry
 * has been deleted earlier.
 *
 * HOWEVER: we must make sure that we get no aliases,
 * which means that we have to call "clear_inode()"
 * _before_ we mark the inode not in use in the inode
 * bitmaps. Otherwise a newly created file might use
 * the same inode number (not actually the same pointer
 * though), and then we'd have two inodes sharing the
 * same inode number and space on the harddisk.
 */
void ecfs_free_inode(handle_t *handle, struct inode *inode)
{
	struct super_block *sb = inode->i_sb;
	int is_directory;
	unsigned long ino;
	struct buffer_head *bitmap_bh = NULL;
	struct buffer_head *bh2;
	ecfs_group_t block_group;
	unsigned long bit;
	struct ecfs_group_desc *gdp;
	struct ecfs_super_block *es;
	struct ecfs_sb_info *sbi;
	int fatal = 0, err, count, cleared;
	struct ecfs_group_info *grp;

	if (!sb) {
		printk(KERN_ERR "ECFS-fs: %s:%d: inode on "
		       "nonexistent device\n", __func__, __LINE__);
		return;
	}
	if (atomic_read(&inode->i_count) > 1) {
		ecfs_msg(sb, KERN_ERR, "%s:%d: inode #%lu: count=%d",
			 __func__, __LINE__, inode->i_ino,
			 atomic_read(&inode->i_count));
		return;
	}
	if (inode->i_nlink) {
		ecfs_msg(sb, KERN_ERR, "%s:%d: inode #%lu: nlink=%d\n",
			 __func__, __LINE__, inode->i_ino, inode->i_nlink);
		return;
	}
	sbi = ECFS_SB(sb);

	ino = inode->i_ino;
	ecfs_debug("freeing inode %lu\n", ino);
	trace_ecfs_free_inode(inode);

	dquot_initialize(inode);
	dquot_free_inode(inode);

	is_directory = S_ISDIR(inode->i_mode);

	/* Do this BEFORE marking the inode not in use or returning an error */
	ecfs_clear_inode(inode);

	es = sbi->s_es;
	if (ino < ECFS_FIRST_INO(sb) || ino > le32_to_cpu(es->s_inodes_count)) {
		ecfs_error(sb, "reserved or nonexistent inode %lu", ino);
		goto error_return;
	}
	block_group = (ino - 1) / ECFS_INODES_PER_GROUP(sb);
	bit = (ino - 1) % ECFS_INODES_PER_GROUP(sb);
	bitmap_bh = ecfs_read_inode_bitmap(sb, block_group);
	/* Don't bother if the inode bitmap is corrupt. */
	if (IS_ERR(bitmap_bh)) {
		fatal = PTR_ERR(bitmap_bh);
		bitmap_bh = NULL;
		goto error_return;
	}
	if (!(sbi->s_mount_state & ECFS_FC_REPLAY)) {
		grp = ecfs_get_group_info(sb, block_group);
		if (!grp || unlikely(ECFS_MB_GRP_IBITMAP_CORRUPT(grp))) {
			fatal = -EFSCORRUPTED;
			goto error_return;
		}
	}

	BUFFER_TRACE(bitmap_bh, "get_write_access");
	fatal = ecfs_journal_get_write_access(handle, sb, bitmap_bh,
					      ECFS_JTR_NONE);
	if (fatal)
		goto error_return;

	fatal = -ESRCH;
	gdp = ecfs_get_group_desc(sb, block_group, &bh2);
	if (gdp) {
		BUFFER_TRACE(bh2, "get_write_access");
		fatal = ecfs_journal_get_write_access(handle, sb, bh2,
						      ECFS_JTR_NONE);
	}
	ecfs_lock_group(sb, block_group);
	cleared = ecfs_test_and_clear_bit(bit, bitmap_bh->b_data);
	if (fatal || !cleared) {
		ecfs_unlock_group(sb, block_group);
		goto out;
	}

	count = ecfs_free_inodes_count(sb, gdp) + 1;
	ecfs_free_inodes_set(sb, gdp, count);
	if (is_directory) {
		count = ecfs_used_dirs_count(sb, gdp) - 1;
		ecfs_used_dirs_set(sb, gdp, count);
		if (percpu_counter_initialized(&sbi->s_dirs_counter))
			percpu_counter_dec(&sbi->s_dirs_counter);
	}
	ecfs_inode_bitmap_csum_set(sb, gdp, bitmap_bh);
	ecfs_group_desc_csum_set(sb, block_group, gdp);
	ecfs_unlock_group(sb, block_group);

	if (percpu_counter_initialized(&sbi->s_freeinodes_counter))
		percpu_counter_inc(&sbi->s_freeinodes_counter);
	if (sbi->s_log_groups_per_flex) {
		struct flex_groups *fg;

		fg = sbi_array_rcu_deref(sbi, s_flex_groups,
					 ecfs_flex_group(sbi, block_group));
		atomic_inc(&fg->free_inodes);
		if (is_directory)
			atomic_dec(&fg->used_dirs);
	}
	BUFFER_TRACE(bh2, "call ecfs_handle_dirty_metadata");
	fatal = ecfs_handle_dirty_metadata(handle, NULL, bh2);
out:
	if (cleared) {
		BUFFER_TRACE(bitmap_bh, "call ecfs_handle_dirty_metadata");
		err = ecfs_handle_dirty_metadata(handle, NULL, bitmap_bh);
		if (!fatal)
			fatal = err;
	} else {
		ecfs_error(sb, "bit already cleared for inode %lu", ino);
		ecfs_mark_group_bitmap_corrupted(sb, block_group,
					ECFS_GROUP_INFO_IBITMAP_CORRUPT);
	}

error_return:
	brelse(bitmap_bh);
	ecfs_std_error(sb, fatal);
}

struct orlov_stats {
	__u64 free_clusters;
	__u32 free_inodes;
	__u32 used_dirs;
};

/*
 * Helper function for Orlov's allocator; returns critical information
 * for a particular block group or flex_bg.  If flex_size is 1, then g
 * is a block group number; otherwise it is flex_bg number.
 */
static void get_orlov_stats(struct super_block *sb, ecfs_group_t g,
			    int flex_size, struct orlov_stats *stats)
{
	struct ecfs_group_desc *desc;

	if (flex_size > 1) {
		struct flex_groups *fg = sbi_array_rcu_deref(ECFS_SB(sb),
							     s_flex_groups, g);
		stats->free_inodes = atomic_read(&fg->free_inodes);
		stats->free_clusters = atomic64_read(&fg->free_clusters);
		stats->used_dirs = atomic_read(&fg->used_dirs);
		return;
	}

	desc = ecfs_get_group_desc(sb, g, NULL);
	if (desc) {
		stats->free_inodes = ecfs_free_inodes_count(sb, desc);
		stats->free_clusters = ecfs_free_group_clusters(sb, desc);
		stats->used_dirs = ecfs_used_dirs_count(sb, desc);
	} else {
		stats->free_inodes = 0;
		stats->free_clusters = 0;
		stats->used_dirs = 0;
	}
}

/*
 * Orlov's allocator for directories.
 *
 * We always try to spread first-level directories.
 *
 * If there are blockgroups with both free inodes and free clusters counts
 * not worse than average we return one with smallest directory count.
 * Otherwise we simply return a random group.
 *
 * For the rest rules look so:
 *
 * It's OK to put directory into a group unless
 * it has too many directories already (max_dirs) or
 * it has too few free inodes left (min_inodes) or
 * it has too few free clusters left (min_clusters) or
 * Parent's group is preferred, if it doesn't satisfy these
 * conditions we search cyclically through the rest. If none
 * of the groups look good we just look for a group with more
 * free inodes than average (starting at parent's group).
 */

static int find_group_orlov(struct super_block *sb, struct inode *parent,
			    ecfs_group_t *group, umode_t mode,
			    const struct qstr *qstr)
{
	ecfs_group_t parent_group = ECFS_I(parent)->i_block_group;
	struct ecfs_sb_info *sbi = ECFS_SB(sb);
	ecfs_group_t real_ngroups = ecfs_get_groups_count(sb);
	int inodes_per_group = ECFS_INODES_PER_GROUP(sb);
	unsigned int freei, avefreei, grp_free;
	ecfs_fsblk_t freec, avefreec;
	unsigned int ndirs;
	int max_dirs, min_inodes;
	ecfs_grpblk_t min_clusters;
	ecfs_group_t i, grp, g, ngroups;
	struct ecfs_group_desc *desc;
	struct orlov_stats stats;
	int flex_size = ecfs_flex_bg_size(sbi);
	struct dx_hash_info hinfo;

	ngroups = real_ngroups;
	if (flex_size > 1) {
		ngroups = (real_ngroups + flex_size - 1) >>
			sbi->s_log_groups_per_flex;
		parent_group >>= sbi->s_log_groups_per_flex;
	}

	freei = percpu_counter_read_positive(&sbi->s_freeinodes_counter);
	avefreei = freei / ngroups;
	freec = percpu_counter_read_positive(&sbi->s_freeclusters_counter);
	avefreec = freec;
	do_div(avefreec, ngroups);
	ndirs = percpu_counter_read_positive(&sbi->s_dirs_counter);

	if (S_ISDIR(mode) &&
	    ((parent == d_inode(sb->s_root)) ||
	     (ecfs_test_inode_flag(parent, ECFS_INODE_TOPDIR)))) {
		int best_ndir = inodes_per_group;
		int ret = -1;

		if (qstr) {
			hinfo.hash_version = DX_HASH_HALF_MD4;
			hinfo.seed = sbi->s_hash_seed;
			ecfsfs_dirhash(parent, qstr->name, qstr->len, &hinfo);
			parent_group = hinfo.hash % ngroups;
		} else
			parent_group = get_random_u32_below(ngroups);
		for (i = 0; i < ngroups; i++) {
			g = (parent_group + i) % ngroups;
			get_orlov_stats(sb, g, flex_size, &stats);
			if (!stats.free_inodes)
				continue;
			if (stats.used_dirs >= best_ndir)
				continue;
			if (stats.free_inodes < avefreei)
				continue;
			if (stats.free_clusters < avefreec)
				continue;
			grp = g;
			ret = 0;
			best_ndir = stats.used_dirs;
		}
		if (ret)
			goto fallback;
	found_flex_bg:
		if (flex_size == 1) {
			*group = grp;
			return 0;
		}

		/*
		 * We pack inodes at the beginning of the flexgroup's
		 * inode tables.  Block allocation decisions will do
		 * something similar, although regular files will
		 * start at 2nd block group of the flexgroup.  See
		 * ecfs_ext_find_goal() and ecfs_find_near().
		 */
		grp *= flex_size;
		for (i = 0; i < flex_size; i++) {
			if (grp+i >= real_ngroups)
				break;
			desc = ecfs_get_group_desc(sb, grp+i, NULL);
			if (desc && ecfs_free_inodes_count(sb, desc)) {
				*group = grp+i;
				return 0;
			}
		}
		goto fallback;
	}

	max_dirs = ndirs / ngroups + inodes_per_group*flex_size / 16;
	min_inodes = avefreei - inodes_per_group*flex_size / 4;
	if (min_inodes < 1)
		min_inodes = 1;
	min_clusters = avefreec - ECFS_CLUSTERS_PER_GROUP(sb)*flex_size / 4;
	if (min_clusters < 0)
		min_clusters = 0;

	/*
	 * Start looking in the flex group where we last allocated an
	 * inode for this parent directory
	 */
	if (ECFS_I(parent)->i_last_alloc_group != ~0) {
		parent_group = ECFS_I(parent)->i_last_alloc_group;
		if (flex_size > 1)
			parent_group >>= sbi->s_log_groups_per_flex;
	}

	for (i = 0; i < ngroups; i++) {
		grp = (parent_group + i) % ngroups;
		get_orlov_stats(sb, grp, flex_size, &stats);
		if (stats.used_dirs >= max_dirs)
			continue;
		if (stats.free_inodes < min_inodes)
			continue;
		if (stats.free_clusters < min_clusters)
			continue;
		goto found_flex_bg;
	}

fallback:
	ngroups = real_ngroups;
	avefreei = freei / ngroups;
fallback_retry:
	parent_group = ECFS_I(parent)->i_block_group;
	for (i = 0; i < ngroups; i++) {
		grp = (parent_group + i) % ngroups;
		desc = ecfs_get_group_desc(sb, grp, NULL);
		if (desc) {
			grp_free = ecfs_free_inodes_count(sb, desc);
			if (grp_free && grp_free >= avefreei) {
				*group = grp;
				return 0;
			}
		}
	}

	if (avefreei) {
		/*
		 * The free-inodes counter is approximate, and for really small
		 * filesystems the above test can fail to find any blockgroups
		 */
		avefreei = 0;
		goto fallback_retry;
	}

	return -1;
}

static int find_group_other(struct super_block *sb, struct inode *parent,
			    ecfs_group_t *group, umode_t mode)
{
	ecfs_group_t parent_group = ECFS_I(parent)->i_block_group;
	ecfs_group_t i, last, ngroups = ecfs_get_groups_count(sb);
	struct ecfs_group_desc *desc;
	int flex_size = ecfs_flex_bg_size(ECFS_SB(sb));

	/*
	 * Try to place the inode is the same flex group as its
	 * parent.  If we can't find space, use the Orlov algorithm to
	 * find another flex group, and store that information in the
	 * parent directory's inode information so that use that flex
	 * group for future allocations.
	 */
	if (flex_size > 1) {
		int retry = 0;

	try_again:
		parent_group &= ~(flex_size-1);
		last = parent_group + flex_size;
		if (last > ngroups)
			last = ngroups;
		for  (i = parent_group; i < last; i++) {
			desc = ecfs_get_group_desc(sb, i, NULL);
			if (desc && ecfs_free_inodes_count(sb, desc)) {
				*group = i;
				return 0;
			}
		}
		if (!retry && ECFS_I(parent)->i_last_alloc_group != ~0) {
			retry = 1;
			parent_group = ECFS_I(parent)->i_last_alloc_group;
			goto try_again;
		}
		/*
		 * If this didn't work, use the Orlov search algorithm
		 * to find a new flex group; we pass in the mode to
		 * avoid the topdir algorithms.
		 */
		*group = parent_group + flex_size;
		if (*group > ngroups)
			*group = 0;
		return find_group_orlov(sb, parent, group, mode, NULL);
	}

	/*
	 * Try to place the inode in its parent directory
	 */
	*group = parent_group;
	desc = ecfs_get_group_desc(sb, *group, NULL);
	if (desc && ecfs_free_inodes_count(sb, desc) &&
	    ecfs_free_group_clusters(sb, desc))
		return 0;

	/*
	 * We're going to place this inode in a different blockgroup from its
	 * parent.  We want to cause files in a common directory to all land in
	 * the same blockgroup.  But we want files which are in a different
	 * directory which shares a blockgroup with our parent to land in a
	 * different blockgroup.
	 *
	 * So add our directory's i_ino into the starting point for the hash.
	 */
	*group = (*group + LOCAL_INO(parent->i_ino)) % ngroups;

	/*
	 * Use a quadratic hash to find a group with a free inode and some free
	 * blocks.
	 */
	for (i = 1; i < ngroups; i <<= 1) {
		*group += i;
		if (*group >= ngroups)
			*group -= ngroups;
		desc = ecfs_get_group_desc(sb, *group, NULL);
		if (desc && ecfs_free_inodes_count(sb, desc) &&
		    ecfs_free_group_clusters(sb, desc))
			return 0;
	}

	/*
	 * That failed: try linear search for a free inode, even if that group
	 * has no free blocks.
	 */
	*group = parent_group;
	for (i = 0; i < ngroups; i++) {
		if (++*group >= ngroups)
			*group = 0;
		desc = ecfs_get_group_desc(sb, *group, NULL);
		if (desc && ecfs_free_inodes_count(sb, desc))
			return 0;
	}

	return -1;
}

/*
 * In no journal mode, if an inode has recently been deleted, we want
 * to avoid reusing it until we're reasonably sure the inode table
 * block has been written back to disk.  (Yes, these values are
 * somewhat arbitrary...)
 */
#define RECENTCY_MIN	60
#define RECENTCY_DIRTY	300

static int recently_deleted(struct super_block *sb, ecfs_group_t group, int ino)
{
	struct ecfs_group_desc	*gdp;
	struct ecfs_inode	*raw_inode;
	struct buffer_head	*bh;
	int inodes_per_block = ECFS_SB(sb)->s_inodes_per_block;
	int offset, ret = 0;
	int recentcy = RECENTCY_MIN;
	u32 dtime, now;

	gdp = ecfs_get_group_desc(sb, group, NULL);
	if (unlikely(!gdp))
		return 0;

	bh = sb_find_get_block(sb, ecfs_inode_table(sb, gdp) +
		       (ino / inodes_per_block));
	if (!bh || !buffer_uptodate(bh))
		/*
		 * If the block is not in the buffer cache, then it
		 * must have been written out, or, most unlikely, is
		 * being migrated - false failure should be OK here.
		 */
		goto out;

	offset = (ino % inodes_per_block) * ECFS_INODE_SIZE(sb);
	raw_inode = (struct ecfs_inode *) (bh->b_data + offset);

	/* i_dtime is only 32 bits on disk, but we only care about relative
	 * times in the range of a few minutes (i.e. long enough to sync a
	 * recently-deleted inode to disk), so using the low 32 bits of the
	 * clock (a 68 year range) is enough, see time_before32() */
	dtime = le32_to_cpu(raw_inode->i_dtime);
	now = ktime_get_real_seconds();
	if (buffer_dirty(bh))
		recentcy += RECENTCY_DIRTY;

	if (dtime && time_before32(dtime, now) &&
	    time_before32(now, dtime + recentcy))
		ret = 1;
out:
	brelse(bh);
	return ret;
}

static int find_inode_bit(struct super_block *sb, ecfs_group_t group,
			  struct buffer_head *bitmap, unsigned long *ino)
{
	bool check_recently_deleted = ECFS_SB(sb)->s_journal == NULL;
	unsigned long recently_deleted_ino = ECFS_INODES_PER_GROUP(sb);

next:
	*ino = ecfs_find_next_zero_bit((unsigned long *)
				       bitmap->b_data,
				       ECFS_INODES_PER_GROUP(sb), *ino);
	if (*ino >= ECFS_INODES_PER_GROUP(sb))
		goto not_found;

	if (check_recently_deleted && recently_deleted(sb, group, *ino)) {
		recently_deleted_ino = *ino;
		*ino = *ino + 1;
		if (*ino < ECFS_INODES_PER_GROUP(sb))
			goto next;
		goto not_found;
	}
	return 1;
not_found:
	if (recently_deleted_ino >= ECFS_INODES_PER_GROUP(sb))
		return 0;
	/*
	 * Not reusing recently deleted inodes is mostly a preference. We don't
	 * want to report ENOSPC or skew allocation patterns because of that.
	 * So return even recently deleted inode if we could find better in the
	 * given range.
	 */
	*ino = recently_deleted_ino;
	return 1;
}

int ecfs_mark_inode_used(struct super_block *sb, int ino)
{
	unsigned long max_ino = le32_to_cpu(ECFS_SB(sb)->s_es->s_inodes_count);
	struct buffer_head *inode_bitmap_bh = NULL, *group_desc_bh = NULL;
	struct ecfs_group_desc *gdp;
	ecfs_group_t group;
	int bit;
	int err;

	if (ino < ECFS_FIRST_INO(sb) || ino > max_ino)
		return -EFSCORRUPTED;

	group = (ino - 1) / ECFS_INODES_PER_GROUP(sb);
	bit = (ino - 1) % ECFS_INODES_PER_GROUP(sb);
	inode_bitmap_bh = ecfs_read_inode_bitmap(sb, group);
	if (IS_ERR(inode_bitmap_bh))
		return PTR_ERR(inode_bitmap_bh);

	if (ecfs_test_bit(bit, inode_bitmap_bh->b_data)) {
		err = 0;
		goto out;
	}

	gdp = ecfs_get_group_desc(sb, group, &group_desc_bh);
	if (!gdp) {
		err = -EINVAL;
		goto out;
	}

	ecfs_set_bit(bit, inode_bitmap_bh->b_data);

	BUFFER_TRACE(inode_bitmap_bh, "call ecfs_handle_dirty_metadata");
	err = ecfs_handle_dirty_metadata(NULL, NULL, inode_bitmap_bh);
	if (err) {
		ecfs_std_error(sb, err);
		goto out;
	}
	err = sync_dirty_buffer(inode_bitmap_bh);
	if (err) {
		ecfs_std_error(sb, err);
		goto out;
	}

	/* We may have to initialize the block bitmap if it isn't already */
	if (ecfs_has_group_desc_csum(sb) &&
	    gdp->bg_flags & cpu_to_le16(ECFS_BG_BLOCK_UNINIT)) {
		struct buffer_head *block_bitmap_bh;

		block_bitmap_bh = ecfs_read_block_bitmap(sb, group);
		if (IS_ERR(block_bitmap_bh)) {
			err = PTR_ERR(block_bitmap_bh);
			goto out;
		}

		BUFFER_TRACE(block_bitmap_bh, "dirty block bitmap");
		err = ecfs_handle_dirty_metadata(NULL, NULL, block_bitmap_bh);
		sync_dirty_buffer(block_bitmap_bh);

		/* recheck and clear flag under lock if we still need to */
		ecfs_lock_group(sb, group);
		if (ecfs_has_group_desc_csum(sb) &&
		    (gdp->bg_flags & cpu_to_le16(ECFS_BG_BLOCK_UNINIT))) {
			gdp->bg_flags &= cpu_to_le16(~ECFS_BG_BLOCK_UNINIT);
			ecfs_free_group_clusters_set(sb, gdp,
				ecfs_free_clusters_after_init(sb, group, gdp));
			ecfs_block_bitmap_csum_set(sb, gdp, block_bitmap_bh);
			ecfs_group_desc_csum_set(sb, group, gdp);
		}
		ecfs_unlock_group(sb, group);
		brelse(block_bitmap_bh);

		if (err) {
			ecfs_std_error(sb, err);
			goto out;
		}
	}

	/* Update the relevant bg descriptor fields */
	if (ecfs_has_group_desc_csum(sb)) {
		int free;

		ecfs_lock_group(sb, group); /* while we modify the bg desc */
		free = ECFS_INODES_PER_GROUP(sb) -
			ecfs_itable_unused_count(sb, gdp);
		if (gdp->bg_flags & cpu_to_le16(ECFS_BG_INODE_UNINIT)) {
			gdp->bg_flags &= cpu_to_le16(~ECFS_BG_INODE_UNINIT);
			free = 0;
		}

		/*
		 * Check the relative inode number against the last used
		 * relative inode number in this group. if it is greater
		 * we need to update the bg_itable_unused count
		 */
		if (bit >= free)
			ecfs_itable_unused_set(sb, gdp,
					(ECFS_INODES_PER_GROUP(sb) - bit - 1));
	} else {
		ecfs_lock_group(sb, group);
	}

	ecfs_free_inodes_set(sb, gdp, ecfs_free_inodes_count(sb, gdp) - 1);
	if (ecfs_has_group_desc_csum(sb)) {
		ecfs_inode_bitmap_csum_set(sb, gdp, inode_bitmap_bh);
		ecfs_group_desc_csum_set(sb, group, gdp);
	}

	ecfs_unlock_group(sb, group);
	err = ecfs_handle_dirty_metadata(NULL, NULL, group_desc_bh);
	sync_dirty_buffer(group_desc_bh);
out:
	brelse(inode_bitmap_bh);
	return err;
}

static int ecfs_xattr_credits_for_new_inode(struct inode *dir, mode_t mode,
					    bool encrypt)
{
	struct super_block *sb = dir->i_sb;
	int nblocks = 0;
#ifdef CONFIG_ECFS_FS_POSIX_ACL
	struct posix_acl *p = get_inode_acl(dir, ACL_TYPE_DEFAULT);

	if (IS_ERR(p))
		return PTR_ERR(p);
	if (p) {
		int acl_size = p->a_count * sizeof(ecfs_acl_entry);

		nblocks += (S_ISDIR(mode) ? 2 : 1) *
			__ecfs_xattr_set_credits(sb, NULL /* inode */,
						 NULL /* block_bh */, acl_size,
						 true /* is_create */);
		posix_acl_release(p);
	}
#endif

#ifdef CONFIG_SECURITY
	{
		int num_security_xattrs = 1;

#ifdef CONFIG_INTEGRITY
		num_security_xattrs++;
#endif
		/*
		 * We assume that security xattrs are never more than 1k.
		 * In practice they are under 128 bytes.
		 */
		nblocks += num_security_xattrs *
			__ecfs_xattr_set_credits(sb, NULL /* inode */,
						 NULL /* block_bh */, 1024,
						 true /* is_create */);
	}
#endif
	if (encrypt)
		nblocks += __ecfs_xattr_set_credits(sb,
						    NULL /* inode */,
						    NULL /* block_bh */,
						    FSCRYPT_SET_CONTEXT_MAX_SIZE,
						    true /* is_create */);
	return nblocks;
}

/*
 * There are two policies for allocating an inode.  If the new inode is
 * a directory, then a forward search is made for a block group with both
 * free space and a low directory-to-inode ratio; if that fails, then of
 * the groups with above-average free space, that group with the fewest
 * directories already is chosen.
 *
 * For other inodes, search forward from the parent directory's block
 * group to find a free inode.
 */
struct inode *__ecfs_new_inode(struct mnt_idmap *idmap,
			       handle_t *handle, struct inode *dir,
			       umode_t mode, const struct qstr *qstr,
			       __u32 goal, uid_t *owner, __u32 i_flags,
			       int handle_type, unsigned int line_no,
			       int nblocks)
{
	struct super_block *sb;
	struct buffer_head *inode_bitmap_bh = NULL;
	struct buffer_head *group_desc_bh;
	ecfs_group_t ngroups, group = 0;
	unsigned long ino = 0;
	struct inode *inode;
	struct ecfs_group_desc *gdp = NULL;
	struct ecfs_inode_info *ei;
	struct ecfs_sb_info *sbi;
	int ret2, err;
	struct inode *ret;
	ecfs_group_t i;
	ecfs_group_t flex_group;
	struct ecfs_group_info *grp = NULL;
	bool encrypt = false;

	/* Cannot create files in a deleted directory */
	if (!dir || !dir->i_nlink)
		return ERR_PTR(-EPERM);

	sb = dir->i_sb;
	sbi = ECFS_SB(sb);

	ret2 = ecfs_emergency_state(sb);
	if (unlikely(ret2))
		return ERR_PTR(ret2);

	ngroups = ecfs_get_groups_count(sb);
	trace_ecfs_request_inode(dir, mode);
	inode = new_inode(sb);
	if (!inode)
		return ERR_PTR(-ENOMEM);
	ei = ECFS_I(inode);

	/*
	 * Initialize owners and quota early so that we don't have to account
	 * for quota initialization worst case in standard inode creating
	 * transaction
	 */
	if (owner) {
		inode->i_mode = mode;
		i_uid_write(inode, owner[0]);
		i_gid_write(inode, owner[1]);
	} else if (test_opt(sb, GRPID)) {
		inode->i_mode = mode;
		inode_fsuid_set(inode, idmap);
		inode->i_gid = dir->i_gid;
	} else
		inode_init_owner(idmap, inode, dir, mode);

	if (ecfs_has_feature_project(sb) &&
	    ecfs_test_inode_flag(dir, ECFS_INODE_PROJINHERIT))
		ei->i_projid = ECFS_I(dir)->i_projid;
	else
		ei->i_projid = make_kprojid(&init_user_ns, ECFS_DEF_PROJID);

	if (!(i_flags & ECFS_EA_INODE_FL)) {
		err = fscrypt_prepare_new_inode(dir, inode, &encrypt);
		if (err)
			goto out;
	}

	err = dquot_initialize(inode);
	if (err)
		goto out;

	if (!handle && sbi->s_journal && !(i_flags & ECFS_EA_INODE_FL)) {
		ret2 = ecfs_xattr_credits_for_new_inode(dir, mode, encrypt);
		if (ret2 < 0) {
			err = ret2;
			goto out;
		}
		nblocks += ret2;
	}

	if (!goal)
		goal = sbi->s_inode_goal;

	if (goal && goal <= le32_to_cpu(sbi->s_es->s_inodes_count)) {
		group = (goal - 1) / ECFS_INODES_PER_GROUP(sb);
		ino = (goal - 1) % ECFS_INODES_PER_GROUP(sb);
		ret2 = 0;
		goto got_group;
	}

	if (S_ISDIR(mode))
		ret2 = find_group_orlov(sb, dir, &group, mode, qstr);
	else
		ret2 = find_group_other(sb, dir, &group, mode);

got_group:
	ECFS_I(dir)->i_last_alloc_group = group;
	err = -ENOSPC;
	if (ret2 == -1)
		goto out;

	/*
	 * Normally we will only go through one pass of this loop,
	 * unless we get unlucky and it turns out the group we selected
	 * had its last inode grabbed by someone else.
	 */
	for (i = 0; i < ngroups; i++, ino = 0) {
		err = -EIO;

		gdp = ecfs_get_group_desc(sb, group, &group_desc_bh);
		if (!gdp)
			goto out;

		/*
		 * Check free inodes count before loading bitmap.
		 */
		if (ecfs_free_inodes_count(sb, gdp) == 0)
			goto next_group;

		if (!(sbi->s_mount_state & ECFS_FC_REPLAY)) {
			grp = ecfs_get_group_info(sb, group);
			/*
			 * Skip groups with already-known suspicious inode
			 * tables
			 */
			if (!grp || ECFS_MB_GRP_IBITMAP_CORRUPT(grp))
				goto next_group;
		}

		brelse(inode_bitmap_bh);
		inode_bitmap_bh = ecfs_read_inode_bitmap(sb, group);
		/* Skip groups with suspicious inode tables */
		if (IS_ERR(inode_bitmap_bh)) {
			inode_bitmap_bh = NULL;
			goto next_group;
		}
		if (!(sbi->s_mount_state & ECFS_FC_REPLAY) &&
		    ECFS_MB_GRP_IBITMAP_CORRUPT(grp))
			goto next_group;

		ret2 = find_inode_bit(sb, group, inode_bitmap_bh, &ino);
		if (!ret2)
			goto next_group;

		if (group == 0 && (ino + 1) < ECFS_FIRST_INO(sb)) {
			ecfs_error(sb, "reserved inode found cleared - "
				   "inode=%lu", ino + 1);
			ecfs_mark_group_bitmap_corrupted(sb, group,
					ECFS_GROUP_INFO_IBITMAP_CORRUPT);
			goto next_group;
		}

		if ((!(sbi->s_mount_state & ECFS_FC_REPLAY)) && !handle) {
			BUG_ON(nblocks <= 0);
			handle = __ecfs_journal_start_sb(NULL, dir->i_sb,
				 line_no, handle_type, nblocks, 0,
				 ecfs_trans_default_revoke_credits(sb));
			if (IS_ERR(handle)) {
				err = PTR_ERR(handle);
				ecfs_std_error(sb, err);
				goto out;
			}
		}
		BUFFER_TRACE(inode_bitmap_bh, "get_write_access");
		err = ecfs_journal_get_write_access(handle, sb, inode_bitmap_bh,
						    ECFS_JTR_NONE);
		if (err) {
			ecfs_std_error(sb, err);
			goto out;
		}
		ecfs_lock_group(sb, group);
		ret2 = ecfs_test_and_set_bit(ino, inode_bitmap_bh->b_data);
		if (ret2) {
			/* Someone already took the bit. Repeat the search
			 * with lock held.
			 */
			ret2 = find_inode_bit(sb, group, inode_bitmap_bh, &ino);
			if (ret2) {
				ecfs_set_bit(ino, inode_bitmap_bh->b_data);
				ret2 = 0;
			} else {
				ret2 = 1; /* we didn't grab the inode */
			}
		}
		ecfs_unlock_group(sb, group);
		ino++;		/* the inode bitmap is zero-based */
		if (!ret2)
			goto got; /* we grabbed the inode! */

next_group:
		if (++group == ngroups)
			group = 0;
	}
	err = -ENOSPC;
	goto out;

got:
	BUFFER_TRACE(inode_bitmap_bh, "call ecfs_handle_dirty_metadata");
	err = ecfs_handle_dirty_metadata(handle, NULL, inode_bitmap_bh);
	if (err) {
		ecfs_std_error(sb, err);
		goto out;
	}

	BUFFER_TRACE(group_desc_bh, "get_write_access");
	err = ecfs_journal_get_write_access(handle, sb, group_desc_bh,
					    ECFS_JTR_NONE);
	if (err) {
		ecfs_std_error(sb, err);
		goto out;
	}

	/* We may have to initialize the block bitmap if it isn't already */
	if (ecfs_has_group_desc_csum(sb) &&
	    gdp->bg_flags & cpu_to_le16(ECFS_BG_BLOCK_UNINIT)) {
		struct buffer_head *block_bitmap_bh;

		block_bitmap_bh = ecfs_read_block_bitmap(sb, group);
		if (IS_ERR(block_bitmap_bh)) {
			err = PTR_ERR(block_bitmap_bh);
			goto out;
		}
		BUFFER_TRACE(block_bitmap_bh, "get block bitmap access");
		err = ecfs_journal_get_write_access(handle, sb, block_bitmap_bh,
						    ECFS_JTR_NONE);
		if (err) {
			brelse(block_bitmap_bh);
			ecfs_std_error(sb, err);
			goto out;
		}

		BUFFER_TRACE(block_bitmap_bh, "dirty block bitmap");
		err = ecfs_handle_dirty_metadata(handle, NULL, block_bitmap_bh);

		/* recheck and clear flag under lock if we still need to */
		ecfs_lock_group(sb, group);
		if (ecfs_has_group_desc_csum(sb) &&
		    (gdp->bg_flags & cpu_to_le16(ECFS_BG_BLOCK_UNINIT))) {
			gdp->bg_flags &= cpu_to_le16(~ECFS_BG_BLOCK_UNINIT);
			ecfs_free_group_clusters_set(sb, gdp,
				ecfs_free_clusters_after_init(sb, group, gdp));
			ecfs_block_bitmap_csum_set(sb, gdp, block_bitmap_bh);
			ecfs_group_desc_csum_set(sb, group, gdp);
		}
		ecfs_unlock_group(sb, group);
		brelse(block_bitmap_bh);

		if (err) {
			ecfs_std_error(sb, err);
			goto out;
		}
	}

	/* Update the relevant bg descriptor fields */
	if (ecfs_has_group_desc_csum(sb)) {
		int free;
		struct ecfs_group_info *grp = NULL;

		if (!(sbi->s_mount_state & ECFS_FC_REPLAY)) {
			grp = ecfs_get_group_info(sb, group);
			if (!grp) {
				err = -EFSCORRUPTED;
				goto out;
			}
			down_read(&grp->alloc_sem); /*
						     * protect vs itable
						     * lazyinit
						     */
		}
		ecfs_lock_group(sb, group); /* while we modify the bg desc */
		free = ECFS_INODES_PER_GROUP(sb) -
			ecfs_itable_unused_count(sb, gdp);
		if (gdp->bg_flags & cpu_to_le16(ECFS_BG_INODE_UNINIT)) {
			gdp->bg_flags &= cpu_to_le16(~ECFS_BG_INODE_UNINIT);
			free = 0;
		}
		/*
		 * Check the relative inode number against the last used
		 * relative inode number in this group. if it is greater
		 * we need to update the bg_itable_unused count
		 */
		if (ino > free)
			ecfs_itable_unused_set(sb, gdp,
					(ECFS_INODES_PER_GROUP(sb) - ino));
		if (!(sbi->s_mount_state & ECFS_FC_REPLAY))
			up_read(&grp->alloc_sem);
	} else {
		ecfs_lock_group(sb, group);
	}

	ecfs_free_inodes_set(sb, gdp, ecfs_free_inodes_count(sb, gdp) - 1);
	if (S_ISDIR(mode)) {
		ecfs_used_dirs_set(sb, gdp, ecfs_used_dirs_count(sb, gdp) + 1);
		if (sbi->s_log_groups_per_flex) {
			ecfs_group_t f = ecfs_flex_group(sbi, group);

			atomic_inc(&sbi_array_rcu_deref(sbi, s_flex_groups,
							f)->used_dirs);
		}
	}
	if (ecfs_has_group_desc_csum(sb)) {
		ecfs_inode_bitmap_csum_set(sb, gdp, inode_bitmap_bh);
		ecfs_group_desc_csum_set(sb, group, gdp);
	}
	ecfs_unlock_group(sb, group);

	BUFFER_TRACE(group_desc_bh, "call ecfs_handle_dirty_metadata");
	err = ecfs_handle_dirty_metadata(handle, NULL, group_desc_bh);
	if (err) {
		ecfs_std_error(sb, err);
		goto out;
	}

	percpu_counter_dec(&sbi->s_freeinodes_counter);
	if (S_ISDIR(mode))
		percpu_counter_inc(&sbi->s_dirs_counter);

	if (sbi->s_log_groups_per_flex) {
		flex_group = ecfs_flex_group(sbi, group);
		atomic_dec(&sbi_array_rcu_deref(sbi, s_flex_groups,
						flex_group)->free_inodes);
	}

	inode->i_ino = ino + group * ECFS_INODES_PER_GROUP(sb); /*to be updated to use node id and disk id here*/
	/* This is the optimal IO size (for stat), not the fs block size */
	inode->i_blocks = 0;
	simple_inode_init_ts(inode);
	ei->i_crtime = inode_get_mtime(inode);

	memset(ei->i_data, 0, sizeof(ei->i_data));
	ei->i_dir_start_lookup = 0;
	ei->i_disksize = 0;

	/* Don't inherit extent flag from directory, amongst others. */
	ei->i_flags =
		ecfs_mask_flags(mode, ECFS_I(dir)->i_flags & ECFS_FL_INHERITED);
	ei->i_flags |= i_flags;
	ei->i_file_acl = 0;
	ei->i_dtime = 0;
	ei->i_block_group = group;
	ei->i_last_alloc_group = ~0;

	ecfs_set_inode_flags(inode, true);
	if (IS_DIRSYNC(inode))
		ecfs_handle_sync(handle);
	if (insert_inode_locked(inode) < 0) {
		/*
		 * Likely a bitmap corruption causing inode to be allocated
		 * twice.
		 */
		err = -EIO;
		ecfs_error(sb, "failed to insert inode %lu: doubly allocated?",
			   inode->i_ino);
		ecfs_mark_group_bitmap_corrupted(sb, group,
					ECFS_GROUP_INFO_IBITMAP_CORRUPT);
		goto out;
	}
	inode->i_generation = get_random_u32();

	/* Precompute checksum seed for inode metadata */
	if (ecfs_has_feature_metadata_csum(sb)) {
		__u32 csum;
		__le64 inum = cpu_to_le64(inode->i_ino);
		__le32 gen = cpu_to_le32(inode->i_generation);
		csum = ecfs_chksum(sbi->s_csum_seed, (__u8 *)&inum,
				   sizeof(inum));
		ei->i_csum_seed = ecfs_chksum(csum, (__u8 *)&gen, sizeof(gen));
	}

	ecfs_clear_state_flags(ei); /* Only relevant on 32-bit archs */
	ecfs_set_inode_state(inode, ECFS_STATE_NEW);

	ei->i_extra_isize = sbi->s_want_extra_isize;
	ei->i_inline_off = 0;
	if (ecfs_has_feature_inline_data(sb) &&
	    (!(ei->i_flags & (ECFS_DAX_FL|ECFS_EA_INODE_FL)) || S_ISDIR(mode)))
		ecfs_set_inode_state(inode, ECFS_STATE_MAY_INLINE_DATA);
	ret = inode;
	err = dquot_alloc_inode(inode);
	if (err)
		goto fail_drop;

	/*
	 * Since the encryption xattr will always be unique, create it first so
	 * that it's less likely to end up in an external xattr block and
	 * prevent its deduplication.
	 */
	if (encrypt) {
		err = fscrypt_set_context(inode, handle);
		if (err)
			goto fail_free_drop;
	}

	if (!(ei->i_flags & ECFS_EA_INODE_FL)) {
		err = ecfs_init_acl(handle, inode, dir);
		if (err)
			goto fail_free_drop;

		err = ecfs_init_security(handle, inode, dir, qstr);
		if (err)
			goto fail_free_drop;
	}

	if (ecfs_has_feature_extents(sb)) {
		/* set extent flag only for directory, file and normal symlink*/
		if (S_ISDIR(mode) || S_ISREG(mode) || S_ISLNK(mode)) {
			ecfs_set_inode_flag(inode, ECFS_INODE_EXTENTS);
			ecfs_ext_tree_init(handle, inode);
		}
	}

	ecfs_set_inode_mapping_order(inode);

	ecfs_update_inode_fsync_trans(handle, inode, 1);

	err = ecfs_mark_inode_dirty(handle, inode);
	if (err) {
		ecfs_std_error(sb, err);
		goto fail_free_drop;
	}

	ecfs_debug("allocating inode %lu\n", inode->i_ino);
	trace_ecfs_allocate_inode(inode, dir, mode);
	brelse(inode_bitmap_bh);
	return ret;

fail_free_drop:
	dquot_free_inode(inode);
fail_drop:
	clear_nlink(inode);
	unlock_new_inode(inode);
out:
	dquot_drop(inode);
	inode->i_flags |= S_NOQUOTA;
	iput(inode);
	brelse(inode_bitmap_bh);
	return ERR_PTR(err);
}

/* Verify that we are loading a valid orphan from disk */
struct inode *ecfs_orphan_get(struct super_block *sb, unsigned long ino)
{
	unsigned long max_ino = le32_to_cpu(ECFS_SB(sb)->s_es->s_inodes_count);
	ecfs_group_t block_group;
	int bit;
	struct buffer_head *bitmap_bh = NULL;
	struct inode *inode = NULL;
	int err = -EFSCORRUPTED;

	if (ino < ECFS_FIRST_INO(sb) || ino > max_ino)
		goto bad_orphan;

	block_group = (ino - 1) / ECFS_INODES_PER_GROUP(sb);
	bit = (ino - 1) % ECFS_INODES_PER_GROUP(sb);
	bitmap_bh = ecfs_read_inode_bitmap(sb, block_group);
	if (IS_ERR(bitmap_bh))
		return ERR_CAST(bitmap_bh);

	/* Having the inode bit set should be a 100% indicator that this
	 * is a valid orphan (no e2fsck run on fs).  Orphans also include
	 * inodes that were being truncated, so we can't check i_nlink==0.
	 */
	if (!ecfs_test_bit(bit, bitmap_bh->b_data))
		goto bad_orphan;

	inode = ecfs_iget(sb, ino, ECFS_IGET_NORMAL);
	if (IS_ERR(inode)) {
		err = PTR_ERR(inode);
		ecfs_error_err(sb, -err,
			       "couldn't read orphan inode %lu (err %d)",
			       ino, err);
		brelse(bitmap_bh);
		return inode;
	}

	/*
	 * If the orphans has i_nlinks > 0 then it should be able to
	 * be truncated, otherwise it won't be removed from the orphan
	 * list during processing and an infinite loop will result.
	 * Similarly, it must not be a bad inode.
	 */
	if ((inode->i_nlink && !ecfs_can_truncate(inode)) ||
	    is_bad_inode(inode))
		goto bad_orphan;

	if (NEXT_ORPHAN(inode) > max_ino)
		goto bad_orphan;
	brelse(bitmap_bh);
	return inode;

bad_orphan:
	ecfs_error(sb, "bad orphan inode %lu", ino);
	if (bitmap_bh)
		printk(KERN_ERR "ecfs_test_bit(bit=%d, block=%llu) = %d\n",
		       bit, (unsigned long long)bitmap_bh->b_blocknr,
		       ecfs_test_bit(bit, bitmap_bh->b_data));
	if (inode) {
		printk(KERN_ERR "is_bad_inode(inode)=%d\n",
		       is_bad_inode(inode));
		printk(KERN_ERR "NEXT_ORPHAN(inode)=%u\n",
		       NEXT_ORPHAN(inode));
		printk(KERN_ERR "max_ino=%lu\n", max_ino);
		printk(KERN_ERR "i_nlink=%u\n", inode->i_nlink);
		/* Avoid freeing blocks if we got a bad deleted inode */
		if (inode->i_nlink == 0)
			inode->i_blocks = 0;
		iput(inode);
	}
	brelse(bitmap_bh);
	return ERR_PTR(err);
}

unsigned long ecfs_count_free_inodes(struct super_block *sb)
{
	unsigned long desc_count;
	struct ecfs_group_desc *gdp;
	ecfs_group_t i, ngroups = ecfs_get_groups_count(sb);
#ifdef ECFSFS_DEBUG
	struct ecfs_super_block *es;
	unsigned long bitmap_count, x;
	struct buffer_head *bitmap_bh = NULL;

	es = ECFS_SB(sb)->s_es;
	desc_count = 0;
	bitmap_count = 0;
	gdp = NULL;
	for (i = 0; i < ngroups; i++) {
		gdp = ecfs_get_group_desc(sb, i, NULL);
		if (!gdp)
			continue;
		desc_count += ecfs_free_inodes_count(sb, gdp);
		brelse(bitmap_bh);
		bitmap_bh = ecfs_read_inode_bitmap(sb, i);
		if (IS_ERR(bitmap_bh)) {
			bitmap_bh = NULL;
			continue;
		}

		x = ecfs_count_free(bitmap_bh->b_data,
				    ECFS_INODES_PER_GROUP(sb) / 8);
		printk(KERN_DEBUG "group %lu: stored = %d, counted = %lu\n",
			(unsigned long) i, ecfs_free_inodes_count(sb, gdp), x);
		bitmap_count += x;
	}
	brelse(bitmap_bh);
	printk(KERN_DEBUG "ecfs_count_free_inodes: "
	       "stored = %u, computed = %lu, %lu\n",
	       le32_to_cpu(es->s_free_inodes_count), desc_count, bitmap_count);
	return desc_count;
#else
	desc_count = 0;
	for (i = 0; i < ngroups; i++) {
		gdp = ecfs_get_group_desc(sb, i, NULL);
		if (!gdp)
			continue;
		desc_count += ecfs_free_inodes_count(sb, gdp);
		cond_resched();
	}
	return desc_count;
#endif
}

/* Called at mount-time, super-block is locked */
unsigned long ecfs_count_dirs(struct super_block * sb)
{
	unsigned long count = 0;
	ecfs_group_t i, ngroups = ecfs_get_groups_count(sb);

	for (i = 0; i < ngroups; i++) {
		struct ecfs_group_desc *gdp = ecfs_get_group_desc(sb, i, NULL);
		if (!gdp)
			continue;
		count += ecfs_used_dirs_count(sb, gdp);
	}
	return count;
}

/*
 * Zeroes not yet zeroed inode table - just write zeroes through the whole
 * inode table. Must be called without any spinlock held. The only place
 * where it is called from on active part of filesystem is ecfslazyinit
 * thread, so we do not need any special locks, however we have to prevent
 * inode allocation from the current group, so we take alloc_sem lock, to
 * block ecfs_new_inode() until we are finished.
 */
int ecfs_init_inode_table(struct super_block *sb, ecfs_group_t group,
				 int barrier)
{
	struct ecfs_group_info *grp = ecfs_get_group_info(sb, group);
	struct ecfs_sb_info *sbi = ECFS_SB(sb);
	struct ecfs_group_desc *gdp = NULL;
	struct buffer_head *group_desc_bh;
	handle_t *handle;
	ecfs_fsblk_t blk;
	int num, ret = 0, used_blks = 0;
	unsigned long used_inos = 0;

	gdp = ecfs_get_group_desc(sb, group, &group_desc_bh);
	if (!gdp || !grp)
		goto out;

	/*
	 * We do not need to lock this, because we are the only one
	 * handling this flag.
	 */
	if (gdp->bg_flags & cpu_to_le16(ECFS_BG_INODE_ZEROED))
		goto out;

	handle = ecfs_journal_start_sb(sb, ECFS_HT_MISC, 1);
	if (IS_ERR(handle)) {
		ret = PTR_ERR(handle);
		goto out;
	}

	down_write(&grp->alloc_sem);
	/*
	 * If inode bitmap was already initialized there may be some
	 * used inodes so we need to skip blocks with used inodes in
	 * inode table.
	 */
	if (!(gdp->bg_flags & cpu_to_le16(ECFS_BG_INODE_UNINIT))) {
		used_inos = ECFS_INODES_PER_GROUP(sb) -
			    ecfs_itable_unused_count(sb, gdp);
		used_blks = DIV_ROUND_UP(used_inos, sbi->s_inodes_per_block);

		/* Bogus inode unused count? */
		if (used_blks < 0 || used_blks > sbi->s_itb_per_group) {
			ecfs_error(sb, "Something is wrong with group %u: "
				   "used itable blocks: %d; "
				   "itable unused count: %u",
				   group, used_blks,
				   ecfs_itable_unused_count(sb, gdp));
			ret = 1;
			goto err_out;
		}

		used_inos += group * ECFS_INODES_PER_GROUP(sb);
		/*
		 * Are there some uninitialized inodes in the inode table
		 * before the first normal inode?
		 */
		if ((used_blks != sbi->s_itb_per_group) &&
		     (used_inos < ECFS_FIRST_INO(sb))) {
			ecfs_error(sb, "Something is wrong with group %u: "
				   "itable unused count: %u; "
				   "itables initialized count: %ld",
				   group, ecfs_itable_unused_count(sb, gdp),
				   used_inos);
			ret = 1;
			goto err_out;
		}
	}

	blk = ecfs_inode_table(sb, gdp) + used_blks;
	num = sbi->s_itb_per_group - used_blks;

	BUFFER_TRACE(group_desc_bh, "get_write_access");
	ret = ecfs_journal_get_write_access(handle, sb, group_desc_bh,
					    ECFS_JTR_NONE);
	if (ret)
		goto err_out;

	/*
	 * Skip zeroout if the inode table is full. But we set the ZEROED
	 * flag anyway, because obviously, when it is full it does not need
	 * further zeroing.
	 */
	if (unlikely(num == 0))
		goto skip_zeroout;

	ecfs_debug("going to zero out inode table in group %d\n",
		   group);
	ret = sb_issue_zeroout(sb, blk, num, GFP_NOFS);
	if (ret < 0)
		goto err_out;
	if (barrier)
		blkdev_issue_flush(sb->s_bdev);

skip_zeroout:
	ecfs_lock_group(sb, group);
	gdp->bg_flags |= cpu_to_le16(ECFS_BG_INODE_ZEROED);
	ecfs_group_desc_csum_set(sb, group, gdp);
	ecfs_unlock_group(sb, group);

	BUFFER_TRACE(group_desc_bh,
		     "call ecfs_handle_dirty_metadata");
	ret = ecfs_handle_dirty_metadata(handle, NULL,
					 group_desc_bh);

err_out:
	up_write(&grp->alloc_sem);
	ecfs_journal_stop(handle);
out:
	return ret;
}
