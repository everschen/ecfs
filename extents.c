// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (c) 2003-2006, Cluster File Systems, Inc, info@clusterfs.com
 * Written by Alex Tomas <alex@clusterfs.com>
 *
 * Architecture independence:
 *   Copyright (c) 2005, Bull S.A.
 *   Written by Pierre Peiffer <pierre.peiffer@bull.net>
 */

/*
 * Extents support for ECFS
 *
 * TODO:
 *   - ecfs*_error() should be used in some situations
 *   - analyze all BUG()/BUG_ON(), use -EIO where appropriate
 *   - smart tree reduction
 */

#include <linux/fs.h>
#include <linux/time.h>
#include <linux/jbd2.h>
#include <linux/highuid.h>
#include <linux/pagemap.h>
#include <linux/quotaops.h>
#include <linux/string.h>
#include <linux/slab.h>
#include <linux/uaccess.h>
#include <linux/fiemap.h>
#include <linux/iomap.h>
#include <linux/sched/mm.h>
#include "ecfs_jbd2.h"
#include "ecfs_extents.h"
#include "xattr.h"

#include <trace/events/ecfs.h>

/*
 * used by extent splitting.
 */
#define ECFS_EXT_MAY_ZEROOUT	0x1  /* safe to zeroout if split fails \
					due to ENOSPC */
#define ECFS_EXT_MARK_UNWRIT1	0x2  /* mark first half unwritten */
#define ECFS_EXT_MARK_UNWRIT2	0x4  /* mark second half unwritten */

#define ECFS_EXT_DATA_VALID1	0x8  /* first half contains valid data */
#define ECFS_EXT_DATA_VALID2	0x10 /* second half contains valid data */

static __le32 ecfs_extent_block_csum(struct inode *inode,
				     struct ecfs_extent_header *eh)
{
	struct ecfs_inode_info *ei = ECFS_I(inode);
	__u32 csum;

	csum = ecfs_chksum(ei->i_csum_seed, (__u8 *)eh,
			   ECFS_EXTENT_TAIL_OFFSET(eh));
	return cpu_to_le32(csum);
}

static int ecfs_extent_block_csum_verify(struct inode *inode,
					 struct ecfs_extent_header *eh)
{
	struct ecfs_extent_tail *et;

	if (!ecfs_has_feature_metadata_csum(inode->i_sb))
		return 1;

	et = find_ecfs_extent_tail(eh);
	if (et->et_checksum != ecfs_extent_block_csum(inode, eh))
		return 0;
	return 1;
}

static void ecfs_extent_block_csum_set(struct inode *inode,
				       struct ecfs_extent_header *eh)
{
	struct ecfs_extent_tail *et;

	if (!ecfs_has_feature_metadata_csum(inode->i_sb))
		return;

	et = find_ecfs_extent_tail(eh);
	et->et_checksum = ecfs_extent_block_csum(inode, eh);
}

static struct ecfs_ext_path *ecfs_split_extent_at(handle_t *handle,
						  struct inode *inode,
						  struct ecfs_ext_path *path,
						  ecfs_lblk_t split,
						  int split_flag, int flags);

static int ecfs_ext_trunc_restart_fn(struct inode *inode, int *dropped)
{
	/*
	 * Drop i_data_sem to avoid deadlock with ecfs_map_blocks.  At this
	 * moment, get_block can be called only for blocks inside i_size since
	 * page cache has been already dropped and writes are blocked by
	 * i_rwsem. So we can safely drop the i_data_sem here.
	 */
	BUG_ON(ECFS_JOURNAL(inode) == NULL);
	ecfs_discard_preallocations(inode);
	up_write(&ECFS_I(inode)->i_data_sem);
	*dropped = 1;
	return 0;
}

static inline void ecfs_ext_path_brelse(struct ecfs_ext_path *path)
{
	brelse(path->p_bh);
	path->p_bh = NULL;
}

static void ecfs_ext_drop_refs(struct ecfs_ext_path *path)
{
	int depth, i;

	if (IS_ERR_OR_NULL(path))
		return;
	depth = path->p_depth;
	for (i = 0; i <= depth; i++, path++)
		ecfs_ext_path_brelse(path);
}

void ecfs_free_ext_path(struct ecfs_ext_path *path)
{
	if (IS_ERR_OR_NULL(path))
		return;
	ecfs_ext_drop_refs(path);
	kfree(path);
}

/*
 * Make sure 'handle' has at least 'check_cred' credits. If not, restart
 * transaction with 'restart_cred' credits. The function drops i_data_sem
 * when restarting transaction and gets it after transaction is restarted.
 *
 * The function returns 0 on success, 1 if transaction had to be restarted,
 * and < 0 in case of fatal error.
 */
int ecfs_datasem_ensure_credits(handle_t *handle, struct inode *inode,
				int check_cred, int restart_cred,
				int revoke_cred)
{
	int ret;
	int dropped = 0;

	ret = ecfs_journal_ensure_credits_fn(handle, check_cred, restart_cred,
		revoke_cred, ecfs_ext_trunc_restart_fn(inode, &dropped));
	if (dropped)
		down_write(&ECFS_I(inode)->i_data_sem);
	return ret;
}

/*
 * could return:
 *  - EROFS
 *  - ENOMEM
 */
static int ecfs_ext_get_access(handle_t *handle, struct inode *inode,
				struct ecfs_ext_path *path)
{
	int err = 0;

	if (path->p_bh) {
		/* path points to block */
		BUFFER_TRACE(path->p_bh, "get_write_access");
		err = ecfs_journal_get_write_access(handle, inode->i_sb,
						    path->p_bh, ECFS_JTR_NONE);
		/*
		 * The extent buffer's verified bit will be set again in
		 * __ecfs_ext_dirty(). We could leave an inconsistent
		 * buffer if the extents updating procudure break off du
		 * to some error happens, force to check it again.
		 */
		if (!err)
			clear_buffer_verified(path->p_bh);
	}
	/* path points to leaf/index in inode body */
	/* we use in-core data, no need to protect them */
	return err;
}

/*
 * could return:
 *  - EROFS
 *  - ENOMEM
 *  - EIO
 */
static int __ecfs_ext_dirty(const char *where, unsigned int line,
			    handle_t *handle, struct inode *inode,
			    struct ecfs_ext_path *path)
{
	int err;

	WARN_ON(!rwsem_is_locked(&ECFS_I(inode)->i_data_sem));
	if (path->p_bh) {
		ecfs_extent_block_csum_set(inode, ext_block_hdr(path->p_bh));
		/* path points to block */
		err = __ecfs_handle_dirty_metadata(where, line, handle,
						   inode, path->p_bh);
		/* Extents updating done, re-set verified flag */
		if (!err)
			set_buffer_verified(path->p_bh);
	} else {
		/* path points to leaf/index in inode body */
		err = ecfs_mark_inode_dirty(handle, inode);
	}
	return err;
}

#define ecfs_ext_dirty(handle, inode, path) \
		__ecfs_ext_dirty(__func__, __LINE__, (handle), (inode), (path))

static ecfs_fsblk_t ecfs_ext_find_goal(struct inode *inode,
			      struct ecfs_ext_path *path,
			      ecfs_lblk_t block)
{
	if (path) {
		int depth = path->p_depth;
		struct ecfs_extent *ex;

		/*
		 * Try to predict block placement assuming that we are
		 * filling in a file which will eventually be
		 * non-sparse --- i.e., in the case of libbfd writing
		 * an ELF object sections out-of-order but in a way
		 * the eventually results in a contiguous object or
		 * executable file, or some database extending a table
		 * space file.  However, this is actually somewhat
		 * non-ideal if we are writing a sparse file such as
		 * qemu or KVM writing a raw image file that is going
		 * to stay fairly sparse, since it will end up
		 * fragmenting the file system's free space.  Maybe we
		 * should have some hueristics or some way to allow
		 * userspace to pass a hint to file system,
		 * especially if the latter case turns out to be
		 * common.
		 */
		ex = path[depth].p_ext;
		if (ex) {
			ecfs_fsblk_t ext_pblk = ecfs_ext_pblock(ex);
			ecfs_lblk_t ext_block = le32_to_cpu(ex->ee_block);

			if (block > ext_block)
				return ext_pblk + (block - ext_block);
			else
				return ext_pblk - (ext_block - block);
		}

		/* it looks like index is empty;
		 * try to find starting block from index itself */
		if (path[depth].p_bh)
			return path[depth].p_bh->b_blocknr;
	}

	/* OK. use inode's group */
	return ecfs_inode_to_goal_block(inode);
}

/*
 * Allocation for a meta data block
 */
static ecfs_fsblk_t
ecfs_ext_new_meta_block(handle_t *handle, struct inode *inode,
			struct ecfs_ext_path *path,
			struct ecfs_extent *ex, int *err, unsigned int flags)
{
	ecfs_fsblk_t goal, newblock;

	goal = ecfs_ext_find_goal(inode, path, le32_to_cpu(ex->ee_block));
	newblock = ecfs_new_meta_blocks(handle, inode, goal, flags,
					NULL, err);
	return newblock;
}

static inline int ecfs_ext_space_block(struct inode *inode, int check)
{
	int size;

	size = (inode->i_sb->s_blocksize - sizeof(struct ecfs_extent_header))
			/ sizeof(struct ecfs_extent);
#ifdef AGGRESSIVE_TEST
	if (!check && size > 6)
		size = 6;
#endif
	return size;
}

static inline int ecfs_ext_space_block_idx(struct inode *inode, int check)
{
	int size;

	size = (inode->i_sb->s_blocksize - sizeof(struct ecfs_extent_header))
			/ sizeof(struct ecfs_extent_idx);
#ifdef AGGRESSIVE_TEST
	if (!check && size > 5)
		size = 5;
#endif
	return size;
}

static inline int ecfs_ext_space_root(struct inode *inode, int check)
{
	int size;

	size = sizeof(ECFS_I(inode)->i_data);
	size -= sizeof(struct ecfs_extent_header);
	size /= sizeof(struct ecfs_extent);
#ifdef AGGRESSIVE_TEST
	if (!check && size > 3)
		size = 3;
#endif
	return size;
}

static inline int ecfs_ext_space_root_idx(struct inode *inode, int check)
{
	int size;

	size = sizeof(ECFS_I(inode)->i_data);
	size -= sizeof(struct ecfs_extent_header);
	size /= sizeof(struct ecfs_extent_idx);
#ifdef AGGRESSIVE_TEST
	if (!check && size > 4)
		size = 4;
#endif
	return size;
}

static inline struct ecfs_ext_path *
ecfs_force_split_extent_at(handle_t *handle, struct inode *inode,
			   struct ecfs_ext_path *path, ecfs_lblk_t lblk,
			   int nofail)
{
	int unwritten = ecfs_ext_is_unwritten(path[path->p_depth].p_ext);
	int flags = ECFS_EX_NOCACHE | ECFS_GET_BLOCKS_PRE_IO;

	if (nofail)
		flags |= ECFS_GET_BLOCKS_METADATA_NOFAIL | ECFS_EX_NOFAIL;

	return ecfs_split_extent_at(handle, inode, path, lblk, unwritten ?
			ECFS_EXT_MARK_UNWRIT1|ECFS_EXT_MARK_UNWRIT2 : 0,
			flags);
}

static int
ecfs_ext_max_entries(struct inode *inode, int depth)
{
	int max;

	if (depth == ext_depth(inode)) {
		if (depth == 0)
			max = ecfs_ext_space_root(inode, 1);
		else
			max = ecfs_ext_space_root_idx(inode, 1);
	} else {
		if (depth == 0)
			max = ecfs_ext_space_block(inode, 1);
		else
			max = ecfs_ext_space_block_idx(inode, 1);
	}

	return max;
}

static int ecfs_valid_extent(struct inode *inode, struct ecfs_extent *ext)
{
	ecfs_fsblk_t block = ecfs_ext_pblock(ext);
	int len = ecfs_ext_get_actual_len(ext);
	ecfs_lblk_t lblock = le32_to_cpu(ext->ee_block);

	/*
	 * We allow neither:
	 *  - zero length
	 *  - overflow/wrap-around
	 */
	if (lblock + len <= lblock)
		return 0;
	return ecfs_inode_block_valid(inode, block, len);
}

static int ecfs_valid_extent_idx(struct inode *inode,
				struct ecfs_extent_idx *ext_idx)
{
	ecfs_fsblk_t block = ecfs_idx_pblock(ext_idx);

	return ecfs_inode_block_valid(inode, block, 1);
}

static int ecfs_valid_extent_entries(struct inode *inode,
				     struct ecfs_extent_header *eh,
				     ecfs_lblk_t lblk, ecfs_fsblk_t *pblk,
				     int depth)
{
	unsigned short entries;
	ecfs_lblk_t lblock = 0;
	ecfs_lblk_t cur = 0;

	if (eh->eh_entries == 0)
		return 1;

	entries = le16_to_cpu(eh->eh_entries);

	if (depth == 0) {
		/* leaf entries */
		struct ecfs_extent *ext = EXT_FIRST_EXTENT(eh);

		/*
		 * The logical block in the first entry should equal to
		 * the number in the index block.
		 */
		if (depth != ext_depth(inode) &&
		    lblk != le32_to_cpu(ext->ee_block))
			return 0;
		while (entries) {
			if (!ecfs_valid_extent(inode, ext))
				return 0;

			/* Check for overlapping extents */
			lblock = le32_to_cpu(ext->ee_block);
			if (lblock < cur) {
				*pblk = ecfs_ext_pblock(ext);
				return 0;
			}
			cur = lblock + ecfs_ext_get_actual_len(ext);
			ext++;
			entries--;
		}
	} else {
		struct ecfs_extent_idx *ext_idx = EXT_FIRST_INDEX(eh);

		/*
		 * The logical block in the first entry should equal to
		 * the number in the parent index block.
		 */
		if (depth != ext_depth(inode) &&
		    lblk != le32_to_cpu(ext_idx->ei_block))
			return 0;
		while (entries) {
			if (!ecfs_valid_extent_idx(inode, ext_idx))
				return 0;

			/* Check for overlapping index extents */
			lblock = le32_to_cpu(ext_idx->ei_block);
			if (lblock < cur) {
				*pblk = ecfs_idx_pblock(ext_idx);
				return 0;
			}
			ext_idx++;
			entries--;
			cur = lblock + 1;
		}
	}
	return 1;
}

static int __ecfs_ext_check(const char *function, unsigned int line,
			    struct inode *inode, struct ecfs_extent_header *eh,
			    int depth, ecfs_fsblk_t pblk, ecfs_lblk_t lblk)
{
	const char *error_msg;
	int max = 0, err = -EFSCORRUPTED;

	if (unlikely(eh->eh_magic != ECFS_EXT_MAGIC)) {
		error_msg = "invalid magic";
		goto corrupted;
	}
	if (unlikely(le16_to_cpu(eh->eh_depth) != depth)) {
		error_msg = "unexpected eh_depth";
		goto corrupted;
	}
	if (unlikely(eh->eh_max == 0)) {
		error_msg = "invalid eh_max";
		goto corrupted;
	}
	max = ecfs_ext_max_entries(inode, depth);
	if (unlikely(le16_to_cpu(eh->eh_max) > max)) {
		error_msg = "too large eh_max";
		goto corrupted;
	}
	if (unlikely(le16_to_cpu(eh->eh_entries) > le16_to_cpu(eh->eh_max))) {
		error_msg = "invalid eh_entries";
		goto corrupted;
	}
	if (unlikely((eh->eh_entries == 0) && (depth > 0))) {
		error_msg = "eh_entries is 0 but eh_depth is > 0";
		goto corrupted;
	}
	if (!ecfs_valid_extent_entries(inode, eh, lblk, &pblk, depth)) {
		error_msg = "invalid extent entries";
		goto corrupted;
	}
	if (unlikely(depth > 32)) {
		error_msg = "too large eh_depth";
		goto corrupted;
	}
	/* Verify checksum on non-root extent tree nodes */
	if (ext_depth(inode) != depth &&
	    !ecfs_extent_block_csum_verify(inode, eh)) {
		error_msg = "extent tree corrupted";
		err = -EFSBADCRC;
		goto corrupted;
	}
	return 0;

corrupted:
	ecfs_error_inode_err(inode, function, line, 0, -err,
			     "pblk %llu bad header/extent: %s - magic %x, "
			     "entries %u, max %u(%u), depth %u(%u)",
			     (unsigned long long) pblk, error_msg,
			     le16_to_cpu(eh->eh_magic),
			     le16_to_cpu(eh->eh_entries),
			     le16_to_cpu(eh->eh_max),
			     max, le16_to_cpu(eh->eh_depth), depth);
	return err;
}

#define ecfs_ext_check(inode, eh, depth, pblk)			\
	__ecfs_ext_check(__func__, __LINE__, (inode), (eh), (depth), (pblk), 0)

int ecfs_ext_check_inode(struct inode *inode)
{
	return ecfs_ext_check(inode, ext_inode_hdr(inode), ext_depth(inode), 0);
}

static void ecfs_cache_extents(struct inode *inode,
			       struct ecfs_extent_header *eh)
{
	struct ecfs_extent *ex = EXT_FIRST_EXTENT(eh);
	ecfs_lblk_t prev = 0;
	int i;

	for (i = le16_to_cpu(eh->eh_entries); i > 0; i--, ex++) {
		unsigned int status = EXTENT_STATUS_WRITTEN;
		ecfs_lblk_t lblk = le32_to_cpu(ex->ee_block);
		int len = ecfs_ext_get_actual_len(ex);

		if (prev && (prev != lblk))
			ecfs_es_cache_extent(inode, prev, lblk - prev, ~0,
					     EXTENT_STATUS_HOLE);

		if (ecfs_ext_is_unwritten(ex))
			status = EXTENT_STATUS_UNWRITTEN;
		ecfs_es_cache_extent(inode, lblk, len,
				     ecfs_ext_pblock(ex), status);
		prev = lblk + len;
	}
}

static struct buffer_head *
__read_extent_tree_block(const char *function, unsigned int line,
			 struct inode *inode, struct ecfs_extent_idx *idx,
			 int depth, int flags)
{
	struct buffer_head		*bh;
	int				err;
	gfp_t				gfp_flags = __GFP_MOVABLE | GFP_NOFS;
	ecfs_fsblk_t			pblk;

	if (flags & ECFS_EX_NOFAIL)
		gfp_flags |= __GFP_NOFAIL;

	pblk = ecfs_idx_pblock(idx);
	bh = sb_getblk_gfp(inode->i_sb, pblk, gfp_flags);
	if (unlikely(!bh))
		return ERR_PTR(-ENOMEM);

	if (!bh_uptodate_or_lock(bh)) {
		trace_ecfs_ext_load_extent(inode, pblk, _RET_IP_);
		err = ecfs_read_bh(bh, 0, NULL, false);
		if (err < 0)
			goto errout;
	}
	if (buffer_verified(bh) && !(flags & ECFS_EX_FORCE_CACHE))
		return bh;
	err = __ecfs_ext_check(function, line, inode, ext_block_hdr(bh),
			       depth, pblk, le32_to_cpu(idx->ei_block));
	if (err)
		goto errout;
	set_buffer_verified(bh);
	/*
	 * If this is a leaf block, cache all of its entries
	 */
	if (!(flags & ECFS_EX_NOCACHE) && depth == 0) {
		struct ecfs_extent_header *eh = ext_block_hdr(bh);
		ecfs_cache_extents(inode, eh);
	}
	return bh;
errout:
	put_bh(bh);
	return ERR_PTR(err);

}

#define read_extent_tree_block(inode, idx, depth, flags)		\
	__read_extent_tree_block(__func__, __LINE__, (inode), (idx),	\
				 (depth), (flags))

/*
 * This function is called to cache a file's extent information in the
 * extent status tree
 */
int ecfs_ext_precache(struct inode *inode)
{
	struct ecfs_inode_info *ei = ECFS_I(inode);
	struct ecfs_ext_path *path = NULL;
	struct buffer_head *bh;
	int i = 0, depth, ret = 0;

	if (!ecfs_test_inode_flag(inode, ECFS_INODE_EXTENTS))
		return 0;	/* not an extent-mapped inode */

	ecfs_check_map_extents_env(inode);

	down_read(&ei->i_data_sem);
	depth = ext_depth(inode);

	/* Don't cache anything if there are no external extent blocks */
	if (!depth) {
		up_read(&ei->i_data_sem);
		return ret;
	}

	path = kcalloc(depth + 1, sizeof(struct ecfs_ext_path),
		       GFP_NOFS);
	if (path == NULL) {
		up_read(&ei->i_data_sem);
		return -ENOMEM;
	}

	path[0].p_hdr = ext_inode_hdr(inode);
	ret = ecfs_ext_check(inode, path[0].p_hdr, depth, 0);
	if (ret)
		goto out;
	path[0].p_idx = EXT_FIRST_INDEX(path[0].p_hdr);
	while (i >= 0) {
		/*
		 * If this is a leaf block or we've reached the end of
		 * the index block, go up
		 */
		if ((i == depth) ||
		    path[i].p_idx > EXT_LAST_INDEX(path[i].p_hdr)) {
			ecfs_ext_path_brelse(path + i);
			i--;
			continue;
		}
		bh = read_extent_tree_block(inode, path[i].p_idx++,
					    depth - i - 1,
					    ECFS_EX_FORCE_CACHE);
		if (IS_ERR(bh)) {
			ret = PTR_ERR(bh);
			break;
		}
		i++;
		path[i].p_bh = bh;
		path[i].p_hdr = ext_block_hdr(bh);
		path[i].p_idx = EXT_FIRST_INDEX(path[i].p_hdr);
	}
	ecfs_set_inode_state(inode, ECFS_STATE_EXT_PRECACHED);
out:
	up_read(&ei->i_data_sem);
	ecfs_free_ext_path(path);
	return ret;
}

#ifdef EXT_DEBUG
static void ecfs_ext_show_path(struct inode *inode, struct ecfs_ext_path *path)
{
	int k, l = path->p_depth;

	ext_debug(inode, "path:");
	for (k = 0; k <= l; k++, path++) {
		if (path->p_idx) {
			ext_debug(inode, "  %d->%llu",
				  le32_to_cpu(path->p_idx->ei_block),
				  ecfs_idx_pblock(path->p_idx));
		} else if (path->p_ext) {
			ext_debug(inode, "  %d:[%d]%d:%llu ",
				  le32_to_cpu(path->p_ext->ee_block),
				  ecfs_ext_is_unwritten(path->p_ext),
				  ecfs_ext_get_actual_len(path->p_ext),
				  ecfs_ext_pblock(path->p_ext));
		} else
			ext_debug(inode, "  []");
	}
	ext_debug(inode, "\n");
}

static void ecfs_ext_show_leaf(struct inode *inode, struct ecfs_ext_path *path)
{
	int depth = ext_depth(inode);
	struct ecfs_extent_header *eh;
	struct ecfs_extent *ex;
	int i;

	if (IS_ERR_OR_NULL(path))
		return;

	eh = path[depth].p_hdr;
	ex = EXT_FIRST_EXTENT(eh);

	ext_debug(inode, "Displaying leaf extents\n");

	for (i = 0; i < le16_to_cpu(eh->eh_entries); i++, ex++) {
		ext_debug(inode, "%d:[%d]%d:%llu ", le32_to_cpu(ex->ee_block),
			  ecfs_ext_is_unwritten(ex),
			  ecfs_ext_get_actual_len(ex), ecfs_ext_pblock(ex));
	}
	ext_debug(inode, "\n");
}

static void ecfs_ext_show_move(struct inode *inode, struct ecfs_ext_path *path,
			ecfs_fsblk_t newblock, int level)
{
	int depth = ext_depth(inode);
	struct ecfs_extent *ex;

	if (depth != level) {
		struct ecfs_extent_idx *idx;
		idx = path[level].p_idx;
		while (idx <= EXT_MAX_INDEX(path[level].p_hdr)) {
			ext_debug(inode, "%d: move %d:%llu in new index %llu\n",
				  level, le32_to_cpu(idx->ei_block),
				  ecfs_idx_pblock(idx), newblock);
			idx++;
		}

		return;
	}

	ex = path[depth].p_ext;
	while (ex <= EXT_MAX_EXTENT(path[depth].p_hdr)) {
		ext_debug(inode, "move %d:%llu:[%d]%d in new leaf %llu\n",
				le32_to_cpu(ex->ee_block),
				ecfs_ext_pblock(ex),
				ecfs_ext_is_unwritten(ex),
				ecfs_ext_get_actual_len(ex),
				newblock);
		ex++;
	}
}

#else
#define ecfs_ext_show_path(inode, path)
#define ecfs_ext_show_leaf(inode, path)
#define ecfs_ext_show_move(inode, path, newblock, level)
#endif

/*
 * ecfs_ext_binsearch_idx:
 * binary search for the closest index of the given block
 * the header must be checked before calling this
 */
static void
ecfs_ext_binsearch_idx(struct inode *inode,
			struct ecfs_ext_path *path, ecfs_lblk_t block)
{
	struct ecfs_extent_header *eh = path->p_hdr;
	struct ecfs_extent_idx *r, *l, *m;


	ext_debug(inode, "binsearch for %u(idx):  ", block);

	l = EXT_FIRST_INDEX(eh) + 1;
	r = EXT_LAST_INDEX(eh);
	while (l <= r) {
		m = l + (r - l) / 2;
		ext_debug(inode, "%p(%u):%p(%u):%p(%u) ", l,
			  le32_to_cpu(l->ei_block), m, le32_to_cpu(m->ei_block),
			  r, le32_to_cpu(r->ei_block));

		if (block < le32_to_cpu(m->ei_block))
			r = m - 1;
		else
			l = m + 1;
	}

	path->p_idx = l - 1;
	ext_debug(inode, "  -> %u->%lld ", le32_to_cpu(path->p_idx->ei_block),
		  ecfs_idx_pblock(path->p_idx));

#ifdef CHECK_BINSEARCH
	{
		struct ecfs_extent_idx *chix, *ix;
		int k;

		chix = ix = EXT_FIRST_INDEX(eh);
		for (k = 0; k < le16_to_cpu(eh->eh_entries); k++, ix++) {
			if (k != 0 && le32_to_cpu(ix->ei_block) <=
			    le32_to_cpu(ix[-1].ei_block)) {
				printk(KERN_DEBUG "k=%d, ix=0x%p, "
				       "first=0x%p\n", k,
				       ix, EXT_FIRST_INDEX(eh));
				printk(KERN_DEBUG "%u <= %u\n",
				       le32_to_cpu(ix->ei_block),
				       le32_to_cpu(ix[-1].ei_block));
			}
			BUG_ON(k && le32_to_cpu(ix->ei_block)
					   <= le32_to_cpu(ix[-1].ei_block));
			if (block < le32_to_cpu(ix->ei_block))
				break;
			chix = ix;
		}
		BUG_ON(chix != path->p_idx);
	}
#endif

}

/*
 * ecfs_ext_binsearch:
 * binary search for closest extent of the given block
 * the header must be checked before calling this
 */
static void
ecfs_ext_binsearch(struct inode *inode,
		struct ecfs_ext_path *path, ecfs_lblk_t block)
{
	struct ecfs_extent_header *eh = path->p_hdr;
	struct ecfs_extent *r, *l, *m;

	if (eh->eh_entries == 0) {
		/*
		 * this leaf is empty:
		 * we get such a leaf in split/add case
		 */
		return;
	}

	ext_debug(inode, "binsearch for %u:  ", block);

	l = EXT_FIRST_EXTENT(eh) + 1;
	r = EXT_LAST_EXTENT(eh);

	while (l <= r) {
		m = l + (r - l) / 2;
		ext_debug(inode, "%p(%u):%p(%u):%p(%u) ", l,
			  le32_to_cpu(l->ee_block), m, le32_to_cpu(m->ee_block),
			  r, le32_to_cpu(r->ee_block));

		if (block < le32_to_cpu(m->ee_block))
			r = m - 1;
		else
			l = m + 1;
	}

	path->p_ext = l - 1;
	ext_debug(inode, "  -> %d:%llu:[%d]%d ",
			le32_to_cpu(path->p_ext->ee_block),
			ecfs_ext_pblock(path->p_ext),
			ecfs_ext_is_unwritten(path->p_ext),
			ecfs_ext_get_actual_len(path->p_ext));

#ifdef CHECK_BINSEARCH
	{
		struct ecfs_extent *chex, *ex;
		int k;

		chex = ex = EXT_FIRST_EXTENT(eh);
		for (k = 0; k < le16_to_cpu(eh->eh_entries); k++, ex++) {
			BUG_ON(k && le32_to_cpu(ex->ee_block)
					  <= le32_to_cpu(ex[-1].ee_block));
			if (block < le32_to_cpu(ex->ee_block))
				break;
			chex = ex;
		}
		BUG_ON(chex != path->p_ext);
	}
#endif

}

void ecfs_ext_tree_init(handle_t *handle, struct inode *inode)
{
	struct ecfs_extent_header *eh;

	eh = ext_inode_hdr(inode);
	eh->eh_depth = 0;
	eh->eh_entries = 0;
	eh->eh_magic = ECFS_EXT_MAGIC;
	eh->eh_max = cpu_to_le16(ecfs_ext_space_root(inode, 0));
	eh->eh_generation = 0;
	ecfs_mark_inode_dirty(handle, inode);
}

struct ecfs_ext_path *
ecfs_find_extent(struct inode *inode, ecfs_lblk_t block,
		 struct ecfs_ext_path *path, int flags)
{
	struct ecfs_extent_header *eh;
	struct buffer_head *bh;
	short int depth, i, ppos = 0;
	int ret;
	gfp_t gfp_flags = GFP_NOFS;

	if (flags & ECFS_EX_NOFAIL)
		gfp_flags |= __GFP_NOFAIL;

	eh = ext_inode_hdr(inode);
	depth = ext_depth(inode);
	if (depth < 0 || depth > ECFS_MAX_EXTENT_DEPTH) {
		ECFS_ERROR_INODE(inode, "inode has invalid extent depth: %d",
				 depth);
		ret = -EFSCORRUPTED;
		goto err;
	}

	if (path) {
		ecfs_ext_drop_refs(path);
		if (depth > path[0].p_maxdepth) {
			kfree(path);
			path = NULL;
		}
	}
	if (!path) {
		/* account possible depth increase */
		path = kcalloc(depth + 2, sizeof(struct ecfs_ext_path),
				gfp_flags);
		if (unlikely(!path))
			return ERR_PTR(-ENOMEM);
		path[0].p_maxdepth = depth + 1;
	}
	path[0].p_hdr = eh;
	path[0].p_bh = NULL;

	i = depth;
	if (!(flags & ECFS_EX_NOCACHE) && depth == 0)
		ecfs_cache_extents(inode, eh);
	/* walk through the tree */
	while (i) {
		ext_debug(inode, "depth %d: num %d, max %d\n",
			  ppos, le16_to_cpu(eh->eh_entries), le16_to_cpu(eh->eh_max));

		ecfs_ext_binsearch_idx(inode, path + ppos, block);
		path[ppos].p_block = ecfs_idx_pblock(path[ppos].p_idx);
		path[ppos].p_depth = i;
		path[ppos].p_ext = NULL;

		bh = read_extent_tree_block(inode, path[ppos].p_idx, --i, flags);
		if (IS_ERR(bh)) {
			ret = PTR_ERR(bh);
			goto err;
		}

		eh = ext_block_hdr(bh);
		ppos++;
		path[ppos].p_bh = bh;
		path[ppos].p_hdr = eh;
	}

	path[ppos].p_depth = i;
	path[ppos].p_ext = NULL;
	path[ppos].p_idx = NULL;

	/* find extent */
	ecfs_ext_binsearch(inode, path + ppos, block);
	/* if not an empty leaf */
	if (path[ppos].p_ext)
		path[ppos].p_block = ecfs_ext_pblock(path[ppos].p_ext);

	ecfs_ext_show_path(inode, path);

	return path;

err:
	ecfs_free_ext_path(path);
	return ERR_PTR(ret);
}

/*
 * ecfs_ext_insert_index:
 * insert new index [@logical;@ptr] into the block at @curp;
 * check where to insert: before @curp or after @curp
 */
static int ecfs_ext_insert_index(handle_t *handle, struct inode *inode,
				 struct ecfs_ext_path *curp,
				 int logical, ecfs_fsblk_t ptr)
{
	struct ecfs_extent_idx *ix;
	int len, err;

	err = ecfs_ext_get_access(handle, inode, curp);
	if (err)
		return err;

	if (unlikely(logical == le32_to_cpu(curp->p_idx->ei_block))) {
		ECFS_ERROR_INODE(inode,
				 "logical %d == ei_block %d!",
				 logical, le32_to_cpu(curp->p_idx->ei_block));
		return -EFSCORRUPTED;
	}

	if (unlikely(le16_to_cpu(curp->p_hdr->eh_entries)
			     >= le16_to_cpu(curp->p_hdr->eh_max))) {
		ECFS_ERROR_INODE(inode,
				 "eh_entries %d >= eh_max %d!",
				 le16_to_cpu(curp->p_hdr->eh_entries),
				 le16_to_cpu(curp->p_hdr->eh_max));
		return -EFSCORRUPTED;
	}

	if (logical > le32_to_cpu(curp->p_idx->ei_block)) {
		/* insert after */
		ext_debug(inode, "insert new index %d after: %llu\n",
			  logical, ptr);
		ix = curp->p_idx + 1;
	} else {
		/* insert before */
		ext_debug(inode, "insert new index %d before: %llu\n",
			  logical, ptr);
		ix = curp->p_idx;
	}

	if (unlikely(ix > EXT_MAX_INDEX(curp->p_hdr))) {
		ECFS_ERROR_INODE(inode, "ix > EXT_MAX_INDEX!");
		return -EFSCORRUPTED;
	}

	len = EXT_LAST_INDEX(curp->p_hdr) - ix + 1;
	BUG_ON(len < 0);
	if (len > 0) {
		ext_debug(inode, "insert new index %d: "
				"move %d indices from 0x%p to 0x%p\n",
				logical, len, ix, ix + 1);
		memmove(ix + 1, ix, len * sizeof(struct ecfs_extent_idx));
	}

	ix->ei_block = cpu_to_le32(logical);
	ecfs_idx_store_pblock(ix, ptr);
	le16_add_cpu(&curp->p_hdr->eh_entries, 1);

	if (unlikely(ix > EXT_LAST_INDEX(curp->p_hdr))) {
		ECFS_ERROR_INODE(inode, "ix > EXT_LAST_INDEX!");
		return -EFSCORRUPTED;
	}

	err = ecfs_ext_dirty(handle, inode, curp);
	ecfs_std_error(inode->i_sb, err);

	return err;
}

/*
 * ecfs_ext_split:
 * inserts new subtree into the path, using free index entry
 * at depth @at:
 * - allocates all needed blocks (new leaf and all intermediate index blocks)
 * - makes decision where to split
 * - moves remaining extents and index entries (right to the split point)
 *   into the newly allocated blocks
 * - initializes subtree
 */
static int ecfs_ext_split(handle_t *handle, struct inode *inode,
			  unsigned int flags,
			  struct ecfs_ext_path *path,
			  struct ecfs_extent *newext, int at)
{
	struct buffer_head *bh = NULL;
	int depth = ext_depth(inode);
	struct ecfs_extent_header *neh;
	struct ecfs_extent_idx *fidx;
	int i = at, k, m, a;
	ecfs_fsblk_t newblock, oldblock;
	__le32 border;
	ecfs_fsblk_t *ablocks = NULL; /* array of allocated blocks */
	gfp_t gfp_flags = GFP_NOFS;
	int err = 0;
	size_t ext_size = 0;

	if (flags & ECFS_EX_NOFAIL)
		gfp_flags |= __GFP_NOFAIL;

	/* make decision: where to split? */
	/* FIXME: now decision is simplest: at current extent */

	/* if current leaf will be split, then we should use
	 * border from split point */
	if (unlikely(path[depth].p_ext > EXT_MAX_EXTENT(path[depth].p_hdr))) {
		ECFS_ERROR_INODE(inode, "p_ext > EXT_MAX_EXTENT!");
		return -EFSCORRUPTED;
	}
	if (path[depth].p_ext != EXT_MAX_EXTENT(path[depth].p_hdr)) {
		border = path[depth].p_ext[1].ee_block;
		ext_debug(inode, "leaf will be split."
				" next leaf starts at %d\n",
				  le32_to_cpu(border));
	} else {
		border = newext->ee_block;
		ext_debug(inode, "leaf will be added."
				" next leaf starts at %d\n",
				le32_to_cpu(border));
	}

	/*
	 * If error occurs, then we break processing
	 * and mark filesystem read-only. index won't
	 * be inserted and tree will be in consistent
	 * state. Next mount will repair buffers too.
	 */

	/*
	 * Get array to track all allocated blocks.
	 * We need this to handle errors and free blocks
	 * upon them.
	 */
	ablocks = kcalloc(depth, sizeof(ecfs_fsblk_t), gfp_flags);
	if (!ablocks)
		return -ENOMEM;

	/* allocate all needed blocks */
	ext_debug(inode, "allocate %d blocks for indexes/leaf\n", depth - at);
	for (a = 0; a < depth - at; a++) {
		newblock = ecfs_ext_new_meta_block(handle, inode, path,
						   newext, &err, flags);
		if (newblock == 0)
			goto cleanup;
		ablocks[a] = newblock;
	}

	/* initialize new leaf */
	newblock = ablocks[--a];
	if (unlikely(newblock == 0)) {
		ECFS_ERROR_INODE(inode, "newblock == 0!");
		err = -EFSCORRUPTED;
		goto cleanup;
	}
	bh = sb_getblk_gfp(inode->i_sb, newblock, __GFP_MOVABLE | GFP_NOFS);
	if (unlikely(!bh)) {
		err = -ENOMEM;
		goto cleanup;
	}
	lock_buffer(bh);

	err = ecfs_journal_get_create_access(handle, inode->i_sb, bh,
					     ECFS_JTR_NONE);
	if (err)
		goto cleanup;

	neh = ext_block_hdr(bh);
	neh->eh_entries = 0;
	neh->eh_max = cpu_to_le16(ecfs_ext_space_block(inode, 0));
	neh->eh_magic = ECFS_EXT_MAGIC;
	neh->eh_depth = 0;
	neh->eh_generation = 0;

	/* move remainder of path[depth] to the new leaf */
	if (unlikely(path[depth].p_hdr->eh_entries !=
		     path[depth].p_hdr->eh_max)) {
		ECFS_ERROR_INODE(inode, "eh_entries %d != eh_max %d!",
				 path[depth].p_hdr->eh_entries,
				 path[depth].p_hdr->eh_max);
		err = -EFSCORRUPTED;
		goto cleanup;
	}
	/* start copy from next extent */
	m = EXT_MAX_EXTENT(path[depth].p_hdr) - path[depth].p_ext++;
	ecfs_ext_show_move(inode, path, newblock, depth);
	if (m) {
		struct ecfs_extent *ex;
		ex = EXT_FIRST_EXTENT(neh);
		memmove(ex, path[depth].p_ext, sizeof(struct ecfs_extent) * m);
		le16_add_cpu(&neh->eh_entries, m);
	}

	/* zero out unused area in the extent block */
	ext_size = sizeof(struct ecfs_extent_header) +
		sizeof(struct ecfs_extent) * le16_to_cpu(neh->eh_entries);
	memset(bh->b_data + ext_size, 0, inode->i_sb->s_blocksize - ext_size);
	ecfs_extent_block_csum_set(inode, neh);
	set_buffer_uptodate(bh);
	unlock_buffer(bh);

	err = ecfs_handle_dirty_metadata(handle, inode, bh);
	if (err)
		goto cleanup;
	brelse(bh);
	bh = NULL;

	/* correct old leaf */
	if (m) {
		err = ecfs_ext_get_access(handle, inode, path + depth);
		if (err)
			goto cleanup;
		le16_add_cpu(&path[depth].p_hdr->eh_entries, -m);
		err = ecfs_ext_dirty(handle, inode, path + depth);
		if (err)
			goto cleanup;

	}

	/* create intermediate indexes */
	k = depth - at - 1;
	if (unlikely(k < 0)) {
		ECFS_ERROR_INODE(inode, "k %d < 0!", k);
		err = -EFSCORRUPTED;
		goto cleanup;
	}
	if (k)
		ext_debug(inode, "create %d intermediate indices\n", k);
	/* insert new index into current index block */
	/* current depth stored in i var */
	i = depth - 1;
	while (k--) {
		oldblock = newblock;
		newblock = ablocks[--a];
		bh = sb_getblk(inode->i_sb, newblock);
		if (unlikely(!bh)) {
			err = -ENOMEM;
			goto cleanup;
		}
		lock_buffer(bh);

		err = ecfs_journal_get_create_access(handle, inode->i_sb, bh,
						     ECFS_JTR_NONE);
		if (err)
			goto cleanup;

		neh = ext_block_hdr(bh);
		neh->eh_entries = cpu_to_le16(1);
		neh->eh_magic = ECFS_EXT_MAGIC;
		neh->eh_max = cpu_to_le16(ecfs_ext_space_block_idx(inode, 0));
		neh->eh_depth = cpu_to_le16(depth - i);
		neh->eh_generation = 0;
		fidx = EXT_FIRST_INDEX(neh);
		fidx->ei_block = border;
		ecfs_idx_store_pblock(fidx, oldblock);

		ext_debug(inode, "int.index at %d (block %llu): %u -> %llu\n",
				i, newblock, le32_to_cpu(border), oldblock);

		/* move remainder of path[i] to the new index block */
		if (unlikely(EXT_MAX_INDEX(path[i].p_hdr) !=
					EXT_LAST_INDEX(path[i].p_hdr))) {
			ECFS_ERROR_INODE(inode,
					 "EXT_MAX_INDEX != EXT_LAST_INDEX ee_block %d!",
					 le32_to_cpu(path[i].p_ext->ee_block));
			err = -EFSCORRUPTED;
			goto cleanup;
		}
		/* start copy indexes */
		m = EXT_MAX_INDEX(path[i].p_hdr) - path[i].p_idx++;
		ext_debug(inode, "cur 0x%p, last 0x%p\n", path[i].p_idx,
				EXT_MAX_INDEX(path[i].p_hdr));
		ecfs_ext_show_move(inode, path, newblock, i);
		if (m) {
			memmove(++fidx, path[i].p_idx,
				sizeof(struct ecfs_extent_idx) * m);
			le16_add_cpu(&neh->eh_entries, m);
		}
		/* zero out unused area in the extent block */
		ext_size = sizeof(struct ecfs_extent_header) +
		   (sizeof(struct ecfs_extent) * le16_to_cpu(neh->eh_entries));
		memset(bh->b_data + ext_size, 0,
			inode->i_sb->s_blocksize - ext_size);
		ecfs_extent_block_csum_set(inode, neh);
		set_buffer_uptodate(bh);
		unlock_buffer(bh);

		err = ecfs_handle_dirty_metadata(handle, inode, bh);
		if (err)
			goto cleanup;
		brelse(bh);
		bh = NULL;

		/* correct old index */
		if (m) {
			err = ecfs_ext_get_access(handle, inode, path + i);
			if (err)
				goto cleanup;
			le16_add_cpu(&path[i].p_hdr->eh_entries, -m);
			err = ecfs_ext_dirty(handle, inode, path + i);
			if (err)
				goto cleanup;
		}

		i--;
	}

	/* insert new index */
	err = ecfs_ext_insert_index(handle, inode, path + at,
				    le32_to_cpu(border), newblock);

cleanup:
	if (bh) {
		if (buffer_locked(bh))
			unlock_buffer(bh);
		brelse(bh);
	}

	if (err) {
		/* free all allocated blocks in error case */
		for (i = 0; i < depth; i++) {
			if (!ablocks[i])
				continue;
			ecfs_free_blocks(handle, inode, NULL, ablocks[i], 1,
					 ECFS_FREE_BLOCKS_METADATA);
		}
	}
	kfree(ablocks);

	return err;
}

/*
 * ecfs_ext_grow_indepth:
 * implements tree growing procedure:
 * - allocates new block
 * - moves top-level data (index block or leaf) into the new block
 * - initializes new top-level, creating index that points to the
 *   just created block
 */
static int ecfs_ext_grow_indepth(handle_t *handle, struct inode *inode,
				 unsigned int flags)
{
	struct ecfs_extent_header *neh;
	struct buffer_head *bh;
	ecfs_fsblk_t newblock, goal = 0;
	struct ecfs_super_block *es = ECFS_SB(inode->i_sb)->s_es;
	int err = 0;
	size_t ext_size = 0;

	/* Try to prepend new index to old one */
	if (ext_depth(inode))
		goal = ecfs_idx_pblock(EXT_FIRST_INDEX(ext_inode_hdr(inode)));
	if (goal > le32_to_cpu(es->s_first_data_block)) {
		flags |= ECFS_MB_HINT_TRY_GOAL;
		goal--;
	} else
		goal = ecfs_inode_to_goal_block(inode);
	newblock = ecfs_new_meta_blocks(handle, inode, goal, flags,
					NULL, &err);
	if (newblock == 0)
		return err;

	bh = sb_getblk_gfp(inode->i_sb, newblock, __GFP_MOVABLE | GFP_NOFS);
	if (unlikely(!bh))
		return -ENOMEM;
	lock_buffer(bh);

	err = ecfs_journal_get_create_access(handle, inode->i_sb, bh,
					     ECFS_JTR_NONE);
	if (err) {
		unlock_buffer(bh);
		goto out;
	}

	ext_size = sizeof(ECFS_I(inode)->i_data);
	/* move top-level index/leaf into new block */
	memmove(bh->b_data, ECFS_I(inode)->i_data, ext_size);
	/* zero out unused area in the extent block */
	memset(bh->b_data + ext_size, 0, inode->i_sb->s_blocksize - ext_size);

	/* set size of new block */
	neh = ext_block_hdr(bh);
	/* old root could have indexes or leaves
	 * so calculate e_max right way */
	if (ext_depth(inode))
		neh->eh_max = cpu_to_le16(ecfs_ext_space_block_idx(inode, 0));
	else
		neh->eh_max = cpu_to_le16(ecfs_ext_space_block(inode, 0));
	neh->eh_magic = ECFS_EXT_MAGIC;
	ecfs_extent_block_csum_set(inode, neh);
	set_buffer_uptodate(bh);
	set_buffer_verified(bh);
	unlock_buffer(bh);

	err = ecfs_handle_dirty_metadata(handle, inode, bh);
	if (err)
		goto out;

	/* Update top-level index: num,max,pointer */
	neh = ext_inode_hdr(inode);
	neh->eh_entries = cpu_to_le16(1);
	ecfs_idx_store_pblock(EXT_FIRST_INDEX(neh), newblock);
	if (neh->eh_depth == 0) {
		/* Root extent block becomes index block */
		neh->eh_max = cpu_to_le16(ecfs_ext_space_root_idx(inode, 0));
		EXT_FIRST_INDEX(neh)->ei_block =
			EXT_FIRST_EXTENT(neh)->ee_block;
	}
	ext_debug(inode, "new root: num %d(%d), lblock %d, ptr %llu\n",
		  le16_to_cpu(neh->eh_entries), le16_to_cpu(neh->eh_max),
		  le32_to_cpu(EXT_FIRST_INDEX(neh)->ei_block),
		  ecfs_idx_pblock(EXT_FIRST_INDEX(neh)));

	le16_add_cpu(&neh->eh_depth, 1);
	err = ecfs_mark_inode_dirty(handle, inode);
out:
	brelse(bh);

	return err;
}

/*
 * ecfs_ext_create_new_leaf:
 * finds empty index and adds new leaf.
 * if no free index is found, then it requests in-depth growing.
 */
static struct ecfs_ext_path *
ecfs_ext_create_new_leaf(handle_t *handle, struct inode *inode,
			 unsigned int mb_flags, unsigned int gb_flags,
			 struct ecfs_ext_path *path,
			 struct ecfs_extent *newext)
{
	struct ecfs_ext_path *curp;
	int depth, i, err = 0;
	ecfs_lblk_t ee_block = le32_to_cpu(newext->ee_block);

repeat:
	i = depth = ext_depth(inode);

	/* walk up to the tree and look for free index entry */
	curp = path + depth;
	while (i > 0 && !EXT_HAS_FREE_INDEX(curp)) {
		i--;
		curp--;
	}

	/* we use already allocated block for index block,
	 * so subsequent data blocks should be contiguous */
	if (EXT_HAS_FREE_INDEX(curp)) {
		/* if we found index with free entry, then use that
		 * entry: create all needed subtree and add new leaf */
		err = ecfs_ext_split(handle, inode, mb_flags, path, newext, i);
		if (err)
			goto errout;

		/* refill path */
		path = ecfs_find_extent(inode, ee_block, path, gb_flags);
		return path;
	}

	/* tree is full, time to grow in depth */
	err = ecfs_ext_grow_indepth(handle, inode, mb_flags);
	if (err)
		goto errout;

	/* refill path */
	path = ecfs_find_extent(inode, ee_block, path, gb_flags);
	if (IS_ERR(path))
		return path;

	/*
	 * only first (depth 0 -> 1) produces free space;
	 * in all other cases we have to split the grown tree
	 */
	depth = ext_depth(inode);
	if (path[depth].p_hdr->eh_entries == path[depth].p_hdr->eh_max) {
		/* now we need to split */
		goto repeat;
	}

	return path;

errout:
	ecfs_free_ext_path(path);
	return ERR_PTR(err);
}

/*
 * search the closest allocated block to the left for *logical
 * and returns it at @logical + it's physical address at @phys
 * if *logical is the smallest allocated block, the function
 * returns 0 at @phys
 * return value contains 0 (success) or error code
 */
static int ecfs_ext_search_left(struct inode *inode,
				struct ecfs_ext_path *path,
				ecfs_lblk_t *logical, ecfs_fsblk_t *phys)
{
	struct ecfs_extent_idx *ix;
	struct ecfs_extent *ex;
	int depth, ee_len;

	if (unlikely(path == NULL)) {
		ECFS_ERROR_INODE(inode, "path == NULL *logical %d!", *logical);
		return -EFSCORRUPTED;
	}
	depth = path->p_depth;
	*phys = 0;

	if (depth == 0 && path->p_ext == NULL)
		return 0;

	/* usually extent in the path covers blocks smaller
	 * then *logical, but it can be that extent is the
	 * first one in the file */

	ex = path[depth].p_ext;
	ee_len = ecfs_ext_get_actual_len(ex);
	if (*logical < le32_to_cpu(ex->ee_block)) {
		if (unlikely(EXT_FIRST_EXTENT(path[depth].p_hdr) != ex)) {
			ECFS_ERROR_INODE(inode,
					 "EXT_FIRST_EXTENT != ex *logical %d ee_block %d!",
					 *logical, le32_to_cpu(ex->ee_block));
			return -EFSCORRUPTED;
		}
		while (--depth >= 0) {
			ix = path[depth].p_idx;
			if (unlikely(ix != EXT_FIRST_INDEX(path[depth].p_hdr))) {
				ECFS_ERROR_INODE(inode,
				  "ix (%d) != EXT_FIRST_INDEX (%d) (depth %d)!",
				  ix != NULL ? le32_to_cpu(ix->ei_block) : 0,
				  le32_to_cpu(EXT_FIRST_INDEX(path[depth].p_hdr)->ei_block),
				  depth);
				return -EFSCORRUPTED;
			}
		}
		return 0;
	}

	if (unlikely(*logical < (le32_to_cpu(ex->ee_block) + ee_len))) {
		ECFS_ERROR_INODE(inode,
				 "logical %d < ee_block %d + ee_len %d!",
				 *logical, le32_to_cpu(ex->ee_block), ee_len);
		return -EFSCORRUPTED;
	}

	*logical = le32_to_cpu(ex->ee_block) + ee_len - 1;
	*phys = ecfs_ext_pblock(ex) + ee_len - 1;
	return 0;
}

/*
 * Search the closest allocated block to the right for *logical
 * and returns it at @logical + it's physical address at @phys.
 * If not exists, return 0 and @phys is set to 0. We will return
 * 1 which means we found an allocated block and ret_ex is valid.
 * Or return a (< 0) error code.
 */
static int ecfs_ext_search_right(struct inode *inode,
				 struct ecfs_ext_path *path,
				 ecfs_lblk_t *logical, ecfs_fsblk_t *phys,
				 struct ecfs_extent *ret_ex, int flags)
{
	struct buffer_head *bh = NULL;
	struct ecfs_extent_header *eh;
	struct ecfs_extent_idx *ix;
	struct ecfs_extent *ex;
	int depth;	/* Note, NOT eh_depth; depth from top of tree */
	int ee_len;

	if (unlikely(path == NULL)) {
		ECFS_ERROR_INODE(inode, "path == NULL *logical %d!", *logical);
		return -EFSCORRUPTED;
	}
	depth = path->p_depth;
	*phys = 0;

	if (depth == 0 && path->p_ext == NULL)
		return 0;

	/* usually extent in the path covers blocks smaller
	 * then *logical, but it can be that extent is the
	 * first one in the file */

	ex = path[depth].p_ext;
	ee_len = ecfs_ext_get_actual_len(ex);
	if (*logical < le32_to_cpu(ex->ee_block)) {
		if (unlikely(EXT_FIRST_EXTENT(path[depth].p_hdr) != ex)) {
			ECFS_ERROR_INODE(inode,
					 "first_extent(path[%d].p_hdr) != ex",
					 depth);
			return -EFSCORRUPTED;
		}
		while (--depth >= 0) {
			ix = path[depth].p_idx;
			if (unlikely(ix != EXT_FIRST_INDEX(path[depth].p_hdr))) {
				ECFS_ERROR_INODE(inode,
						 "ix != EXT_FIRST_INDEX *logical %d!",
						 *logical);
				return -EFSCORRUPTED;
			}
		}
		goto found_extent;
	}

	if (unlikely(*logical < (le32_to_cpu(ex->ee_block) + ee_len))) {
		ECFS_ERROR_INODE(inode,
				 "logical %d < ee_block %d + ee_len %d!",
				 *logical, le32_to_cpu(ex->ee_block), ee_len);
		return -EFSCORRUPTED;
	}

	if (ex != EXT_LAST_EXTENT(path[depth].p_hdr)) {
		/* next allocated block in this leaf */
		ex++;
		goto found_extent;
	}

	/* go up and search for index to the right */
	while (--depth >= 0) {
		ix = path[depth].p_idx;
		if (ix != EXT_LAST_INDEX(path[depth].p_hdr))
			goto got_index;
	}

	/* we've gone up to the root and found no index to the right */
	return 0;

got_index:
	/* we've found index to the right, let's
	 * follow it and find the closest allocated
	 * block to the right */
	ix++;
	while (++depth < path->p_depth) {
		/* subtract from p_depth to get proper eh_depth */
		bh = read_extent_tree_block(inode, ix, path->p_depth - depth,
					    flags);
		if (IS_ERR(bh))
			return PTR_ERR(bh);
		eh = ext_block_hdr(bh);
		ix = EXT_FIRST_INDEX(eh);
		put_bh(bh);
	}

	bh = read_extent_tree_block(inode, ix, path->p_depth - depth, flags);
	if (IS_ERR(bh))
		return PTR_ERR(bh);
	eh = ext_block_hdr(bh);
	ex = EXT_FIRST_EXTENT(eh);
found_extent:
	*logical = le32_to_cpu(ex->ee_block);
	*phys = ecfs_ext_pblock(ex);
	if (ret_ex)
		*ret_ex = *ex;
	if (bh)
		put_bh(bh);
	return 1;
}

/*
 * ecfs_ext_next_allocated_block:
 * returns allocated block in subsequent extent or EXT_MAX_BLOCKS.
 * NOTE: it considers block number from index entry as
 * allocated block. Thus, index entries have to be consistent
 * with leaves.
 */
ecfs_lblk_t
ecfs_ext_next_allocated_block(struct ecfs_ext_path *path)
{
	int depth;

	BUG_ON(path == NULL);
	depth = path->p_depth;

	if (depth == 0 && path->p_ext == NULL)
		return EXT_MAX_BLOCKS;

	while (depth >= 0) {
		struct ecfs_ext_path *p = &path[depth];

		if (depth == path->p_depth) {
			/* leaf */
			if (p->p_ext && p->p_ext != EXT_LAST_EXTENT(p->p_hdr))
				return le32_to_cpu(p->p_ext[1].ee_block);
		} else {
			/* index */
			if (p->p_idx != EXT_LAST_INDEX(p->p_hdr))
				return le32_to_cpu(p->p_idx[1].ei_block);
		}
		depth--;
	}

	return EXT_MAX_BLOCKS;
}

/*
 * ecfs_ext_next_leaf_block:
 * returns first allocated block from next leaf or EXT_MAX_BLOCKS
 */
static ecfs_lblk_t ecfs_ext_next_leaf_block(struct ecfs_ext_path *path)
{
	int depth;

	BUG_ON(path == NULL);
	depth = path->p_depth;

	/* zero-tree has no leaf blocks at all */
	if (depth == 0)
		return EXT_MAX_BLOCKS;

	/* go to index block */
	depth--;

	while (depth >= 0) {
		if (path[depth].p_idx !=
				EXT_LAST_INDEX(path[depth].p_hdr))
			return (ecfs_lblk_t)
				le32_to_cpu(path[depth].p_idx[1].ei_block);
		depth--;
	}

	return EXT_MAX_BLOCKS;
}

/*
 * ecfs_ext_correct_indexes:
 * if leaf gets modified and modified extent is first in the leaf,
 * then we have to correct all indexes above.
 * TODO: do we need to correct tree in all cases?
 */
static int ecfs_ext_correct_indexes(handle_t *handle, struct inode *inode,
				struct ecfs_ext_path *path)
{
	struct ecfs_extent_header *eh;
	int depth = ext_depth(inode);
	struct ecfs_extent *ex;
	__le32 border;
	int k, err = 0;

	eh = path[depth].p_hdr;
	ex = path[depth].p_ext;

	if (unlikely(ex == NULL || eh == NULL)) {
		ECFS_ERROR_INODE(inode,
				 "ex %p == NULL or eh %p == NULL", ex, eh);
		return -EFSCORRUPTED;
	}

	if (depth == 0) {
		/* there is no tree at all */
		return 0;
	}

	if (ex != EXT_FIRST_EXTENT(eh)) {
		/* we correct tree if first leaf got modified only */
		return 0;
	}

	/*
	 * TODO: we need correction if border is smaller than current one
	 */
	k = depth - 1;
	border = path[depth].p_ext->ee_block;
	err = ecfs_ext_get_access(handle, inode, path + k);
	if (err)
		return err;
	path[k].p_idx->ei_block = border;
	err = ecfs_ext_dirty(handle, inode, path + k);
	if (err)
		return err;

	while (k--) {
		/* change all left-side indexes */
		if (path[k+1].p_idx != EXT_FIRST_INDEX(path[k+1].p_hdr))
			break;
		err = ecfs_ext_get_access(handle, inode, path + k);
		if (err)
			goto clean;
		path[k].p_idx->ei_block = border;
		err = ecfs_ext_dirty(handle, inode, path + k);
		if (err)
			goto clean;
	}
	return 0;

clean:
	/*
	 * The path[k].p_bh is either unmodified or with no verified bit
	 * set (see ecfs_ext_get_access()). So just clear the verified bit
	 * of the successfully modified extents buffers, which will force
	 * these extents to be checked to avoid using inconsistent data.
	 */
	while (++k < depth)
		clear_buffer_verified(path[k].p_bh);

	return err;
}

static int ecfs_can_extents_be_merged(struct inode *inode,
				      struct ecfs_extent *ex1,
				      struct ecfs_extent *ex2)
{
	unsigned short ext1_ee_len, ext2_ee_len;

	if (ecfs_ext_is_unwritten(ex1) != ecfs_ext_is_unwritten(ex2))
		return 0;

	ext1_ee_len = ecfs_ext_get_actual_len(ex1);
	ext2_ee_len = ecfs_ext_get_actual_len(ex2);

	if (le32_to_cpu(ex1->ee_block) + ext1_ee_len !=
			le32_to_cpu(ex2->ee_block))
		return 0;

	if (ext1_ee_len + ext2_ee_len > EXT_INIT_MAX_LEN)
		return 0;

	if (ecfs_ext_is_unwritten(ex1) &&
	    ext1_ee_len + ext2_ee_len > EXT_UNWRITTEN_MAX_LEN)
		return 0;
#ifdef AGGRESSIVE_TEST
	if (ext1_ee_len >= 4)
		return 0;
#endif

	if (ecfs_ext_pblock(ex1) + ext1_ee_len == ecfs_ext_pblock(ex2))
		return 1;
	return 0;
}

/*
 * This function tries to merge the "ex" extent to the next extent in the tree.
 * It always tries to merge towards right. If you want to merge towards
 * left, pass "ex - 1" as argument instead of "ex".
 * Returns 0 if the extents (ex and ex+1) were _not_ merged and returns
 * 1 if they got merged.
 */
static int ecfs_ext_try_to_merge_right(struct inode *inode,
				 struct ecfs_ext_path *path,
				 struct ecfs_extent *ex)
{
	struct ecfs_extent_header *eh;
	unsigned int depth, len;
	int merge_done = 0, unwritten;

	depth = ext_depth(inode);
	BUG_ON(path[depth].p_hdr == NULL);
	eh = path[depth].p_hdr;

	while (ex < EXT_LAST_EXTENT(eh)) {
		if (!ecfs_can_extents_be_merged(inode, ex, ex + 1))
			break;
		/* merge with next extent! */
		unwritten = ecfs_ext_is_unwritten(ex);
		ex->ee_len = cpu_to_le16(ecfs_ext_get_actual_len(ex)
				+ ecfs_ext_get_actual_len(ex + 1));
		if (unwritten)
			ecfs_ext_mark_unwritten(ex);

		if (ex + 1 < EXT_LAST_EXTENT(eh)) {
			len = (EXT_LAST_EXTENT(eh) - ex - 1)
				* sizeof(struct ecfs_extent);
			memmove(ex + 1, ex + 2, len);
		}
		le16_add_cpu(&eh->eh_entries, -1);
		merge_done = 1;
		WARN_ON(eh->eh_entries == 0);
		if (!eh->eh_entries)
			ECFS_ERROR_INODE(inode, "eh->eh_entries = 0!");
	}

	return merge_done;
}

/*
 * This function does a very simple check to see if we can collapse
 * an extent tree with a single extent tree leaf block into the inode.
 */
static void ecfs_ext_try_to_merge_up(handle_t *handle,
				     struct inode *inode,
				     struct ecfs_ext_path *path)
{
	size_t s;
	unsigned max_root = ecfs_ext_space_root(inode, 0);
	ecfs_fsblk_t blk;

	if ((path[0].p_depth != 1) ||
	    (le16_to_cpu(path[0].p_hdr->eh_entries) != 1) ||
	    (le16_to_cpu(path[1].p_hdr->eh_entries) > max_root))
		return;

	/*
	 * We need to modify the block allocation bitmap and the block
	 * group descriptor to release the extent tree block.  If we
	 * can't get the journal credits, give up.
	 */
	if (ecfs_journal_extend(handle, 2,
			ecfs_free_metadata_revoke_credits(inode->i_sb, 1)))
		return;

	/*
	 * Copy the extent data up to the inode
	 */
	blk = ecfs_idx_pblock(path[0].p_idx);
	s = le16_to_cpu(path[1].p_hdr->eh_entries) *
		sizeof(struct ecfs_extent_idx);
	s += sizeof(struct ecfs_extent_header);

	path[1].p_maxdepth = path[0].p_maxdepth;
	memcpy(path[0].p_hdr, path[1].p_hdr, s);
	path[0].p_depth = 0;
	path[0].p_ext = EXT_FIRST_EXTENT(path[0].p_hdr) +
		(path[1].p_ext - EXT_FIRST_EXTENT(path[1].p_hdr));
	path[0].p_hdr->eh_max = cpu_to_le16(max_root);

	ecfs_ext_path_brelse(path + 1);
	ecfs_free_blocks(handle, inode, NULL, blk, 1,
			 ECFS_FREE_BLOCKS_METADATA | ECFS_FREE_BLOCKS_FORGET);
}

/*
 * This function tries to merge the @ex extent to neighbours in the tree, then
 * tries to collapse the extent tree into the inode.
 */
static void ecfs_ext_try_to_merge(handle_t *handle,
				  struct inode *inode,
				  struct ecfs_ext_path *path,
				  struct ecfs_extent *ex)
{
	struct ecfs_extent_header *eh;
	unsigned int depth;
	int merge_done = 0;

	depth = ext_depth(inode);
	BUG_ON(path[depth].p_hdr == NULL);
	eh = path[depth].p_hdr;

	if (ex > EXT_FIRST_EXTENT(eh))
		merge_done = ecfs_ext_try_to_merge_right(inode, path, ex - 1);

	if (!merge_done)
		(void) ecfs_ext_try_to_merge_right(inode, path, ex);

	ecfs_ext_try_to_merge_up(handle, inode, path);
}

/*
 * check if a portion of the "newext" extent overlaps with an
 * existing extent.
 *
 * If there is an overlap discovered, it updates the length of the newext
 * such that there will be no overlap, and then returns 1.
 * If there is no overlap found, it returns 0.
 */
static unsigned int ecfs_ext_check_overlap(struct ecfs_sb_info *sbi,
					   struct inode *inode,
					   struct ecfs_extent *newext,
					   struct ecfs_ext_path *path)
{
	ecfs_lblk_t b1, b2;
	unsigned int depth, len1;
	unsigned int ret = 0;

	b1 = le32_to_cpu(newext->ee_block);
	len1 = ecfs_ext_get_actual_len(newext);
	depth = ext_depth(inode);
	if (!path[depth].p_ext)
		goto out;
	b2 = ECFS_LBLK_CMASK(sbi, le32_to_cpu(path[depth].p_ext->ee_block));

	/*
	 * get the next allocated block if the extent in the path
	 * is before the requested block(s)
	 */
	if (b2 < b1) {
		b2 = ecfs_ext_next_allocated_block(path);
		if (b2 == EXT_MAX_BLOCKS)
			goto out;
		b2 = ECFS_LBLK_CMASK(sbi, b2);
	}

	/* check for wrap through zero on extent logical start block*/
	if (b1 + len1 < b1) {
		len1 = EXT_MAX_BLOCKS - b1;
		newext->ee_len = cpu_to_le16(len1);
		ret = 1;
	}

	/* check for overlap */
	if (b1 + len1 > b2) {
		newext->ee_len = cpu_to_le16(b2 - b1);
		ret = 1;
	}
out:
	return ret;
}

/*
 * ecfs_ext_insert_extent:
 * tries to merge requested extent into the existing extent or
 * inserts requested extent as new one into the tree,
 * creating new leaf in the no-space case.
 */
struct ecfs_ext_path *
ecfs_ext_insert_extent(handle_t *handle, struct inode *inode,
		       struct ecfs_ext_path *path,
		       struct ecfs_extent *newext, int gb_flags)
{
	struct ecfs_extent_header *eh;
	struct ecfs_extent *ex, *fex;
	struct ecfs_extent *nearex; /* nearest extent */
	int depth, len, err = 0;
	ecfs_lblk_t next;
	int mb_flags = 0, unwritten;

	if (gb_flags & ECFS_GET_BLOCKS_DELALLOC_RESERVE)
		mb_flags |= ECFS_MB_DELALLOC_RESERVED;
	if (unlikely(ecfs_ext_get_actual_len(newext) == 0)) {
		ECFS_ERROR_INODE(inode, "ecfs_ext_get_actual_len(newext) == 0");
		err = -EFSCORRUPTED;
		goto errout;
	}
	depth = ext_depth(inode);
	ex = path[depth].p_ext;
	eh = path[depth].p_hdr;
	if (unlikely(path[depth].p_hdr == NULL)) {
		ECFS_ERROR_INODE(inode, "path[%d].p_hdr == NULL", depth);
		err = -EFSCORRUPTED;
		goto errout;
	}

	/* try to insert block into found extent and return */
	if (ex && !(gb_flags & ECFS_GET_BLOCKS_PRE_IO)) {

		/*
		 * Try to see whether we should rather test the extent on
		 * right from ex, or from the left of ex. This is because
		 * ecfs_find_extent() can return either extent on the
		 * left, or on the right from the searched position. This
		 * will make merging more effective.
		 */
		if (ex < EXT_LAST_EXTENT(eh) &&
		    (le32_to_cpu(ex->ee_block) +
		    ecfs_ext_get_actual_len(ex) <
		    le32_to_cpu(newext->ee_block))) {
			ex += 1;
			goto prepend;
		} else if ((ex > EXT_FIRST_EXTENT(eh)) &&
			   (le32_to_cpu(newext->ee_block) +
			   ecfs_ext_get_actual_len(newext) <
			   le32_to_cpu(ex->ee_block)))
			ex -= 1;

		/* Try to append newex to the ex */
		if (ecfs_can_extents_be_merged(inode, ex, newext)) {
			ext_debug(inode, "append [%d]%d block to %u:[%d]%d"
				  "(from %llu)\n",
				  ecfs_ext_is_unwritten(newext),
				  ecfs_ext_get_actual_len(newext),
				  le32_to_cpu(ex->ee_block),
				  ecfs_ext_is_unwritten(ex),
				  ecfs_ext_get_actual_len(ex),
				  ecfs_ext_pblock(ex));
			err = ecfs_ext_get_access(handle, inode,
						  path + depth);
			if (err)
				goto errout;
			unwritten = ecfs_ext_is_unwritten(ex);
			ex->ee_len = cpu_to_le16(ecfs_ext_get_actual_len(ex)
					+ ecfs_ext_get_actual_len(newext));
			if (unwritten)
				ecfs_ext_mark_unwritten(ex);
			nearex = ex;
			goto merge;
		}

prepend:
		/* Try to prepend newex to the ex */
		if (ecfs_can_extents_be_merged(inode, newext, ex)) {
			ext_debug(inode, "prepend %u[%d]%d block to %u:[%d]%d"
				  "(from %llu)\n",
				  le32_to_cpu(newext->ee_block),
				  ecfs_ext_is_unwritten(newext),
				  ecfs_ext_get_actual_len(newext),
				  le32_to_cpu(ex->ee_block),
				  ecfs_ext_is_unwritten(ex),
				  ecfs_ext_get_actual_len(ex),
				  ecfs_ext_pblock(ex));
			err = ecfs_ext_get_access(handle, inode,
						  path + depth);
			if (err)
				goto errout;

			unwritten = ecfs_ext_is_unwritten(ex);
			ex->ee_block = newext->ee_block;
			ecfs_ext_store_pblock(ex, ecfs_ext_pblock(newext));
			ex->ee_len = cpu_to_le16(ecfs_ext_get_actual_len(ex)
					+ ecfs_ext_get_actual_len(newext));
			if (unwritten)
				ecfs_ext_mark_unwritten(ex);
			nearex = ex;
			goto merge;
		}
	}

	depth = ext_depth(inode);
	eh = path[depth].p_hdr;
	if (le16_to_cpu(eh->eh_entries) < le16_to_cpu(eh->eh_max))
		goto has_space;

	/* probably next leaf has space for us? */
	fex = EXT_LAST_EXTENT(eh);
	next = EXT_MAX_BLOCKS;
	if (le32_to_cpu(newext->ee_block) > le32_to_cpu(fex->ee_block))
		next = ecfs_ext_next_leaf_block(path);
	if (next != EXT_MAX_BLOCKS) {
		struct ecfs_ext_path *npath;

		ext_debug(inode, "next leaf block - %u\n", next);
		npath = ecfs_find_extent(inode, next, NULL, gb_flags);
		if (IS_ERR(npath)) {
			err = PTR_ERR(npath);
			goto errout;
		}
		BUG_ON(npath->p_depth != path->p_depth);
		eh = npath[depth].p_hdr;
		if (le16_to_cpu(eh->eh_entries) < le16_to_cpu(eh->eh_max)) {
			ext_debug(inode, "next leaf isn't full(%d)\n",
				  le16_to_cpu(eh->eh_entries));
			ecfs_free_ext_path(path);
			path = npath;
			goto has_space;
		}
		ext_debug(inode, "next leaf has no free space(%d,%d)\n",
			  le16_to_cpu(eh->eh_entries), le16_to_cpu(eh->eh_max));
		ecfs_free_ext_path(npath);
	}

	/*
	 * There is no free space in the found leaf.
	 * We're gonna add a new leaf in the tree.
	 */
	if (gb_flags & ECFS_GET_BLOCKS_METADATA_NOFAIL)
		mb_flags |= ECFS_MB_USE_RESERVED;
	path = ecfs_ext_create_new_leaf(handle, inode, mb_flags, gb_flags,
					path, newext);
	if (IS_ERR(path))
		return path;
	depth = ext_depth(inode);
	eh = path[depth].p_hdr;

has_space:
	nearex = path[depth].p_ext;

	err = ecfs_ext_get_access(handle, inode, path + depth);
	if (err)
		goto errout;

	if (!nearex) {
		/* there is no extent in this leaf, create first one */
		ext_debug(inode, "first extent in the leaf: %u:%llu:[%d]%d\n",
				le32_to_cpu(newext->ee_block),
				ecfs_ext_pblock(newext),
				ecfs_ext_is_unwritten(newext),
				ecfs_ext_get_actual_len(newext));
		nearex = EXT_FIRST_EXTENT(eh);
	} else {
		if (le32_to_cpu(newext->ee_block)
			   > le32_to_cpu(nearex->ee_block)) {
			/* Insert after */
			ext_debug(inode, "insert %u:%llu:[%d]%d before: "
					"nearest %p\n",
					le32_to_cpu(newext->ee_block),
					ecfs_ext_pblock(newext),
					ecfs_ext_is_unwritten(newext),
					ecfs_ext_get_actual_len(newext),
					nearex);
			nearex++;
		} else {
			/* Insert before */
			BUG_ON(newext->ee_block == nearex->ee_block);
			ext_debug(inode, "insert %u:%llu:[%d]%d after: "
					"nearest %p\n",
					le32_to_cpu(newext->ee_block),
					ecfs_ext_pblock(newext),
					ecfs_ext_is_unwritten(newext),
					ecfs_ext_get_actual_len(newext),
					nearex);
		}
		len = EXT_LAST_EXTENT(eh) - nearex + 1;
		if (len > 0) {
			ext_debug(inode, "insert %u:%llu:[%d]%d: "
					"move %d extents from 0x%p to 0x%p\n",
					le32_to_cpu(newext->ee_block),
					ecfs_ext_pblock(newext),
					ecfs_ext_is_unwritten(newext),
					ecfs_ext_get_actual_len(newext),
					len, nearex, nearex + 1);
			memmove(nearex + 1, nearex,
				len * sizeof(struct ecfs_extent));
		}
	}

	le16_add_cpu(&eh->eh_entries, 1);
	path[depth].p_ext = nearex;
	nearex->ee_block = newext->ee_block;
	ecfs_ext_store_pblock(nearex, ecfs_ext_pblock(newext));
	nearex->ee_len = newext->ee_len;

merge:
	/* try to merge extents */
	if (!(gb_flags & ECFS_GET_BLOCKS_PRE_IO))
		ecfs_ext_try_to_merge(handle, inode, path, nearex);

	/* time to correct all indexes above */
	err = ecfs_ext_correct_indexes(handle, inode, path);
	if (err)
		goto errout;

	err = ecfs_ext_dirty(handle, inode, path + path->p_depth);
	if (err)
		goto errout;

	return path;

errout:
	ecfs_free_ext_path(path);
	return ERR_PTR(err);
}

static int ecfs_fill_es_cache_info(struct inode *inode,
				   ecfs_lblk_t block, ecfs_lblk_t num,
				   struct fiemap_extent_info *fieinfo)
{
	ecfs_lblk_t next, end = block + num - 1;
	struct extent_status es;
	unsigned char blksize_bits = inode->i_sb->s_blocksize_bits;
	unsigned int flags;
	int err;

	while (block <= end) {
		next = 0;
		flags = 0;
		if (!ecfs_es_lookup_extent(inode, block, &next, &es))
			break;
		if (ecfs_es_is_unwritten(&es))
			flags |= FIEMAP_EXTENT_UNWRITTEN;
		if (ecfs_es_is_delayed(&es))
			flags |= (FIEMAP_EXTENT_DELALLOC |
				  FIEMAP_EXTENT_UNKNOWN);
		if (ecfs_es_is_hole(&es))
			flags |= ECFS_FIEMAP_EXTENT_HOLE;
		if (next == 0)
			flags |= FIEMAP_EXTENT_LAST;
		if (flags & (FIEMAP_EXTENT_DELALLOC|
			     ECFS_FIEMAP_EXTENT_HOLE))
			es.es_pblk = 0;
		else
			es.es_pblk = ecfs_es_pblock(&es);
		err = fiemap_fill_next_extent(fieinfo,
				(__u64)es.es_lblk << blksize_bits,
				(__u64)es.es_pblk << blksize_bits,
				(__u64)es.es_len << blksize_bits,
				flags);
		if (next == 0)
			break;
		block = next;
		if (err < 0)
			return err;
		if (err == 1)
			return 0;
	}
	return 0;
}


/*
 * ecfs_ext_find_hole - find hole around given block according to the given path
 * @inode:	inode we lookup in
 * @path:	path in extent tree to @lblk
 * @lblk:	pointer to logical block around which we want to determine hole
 *
 * Determine hole length (and start if easily possible) around given logical
 * block. We don't try too hard to find the beginning of the hole but @path
 * actually points to extent before @lblk, we provide it.
 *
 * The function returns the length of a hole starting at @lblk. We update @lblk
 * to the beginning of the hole if we managed to find it.
 */
static ecfs_lblk_t ecfs_ext_find_hole(struct inode *inode,
				      struct ecfs_ext_path *path,
				      ecfs_lblk_t *lblk)
{
	int depth = ext_depth(inode);
	struct ecfs_extent *ex;
	ecfs_lblk_t len;

	ex = path[depth].p_ext;
	if (ex == NULL) {
		/* there is no extent yet, so gap is [0;-] */
		*lblk = 0;
		len = EXT_MAX_BLOCKS;
	} else if (*lblk < le32_to_cpu(ex->ee_block)) {
		len = le32_to_cpu(ex->ee_block) - *lblk;
	} else if (*lblk >= le32_to_cpu(ex->ee_block)
			+ ecfs_ext_get_actual_len(ex)) {
		ecfs_lblk_t next;

		*lblk = le32_to_cpu(ex->ee_block) + ecfs_ext_get_actual_len(ex);
		next = ecfs_ext_next_allocated_block(path);
		BUG_ON(next == *lblk);
		len = next - *lblk;
	} else {
		BUG();
	}
	return len;
}

/*
 * ecfs_ext_rm_idx:
 * removes index from the index block.
 */
static int ecfs_ext_rm_idx(handle_t *handle, struct inode *inode,
			struct ecfs_ext_path *path, int depth)
{
	int err;
	ecfs_fsblk_t leaf;
	int k = depth - 1;

	/* free index block */
	leaf = ecfs_idx_pblock(path[k].p_idx);
	if (unlikely(path[k].p_hdr->eh_entries == 0)) {
		ECFS_ERROR_INODE(inode, "path[%d].p_hdr->eh_entries == 0", k);
		return -EFSCORRUPTED;
	}
	err = ecfs_ext_get_access(handle, inode, path + k);
	if (err)
		return err;

	if (path[k].p_idx != EXT_LAST_INDEX(path[k].p_hdr)) {
		int len = EXT_LAST_INDEX(path[k].p_hdr) - path[k].p_idx;
		len *= sizeof(struct ecfs_extent_idx);
		memmove(path[k].p_idx, path[k].p_idx + 1, len);
	}

	le16_add_cpu(&path[k].p_hdr->eh_entries, -1);
	err = ecfs_ext_dirty(handle, inode, path + k);
	if (err)
		return err;
	ext_debug(inode, "index is empty, remove it, free block %llu\n", leaf);
	trace_ecfs_ext_rm_idx(inode, leaf);

	ecfs_free_blocks(handle, inode, NULL, leaf, 1,
			 ECFS_FREE_BLOCKS_METADATA | ECFS_FREE_BLOCKS_FORGET);

	while (--k >= 0) {
		if (path[k + 1].p_idx != EXT_FIRST_INDEX(path[k + 1].p_hdr))
			break;
		err = ecfs_ext_get_access(handle, inode, path + k);
		if (err)
			goto clean;
		path[k].p_idx->ei_block = path[k + 1].p_idx->ei_block;
		err = ecfs_ext_dirty(handle, inode, path + k);
		if (err)
			goto clean;
	}
	return 0;

clean:
	/*
	 * The path[k].p_bh is either unmodified or with no verified bit
	 * set (see ecfs_ext_get_access()). So just clear the verified bit
	 * of the successfully modified extents buffers, which will force
	 * these extents to be checked to avoid using inconsistent data.
	 */
	while (++k < depth)
		clear_buffer_verified(path[k].p_bh);

	return err;
}

/*
 * ecfs_ext_calc_credits_for_single_extent:
 * This routine returns max. credits that needed to insert an extent
 * to the extent tree.
 * When pass the actual path, the caller should calculate credits
 * under i_data_sem.
 */
int ecfs_ext_calc_credits_for_single_extent(struct inode *inode, int nrblocks,
						struct ecfs_ext_path *path)
{
	if (path) {
		int depth = ext_depth(inode);
		int ret = 0;

		/* probably there is space in leaf? */
		if (le16_to_cpu(path[depth].p_hdr->eh_entries)
				< le16_to_cpu(path[depth].p_hdr->eh_max)) {

			/*
			 *  There are some space in the leaf tree, no
			 *  need to account for leaf block credit
			 *
			 *  bitmaps and block group descriptor blocks
			 *  and other metadata blocks still need to be
			 *  accounted.
			 */
			/* 1 bitmap, 1 block group descriptor */
			ret = 2 + ECFS_META_TRANS_BLOCKS(inode->i_sb);
			return ret;
		}
	}

	return ecfs_chunk_trans_blocks(inode, nrblocks);
}

/*
 * How many index/leaf blocks need to change/allocate to add @extents extents?
 *
 * If we add a single extent, then in the worse case, each tree level
 * index/leaf need to be changed in case of the tree split.
 *
 * If more extents are inserted, they could cause the whole tree split more
 * than once, but this is really rare.
 */
int ecfs_ext_index_trans_blocks(struct inode *inode, int extents)
{
	int index;

	/* If we are converting the inline data, only one is needed here. */
	if (ecfs_has_inline_data(inode))
		return 1;

	/*
	 * Extent tree can change between the time we estimate credits and
	 * the time we actually modify the tree. Assume the worst case.
	 */
	if (extents <= 1)
		index = (ECFS_MAX_EXTENT_DEPTH * 2) + extents;
	else
		index = (ECFS_MAX_EXTENT_DEPTH * 3) +
			DIV_ROUND_UP(extents, ecfs_ext_space_block(inode, 0));

	return index;
}

static inline int get_default_free_blocks_flags(struct inode *inode)
{
	if (S_ISDIR(inode->i_mode) || S_ISLNK(inode->i_mode) ||
	    ecfs_test_inode_flag(inode, ECFS_INODE_EA_INODE))
		return ECFS_FREE_BLOCKS_METADATA | ECFS_FREE_BLOCKS_FORGET;
	else if (ecfs_should_journal_data(inode))
		return ECFS_FREE_BLOCKS_FORGET;
	return 0;
}

/*
 * ecfs_rereserve_cluster - increment the reserved cluster count when
 *                          freeing a cluster with a pending reservation
 *
 * @inode - file containing the cluster
 * @lblk - logical block in cluster to be reserved
 *
 * Increments the reserved cluster count and adjusts quota in a bigalloc
 * file system when freeing a partial cluster containing at least one
 * delayed and unwritten block.  A partial cluster meeting that
 * requirement will have a pending reservation.  If so, the
 * RERESERVE_CLUSTER flag is used when calling ecfs_free_blocks() to
 * defer reserved and allocated space accounting to a subsequent call
 * to this function.
 */
static void ecfs_rereserve_cluster(struct inode *inode, ecfs_lblk_t lblk)
{
	struct ecfs_sb_info *sbi = ECFS_SB(inode->i_sb);
	struct ecfs_inode_info *ei = ECFS_I(inode);

	dquot_reclaim_block(inode, ECFS_C2B(sbi, 1));

	spin_lock(&ei->i_block_reservation_lock);
	ei->i_reserved_data_blocks++;
	percpu_counter_add(&sbi->s_dirtyclusters_counter, 1);
	spin_unlock(&ei->i_block_reservation_lock);

	percpu_counter_add(&sbi->s_freeclusters_counter, 1);
	ecfs_remove_pending(inode, lblk);
}

static int ecfs_remove_blocks(handle_t *handle, struct inode *inode,
			      struct ecfs_extent *ex,
			      struct partial_cluster *partial,
			      ecfs_lblk_t from, ecfs_lblk_t to)
{
	struct ecfs_sb_info *sbi = ECFS_SB(inode->i_sb);
	unsigned short ee_len = ecfs_ext_get_actual_len(ex);
	ecfs_fsblk_t last_pblk, pblk;
	ecfs_lblk_t num;
	int flags;

	/* only extent tail removal is allowed */
	if (from < le32_to_cpu(ex->ee_block) ||
	    to != le32_to_cpu(ex->ee_block) + ee_len - 1) {
		ecfs_error(sbi->s_sb,
			   "strange request: removal(2) %u-%u from %u:%u",
			   from, to, le32_to_cpu(ex->ee_block), ee_len);
		return 0;
	}

#ifdef EXTENTS_STATS
	spin_lock(&sbi->s_ext_stats_lock);
	sbi->s_ext_blocks += ee_len;
	sbi->s_ext_extents++;
	if (ee_len < sbi->s_ext_min)
		sbi->s_ext_min = ee_len;
	if (ee_len > sbi->s_ext_max)
		sbi->s_ext_max = ee_len;
	if (ext_depth(inode) > sbi->s_depth_max)
		sbi->s_depth_max = ext_depth(inode);
	spin_unlock(&sbi->s_ext_stats_lock);
#endif

	trace_ecfs_remove_blocks(inode, ex, from, to, partial);

	/*
	 * if we have a partial cluster, and it's different from the
	 * cluster of the last block in the extent, we free it
	 */
	last_pblk = ecfs_ext_pblock(ex) + ee_len - 1;

	if (partial->state != initial &&
	    partial->pclu != ECFS_B2C(sbi, last_pblk)) {
		if (partial->state == tofree) {
			flags = get_default_free_blocks_flags(inode);
			if (ecfs_is_pending(inode, partial->lblk))
				flags |= ECFS_FREE_BLOCKS_RERESERVE_CLUSTER;
			ecfs_free_blocks(handle, inode, NULL,
					 ECFS_C2B(sbi, partial->pclu),
					 sbi->s_cluster_ratio, flags);
			if (flags & ECFS_FREE_BLOCKS_RERESERVE_CLUSTER)
				ecfs_rereserve_cluster(inode, partial->lblk);
		}
		partial->state = initial;
	}

	num = le32_to_cpu(ex->ee_block) + ee_len - from;
	pblk = ecfs_ext_pblock(ex) + ee_len - num;

	/*
	 * We free the partial cluster at the end of the extent (if any),
	 * unless the cluster is used by another extent (partial_cluster
	 * state is nofree).  If a partial cluster exists here, it must be
	 * shared with the last block in the extent.
	 */
	flags = get_default_free_blocks_flags(inode);

	/* partial, left end cluster aligned, right end unaligned */
	if ((ECFS_LBLK_COFF(sbi, to) != sbi->s_cluster_ratio - 1) &&
	    (ECFS_LBLK_CMASK(sbi, to) >= from) &&
	    (partial->state != nofree)) {
		if (ecfs_is_pending(inode, to))
			flags |= ECFS_FREE_BLOCKS_RERESERVE_CLUSTER;
		ecfs_free_blocks(handle, inode, NULL,
				 ECFS_PBLK_CMASK(sbi, last_pblk),
				 sbi->s_cluster_ratio, flags);
		if (flags & ECFS_FREE_BLOCKS_RERESERVE_CLUSTER)
			ecfs_rereserve_cluster(inode, to);
		partial->state = initial;
		flags = get_default_free_blocks_flags(inode);
	}

	flags |= ECFS_FREE_BLOCKS_NOFREE_LAST_CLUSTER;

	/*
	 * For bigalloc file systems, we never free a partial cluster
	 * at the beginning of the extent.  Instead, we check to see if we
	 * need to free it on a subsequent call to ecfs_remove_blocks,
	 * or at the end of ecfs_ext_rm_leaf or ecfs_ext_remove_space.
	 */
	flags |= ECFS_FREE_BLOCKS_NOFREE_FIRST_CLUSTER;
	ecfs_free_blocks(handle, inode, NULL, pblk, num, flags);

	/* reset the partial cluster if we've freed past it */
	if (partial->state != initial && partial->pclu != ECFS_B2C(sbi, pblk))
		partial->state = initial;

	/*
	 * If we've freed the entire extent but the beginning is not left
	 * cluster aligned and is not marked as ineligible for freeing we
	 * record the partial cluster at the beginning of the extent.  It
	 * wasn't freed by the preceding ecfs_free_blocks() call, and we
	 * need to look farther to the left to determine if it's to be freed
	 * (not shared with another extent). Else, reset the partial
	 * cluster - we're either  done freeing or the beginning of the
	 * extent is left cluster aligned.
	 */
	if (ECFS_LBLK_COFF(sbi, from) && num == ee_len) {
		if (partial->state == initial) {
			partial->pclu = ECFS_B2C(sbi, pblk);
			partial->lblk = from;
			partial->state = tofree;
		}
	} else {
		partial->state = initial;
	}

	return 0;
}

/*
 * ecfs_ext_rm_leaf() Removes the extents associated with the
 * blocks appearing between "start" and "end".  Both "start"
 * and "end" must appear in the same extent or EIO is returned.
 *
 * @handle: The journal handle
 * @inode:  The files inode
 * @path:   The path to the leaf
 * @partial_cluster: The cluster which we'll have to free if all extents
 *                   has been released from it.  However, if this value is
 *                   negative, it's a cluster just to the right of the
 *                   punched region and it must not be freed.
 * @start:  The first block to remove
 * @end:   The last block to remove
 */
static int
ecfs_ext_rm_leaf(handle_t *handle, struct inode *inode,
		 struct ecfs_ext_path *path,
		 struct partial_cluster *partial,
		 ecfs_lblk_t start, ecfs_lblk_t end)
{
	struct ecfs_sb_info *sbi = ECFS_SB(inode->i_sb);
	int err = 0, correct_index = 0;
	int depth = ext_depth(inode), credits, revoke_credits;
	struct ecfs_extent_header *eh;
	ecfs_lblk_t a, b;
	unsigned num;
	ecfs_lblk_t ex_ee_block;
	unsigned short ex_ee_len;
	unsigned unwritten = 0;
	struct ecfs_extent *ex;
	ecfs_fsblk_t pblk;

	/* the header must be checked already in ecfs_ext_remove_space() */
	ext_debug(inode, "truncate since %u in leaf to %u\n", start, end);
	if (!path[depth].p_hdr)
		path[depth].p_hdr = ext_block_hdr(path[depth].p_bh);
	eh = path[depth].p_hdr;
	if (unlikely(path[depth].p_hdr == NULL)) {
		ECFS_ERROR_INODE(inode, "path[%d].p_hdr == NULL", depth);
		return -EFSCORRUPTED;
	}
	/* find where to start removing */
	ex = path[depth].p_ext;
	if (!ex)
		ex = EXT_LAST_EXTENT(eh);

	ex_ee_block = le32_to_cpu(ex->ee_block);
	ex_ee_len = ecfs_ext_get_actual_len(ex);

	trace_ecfs_ext_rm_leaf(inode, start, ex, partial);

	while (ex >= EXT_FIRST_EXTENT(eh) &&
			ex_ee_block + ex_ee_len > start) {

		if (ecfs_ext_is_unwritten(ex))
			unwritten = 1;
		else
			unwritten = 0;

		ext_debug(inode, "remove ext %u:[%d]%d\n", ex_ee_block,
			  unwritten, ex_ee_len);
		path[depth].p_ext = ex;

		a = max(ex_ee_block, start);
		b = min(ex_ee_block + ex_ee_len - 1, end);

		ext_debug(inode, "  border %u:%u\n", a, b);

		/* If this extent is beyond the end of the hole, skip it */
		if (end < ex_ee_block) {
			/*
			 * We're going to skip this extent and move to another,
			 * so note that its first cluster is in use to avoid
			 * freeing it when removing blocks.  Eventually, the
			 * right edge of the truncated/punched region will
			 * be just to the left.
			 */
			if (sbi->s_cluster_ratio > 1) {
				pblk = ecfs_ext_pblock(ex);
				partial->pclu = ECFS_B2C(sbi, pblk);
				partial->state = nofree;
			}
			ex--;
			ex_ee_block = le32_to_cpu(ex->ee_block);
			ex_ee_len = ecfs_ext_get_actual_len(ex);
			continue;
		} else if (b != ex_ee_block + ex_ee_len - 1) {
			ECFS_ERROR_INODE(inode,
					 "can not handle truncate %u:%u "
					 "on extent %u:%u",
					 start, end, ex_ee_block,
					 ex_ee_block + ex_ee_len - 1);
			err = -EFSCORRUPTED;
			goto out;
		} else if (a != ex_ee_block) {
			/* remove tail of the extent */
			num = a - ex_ee_block;
		} else {
			/* remove whole extent: excellent! */
			num = 0;
		}
		/*
		 * 3 for leaf, sb, and inode plus 2 (bmap and group
		 * descriptor) for each block group; assume two block
		 * groups plus ex_ee_len/blocks_per_block_group for
		 * the worst case
		 */
		credits = 7 + 2*(ex_ee_len/ECFS_BLOCKS_PER_GROUP(inode->i_sb));
		if (ex == EXT_FIRST_EXTENT(eh)) {
			correct_index = 1;
			credits += (ext_depth(inode)) + 1;
		}
		credits += ECFS_MAXQUOTAS_TRANS_BLOCKS(inode->i_sb);
		/*
		 * We may end up freeing some index blocks and data from the
		 * punched range. Note that partial clusters are accounted for
		 * by ecfs_free_data_revoke_credits().
		 */
		revoke_credits =
			ecfs_free_metadata_revoke_credits(inode->i_sb,
							  ext_depth(inode)) +
			ecfs_free_data_revoke_credits(inode, b - a + 1);

		err = ecfs_datasem_ensure_credits(handle, inode, credits,
						  credits, revoke_credits);
		if (err) {
			if (err > 0)
				err = -EAGAIN;
			goto out;
		}

		err = ecfs_ext_get_access(handle, inode, path + depth);
		if (err)
			goto out;

		err = ecfs_remove_blocks(handle, inode, ex, partial, a, b);
		if (err)
			goto out;

		if (num == 0)
			/* this extent is removed; mark slot entirely unused */
			ecfs_ext_store_pblock(ex, 0);

		ex->ee_len = cpu_to_le16(num);
		/*
		 * Do not mark unwritten if all the blocks in the
		 * extent have been removed.
		 */
		if (unwritten && num)
			ecfs_ext_mark_unwritten(ex);
		/*
		 * If the extent was completely released,
		 * we need to remove it from the leaf
		 */
		if (num == 0) {
			if (end != EXT_MAX_BLOCKS - 1) {
				/*
				 * For hole punching, we need to scoot all the
				 * extents up when an extent is removed so that
				 * we dont have blank extents in the middle
				 */
				memmove(ex, ex+1, (EXT_LAST_EXTENT(eh) - ex) *
					sizeof(struct ecfs_extent));

				/* Now get rid of the one at the end */
				memset(EXT_LAST_EXTENT(eh), 0,
					sizeof(struct ecfs_extent));
			}
			le16_add_cpu(&eh->eh_entries, -1);
		}

		err = ecfs_ext_dirty(handle, inode, path + depth);
		if (err)
			goto out;

		ext_debug(inode, "new extent: %u:%u:%llu\n", ex_ee_block, num,
				ecfs_ext_pblock(ex));
		ex--;
		ex_ee_block = le32_to_cpu(ex->ee_block);
		ex_ee_len = ecfs_ext_get_actual_len(ex);
	}

	if (correct_index && eh->eh_entries)
		err = ecfs_ext_correct_indexes(handle, inode, path);

	/*
	 * If there's a partial cluster and at least one extent remains in
	 * the leaf, free the partial cluster if it isn't shared with the
	 * current extent.  If it is shared with the current extent
	 * we reset the partial cluster because we've reached the start of the
	 * truncated/punched region and we're done removing blocks.
	 */
	if (partial->state == tofree && ex >= EXT_FIRST_EXTENT(eh)) {
		pblk = ecfs_ext_pblock(ex) + ex_ee_len - 1;
		if (partial->pclu != ECFS_B2C(sbi, pblk)) {
			int flags = get_default_free_blocks_flags(inode);

			if (ecfs_is_pending(inode, partial->lblk))
				flags |= ECFS_FREE_BLOCKS_RERESERVE_CLUSTER;
			ecfs_free_blocks(handle, inode, NULL,
					 ECFS_C2B(sbi, partial->pclu),
					 sbi->s_cluster_ratio, flags);
			if (flags & ECFS_FREE_BLOCKS_RERESERVE_CLUSTER)
				ecfs_rereserve_cluster(inode, partial->lblk);
		}
		partial->state = initial;
	}

	/* if this leaf is free, then we should
	 * remove it from index block above */
	if (err == 0 && eh->eh_entries == 0 && path[depth].p_bh != NULL)
		err = ecfs_ext_rm_idx(handle, inode, path, depth);

out:
	return err;
}

/*
 * ecfs_ext_more_to_rm:
 * returns 1 if current index has to be freed (even partial)
 */
static int
ecfs_ext_more_to_rm(struct ecfs_ext_path *path)
{
	BUG_ON(path->p_idx == NULL);

	if (path->p_idx < EXT_FIRST_INDEX(path->p_hdr))
		return 0;

	/*
	 * if truncate on deeper level happened, it wasn't partial,
	 * so we have to consider current index for truncation
	 */
	if (le16_to_cpu(path->p_hdr->eh_entries) == path->p_block)
		return 0;
	return 1;
}

int ecfs_ext_remove_space(struct inode *inode, ecfs_lblk_t start,
			  ecfs_lblk_t end)
{
	struct ecfs_sb_info *sbi = ECFS_SB(inode->i_sb);
	int depth = ext_depth(inode);
	struct ecfs_ext_path *path = NULL;
	struct partial_cluster partial;
	handle_t *handle;
	int i = 0, err = 0;
	int flags = ECFS_EX_NOCACHE | ECFS_EX_NOFAIL;

	partial.pclu = 0;
	partial.lblk = 0;
	partial.state = initial;

	ext_debug(inode, "truncate since %u to %u\n", start, end);

	/* probably first extent we're gonna free will be last in block */
	handle = ecfs_journal_start_with_revoke(inode, ECFS_HT_TRUNCATE,
			depth + 1,
			ecfs_free_metadata_revoke_credits(inode->i_sb, depth));
	if (IS_ERR(handle))
		return PTR_ERR(handle);

again:
	trace_ecfs_ext_remove_space(inode, start, end, depth);

	/*
	 * Check if we are removing extents inside the extent tree. If that
	 * is the case, we are going to punch a hole inside the extent tree
	 * so we have to check whether we need to split the extent covering
	 * the last block to remove so we can easily remove the part of it
	 * in ecfs_ext_rm_leaf().
	 */
	if (end < EXT_MAX_BLOCKS - 1) {
		struct ecfs_extent *ex;
		ecfs_lblk_t ee_block, ex_end, lblk;
		ecfs_fsblk_t pblk;

		/* find extent for or closest extent to this block */
		path = ecfs_find_extent(inode, end, NULL, flags);
		if (IS_ERR(path)) {
			ecfs_journal_stop(handle);
			return PTR_ERR(path);
		}
		depth = ext_depth(inode);
		/* Leaf not may not exist only if inode has no blocks at all */
		ex = path[depth].p_ext;
		if (!ex) {
			if (depth) {
				ECFS_ERROR_INODE(inode,
						 "path[%d].p_hdr == NULL",
						 depth);
				err = -EFSCORRUPTED;
			}
			goto out;
		}

		ee_block = le32_to_cpu(ex->ee_block);
		ex_end = ee_block + ecfs_ext_get_actual_len(ex) - 1;

		/*
		 * See if the last block is inside the extent, if so split
		 * the extent at 'end' block so we can easily remove the
		 * tail of the first part of the split extent in
		 * ecfs_ext_rm_leaf().
		 */
		if (end >= ee_block && end < ex_end) {

			/*
			 * If we're going to split the extent, note that
			 * the cluster containing the block after 'end' is
			 * in use to avoid freeing it when removing blocks.
			 */
			if (sbi->s_cluster_ratio > 1) {
				pblk = ecfs_ext_pblock(ex) + end - ee_block + 1;
				partial.pclu = ECFS_B2C(sbi, pblk);
				partial.state = nofree;
			}

			/*
			 * Split the extent in two so that 'end' is the last
			 * block in the first new extent. Also we should not
			 * fail removing space due to ENOSPC so try to use
			 * reserved block if that happens.
			 */
			path = ecfs_force_split_extent_at(handle, inode, path,
							  end + 1, 1);
			if (IS_ERR(path)) {
				err = PTR_ERR(path);
				goto out;
			}
		} else if (sbi->s_cluster_ratio > 1 && end >= ex_end &&
			   partial.state == initial) {
			/*
			 * If we're punching, there's an extent to the right.
			 * If the partial cluster hasn't been set, set it to
			 * that extent's first cluster and its state to nofree
			 * so it won't be freed should it contain blocks to be
			 * removed. If it's already set (tofree/nofree), we're
			 * retrying and keep the original partial cluster info
			 * so a cluster marked tofree as a result of earlier
			 * extent removal is not lost.
			 */
			lblk = ex_end + 1;
			err = ecfs_ext_search_right(inode, path, &lblk, &pblk,
						    NULL, flags);
			if (err < 0)
				goto out;
			if (pblk) {
				partial.pclu = ECFS_B2C(sbi, pblk);
				partial.state = nofree;
			}
		}
	}
	/*
	 * We start scanning from right side, freeing all the blocks
	 * after i_size and walking into the tree depth-wise.
	 */
	depth = ext_depth(inode);
	if (path) {
		int k = i = depth;
		while (--k > 0)
			path[k].p_block =
				le16_to_cpu(path[k].p_hdr->eh_entries)+1;
	} else {
		path = kcalloc(depth + 1, sizeof(struct ecfs_ext_path),
			       GFP_NOFS | __GFP_NOFAIL);
		if (path == NULL) {
			ecfs_journal_stop(handle);
			return -ENOMEM;
		}
		path[0].p_maxdepth = path[0].p_depth = depth;
		path[0].p_hdr = ext_inode_hdr(inode);
		i = 0;

		if (ecfs_ext_check(inode, path[0].p_hdr, depth, 0)) {
			err = -EFSCORRUPTED;
			goto out;
		}
	}
	err = 0;

	while (i >= 0 && err == 0) {
		if (i == depth) {
			/* this is leaf block */
			err = ecfs_ext_rm_leaf(handle, inode, path,
					       &partial, start, end);
			/* root level has p_bh == NULL, brelse() eats this */
			ecfs_ext_path_brelse(path + i);
			i--;
			continue;
		}

		/* this is index block */
		if (!path[i].p_hdr) {
			ext_debug(inode, "initialize header\n");
			path[i].p_hdr = ext_block_hdr(path[i].p_bh);
		}

		if (!path[i].p_idx) {
			/* this level hasn't been touched yet */
			path[i].p_idx = EXT_LAST_INDEX(path[i].p_hdr);
			path[i].p_block = le16_to_cpu(path[i].p_hdr->eh_entries)+1;
			ext_debug(inode, "init index ptr: hdr 0x%p, num %d\n",
				  path[i].p_hdr,
				  le16_to_cpu(path[i].p_hdr->eh_entries));
		} else {
			/* we were already here, see at next index */
			path[i].p_idx--;
		}

		ext_debug(inode, "level %d - index, first 0x%p, cur 0x%p\n",
				i, EXT_FIRST_INDEX(path[i].p_hdr),
				path[i].p_idx);
		if (ecfs_ext_more_to_rm(path + i)) {
			struct buffer_head *bh;
			/* go to the next level */
			ext_debug(inode, "move to level %d (block %llu)\n",
				  i + 1, ecfs_idx_pblock(path[i].p_idx));
			memset(path + i + 1, 0, sizeof(*path));
			bh = read_extent_tree_block(inode, path[i].p_idx,
						    depth - i - 1, flags);
			if (IS_ERR(bh)) {
				/* should we reset i_size? */
				err = PTR_ERR(bh);
				break;
			}
			/* Yield here to deal with large extent trees.
			 * Should be a no-op if we did IO above. */
			cond_resched();
			if (WARN_ON(i + 1 > depth)) {
				err = -EFSCORRUPTED;
				break;
			}
			path[i + 1].p_bh = bh;

			/* save actual number of indexes since this
			 * number is changed at the next iteration */
			path[i].p_block = le16_to_cpu(path[i].p_hdr->eh_entries);
			i++;
		} else {
			/* we finished processing this index, go up */
			if (path[i].p_hdr->eh_entries == 0 && i > 0) {
				/* index is empty, remove it;
				 * handle must be already prepared by the
				 * truncatei_leaf() */
				err = ecfs_ext_rm_idx(handle, inode, path, i);
			}
			/* root level has p_bh == NULL, brelse() eats this */
			ecfs_ext_path_brelse(path + i);
			i--;
			ext_debug(inode, "return to level %d\n", i);
		}
	}

	trace_ecfs_ext_remove_space_done(inode, start, end, depth, &partial,
					 path->p_hdr->eh_entries);

	/*
	 * if there's a partial cluster and we have removed the first extent
	 * in the file, then we also free the partial cluster, if any
	 */
	if (partial.state == tofree && err == 0) {
		int flags = get_default_free_blocks_flags(inode);

		if (ecfs_is_pending(inode, partial.lblk))
			flags |= ECFS_FREE_BLOCKS_RERESERVE_CLUSTER;
		ecfs_free_blocks(handle, inode, NULL,
				 ECFS_C2B(sbi, partial.pclu),
				 sbi->s_cluster_ratio, flags);
		if (flags & ECFS_FREE_BLOCKS_RERESERVE_CLUSTER)
			ecfs_rereserve_cluster(inode, partial.lblk);
		partial.state = initial;
	}

	/* TODO: flexible tree reduction should be here */
	if (path->p_hdr->eh_entries == 0) {
		/*
		 * truncate to zero freed all the tree,
		 * so we need to correct eh_depth
		 */
		err = ecfs_ext_get_access(handle, inode, path);
		if (err == 0) {
			ext_inode_hdr(inode)->eh_depth = 0;
			ext_inode_hdr(inode)->eh_max =
				cpu_to_le16(ecfs_ext_space_root(inode, 0));
			err = ecfs_ext_dirty(handle, inode, path);
		}
	}
out:
	ecfs_free_ext_path(path);
	path = NULL;
	if (err == -EAGAIN)
		goto again;
	ecfs_journal_stop(handle);

	return err;
}

/*
 * called at mount time
 */
void ecfs_ext_init(struct super_block *sb)
{
	/*
	 * possible initialization would be here
	 */

	if (ecfs_has_feature_extents(sb)) {
#if defined(AGGRESSIVE_TEST) || defined(CHECK_BINSEARCH) || defined(EXTENTS_STATS)
		printk(KERN_INFO "ECFS-fs: file extents enabled"
#ifdef AGGRESSIVE_TEST
		       ", aggressive tests"
#endif
#ifdef CHECK_BINSEARCH
		       ", check binsearch"
#endif
#ifdef EXTENTS_STATS
		       ", stats"
#endif
		       "\n");
#endif
#ifdef EXTENTS_STATS
		spin_lock_init(&ECFS_SB(sb)->s_ext_stats_lock);
		ECFS_SB(sb)->s_ext_min = 1 << 30;
		ECFS_SB(sb)->s_ext_max = 0;
#endif
	}
}

/*
 * called at umount time
 */
void ecfs_ext_release(struct super_block *sb)
{
	if (!ecfs_has_feature_extents(sb))
		return;

#ifdef EXTENTS_STATS
	if (ECFS_SB(sb)->s_ext_blocks && ECFS_SB(sb)->s_ext_extents) {
		struct ecfs_sb_info *sbi = ECFS_SB(sb);
		printk(KERN_ERR "ECFS-fs: %lu blocks in %lu extents (%lu ave)\n",
			sbi->s_ext_blocks, sbi->s_ext_extents,
			sbi->s_ext_blocks / sbi->s_ext_extents);
		printk(KERN_ERR "ECFS-fs: extents: %lu min, %lu max, max depth %lu\n",
			sbi->s_ext_min, sbi->s_ext_max, sbi->s_depth_max);
	}
#endif
}

static void ecfs_zeroout_es(struct inode *inode, struct ecfs_extent *ex)
{
	ecfs_lblk_t  ee_block;
	ecfs_fsblk_t ee_pblock;
	unsigned int ee_len;

	ee_block  = le32_to_cpu(ex->ee_block);
	ee_len    = ecfs_ext_get_actual_len(ex);
	ee_pblock = ecfs_ext_pblock(ex);

	if (ee_len == 0)
		return;

	ecfs_es_insert_extent(inode, ee_block, ee_len, ee_pblock,
			      EXTENT_STATUS_WRITTEN, false);
}

/* FIXME!! we need to try to merge to left or right after zero-out  */
static int ecfs_ext_zeroout(struct inode *inode, struct ecfs_extent *ex)
{
	ecfs_fsblk_t ee_pblock;
	unsigned int ee_len;

	ee_len    = ecfs_ext_get_actual_len(ex);
	ee_pblock = ecfs_ext_pblock(ex);
	return ecfs_issue_zeroout(inode, le32_to_cpu(ex->ee_block), ee_pblock,
				  ee_len);
}

/*
 * ecfs_split_extent_at() splits an extent at given block.
 *
 * @handle: the journal handle
 * @inode: the file inode
 * @path: the path to the extent
 * @split: the logical block where the extent is splitted.
 * @split_flags: indicates if the extent could be zeroout if split fails, and
 *		 the states(init or unwritten) of new extents.
 * @flags: flags used to insert new extent to extent tree.
 *
 *
 * Splits extent [a, b] into two extents [a, @split) and [@split, b], states
 * of which are determined by split_flag.
 *
 * There are two cases:
 *  a> the extent are splitted into two extent.
 *  b> split is not needed, and just mark the extent.
 *
 * Return an extent path pointer on success, or an error pointer on failure.
 */
static struct ecfs_ext_path *ecfs_split_extent_at(handle_t *handle,
						  struct inode *inode,
						  struct ecfs_ext_path *path,
						  ecfs_lblk_t split,
						  int split_flag, int flags)
{
	ecfs_fsblk_t newblock;
	ecfs_lblk_t ee_block;
	struct ecfs_extent *ex, newex, orig_ex, zero_ex;
	struct ecfs_extent *ex2 = NULL;
	unsigned int ee_len, depth;
	int err = 0;

	BUG_ON((split_flag & (ECFS_EXT_DATA_VALID1 | ECFS_EXT_DATA_VALID2)) ==
	       (ECFS_EXT_DATA_VALID1 | ECFS_EXT_DATA_VALID2));

	ext_debug(inode, "logical block %llu\n", (unsigned long long)split);

	ecfs_ext_show_leaf(inode, path);

	depth = ext_depth(inode);
	ex = path[depth].p_ext;
	ee_block = le32_to_cpu(ex->ee_block);
	ee_len = ecfs_ext_get_actual_len(ex);
	newblock = split - ee_block + ecfs_ext_pblock(ex);

	BUG_ON(split < ee_block || split >= (ee_block + ee_len));
	BUG_ON(!ecfs_ext_is_unwritten(ex) &&
	       split_flag & (ECFS_EXT_MAY_ZEROOUT |
			     ECFS_EXT_MARK_UNWRIT1 |
			     ECFS_EXT_MARK_UNWRIT2));

	err = ecfs_ext_get_access(handle, inode, path + depth);
	if (err)
		goto out;

	if (split == ee_block) {
		/*
		 * case b: block @split is the block that the extent begins with
		 * then we just change the state of the extent, and splitting
		 * is not needed.
		 */
		if (split_flag & ECFS_EXT_MARK_UNWRIT2)
			ecfs_ext_mark_unwritten(ex);
		else
			ecfs_ext_mark_initialized(ex);

		if (!(flags & ECFS_GET_BLOCKS_PRE_IO))
			ecfs_ext_try_to_merge(handle, inode, path, ex);

		err = ecfs_ext_dirty(handle, inode, path + path->p_depth);
		goto out;
	}

	/* case a */
	memcpy(&orig_ex, ex, sizeof(orig_ex));
	ex->ee_len = cpu_to_le16(split - ee_block);
	if (split_flag & ECFS_EXT_MARK_UNWRIT1)
		ecfs_ext_mark_unwritten(ex);

	/*
	 * path may lead to new leaf, not to original leaf any more
	 * after ecfs_ext_insert_extent() returns,
	 */
	err = ecfs_ext_dirty(handle, inode, path + depth);
	if (err)
		goto fix_extent_len;

	ex2 = &newex;
	ex2->ee_block = cpu_to_le32(split);
	ex2->ee_len   = cpu_to_le16(ee_len - (split - ee_block));
	ecfs_ext_store_pblock(ex2, newblock);
	if (split_flag & ECFS_EXT_MARK_UNWRIT2)
		ecfs_ext_mark_unwritten(ex2);

	path = ecfs_ext_insert_extent(handle, inode, path, &newex, flags);
	if (!IS_ERR(path))
		goto out;

	err = PTR_ERR(path);
	if (err != -ENOSPC && err != -EDQUOT && err != -ENOMEM)
		return path;

	/*
	 * Get a new path to try to zeroout or fix the extent length.
	 * Using ECFS_EX_NOFAIL guarantees that ecfs_find_extent()
	 * will not return -ENOMEM, otherwise -ENOMEM will cause a
	 * retry in do_writepages(), and a WARN_ON may be triggered
	 * in ecfs_da_update_reserve_space() due to an incorrect
	 * ee_len causing the i_reserved_data_blocks exception.
	 */
	path = ecfs_find_extent(inode, ee_block, NULL, flags | ECFS_EX_NOFAIL);
	if (IS_ERR(path)) {
		ECFS_ERROR_INODE(inode, "Failed split extent on %u, err %ld",
				 split, PTR_ERR(path));
		return path;
	}
	depth = ext_depth(inode);
	ex = path[depth].p_ext;

	if (ECFS_EXT_MAY_ZEROOUT & split_flag) {
		if (split_flag & (ECFS_EXT_DATA_VALID1|ECFS_EXT_DATA_VALID2)) {
			if (split_flag & ECFS_EXT_DATA_VALID1) {
				err = ecfs_ext_zeroout(inode, ex2);
				zero_ex.ee_block = ex2->ee_block;
				zero_ex.ee_len = cpu_to_le16(
						ecfs_ext_get_actual_len(ex2));
				ecfs_ext_store_pblock(&zero_ex,
						      ecfs_ext_pblock(ex2));
			} else {
				err = ecfs_ext_zeroout(inode, ex);
				zero_ex.ee_block = ex->ee_block;
				zero_ex.ee_len = cpu_to_le16(
						ecfs_ext_get_actual_len(ex));
				ecfs_ext_store_pblock(&zero_ex,
						      ecfs_ext_pblock(ex));
			}
		} else {
			err = ecfs_ext_zeroout(inode, &orig_ex);
			zero_ex.ee_block = orig_ex.ee_block;
			zero_ex.ee_len = cpu_to_le16(
						ecfs_ext_get_actual_len(&orig_ex));
			ecfs_ext_store_pblock(&zero_ex,
					      ecfs_ext_pblock(&orig_ex));
		}

		if (!err) {
			/* update the extent length and mark as initialized */
			ex->ee_len = cpu_to_le16(ee_len);
			ecfs_ext_try_to_merge(handle, inode, path, ex);
			err = ecfs_ext_dirty(handle, inode, path + path->p_depth);
			if (!err)
				/* update extent status tree */
				ecfs_zeroout_es(inode, &zero_ex);
			/* If we failed at this point, we don't know in which
			 * state the extent tree exactly is so don't try to fix
			 * length of the original extent as it may do even more
			 * damage.
			 */
			goto out;
		}
	}

fix_extent_len:
	ex->ee_len = orig_ex.ee_len;
	/*
	 * Ignore ecfs_ext_dirty return value since we are already in error path
	 * and err is a non-zero error code.
	 */
	ecfs_ext_dirty(handle, inode, path + path->p_depth);
out:
	if (err) {
		ecfs_free_ext_path(path);
		path = ERR_PTR(err);
	}
	ecfs_ext_show_leaf(inode, path);
	return path;
}

/*
 * ecfs_split_extent() splits an extent and mark extent which is covered
 * by @map as split_flags indicates
 *
 * It may result in splitting the extent into multiple extents (up to three)
 * There are three possibilities:
 *   a> There is no split required
 *   b> Splits in two extents: Split is happening at either end of the extent
 *   c> Splits in three extents: Somone is splitting in middle of the extent
 *
 */
static struct ecfs_ext_path *ecfs_split_extent(handle_t *handle,
					       struct inode *inode,
					       struct ecfs_ext_path *path,
					       struct ecfs_map_blocks *map,
					       int split_flag, int flags,
					       unsigned int *allocated)
{
	ecfs_lblk_t ee_block;
	struct ecfs_extent *ex;
	unsigned int ee_len, depth;
	int unwritten;
	int split_flag1, flags1;

	depth = ext_depth(inode);
	ex = path[depth].p_ext;
	ee_block = le32_to_cpu(ex->ee_block);
	ee_len = ecfs_ext_get_actual_len(ex);
	unwritten = ecfs_ext_is_unwritten(ex);

	if (map->m_lblk + map->m_len < ee_block + ee_len) {
		split_flag1 = split_flag & ECFS_EXT_MAY_ZEROOUT;
		flags1 = flags | ECFS_GET_BLOCKS_PRE_IO;
		if (unwritten)
			split_flag1 |= ECFS_EXT_MARK_UNWRIT1 |
				       ECFS_EXT_MARK_UNWRIT2;
		if (split_flag & ECFS_EXT_DATA_VALID2)
			split_flag1 |= ECFS_EXT_DATA_VALID1;
		path = ecfs_split_extent_at(handle, inode, path,
				map->m_lblk + map->m_len, split_flag1, flags1);
		if (IS_ERR(path))
			return path;
		/*
		 * Update path is required because previous ecfs_split_extent_at
		 * may result in split of original leaf or extent zeroout.
		 */
		path = ecfs_find_extent(inode, map->m_lblk, path, flags);
		if (IS_ERR(path))
			return path;
		depth = ext_depth(inode);
		ex = path[depth].p_ext;
		if (!ex) {
			ECFS_ERROR_INODE(inode, "unexpected hole at %lu",
					(unsigned long) map->m_lblk);
			ecfs_free_ext_path(path);
			return ERR_PTR(-EFSCORRUPTED);
		}
		unwritten = ecfs_ext_is_unwritten(ex);
	}

	if (map->m_lblk >= ee_block) {
		split_flag1 = split_flag & ECFS_EXT_DATA_VALID2;
		if (unwritten) {
			split_flag1 |= ECFS_EXT_MARK_UNWRIT1;
			split_flag1 |= split_flag & (ECFS_EXT_MAY_ZEROOUT |
						     ECFS_EXT_MARK_UNWRIT2);
		}
		path = ecfs_split_extent_at(handle, inode, path,
				map->m_lblk, split_flag1, flags);
		if (IS_ERR(path))
			return path;
	}

	if (allocated) {
		if (map->m_lblk + map->m_len > ee_block + ee_len)
			*allocated = ee_len - (map->m_lblk - ee_block);
		else
			*allocated = map->m_len;
	}
	ecfs_ext_show_leaf(inode, path);
	return path;
}

/*
 * This function is called by ecfs_ext_map_blocks() if someone tries to write
 * to an unwritten extent. It may result in splitting the unwritten
 * extent into multiple extents (up to three - one initialized and two
 * unwritten).
 * There are three possibilities:
 *   a> There is no split required: Entire extent should be initialized
 *   b> Splits in two extents: Write is happening at either end of the extent
 *   c> Splits in three extents: Somone is writing in middle of the extent
 *
 * Pre-conditions:
 *  - The extent pointed to by 'path' is unwritten.
 *  - The extent pointed to by 'path' contains a superset
 *    of the logical span [map->m_lblk, map->m_lblk + map->m_len).
 *
 * Post-conditions on success:
 *  - the returned value is the number of blocks beyond map->l_lblk
 *    that are allocated and initialized.
 *    It is guaranteed to be >= map->m_len.
 */
static struct ecfs_ext_path *
ecfs_ext_convert_to_initialized(handle_t *handle, struct inode *inode,
			struct ecfs_map_blocks *map, struct ecfs_ext_path *path,
			int flags, unsigned int *allocated)
{
	struct ecfs_sb_info *sbi;
	struct ecfs_extent_header *eh;
	struct ecfs_map_blocks split_map;
	struct ecfs_extent zero_ex1, zero_ex2;
	struct ecfs_extent *ex, *abut_ex;
	ecfs_lblk_t ee_block, eof_block;
	unsigned int ee_len, depth, map_len = map->m_len;
	int err = 0;
	int split_flag = ECFS_EXT_DATA_VALID2;
	unsigned int max_zeroout = 0;

	ext_debug(inode, "logical block %llu, max_blocks %u\n",
		  (unsigned long long)map->m_lblk, map_len);

	sbi = ECFS_SB(inode->i_sb);
	eof_block = (ECFS_I(inode)->i_disksize + inode->i_sb->s_blocksize - 1)
			>> inode->i_sb->s_blocksize_bits;
	if (eof_block < map->m_lblk + map_len)
		eof_block = map->m_lblk + map_len;

	depth = ext_depth(inode);
	eh = path[depth].p_hdr;
	ex = path[depth].p_ext;
	ee_block = le32_to_cpu(ex->ee_block);
	ee_len = ecfs_ext_get_actual_len(ex);
	zero_ex1.ee_len = 0;
	zero_ex2.ee_len = 0;

	trace_ecfs_ext_convert_to_initialized_enter(inode, map, ex);

	/* Pre-conditions */
	BUG_ON(!ecfs_ext_is_unwritten(ex));
	BUG_ON(!in_range(map->m_lblk, ee_block, ee_len));

	/*
	 * Attempt to transfer newly initialized blocks from the currently
	 * unwritten extent to its neighbor. This is much cheaper
	 * than an insertion followed by a merge as those involve costly
	 * memmove() calls. Transferring to the left is the common case in
	 * steady state for workloads doing fallocate(FALLOC_FL_KEEP_SIZE)
	 * followed by append writes.
	 *
	 * Limitations of the current logic:
	 *  - L1: we do not deal with writes covering the whole extent.
	 *    This would require removing the extent if the transfer
	 *    is possible.
	 *  - L2: we only attempt to merge with an extent stored in the
	 *    same extent tree node.
	 */
	*allocated = 0;
	if ((map->m_lblk == ee_block) &&
		/* See if we can merge left */
		(map_len < ee_len) &&		/*L1*/
		(ex > EXT_FIRST_EXTENT(eh))) {	/*L2*/
		ecfs_lblk_t prev_lblk;
		ecfs_fsblk_t prev_pblk, ee_pblk;
		unsigned int prev_len;

		abut_ex = ex - 1;
		prev_lblk = le32_to_cpu(abut_ex->ee_block);
		prev_len = ecfs_ext_get_actual_len(abut_ex);
		prev_pblk = ecfs_ext_pblock(abut_ex);
		ee_pblk = ecfs_ext_pblock(ex);

		/*
		 * A transfer of blocks from 'ex' to 'abut_ex' is allowed
		 * upon those conditions:
		 * - C1: abut_ex is initialized,
		 * - C2: abut_ex is logically abutting ex,
		 * - C3: abut_ex is physically abutting ex,
		 * - C4: abut_ex can receive the additional blocks without
		 *   overflowing the (initialized) length limit.
		 */
		if ((!ecfs_ext_is_unwritten(abut_ex)) &&		/*C1*/
			((prev_lblk + prev_len) == ee_block) &&		/*C2*/
			((prev_pblk + prev_len) == ee_pblk) &&		/*C3*/
			(prev_len < (EXT_INIT_MAX_LEN - map_len))) {	/*C4*/
			err = ecfs_ext_get_access(handle, inode, path + depth);
			if (err)
				goto errout;

			trace_ecfs_ext_convert_to_initialized_fastpath(inode,
				map, ex, abut_ex);

			/* Shift the start of ex by 'map_len' blocks */
			ex->ee_block = cpu_to_le32(ee_block + map_len);
			ecfs_ext_store_pblock(ex, ee_pblk + map_len);
			ex->ee_len = cpu_to_le16(ee_len - map_len);
			ecfs_ext_mark_unwritten(ex); /* Restore the flag */

			/* Extend abut_ex by 'map_len' blocks */
			abut_ex->ee_len = cpu_to_le16(prev_len + map_len);

			/* Result: number of initialized blocks past m_lblk */
			*allocated = map_len;
		}
	} else if (((map->m_lblk + map_len) == (ee_block + ee_len)) &&
		   (map_len < ee_len) &&	/*L1*/
		   ex < EXT_LAST_EXTENT(eh)) {	/*L2*/
		/* See if we can merge right */
		ecfs_lblk_t next_lblk;
		ecfs_fsblk_t next_pblk, ee_pblk;
		unsigned int next_len;

		abut_ex = ex + 1;
		next_lblk = le32_to_cpu(abut_ex->ee_block);
		next_len = ecfs_ext_get_actual_len(abut_ex);
		next_pblk = ecfs_ext_pblock(abut_ex);
		ee_pblk = ecfs_ext_pblock(ex);

		/*
		 * A transfer of blocks from 'ex' to 'abut_ex' is allowed
		 * upon those conditions:
		 * - C1: abut_ex is initialized,
		 * - C2: abut_ex is logically abutting ex,
		 * - C3: abut_ex is physically abutting ex,
		 * - C4: abut_ex can receive the additional blocks without
		 *   overflowing the (initialized) length limit.
		 */
		if ((!ecfs_ext_is_unwritten(abut_ex)) &&		/*C1*/
		    ((map->m_lblk + map_len) == next_lblk) &&		/*C2*/
		    ((ee_pblk + ee_len) == next_pblk) &&		/*C3*/
		    (next_len < (EXT_INIT_MAX_LEN - map_len))) {	/*C4*/
			err = ecfs_ext_get_access(handle, inode, path + depth);
			if (err)
				goto errout;

			trace_ecfs_ext_convert_to_initialized_fastpath(inode,
				map, ex, abut_ex);

			/* Shift the start of abut_ex by 'map_len' blocks */
			abut_ex->ee_block = cpu_to_le32(next_lblk - map_len);
			ecfs_ext_store_pblock(abut_ex, next_pblk - map_len);
			ex->ee_len = cpu_to_le16(ee_len - map_len);
			ecfs_ext_mark_unwritten(ex); /* Restore the flag */

			/* Extend abut_ex by 'map_len' blocks */
			abut_ex->ee_len = cpu_to_le16(next_len + map_len);

			/* Result: number of initialized blocks past m_lblk */
			*allocated = map_len;
		}
	}
	if (*allocated) {
		/* Mark the block containing both extents as dirty */
		err = ecfs_ext_dirty(handle, inode, path + depth);

		/* Update path to point to the right extent */
		path[depth].p_ext = abut_ex;
		if (err)
			goto errout;
		goto out;
	} else
		*allocated = ee_len - (map->m_lblk - ee_block);

	WARN_ON(map->m_lblk < ee_block);
	/*
	 * It is safe to convert extent to initialized via explicit
	 * zeroout only if extent is fully inside i_size or new_size.
	 */
	split_flag |= ee_block + ee_len <= eof_block ? ECFS_EXT_MAY_ZEROOUT : 0;

	if (ECFS_EXT_MAY_ZEROOUT & split_flag)
		max_zeroout = sbi->s_extent_max_zeroout_kb >>
			(inode->i_sb->s_blocksize_bits - 10);

	/*
	 * five cases:
	 * 1. split the extent into three extents.
	 * 2. split the extent into two extents, zeroout the head of the first
	 *    extent.
	 * 3. split the extent into two extents, zeroout the tail of the second
	 *    extent.
	 * 4. split the extent into two extents with out zeroout.
	 * 5. no splitting needed, just possibly zeroout the head and / or the
	 *    tail of the extent.
	 */
	split_map.m_lblk = map->m_lblk;
	split_map.m_len = map->m_len;

	if (max_zeroout && (*allocated > split_map.m_len)) {
		if (*allocated <= max_zeroout) {
			/* case 3 or 5 */
			zero_ex1.ee_block =
				 cpu_to_le32(split_map.m_lblk +
					     split_map.m_len);
			zero_ex1.ee_len =
				cpu_to_le16(*allocated - split_map.m_len);
			ecfs_ext_store_pblock(&zero_ex1,
				ecfs_ext_pblock(ex) + split_map.m_lblk +
				split_map.m_len - ee_block);
			err = ecfs_ext_zeroout(inode, &zero_ex1);
			if (err)
				goto fallback;
			split_map.m_len = *allocated;
		}
		if (split_map.m_lblk - ee_block + split_map.m_len <
								max_zeroout) {
			/* case 2 or 5 */
			if (split_map.m_lblk != ee_block) {
				zero_ex2.ee_block = ex->ee_block;
				zero_ex2.ee_len = cpu_to_le16(split_map.m_lblk -
							ee_block);
				ecfs_ext_store_pblock(&zero_ex2,
						      ecfs_ext_pblock(ex));
				err = ecfs_ext_zeroout(inode, &zero_ex2);
				if (err)
					goto fallback;
			}

			split_map.m_len += split_map.m_lblk - ee_block;
			split_map.m_lblk = ee_block;
			*allocated = map->m_len;
		}
	}

fallback:
	path = ecfs_split_extent(handle, inode, path, &split_map, split_flag,
				 flags, NULL);
	if (IS_ERR(path))
		return path;
out:
	/* If we have gotten a failure, don't zero out status tree */
	ecfs_zeroout_es(inode, &zero_ex1);
	ecfs_zeroout_es(inode, &zero_ex2);
	return path;

errout:
	ecfs_free_ext_path(path);
	return ERR_PTR(err);
}

/*
 * This function is called by ecfs_ext_map_blocks() from
 * ecfs_get_blocks_dio_write() when DIO to write
 * to an unwritten extent.
 *
 * Writing to an unwritten extent may result in splitting the unwritten
 * extent into multiple initialized/unwritten extents (up to three)
 * There are three possibilities:
 *   a> There is no split required: Entire extent should be unwritten
 *   b> Splits in two extents: Write is happening at either end of the extent
 *   c> Splits in three extents: Somone is writing in middle of the extent
 *
 * This works the same way in the case of initialized -> unwritten conversion.
 *
 * One of more index blocks maybe needed if the extent tree grow after
 * the unwritten extent split. To prevent ENOSPC occur at the IO
 * complete, we need to split the unwritten extent before DIO submit
 * the IO. The unwritten extent called at this time will be split
 * into three unwritten extent(at most). After IO complete, the part
 * being filled will be convert to initialized by the end_io callback function
 * via ecfs_convert_unwritten_extents().
 *
 * The size of unwritten extent to be written is passed to the caller via the
 * allocated pointer. Return an extent path pointer on success, or an error
 * pointer on failure.
 */
static struct ecfs_ext_path *ecfs_split_convert_extents(handle_t *handle,
					struct inode *inode,
					struct ecfs_map_blocks *map,
					struct ecfs_ext_path *path,
					int flags, unsigned int *allocated)
{
	ecfs_lblk_t eof_block;
	ecfs_lblk_t ee_block;
	struct ecfs_extent *ex;
	unsigned int ee_len;
	int split_flag = 0, depth;

	ext_debug(inode, "logical block %llu, max_blocks %u\n",
		  (unsigned long long)map->m_lblk, map->m_len);

	eof_block = (ECFS_I(inode)->i_disksize + inode->i_sb->s_blocksize - 1)
			>> inode->i_sb->s_blocksize_bits;
	if (eof_block < map->m_lblk + map->m_len)
		eof_block = map->m_lblk + map->m_len;
	/*
	 * It is safe to convert extent to initialized via explicit
	 * zeroout only if extent is fully inside i_size or new_size.
	 */
	depth = ext_depth(inode);
	ex = path[depth].p_ext;
	ee_block = le32_to_cpu(ex->ee_block);
	ee_len = ecfs_ext_get_actual_len(ex);

	/* Convert to unwritten */
	if (flags & ECFS_GET_BLOCKS_CONVERT_UNWRITTEN) {
		split_flag |= ECFS_EXT_DATA_VALID1;
	/* Convert to initialized */
	} else if (flags & ECFS_GET_BLOCKS_CONVERT) {
		split_flag |= ee_block + ee_len <= eof_block ?
			      ECFS_EXT_MAY_ZEROOUT : 0;
		split_flag |= (ECFS_EXT_MARK_UNWRIT2 | ECFS_EXT_DATA_VALID2);
	}
	flags |= ECFS_GET_BLOCKS_PRE_IO;
	return ecfs_split_extent(handle, inode, path, map, split_flag, flags,
				 allocated);
}

static struct ecfs_ext_path *
ecfs_convert_unwritten_extents_endio(handle_t *handle, struct inode *inode,
				     struct ecfs_map_blocks *map,
				     struct ecfs_ext_path *path)
{
	struct ecfs_extent *ex;
	ecfs_lblk_t ee_block;
	unsigned int ee_len;
	int depth;
	int err = 0;

	depth = ext_depth(inode);
	ex = path[depth].p_ext;
	ee_block = le32_to_cpu(ex->ee_block);
	ee_len = ecfs_ext_get_actual_len(ex);

	ext_debug(inode, "logical block %llu, max_blocks %u\n",
		  (unsigned long long)ee_block, ee_len);

	/* If extent is larger than requested it is a clear sign that we still
	 * have some extent state machine issues left. So extent_split is still
	 * required.
	 * TODO: Once all related issues will be fixed this situation should be
	 * illegal.
	 */
	if (ee_block != map->m_lblk || ee_len > map->m_len) {
#ifdef CONFIG_ECFS_DEBUG
		ecfs_warning(inode->i_sb, "Inode (%ld) finished: extent logical block %llu,"
			     " len %u; IO logical block %llu, len %u",
			     inode->i_ino, (unsigned long long)ee_block, ee_len,
			     (unsigned long long)map->m_lblk, map->m_len);
#endif
		path = ecfs_split_convert_extents(handle, inode, map, path,
						ECFS_GET_BLOCKS_CONVERT, NULL);
		if (IS_ERR(path))
			return path;

		path = ecfs_find_extent(inode, map->m_lblk, path, 0);
		if (IS_ERR(path))
			return path;
		depth = ext_depth(inode);
		ex = path[depth].p_ext;
	}

	err = ecfs_ext_get_access(handle, inode, path + depth);
	if (err)
		goto errout;
	/* first mark the extent as initialized */
	ecfs_ext_mark_initialized(ex);

	/* note: ecfs_ext_correct_indexes() isn't needed here because
	 * borders are not changed
	 */
	ecfs_ext_try_to_merge(handle, inode, path, ex);

	/* Mark modified extent as dirty */
	err = ecfs_ext_dirty(handle, inode, path + path->p_depth);
	if (err)
		goto errout;

	ecfs_ext_show_leaf(inode, path);
	return path;

errout:
	ecfs_free_ext_path(path);
	return ERR_PTR(err);
}

static struct ecfs_ext_path *
convert_initialized_extent(handle_t *handle, struct inode *inode,
			   struct ecfs_map_blocks *map,
			   struct ecfs_ext_path *path,
			   unsigned int *allocated)
{
	struct ecfs_extent *ex;
	ecfs_lblk_t ee_block;
	unsigned int ee_len;
	int depth;
	int err = 0;

	/*
	 * Make sure that the extent is no bigger than we support with
	 * unwritten extent
	 */
	if (map->m_len > EXT_UNWRITTEN_MAX_LEN)
		map->m_len = EXT_UNWRITTEN_MAX_LEN / 2;

	depth = ext_depth(inode);
	ex = path[depth].p_ext;
	ee_block = le32_to_cpu(ex->ee_block);
	ee_len = ecfs_ext_get_actual_len(ex);

	ext_debug(inode, "logical block %llu, max_blocks %u\n",
		  (unsigned long long)ee_block, ee_len);

	if (ee_block != map->m_lblk || ee_len > map->m_len) {
		path = ecfs_split_convert_extents(handle, inode, map, path,
				ECFS_GET_BLOCKS_CONVERT_UNWRITTEN, NULL);
		if (IS_ERR(path))
			return path;

		path = ecfs_find_extent(inode, map->m_lblk, path, 0);
		if (IS_ERR(path))
			return path;
		depth = ext_depth(inode);
		ex = path[depth].p_ext;
		if (!ex) {
			ECFS_ERROR_INODE(inode, "unexpected hole at %lu",
					 (unsigned long) map->m_lblk);
			err = -EFSCORRUPTED;
			goto errout;
		}
	}

	err = ecfs_ext_get_access(handle, inode, path + depth);
	if (err)
		goto errout;
	/* first mark the extent as unwritten */
	ecfs_ext_mark_unwritten(ex);

	/* note: ecfs_ext_correct_indexes() isn't needed here because
	 * borders are not changed
	 */
	ecfs_ext_try_to_merge(handle, inode, path, ex);

	/* Mark modified extent as dirty */
	err = ecfs_ext_dirty(handle, inode, path + path->p_depth);
	if (err)
		goto errout;
	ecfs_ext_show_leaf(inode, path);

	ecfs_update_inode_fsync_trans(handle, inode, 1);

	map->m_flags |= ECFS_MAP_UNWRITTEN;
	if (*allocated > map->m_len)
		*allocated = map->m_len;
	map->m_len = *allocated;
	return path;

errout:
	ecfs_free_ext_path(path);
	return ERR_PTR(err);
}

static struct ecfs_ext_path *
ecfs_ext_handle_unwritten_extents(handle_t *handle, struct inode *inode,
			struct ecfs_map_blocks *map,
			struct ecfs_ext_path *path, int flags,
			unsigned int *allocated, ecfs_fsblk_t newblock)
{
	int err = 0;

	ext_debug(inode, "logical block %llu, max_blocks %u, flags 0x%x, allocated %u\n",
		  (unsigned long long)map->m_lblk, map->m_len, flags,
		  *allocated);
	ecfs_ext_show_leaf(inode, path);

	/*
	 * When writing into unwritten space, we should not fail to
	 * allocate metadata blocks for the new extent block if needed.
	 */
	flags |= ECFS_GET_BLOCKS_METADATA_NOFAIL;

	trace_ecfs_ext_handle_unwritten_extents(inode, map, flags,
						*allocated, newblock);

	/* get_block() before submitting IO, split the extent */
	if (flags & ECFS_GET_BLOCKS_PRE_IO) {
		path = ecfs_split_convert_extents(handle, inode, map, path,
				flags | ECFS_GET_BLOCKS_CONVERT, allocated);
		if (IS_ERR(path))
			return path;
		/*
		 * shouldn't get a 0 allocated when splitting an extent unless
		 * m_len is 0 (bug) or extent has been corrupted
		 */
		if (unlikely(*allocated == 0)) {
			ECFS_ERROR_INODE(inode,
					 "unexpected allocated == 0, m_len = %u",
					 map->m_len);
			err = -EFSCORRUPTED;
			goto errout;
		}
		map->m_flags |= ECFS_MAP_UNWRITTEN;
		goto out;
	}
	/* IO end_io complete, convert the filled extent to written */
	if (flags & ECFS_GET_BLOCKS_CONVERT) {
		path = ecfs_convert_unwritten_extents_endio(handle, inode,
							    map, path);
		if (IS_ERR(path))
			return path;
		ecfs_update_inode_fsync_trans(handle, inode, 1);
		goto map_out;
	}
	/* buffered IO cases */
	/*
	 * repeat fallocate creation request
	 * we already have an unwritten extent
	 */
	if (flags & ECFS_GET_BLOCKS_UNWRIT_EXT) {
		map->m_flags |= ECFS_MAP_UNWRITTEN;
		goto map_out;
	}

	/* buffered READ or buffered write_begin() lookup */
	if ((flags & ECFS_GET_BLOCKS_CREATE) == 0) {
		/*
		 * We have blocks reserved already.  We
		 * return allocated blocks so that delalloc
		 * won't do block reservation for us.  But
		 * the buffer head will be unmapped so that
		 * a read from the block returns 0s.
		 */
		map->m_flags |= ECFS_MAP_UNWRITTEN;
		goto out1;
	}

	/*
	 * Default case when (flags & ECFS_GET_BLOCKS_CREATE) == 1.
	 * For buffered writes, at writepage time, etc.  Convert a
	 * discovered unwritten extent to written.
	 */
	path = ecfs_ext_convert_to_initialized(handle, inode, map, path,
					       flags, allocated);
	if (IS_ERR(path))
		return path;
	ecfs_update_inode_fsync_trans(handle, inode, 1);
	/*
	 * shouldn't get a 0 allocated when converting an unwritten extent
	 * unless m_len is 0 (bug) or extent has been corrupted
	 */
	if (unlikely(*allocated == 0)) {
		ECFS_ERROR_INODE(inode, "unexpected allocated == 0, m_len = %u",
				 map->m_len);
		err = -EFSCORRUPTED;
		goto errout;
	}

out:
	map->m_flags |= ECFS_MAP_NEW;
map_out:
	map->m_flags |= ECFS_MAP_MAPPED;
out1:
	map->m_pblk = newblock;
	if (*allocated > map->m_len)
		*allocated = map->m_len;
	map->m_len = *allocated;
	ecfs_ext_show_leaf(inode, path);
	return path;

errout:
	ecfs_free_ext_path(path);
	return ERR_PTR(err);
}

/*
 * get_implied_cluster_alloc - check to see if the requested
 * allocation (in the map structure) overlaps with a cluster already
 * allocated in an extent.
 *	@sb	The filesystem superblock structure
 *	@map	The requested lblk->pblk mapping
 *	@ex	The extent structure which might contain an implied
 *			cluster allocation
 *
 * This function is called by ecfs_ext_map_blocks() after we failed to
 * find blocks that were already in the inode's extent tree.  Hence,
 * we know that the beginning of the requested region cannot overlap
 * the extent from the inode's extent tree.  There are three cases we
 * want to catch.  The first is this case:
 *
 *		 |--- cluster # N--|
 *    |--- extent ---|	|---- requested region ---|
 *			|==========|
 *
 * The second case that we need to test for is this one:
 *
 *   |--------- cluster # N ----------------|
 *	   |--- requested region --|   |------- extent ----|
 *	   |=======================|
 *
 * The third case is when the requested region lies between two extents
 * within the same cluster:
 *          |------------- cluster # N-------------|
 * |----- ex -----|                  |---- ex_right ----|
 *                  |------ requested region ------|
 *                  |================|
 *
 * In each of the above cases, we need to set the map->m_pblk and
 * map->m_len so it corresponds to the return the extent labelled as
 * "|====|" from cluster #N, since it is already in use for data in
 * cluster ECFS_B2C(sbi, map->m_lblk).	We will then return 1 to
 * signal to ecfs_ext_map_blocks() that map->m_pblk should be treated
 * as a new "allocated" block region.  Otherwise, we will return 0 and
 * ecfs_ext_map_blocks() will then allocate one or more new clusters
 * by calling ecfs_mb_new_blocks().
 */
static int get_implied_cluster_alloc(struct super_block *sb,
				     struct ecfs_map_blocks *map,
				     struct ecfs_extent *ex,
				     struct ecfs_ext_path *path)
{
	struct ecfs_sb_info *sbi = ECFS_SB(sb);
	ecfs_lblk_t c_offset = ECFS_LBLK_COFF(sbi, map->m_lblk);
	ecfs_lblk_t ex_cluster_start, ex_cluster_end;
	ecfs_lblk_t rr_cluster_start;
	ecfs_lblk_t ee_block = le32_to_cpu(ex->ee_block);
	ecfs_fsblk_t ee_start = ecfs_ext_pblock(ex);
	unsigned short ee_len = ecfs_ext_get_actual_len(ex);

	/* The extent passed in that we are trying to match */
	ex_cluster_start = ECFS_B2C(sbi, ee_block);
	ex_cluster_end = ECFS_B2C(sbi, ee_block + ee_len - 1);

	/* The requested region passed into ecfs_map_blocks() */
	rr_cluster_start = ECFS_B2C(sbi, map->m_lblk);

	if ((rr_cluster_start == ex_cluster_end) ||
	    (rr_cluster_start == ex_cluster_start)) {
		if (rr_cluster_start == ex_cluster_end)
			ee_start += ee_len - 1;
		map->m_pblk = ECFS_PBLK_CMASK(sbi, ee_start) + c_offset;
		map->m_len = min(map->m_len,
				 (unsigned) sbi->s_cluster_ratio - c_offset);
		/*
		 * Check for and handle this case:
		 *
		 *   |--------- cluster # N-------------|
		 *		       |------- extent ----|
		 *	   |--- requested region ---|
		 *	   |===========|
		 */

		if (map->m_lblk < ee_block)
			map->m_len = min(map->m_len, ee_block - map->m_lblk);

		/*
		 * Check for the case where there is already another allocated
		 * block to the right of 'ex' but before the end of the cluster.
		 *
		 *          |------------- cluster # N-------------|
		 * |----- ex -----|                  |---- ex_right ----|
		 *                  |------ requested region ------|
		 *                  |================|
		 */
		if (map->m_lblk > ee_block) {
			ecfs_lblk_t next = ecfs_ext_next_allocated_block(path);
			map->m_len = min(map->m_len, next - map->m_lblk);
		}

		trace_ecfs_get_implied_cluster_alloc_exit(sb, map, 1);
		return 1;
	}

	trace_ecfs_get_implied_cluster_alloc_exit(sb, map, 0);
	return 0;
}

/*
 * Determine hole length around the given logical block, first try to
 * locate and expand the hole from the given @path, and then adjust it
 * if it's partially or completely converted to delayed extents, insert
 * it into the extent cache tree if it's indeed a hole, finally return
 * the length of the determined extent.
 */
static ecfs_lblk_t ecfs_ext_determine_insert_hole(struct inode *inode,
						  struct ecfs_ext_path *path,
						  ecfs_lblk_t lblk)
{
	ecfs_lblk_t hole_start, len;
	struct extent_status es;

	hole_start = lblk;
	len = ecfs_ext_find_hole(inode, path, &hole_start);
again:
	ecfs_es_find_extent_range(inode, &ecfs_es_is_delayed, hole_start,
				  hole_start + len - 1, &es);
	if (!es.es_len)
		goto insert_hole;

	/*
	 * There's a delalloc extent in the hole, handle it if the delalloc
	 * extent is in front of, behind and straddle the queried range.
	 */
	if (lblk >= es.es_lblk + es.es_len) {
		/*
		 * The delalloc extent is in front of the queried range,
		 * find again from the queried start block.
		 */
		len -= lblk - hole_start;
		hole_start = lblk;
		goto again;
	} else if (in_range(lblk, es.es_lblk, es.es_len)) {
		/*
		 * The delalloc extent containing lblk, it must have been
		 * added after ecfs_map_blocks() checked the extent status
		 * tree so we are not holding i_rwsem and delalloc info is
		 * only stabilized by i_data_sem we are going to release
		 * soon. Don't modify the extent status tree and report
		 * extent as a hole, just adjust the length to the delalloc
		 * extent's after lblk.
		 */
		len = es.es_lblk + es.es_len - lblk;
		return len;
	} else {
		/*
		 * The delalloc extent is partially or completely behind
		 * the queried range, update hole length until the
		 * beginning of the delalloc extent.
		 */
		len = min(es.es_lblk - hole_start, len);
	}

insert_hole:
	/* Put just found gap into cache to speed up subsequent requests */
	ext_debug(inode, " -> %u:%u\n", hole_start, len);
	ecfs_es_insert_extent(inode, hole_start, len, ~0,
			      EXTENT_STATUS_HOLE, false);

	/* Update hole_len to reflect hole size after lblk */
	if (hole_start != lblk)
		len -= lblk - hole_start;

	return len;
}

/*
 * Block allocation/map/preallocation routine for extents based files
 *
 *
 * Need to be called with
 * down_read(&ECFS_I(inode)->i_data_sem) if not allocating file system block
 * (ie, flags is zero). Otherwise down_write(&ECFS_I(inode)->i_data_sem)
 *
 * return > 0, number of blocks already mapped/allocated
 *          if flags doesn't contain ECFS_GET_BLOCKS_CREATE and these are pre-allocated blocks
 *          	buffer head is unmapped
 *          otherwise blocks are mapped
 *
 * return = 0, if plain look up failed (blocks have not been allocated)
 *          buffer head is unmapped
 *
 * return < 0, error case.
 */
int ecfs_ext_map_blocks(handle_t *handle, struct inode *inode,
			struct ecfs_map_blocks *map, int flags)
{
	struct ecfs_ext_path *path = NULL;
	struct ecfs_extent newex, *ex, ex2;
	struct ecfs_sb_info *sbi = ECFS_SB(inode->i_sb);
	ecfs_fsblk_t newblock = 0, pblk;
	int err = 0, depth;
	unsigned int allocated = 0, offset = 0;
	unsigned int allocated_clusters = 0;
	struct ecfs_allocation_request ar;
	ecfs_lblk_t cluster_offset;

	ext_debug(inode, "blocks %u/%u requested\n", map->m_lblk, map->m_len);
	trace_ecfs_ext_map_blocks_enter(inode, map->m_lblk, map->m_len, flags);

	/* find extent for this block */
	path = ecfs_find_extent(inode, map->m_lblk, NULL, flags);
	if (IS_ERR(path)) {
		err = PTR_ERR(path);
		goto out;
	}

	depth = ext_depth(inode);

	/*
	 * consistent leaf must not be empty;
	 * this situation is possible, though, _during_ tree modification;
	 * this is why assert can't be put in ecfs_find_extent()
	 */
	if (unlikely(path[depth].p_ext == NULL && depth != 0)) {
		ECFS_ERROR_INODE(inode, "bad extent address "
				 "lblock: %lu, depth: %d pblock %lld",
				 (unsigned long) map->m_lblk, depth,
				 path[depth].p_block);
		err = -EFSCORRUPTED;
		goto out;
	}

	ex = path[depth].p_ext;
	if (ex) {
		ecfs_lblk_t ee_block = le32_to_cpu(ex->ee_block);
		ecfs_fsblk_t ee_start = ecfs_ext_pblock(ex);
		unsigned short ee_len;


		/*
		 * unwritten extents are treated as holes, except that
		 * we split out initialized portions during a write.
		 */
		ee_len = ecfs_ext_get_actual_len(ex);

		trace_ecfs_ext_show_extent(inode, ee_block, ee_start, ee_len);

		/* if found extent covers block, simply return it */
		if (in_range(map->m_lblk, ee_block, ee_len)) {
			newblock = map->m_lblk - ee_block + ee_start;
			/* number of remaining blocks in the extent */
			allocated = ee_len - (map->m_lblk - ee_block);
			ext_debug(inode, "%u fit into %u:%d -> %llu\n",
				  map->m_lblk, ee_block, ee_len, newblock);

			/*
			 * If the extent is initialized check whether the
			 * caller wants to convert it to unwritten.
			 */
			if ((!ecfs_ext_is_unwritten(ex)) &&
			    (flags & ECFS_GET_BLOCKS_CONVERT_UNWRITTEN)) {
				path = convert_initialized_extent(handle,
					inode, map, path, &allocated);
				if (IS_ERR(path))
					err = PTR_ERR(path);
				goto out;
			} else if (!ecfs_ext_is_unwritten(ex)) {
				map->m_flags |= ECFS_MAP_MAPPED;
				map->m_pblk = newblock;
				if (allocated > map->m_len)
					allocated = map->m_len;
				map->m_len = allocated;
				ecfs_ext_show_leaf(inode, path);
				goto out;
			}

			path = ecfs_ext_handle_unwritten_extents(
				handle, inode, map, path, flags,
				&allocated, newblock);
			if (IS_ERR(path))
				err = PTR_ERR(path);
			goto out;
		}
	}

	/*
	 * requested block isn't allocated yet;
	 * we couldn't try to create block if flags doesn't contain ECFS_GET_BLOCKS_CREATE
	 */
	if ((flags & ECFS_GET_BLOCKS_CREATE) == 0) {
		ecfs_lblk_t len;

		len = ecfs_ext_determine_insert_hole(inode, path, map->m_lblk);

		map->m_pblk = 0;
		map->m_len = min_t(unsigned int, map->m_len, len);
		goto out;
	}

	/*
	 * Okay, we need to do block allocation.
	 */
	newex.ee_block = cpu_to_le32(map->m_lblk);
	cluster_offset = ECFS_LBLK_COFF(sbi, map->m_lblk);

	/*
	 * If we are doing bigalloc, check to see if the extent returned
	 * by ecfs_find_extent() implies a cluster we can use.
	 */
	if (cluster_offset && ex &&
	    get_implied_cluster_alloc(inode->i_sb, map, ex, path)) {
		ar.len = allocated = map->m_len;
		newblock = map->m_pblk;
		goto got_allocated_blocks;
	}

	/* find neighbour allocated blocks */
	ar.lleft = map->m_lblk;
	err = ecfs_ext_search_left(inode, path, &ar.lleft, &ar.pleft);
	if (err)
		goto out;
	ar.lright = map->m_lblk;
	err = ecfs_ext_search_right(inode, path, &ar.lright, &ar.pright,
				    &ex2, flags);
	if (err < 0)
		goto out;

	/* Check if the extent after searching to the right implies a
	 * cluster we can use. */
	if ((sbi->s_cluster_ratio > 1) && err &&
	    get_implied_cluster_alloc(inode->i_sb, map, &ex2, path)) {
		ar.len = allocated = map->m_len;
		newblock = map->m_pblk;
		err = 0;
		goto got_allocated_blocks;
	}

	/*
	 * See if request is beyond maximum number of blocks we can have in
	 * a single extent. For an initialized extent this limit is
	 * EXT_INIT_MAX_LEN and for an unwritten extent this limit is
	 * EXT_UNWRITTEN_MAX_LEN.
	 */
	if (map->m_len > EXT_INIT_MAX_LEN &&
	    !(flags & ECFS_GET_BLOCKS_UNWRIT_EXT))
		map->m_len = EXT_INIT_MAX_LEN;
	else if (map->m_len > EXT_UNWRITTEN_MAX_LEN &&
		 (flags & ECFS_GET_BLOCKS_UNWRIT_EXT))
		map->m_len = EXT_UNWRITTEN_MAX_LEN;

	/* Check if we can really insert (m_lblk)::(m_lblk + m_len) extent */
	newex.ee_len = cpu_to_le16(map->m_len);
	err = ecfs_ext_check_overlap(sbi, inode, &newex, path);
	if (err)
		allocated = ecfs_ext_get_actual_len(&newex);
	else
		allocated = map->m_len;

	/* allocate new block */
	ar.inode = inode;
	ar.goal = ecfs_ext_find_goal(inode, path, map->m_lblk);
	ar.logical = map->m_lblk;
	/*
	 * We calculate the offset from the beginning of the cluster
	 * for the logical block number, since when we allocate a
	 * physical cluster, the physical block should start at the
	 * same offset from the beginning of the cluster.  This is
	 * needed so that future calls to get_implied_cluster_alloc()
	 * work correctly.
	 */
	offset = ECFS_LBLK_COFF(sbi, map->m_lblk);
	ar.len = ECFS_NUM_B2C(sbi, offset+allocated);
	ar.goal -= offset;
	ar.logical -= offset;
	if (S_ISREG(inode->i_mode))
		ar.flags = ECFS_MB_HINT_DATA;
	else
		/* disable in-core preallocation for non-regular files */
		ar.flags = 0;
	if (flags & ECFS_GET_BLOCKS_NO_NORMALIZE)
		ar.flags |= ECFS_MB_HINT_NOPREALLOC;
	if (flags & ECFS_GET_BLOCKS_DELALLOC_RESERVE)
		ar.flags |= ECFS_MB_DELALLOC_RESERVED;
	if (flags & ECFS_GET_BLOCKS_METADATA_NOFAIL)
		ar.flags |= ECFS_MB_USE_RESERVED;
	newblock = ecfs_mb_new_blocks(handle, &ar, &err);
	if (!newblock)
		goto out;
	allocated_clusters = ar.len;
	ar.len = ECFS_C2B(sbi, ar.len) - offset;
	ext_debug(inode, "allocate new block: goal %llu, found %llu/%u, requested %u\n",
		  ar.goal, newblock, ar.len, allocated);
	if (ar.len > allocated)
		ar.len = allocated;

got_allocated_blocks:
	/* try to insert new extent into found leaf and return */
	pblk = newblock + offset;
	ecfs_ext_store_pblock(&newex, pblk);
	newex.ee_len = cpu_to_le16(ar.len);
	/* Mark unwritten */
	if (flags & ECFS_GET_BLOCKS_UNWRIT_EXT) {
		ecfs_ext_mark_unwritten(&newex);
		map->m_flags |= ECFS_MAP_UNWRITTEN;
	}

	path = ecfs_ext_insert_extent(handle, inode, path, &newex, flags);
	if (IS_ERR(path)) {
		err = PTR_ERR(path);
		if (allocated_clusters) {
			int fb_flags = 0;

			/*
			 * free data blocks we just allocated.
			 * not a good idea to call discard here directly,
			 * but otherwise we'd need to call it every free().
			 */
			ecfs_discard_preallocations(inode);
			if (flags & ECFS_GET_BLOCKS_DELALLOC_RESERVE)
				fb_flags = ECFS_FREE_BLOCKS_NO_QUOT_UPDATE;
			ecfs_free_blocks(handle, inode, NULL, newblock,
					 ECFS_C2B(sbi, allocated_clusters),
					 fb_flags);
		}
		goto out;
	}

	/*
	 * Cache the extent and update transaction to commit on fdatasync only
	 * when it is _not_ an unwritten extent.
	 */
	if ((flags & ECFS_GET_BLOCKS_UNWRIT_EXT) == 0)
		ecfs_update_inode_fsync_trans(handle, inode, 1);
	else
		ecfs_update_inode_fsync_trans(handle, inode, 0);

	map->m_flags |= (ECFS_MAP_NEW | ECFS_MAP_MAPPED);
	map->m_pblk = pblk;
	map->m_len = ar.len;
	allocated = map->m_len;
	ecfs_ext_show_leaf(inode, path);
out:
	/*
	 * We never use ECFS_GET_BLOCKS_QUERY_LAST_IN_LEAF with CREATE flag.
	 * So we know that the depth used here is correct, since there was no
	 * block allocation done if ECFS_GET_BLOCKS_QUERY_LAST_IN_LEAF is set.
	 * If tomorrow we start using this QUERY flag with CREATE, then we will
	 * need to re-calculate the depth as it might have changed due to block
	 * allocation.
	 */
	if (flags & ECFS_GET_BLOCKS_QUERY_LAST_IN_LEAF) {
		WARN_ON_ONCE(flags & ECFS_GET_BLOCKS_CREATE);
		if (!err && ex && (ex == EXT_LAST_EXTENT(path[depth].p_hdr)))
			map->m_flags |= ECFS_MAP_QUERY_LAST_IN_LEAF;
	}

	ecfs_free_ext_path(path);

	trace_ecfs_ext_map_blocks_exit(inode, flags, map,
				       err ? err : allocated);
	return err ? err : allocated;
}

int ecfs_ext_truncate(handle_t *handle, struct inode *inode)
{
	struct super_block *sb = inode->i_sb;
	ecfs_lblk_t last_block;
	int err = 0;

	/*
	 * TODO: optimization is possible here.
	 * Probably we need not scan at all,
	 * because page truncation is enough.
	 */

	/* we have to know where to truncate from in crash case */
	ECFS_I(inode)->i_disksize = inode->i_size;
	err = ecfs_mark_inode_dirty(handle, inode);
	if (err)
		return err;

	last_block = (inode->i_size + sb->s_blocksize - 1)
			>> ECFS_BLOCK_SIZE_BITS(sb);
	ecfs_es_remove_extent(inode, last_block, EXT_MAX_BLOCKS - last_block);

retry_remove_space:
	err = ecfs_ext_remove_space(inode, last_block, EXT_MAX_BLOCKS - 1);
	if (err == -ENOMEM) {
		memalloc_retry_wait(GFP_ATOMIC);
		goto retry_remove_space;
	}
	return err;
}

static int ecfs_alloc_file_blocks(struct file *file, ecfs_lblk_t offset,
				  ecfs_lblk_t len, loff_t new_size,
				  int flags)
{
	struct inode *inode = file_inode(file);
	handle_t *handle;
	int ret = 0, ret2 = 0, ret3 = 0;
	int retries = 0;
	int depth = 0;
	struct ecfs_map_blocks map;
	unsigned int credits;
	loff_t epos, old_size = i_size_read(inode);
	unsigned int blkbits = inode->i_blkbits;
	bool alloc_zero = false;

	BUG_ON(!ecfs_test_inode_flag(inode, ECFS_INODE_EXTENTS));
	map.m_lblk = offset;
	map.m_len = len;
	/*
	 * Don't normalize the request if it can fit in one extent so
	 * that it doesn't get unnecessarily split into multiple
	 * extents.
	 */
	if (len <= EXT_UNWRITTEN_MAX_LEN)
		flags |= ECFS_GET_BLOCKS_NO_NORMALIZE;

	/*
	 * Do the actual write zero during a running journal transaction
	 * costs a lot. First allocate an unwritten extent and then
	 * convert it to written after zeroing it out.
	 */
	if (flags & ECFS_GET_BLOCKS_ZERO) {
		flags &= ~ECFS_GET_BLOCKS_ZERO;
		flags |= ECFS_GET_BLOCKS_UNWRIT_EXT;
		alloc_zero = true;
	}

	/*
	 * credits to insert 1 extent into extent tree
	 */
	credits = ecfs_chunk_trans_blocks(inode, len);
	depth = ext_depth(inode);

retry:
	while (len) {
		/*
		 * Recalculate credits when extent tree depth changes.
		 */
		if (depth != ext_depth(inode)) {
			credits = ecfs_chunk_trans_blocks(inode, len);
			depth = ext_depth(inode);
		}

		handle = ecfs_journal_start(inode, ECFS_HT_MAP_BLOCKS,
					    credits);
		if (IS_ERR(handle)) {
			ret = PTR_ERR(handle);
			break;
		}
		ret = ecfs_map_blocks(handle, inode, &map, flags);
		if (ret <= 0) {
			ecfs_debug("inode #%lu: block %u: len %u: "
				   "ecfs_ext_map_blocks returned %d",
				   inode->i_ino, map.m_lblk,
				   map.m_len, ret);
			ecfs_mark_inode_dirty(handle, inode);
			ecfs_journal_stop(handle);
			break;
		}
		/*
		 * allow a full retry cycle for any remaining allocations
		 */
		retries = 0;
		epos = (loff_t)(map.m_lblk + ret) << blkbits;
		inode_set_ctime_current(inode);
		if (new_size) {
			if (epos > new_size)
				epos = new_size;
			if (ecfs_update_inode_size(inode, epos) & 0x1)
				inode_set_mtime_to_ts(inode,
						      inode_get_ctime(inode));
			if (epos > old_size) {
				pagecache_isize_extended(inode, old_size, epos);
				ecfs_zero_partial_blocks(handle, inode,
						     old_size, epos - old_size);
			}
		}
		ret2 = ecfs_mark_inode_dirty(handle, inode);
		ecfs_update_inode_fsync_trans(handle, inode, 1);
		ret3 = ecfs_journal_stop(handle);
		ret2 = ret3 ? ret3 : ret2;
		if (unlikely(ret2))
			break;

		if (alloc_zero &&
		    (map.m_flags & (ECFS_MAP_MAPPED | ECFS_MAP_UNWRITTEN))) {
			ret2 = ecfs_issue_zeroout(inode, map.m_lblk, map.m_pblk,
						  map.m_len);
			if (likely(!ret2))
				ret2 = ecfs_convert_unwritten_extents(NULL,
					inode, (loff_t)map.m_lblk << blkbits,
					(loff_t)map.m_len << blkbits);
			if (ret2)
				break;
		}

		map.m_lblk += ret;
		map.m_len = len = len - ret;
	}
	if (ret == -ENOSPC && ecfs_should_retry_alloc(inode->i_sb, &retries))
		goto retry;

	return ret > 0 ? ret2 : ret;
}

static int ecfs_collapse_range(struct file *file, loff_t offset, loff_t len);

static int ecfs_insert_range(struct file *file, loff_t offset, loff_t len);

static long ecfs_zero_range(struct file *file, loff_t offset,
			    loff_t len, int mode)
{
	struct inode *inode = file_inode(file);
	handle_t *handle = NULL;
	loff_t new_size = 0;
	loff_t end = offset + len;
	ecfs_lblk_t start_lblk, end_lblk;
	unsigned int blocksize = i_blocksize(inode);
	unsigned int blkbits = inode->i_blkbits;
	int ret, flags, credits;

	trace_ecfs_zero_range(inode, offset, len, mode);
	WARN_ON_ONCE(!inode_is_locked(inode));

	/* Indirect files do not support unwritten extents */
	if (!(ecfs_test_inode_flag(inode, ECFS_INODE_EXTENTS)))
		return -EOPNOTSUPP;

	if (!(mode & FALLOC_FL_KEEP_SIZE) &&
	    (end > inode->i_size || end > ECFS_I(inode)->i_disksize)) {
		new_size = end;
		ret = inode_newsize_ok(inode, new_size);
		if (ret)
			return ret;
	}

	flags = ECFS_GET_BLOCKS_CREATE_UNWRIT_EXT;
	/* Preallocate the range including the unaligned edges */
	if (!IS_ALIGNED(offset | end, blocksize)) {
		ecfs_lblk_t alloc_lblk = offset >> blkbits;
		ecfs_lblk_t len_lblk = ECFS_MAX_BLOCKS(len, offset, blkbits);

		ret = ecfs_alloc_file_blocks(file, alloc_lblk, len_lblk,
					     new_size, flags);
		if (ret)
			return ret;
	}

	ret = ecfs_update_disksize_before_punch(inode, offset, len);
	if (ret)
		return ret;

	/* Now release the pages and zero block aligned part of pages */
	ret = ecfs_truncate_page_cache_block_range(inode, offset, end);
	if (ret)
		return ret;

	/* Zero range excluding the unaligned edges */
	start_lblk = ECFS_B_TO_LBLK(inode, offset);
	end_lblk = end >> blkbits;
	if (end_lblk > start_lblk) {
		ecfs_lblk_t zero_blks = end_lblk - start_lblk;

		if (mode & FALLOC_FL_WRITE_ZEROES)
			flags = ECFS_GET_BLOCKS_CREATE_ZERO | ECFS_EX_NOCACHE;
		else
			flags |= (ECFS_GET_BLOCKS_CONVERT_UNWRITTEN |
				  ECFS_EX_NOCACHE);
		ret = ecfs_alloc_file_blocks(file, start_lblk, zero_blks,
					     new_size, flags);
		if (ret)
			return ret;
	}
	/* Finish zeroing out if it doesn't contain partial block */
	if (IS_ALIGNED(offset | end, blocksize))
		return ret;

	/*
	 * In worst case we have to writeout two nonadjacent unwritten
	 * blocks and update the inode
	 */
	credits = (2 * ecfs_ext_index_trans_blocks(inode, 2)) + 1;
	if (ecfs_should_journal_data(inode))
		credits += 2;
	handle = ecfs_journal_start(inode, ECFS_HT_MISC, credits);
	if (IS_ERR(handle)) {
		ret = PTR_ERR(handle);
		ecfs_std_error(inode->i_sb, ret);
		return ret;
	}

	/* Zero out partial block at the edges of the range */
	ret = ecfs_zero_partial_blocks(handle, inode, offset, len);
	if (ret)
		goto out_handle;

	if (new_size)
		ecfs_update_inode_size(inode, new_size);
	ret = ecfs_mark_inode_dirty(handle, inode);
	if (unlikely(ret))
		goto out_handle;

	ecfs_update_inode_fsync_trans(handle, inode, 1);
	if (file->f_flags & O_SYNC)
		ecfs_handle_sync(handle);

out_handle:
	ecfs_journal_stop(handle);
	return ret;
}

static long ecfs_do_fallocate(struct file *file, loff_t offset,
			      loff_t len, int mode)
{
	struct inode *inode = file_inode(file);
	loff_t end = offset + len;
	loff_t new_size = 0;
	ecfs_lblk_t start_lblk, len_lblk;
	int ret;

	trace_ecfs_fallocate_enter(inode, offset, len, mode);
	WARN_ON_ONCE(!inode_is_locked(inode));

	start_lblk = offset >> inode->i_blkbits;
	len_lblk = ECFS_MAX_BLOCKS(len, offset, inode->i_blkbits);

	/* We only support preallocation for extent-based files only. */
	if (!(ecfs_test_inode_flag(inode, ECFS_INODE_EXTENTS))) {
		ret = -EOPNOTSUPP;
		goto out;
	}

	if (!(mode & FALLOC_FL_KEEP_SIZE) &&
	    (end > inode->i_size || end > ECFS_I(inode)->i_disksize)) {
		new_size = end;
		ret = inode_newsize_ok(inode, new_size);
		if (ret)
			goto out;
	}

	ret = ecfs_alloc_file_blocks(file, start_lblk, len_lblk, new_size,
				     ECFS_GET_BLOCKS_CREATE_UNWRIT_EXT);
	if (ret)
		goto out;

	if (file->f_flags & O_SYNC && ECFS_SB(inode->i_sb)->s_journal) {
		ret = ecfs_fc_commit(ECFS_SB(inode->i_sb)->s_journal,
					ECFS_I(inode)->i_sync_tid);
	}
out:
	trace_ecfs_fallocate_exit(inode, offset, len_lblk, ret);
	return ret;
}

/*
 * preallocate space for a file. This implements ecfs's fallocate file
 * operation, which gets called from sys_fallocate system call.
 * For block-mapped files, posix_fallocate should fall back to the method
 * of writing zeroes to the required new blocks (the same behavior which is
 * expected for file systems which do not support fallocate() system call).
 */
long ecfs_fallocate(struct file *file, int mode, loff_t offset, loff_t len)
{
	struct inode *inode = file_inode(file);
	struct address_space *mapping = file->f_mapping;
	int ret;

	/*
	 * Encrypted inodes can't handle collapse range or insert
	 * range since we would need to re-encrypt blocks with a
	 * different IV or XTS tweak (which are based on the logical
	 * block number).
	 */
	if (IS_ENCRYPTED(inode) &&
	    (mode & (FALLOC_FL_COLLAPSE_RANGE | FALLOC_FL_INSERT_RANGE)))
		return -EOPNOTSUPP;
	/*
	 * Don't allow writing zeroes if the underlying device does not
	 * enable the unmap write zeroes operation.
	 */
	if ((mode & FALLOC_FL_WRITE_ZEROES) &&
	    !bdev_write_zeroes_unmap_sectors(inode->i_sb->s_bdev))
		return -EOPNOTSUPP;

	/* Return error if mode is not supported */
	if (mode & ~(FALLOC_FL_KEEP_SIZE | FALLOC_FL_PUNCH_HOLE |
		     FALLOC_FL_ZERO_RANGE | FALLOC_FL_COLLAPSE_RANGE |
		     FALLOC_FL_INSERT_RANGE | FALLOC_FL_WRITE_ZEROES))
		return -EOPNOTSUPP;

	inode_lock(inode);
	ret = ecfs_convert_inline_data(inode);
	if (ret)
		goto out_inode_lock;

	/* Wait all existing dio workers, newcomers will block on i_rwsem */
	inode_dio_wait(inode);

	ret = file_modified(file);
	if (ret)
		goto out_inode_lock;

	if ((mode & FALLOC_FL_MODE_MASK) == FALLOC_FL_ALLOCATE_RANGE) {
		ret = ecfs_do_fallocate(file, offset, len, mode);
		goto out_inode_lock;
	}

	/*
	 * Follow-up operations will drop page cache, hold invalidate lock
	 * to prevent page faults from reinstantiating pages we have
	 * released from page cache.
	 */
	filemap_invalidate_lock(mapping);

	ret = ecfs_break_layouts(inode);
	if (ret)
		goto out_invalidate_lock;

	switch (mode & FALLOC_FL_MODE_MASK) {
	case FALLOC_FL_PUNCH_HOLE:
		ret = ecfs_punch_hole(file, offset, len);
		break;
	case FALLOC_FL_COLLAPSE_RANGE:
		ret = ecfs_collapse_range(file, offset, len);
		break;
	case FALLOC_FL_INSERT_RANGE:
		ret = ecfs_insert_range(file, offset, len);
		break;
	case FALLOC_FL_ZERO_RANGE:
	case FALLOC_FL_WRITE_ZEROES:
		ret = ecfs_zero_range(file, offset, len, mode);
		break;
	default:
		ret = -EOPNOTSUPP;
	}

out_invalidate_lock:
	filemap_invalidate_unlock(mapping);
out_inode_lock:
	inode_unlock(inode);
	return ret;
}

/*
 * This function converts a range of blocks to written extents. The caller of
 * this function will pass the start offset and the size. all unwritten extents
 * within this range will be converted to written extents.
 *
 * This function is called from the direct IO end io call back function for
 * atomic writes, to convert the unwritten extents after IO is completed.
 *
 * Note that the requirement for atomic writes is that all conversion should
 * happen atomically in a single fs journal transaction. We mainly only allocate
 * unwritten extents either on a hole on a pre-exiting unwritten extent range in
 * ecfs_map_blocks_atomic_write(). The only case where we can have multiple
 * unwritten extents in a range [offset, offset+len) is when there is a split
 * unwritten extent between two leaf nodes which was cached in extent status
 * cache during ecfs_iomap_alloc() time. That will allow
 * ecfs_map_blocks_atomic_write() to return the unwritten extent range w/o going
 * into the slow path. That means we might need a loop for conversion of this
 * unwritten extent split across leaf block within a single journal transaction.
 * Split extents across leaf nodes is a rare case, but let's still handle that
 * to meet the requirements of multi-fsblock atomic writes.
 *
 * Returns 0 on success.
 */
int ecfs_convert_unwritten_extents_atomic(handle_t *handle, struct inode *inode,
					  loff_t offset, ssize_t len)
{
	unsigned int max_blocks;
	int ret = 0, ret2 = 0, ret3 = 0;
	struct ecfs_map_blocks map;
	unsigned int blkbits = inode->i_blkbits;
	unsigned int credits = 0;
	int flags = ECFS_GET_BLOCKS_IO_CONVERT_EXT | ECFS_EX_NOCACHE;

	map.m_lblk = offset >> blkbits;
	max_blocks = ECFS_MAX_BLOCKS(len, offset, blkbits);

	if (!handle) {
		/*
		 * TODO: An optimization can be added later by having an extent
		 * status flag e.g. EXTENT_STATUS_SPLIT_LEAF. If we query that
		 * it can tell if the extent in the cache is a split extent.
		 * But for now let's assume pextents as 2 always.
		 */
		credits = ecfs_meta_trans_blocks(inode, max_blocks, 2);
	}

	if (credits) {
		handle = ecfs_journal_start(inode, ECFS_HT_MAP_BLOCKS, credits);
		if (IS_ERR(handle)) {
			ret = PTR_ERR(handle);
			return ret;
		}
	}

	while (ret >= 0 && ret < max_blocks) {
		map.m_lblk += ret;
		map.m_len = (max_blocks -= ret);
		ret = ecfs_map_blocks(handle, inode, &map, flags);
		if (ret != max_blocks)
			ecfs_msg(inode->i_sb, KERN_INFO,
				     "inode #%lu: block %u: len %u: "
				     "split block mapping found for atomic write, "
				     "ret = %d",
				     inode->i_ino, map.m_lblk,
				     map.m_len, ret);
		if (ret <= 0)
			break;
	}

	ret2 = ecfs_mark_inode_dirty(handle, inode);

	if (credits) {
		ret3 = ecfs_journal_stop(handle);
		if (unlikely(ret3))
			ret2 = ret3;
	}

	if (ret <= 0 || ret2)
		ecfs_warning(inode->i_sb,
			     "inode #%lu: block %u: len %u: "
			     "returned %d or %d",
			     inode->i_ino, map.m_lblk,
			     map.m_len, ret, ret2);

	return ret > 0 ? ret2 : ret;
}

/*
 * This function convert a range of blocks to written extents
 * The caller of this function will pass the start offset and the size.
 * all unwritten extents within this range will be converted to
 * written extents.
 *
 * This function is called from the direct IO end io call back
 * function, to convert the fallocated extents after IO is completed.
 * Returns 0 on success.
 */
int ecfs_convert_unwritten_extents(handle_t *handle, struct inode *inode,
				   loff_t offset, ssize_t len)
{
	unsigned int max_blocks;
	int ret = 0, ret2 = 0, ret3 = 0;
	struct ecfs_map_blocks map;
	unsigned int blkbits = inode->i_blkbits;
	unsigned int credits = 0;

	map.m_lblk = offset >> blkbits;
	max_blocks = ECFS_MAX_BLOCKS(len, offset, blkbits);

	if (!handle) {
		/*
		 * credits to insert 1 extent into extent tree
		 */
		credits = ecfs_chunk_trans_blocks(inode, max_blocks);
	}
	while (ret >= 0 && ret < max_blocks) {
		map.m_lblk += ret;
		map.m_len = (max_blocks -= ret);
		if (credits) {
			handle = ecfs_journal_start(inode, ECFS_HT_MAP_BLOCKS,
						    credits);
			if (IS_ERR(handle)) {
				ret = PTR_ERR(handle);
				break;
			}
		}
		/*
		 * Do not cache any unrelated extents, as it does not hold the
		 * i_rwsem or invalidate_lock, which could corrupt the extent
		 * status tree.
		 */
		ret = ecfs_map_blocks(handle, inode, &map,
				      ECFS_GET_BLOCKS_IO_CONVERT_EXT |
				      ECFS_EX_NOCACHE);
		if (ret <= 0)
			ecfs_warning(inode->i_sb,
				     "inode #%lu: block %u: len %u: "
				     "ecfs_ext_map_blocks returned %d",
				     inode->i_ino, map.m_lblk,
				     map.m_len, ret);
		ret2 = ecfs_mark_inode_dirty(handle, inode);
		if (credits) {
			ret3 = ecfs_journal_stop(handle);
			if (unlikely(ret3))
				ret2 = ret3;
		}

		if (ret <= 0 || ret2)
			break;
	}
	return ret > 0 ? ret2 : ret;
}

int ecfs_convert_unwritten_io_end_vec(handle_t *handle, ecfs_io_end_t *io_end)
{
	int ret = 0, err = 0;
	struct ecfs_io_end_vec *io_end_vec;

	/*
	 * This is somewhat ugly but the idea is clear: When transaction is
	 * reserved, everything goes into it. Otherwise we rather start several
	 * smaller transactions for conversion of each extent separately.
	 */
	if (handle) {
		handle = ecfs_journal_start_reserved(handle,
						     ECFS_HT_EXT_CONVERT);
		if (IS_ERR(handle))
			return PTR_ERR(handle);
	}

	list_for_each_entry(io_end_vec, &io_end->list_vec, list) {
		ret = ecfs_convert_unwritten_extents(handle, io_end->inode,
						     io_end_vec->offset,
						     io_end_vec->size);
		if (ret)
			break;
	}

	if (handle)
		err = ecfs_journal_stop(handle);

	return ret < 0 ? ret : err;
}

static int ecfs_iomap_xattr_fiemap(struct inode *inode, struct iomap *iomap)
{
	__u64 physical = 0;
	__u64 length = 0;
	int blockbits = inode->i_sb->s_blocksize_bits;
	int error = 0;
	u16 iomap_type;

	/* in-inode? */
	if (ecfs_test_inode_state(inode, ECFS_STATE_XATTR)) {
		struct ecfs_iloc iloc;
		int offset;	/* offset of xattr in inode */

		error = ecfs_get_inode_loc(inode, &iloc);
		if (error)
			return error;
		physical = (__u64)iloc.bh->b_blocknr << blockbits;
		offset = ECFS_GOOD_OLD_INODE_SIZE +
				ECFS_I(inode)->i_extra_isize;
		physical += offset;
		length = ECFS_SB(inode->i_sb)->s_inode_size - offset;
		brelse(iloc.bh);
		iomap_type = IOMAP_INLINE;
	} else if (ECFS_I(inode)->i_file_acl) { /* external block */
		physical = (__u64)ECFS_I(inode)->i_file_acl << blockbits;
		length = inode->i_sb->s_blocksize;
		iomap_type = IOMAP_MAPPED;
	} else {
		/* no in-inode or external block for xattr, so return -ENOENT */
		error = -ENOENT;
		goto out;
	}

	iomap->addr = physical;
	iomap->offset = 0;
	iomap->length = length;
	iomap->type = iomap_type;
	iomap->flags = 0;
out:
	return error;
}

static int ecfs_iomap_xattr_begin(struct inode *inode, loff_t offset,
				  loff_t length, unsigned flags,
				  struct iomap *iomap, struct iomap *srcmap)
{
	int error;

	error = ecfs_iomap_xattr_fiemap(inode, iomap);
	if (error == 0 && (offset >= iomap->length))
		error = -ENOENT;
	return error;
}

static const struct iomap_ops ecfs_iomap_xattr_ops = {
	.iomap_begin		= ecfs_iomap_xattr_begin,
};

static int ecfs_fiemap_check_ranges(struct inode *inode, u64 start, u64 *len)
{
	u64 maxbytes = ecfs_get_maxbytes(inode);

	if (*len == 0)
		return -EINVAL;
	if (start > maxbytes)
		return -EFBIG;

	/*
	 * Shrink request scope to what the fs can actually handle.
	 */
	if (*len > maxbytes || (maxbytes - *len) < start)
		*len = maxbytes - start;
	return 0;
}

int ecfs_fiemap(struct inode *inode, struct fiemap_extent_info *fieinfo,
		u64 start, u64 len)
{
	int error = 0;

	inode_lock_shared(inode);
	if (fieinfo->fi_flags & FIEMAP_FLAG_CACHE) {
		error = ecfs_ext_precache(inode);
		if (error)
			goto unlock;
		fieinfo->fi_flags &= ~FIEMAP_FLAG_CACHE;
	}

	/*
	 * For bitmap files the maximum size limit could be smaller than
	 * s_maxbytes, so check len here manually instead of just relying on the
	 * generic check.
	 */
	error = ecfs_fiemap_check_ranges(inode, start, &len);
	if (error)
		goto unlock;

	if (fieinfo->fi_flags & FIEMAP_FLAG_XATTR) {
		fieinfo->fi_flags &= ~FIEMAP_FLAG_XATTR;
		error = iomap_fiemap(inode, fieinfo, start, len,
				     &ecfs_iomap_xattr_ops);
	} else {
		error = iomap_fiemap(inode, fieinfo, start, len,
				     &ecfs_iomap_report_ops);
	}
unlock:
	inode_unlock_shared(inode);
	return error;
}

int ecfs_get_es_cache(struct inode *inode, struct fiemap_extent_info *fieinfo,
		      __u64 start, __u64 len)
{
	ecfs_lblk_t start_blk, len_blks;
	__u64 last_blk;
	int error = 0;

	if (ecfs_has_inline_data(inode)) {
		int has_inline;

		down_read(&ECFS_I(inode)->xattr_sem);
		has_inline = ecfs_has_inline_data(inode);
		up_read(&ECFS_I(inode)->xattr_sem);
		if (has_inline)
			return 0;
	}

	if (fieinfo->fi_flags & FIEMAP_FLAG_CACHE) {
		inode_lock_shared(inode);
		error = ecfs_ext_precache(inode);
		inode_unlock_shared(inode);
		if (error)
			return error;
		fieinfo->fi_flags &= ~FIEMAP_FLAG_CACHE;
	}

	error = fiemap_prep(inode, fieinfo, start, &len, 0);
	if (error)
		return error;

	error = ecfs_fiemap_check_ranges(inode, start, &len);
	if (error)
		return error;

	start_blk = start >> inode->i_sb->s_blocksize_bits;
	last_blk = (start + len - 1) >> inode->i_sb->s_blocksize_bits;
	if (last_blk >= EXT_MAX_BLOCKS)
		last_blk = EXT_MAX_BLOCKS-1;
	len_blks = ((ecfs_lblk_t) last_blk) - start_blk + 1;

	/*
	 * Walk the extent tree gathering extent information
	 * and pushing extents back to the user.
	 */
	return ecfs_fill_es_cache_info(inode, start_blk, len_blks, fieinfo);
}

/*
 * ecfs_ext_shift_path_extents:
 * Shift the extents of a path structure lying between path[depth].p_ext
 * and EXT_LAST_EXTENT(path[depth].p_hdr), by @shift blocks. @SHIFT tells
 * if it is right shift or left shift operation.
 */
static int
ecfs_ext_shift_path_extents(struct ecfs_ext_path *path, ecfs_lblk_t shift,
			    struct inode *inode, handle_t *handle,
			    enum SHIFT_DIRECTION SHIFT)
{
	int depth, err = 0;
	struct ecfs_extent *ex_start, *ex_last;
	bool update = false;
	int credits, restart_credits;
	depth = path->p_depth;

	while (depth >= 0) {
		if (depth == path->p_depth) {
			ex_start = path[depth].p_ext;
			if (!ex_start)
				return -EFSCORRUPTED;

			ex_last = EXT_LAST_EXTENT(path[depth].p_hdr);
			/* leaf + sb + inode */
			credits = 3;
			if (ex_start == EXT_FIRST_EXTENT(path[depth].p_hdr)) {
				update = true;
				/* extent tree + sb + inode */
				credits = depth + 2;
			}

			restart_credits = ecfs_chunk_trans_extent(inode, 0);
			err = ecfs_datasem_ensure_credits(handle, inode, credits,
					restart_credits, 0);
			if (err) {
				if (err > 0)
					err = -EAGAIN;
				goto out;
			}

			err = ecfs_ext_get_access(handle, inode, path + depth);
			if (err)
				goto out;

			while (ex_start <= ex_last) {
				if (SHIFT == SHIFT_LEFT) {
					le32_add_cpu(&ex_start->ee_block,
						-shift);
					/* Try to merge to the left. */
					if ((ex_start >
					    EXT_FIRST_EXTENT(path[depth].p_hdr))
					    &&
					    ecfs_ext_try_to_merge_right(inode,
					    path, ex_start - 1))
						ex_last--;
					else
						ex_start++;
				} else {
					le32_add_cpu(&ex_last->ee_block, shift);
					ecfs_ext_try_to_merge_right(inode, path,
						ex_last);
					ex_last--;
				}
			}
			err = ecfs_ext_dirty(handle, inode, path + depth);
			if (err)
				goto out;

			if (--depth < 0 || !update)
				break;
		}

		/* Update index too */
		err = ecfs_ext_get_access(handle, inode, path + depth);
		if (err)
			goto out;

		if (SHIFT == SHIFT_LEFT)
			le32_add_cpu(&path[depth].p_idx->ei_block, -shift);
		else
			le32_add_cpu(&path[depth].p_idx->ei_block, shift);
		err = ecfs_ext_dirty(handle, inode, path + depth);
		if (err)
			goto out;

		/* we are done if current index is not a starting index */
		if (path[depth].p_idx != EXT_FIRST_INDEX(path[depth].p_hdr))
			break;

		depth--;
	}

out:
	return err;
}

/*
 * ecfs_ext_shift_extents:
 * All the extents which lies in the range from @start to the last allocated
 * block for the @inode are shifted either towards left or right (depending
 * upon @SHIFT) by @shift blocks.
 * On success, 0 is returned, error otherwise.
 */
static int
ecfs_ext_shift_extents(struct inode *inode, handle_t *handle,
		       ecfs_lblk_t start, ecfs_lblk_t shift,
		       enum SHIFT_DIRECTION SHIFT)
{
	struct ecfs_ext_path *path;
	int ret = 0, depth;
	struct ecfs_extent *extent;
	ecfs_lblk_t stop, *iterator, ex_start, ex_end;
	ecfs_lblk_t tmp = EXT_MAX_BLOCKS;

	/* Let path point to the last extent */
	path = ecfs_find_extent(inode, EXT_MAX_BLOCKS - 1, NULL,
				ECFS_EX_NOCACHE);
	if (IS_ERR(path))
		return PTR_ERR(path);

	depth = path->p_depth;
	extent = path[depth].p_ext;
	if (!extent)
		goto out;

	stop = le32_to_cpu(extent->ee_block);

       /*
	* For left shifts, make sure the hole on the left is big enough to
	* accommodate the shift.  For right shifts, make sure the last extent
	* won't be shifted beyond EXT_MAX_BLOCKS.
	*/
	if (SHIFT == SHIFT_LEFT) {
		path = ecfs_find_extent(inode, start - 1, path,
					ECFS_EX_NOCACHE);
		if (IS_ERR(path))
			return PTR_ERR(path);
		depth = path->p_depth;
		extent =  path[depth].p_ext;
		if (extent) {
			ex_start = le32_to_cpu(extent->ee_block);
			ex_end = le32_to_cpu(extent->ee_block) +
				ecfs_ext_get_actual_len(extent);
		} else {
			ex_start = 0;
			ex_end = 0;
		}

		if ((start == ex_start && shift > ex_start) ||
		    (shift > start - ex_end)) {
			ret = -EINVAL;
			goto out;
		}
	} else {
		if (shift > EXT_MAX_BLOCKS -
		    (stop + ecfs_ext_get_actual_len(extent))) {
			ret = -EINVAL;
			goto out;
		}
	}

	/*
	 * In case of left shift, iterator points to start and it is increased
	 * till we reach stop. In case of right shift, iterator points to stop
	 * and it is decreased till we reach start.
	 */
again:
	ret = 0;
	if (SHIFT == SHIFT_LEFT)
		iterator = &start;
	else
		iterator = &stop;

	if (tmp != EXT_MAX_BLOCKS)
		*iterator = tmp;

	/*
	 * Its safe to start updating extents.  Start and stop are unsigned, so
	 * in case of right shift if extent with 0 block is reached, iterator
	 * becomes NULL to indicate the end of the loop.
	 */
	while (iterator && start <= stop) {
		path = ecfs_find_extent(inode, *iterator, path,
					ECFS_EX_NOCACHE);
		if (IS_ERR(path))
			return PTR_ERR(path);
		depth = path->p_depth;
		extent = path[depth].p_ext;
		if (!extent) {
			ECFS_ERROR_INODE(inode, "unexpected hole at %lu",
					 (unsigned long) *iterator);
			return -EFSCORRUPTED;
		}
		if (SHIFT == SHIFT_LEFT && *iterator >
		    le32_to_cpu(extent->ee_block)) {
			/* Hole, move to the next extent */
			if (extent < EXT_LAST_EXTENT(path[depth].p_hdr)) {
				path[depth].p_ext++;
			} else {
				*iterator = ecfs_ext_next_allocated_block(path);
				continue;
			}
		}

		tmp = *iterator;
		if (SHIFT == SHIFT_LEFT) {
			extent = EXT_LAST_EXTENT(path[depth].p_hdr);
			*iterator = le32_to_cpu(extent->ee_block) +
					ecfs_ext_get_actual_len(extent);
		} else {
			extent = EXT_FIRST_EXTENT(path[depth].p_hdr);
			if (le32_to_cpu(extent->ee_block) > start)
				*iterator = le32_to_cpu(extent->ee_block) - 1;
			else if (le32_to_cpu(extent->ee_block) == start)
				iterator = NULL;
			else {
				extent = EXT_LAST_EXTENT(path[depth].p_hdr);
				while (le32_to_cpu(extent->ee_block) >= start)
					extent--;

				if (extent == EXT_LAST_EXTENT(path[depth].p_hdr))
					break;

				extent++;
				iterator = NULL;
			}
			path[depth].p_ext = extent;
		}
		ret = ecfs_ext_shift_path_extents(path, shift, inode,
				handle, SHIFT);
		/* iterator can be NULL which means we should break */
		if (ret == -EAGAIN)
			goto again;
		if (ret)
			break;
	}
out:
	ecfs_free_ext_path(path);
	return ret;
}

/*
 * ecfs_collapse_range:
 * This implements the fallocate's collapse range functionality for ecfs
 * Returns: 0 and non-zero on error.
 */
static int ecfs_collapse_range(struct file *file, loff_t offset, loff_t len)
{
	struct inode *inode = file_inode(file);
	struct super_block *sb = inode->i_sb;
	struct address_space *mapping = inode->i_mapping;
	loff_t end = offset + len;
	ecfs_lblk_t start_lblk, end_lblk;
	handle_t *handle;
	unsigned int credits;
	loff_t start, new_size;
	int ret;

	trace_ecfs_collapse_range(inode, offset, len);
	WARN_ON_ONCE(!inode_is_locked(inode));

	/* Currently just for extent based files */
	if (!ecfs_test_inode_flag(inode, ECFS_INODE_EXTENTS))
		return -EOPNOTSUPP;
	/* Collapse range works only on fs cluster size aligned regions. */
	if (!IS_ALIGNED(offset | len, ECFS_CLUSTER_SIZE(sb)))
		return -EINVAL;
	/*
	 * There is no need to overlap collapse range with EOF, in which case
	 * it is effectively a truncate operation
	 */
	if (end >= inode->i_size)
		return -EINVAL;

	/*
	 * Write tail of the last page before removed range and data that
	 * will be shifted since they will get removed from the page cache
	 * below. We are also protected from pages becoming dirty by
	 * i_rwsem and invalidate_lock.
	 * Need to round down offset to be aligned with page size boundary
	 * for page size > block size.
	 */
	start = round_down(offset, PAGE_SIZE);
	ret = filemap_write_and_wait_range(mapping, start, offset);
	if (!ret)
		ret = filemap_write_and_wait_range(mapping, end, LLONG_MAX);
	if (ret)
		return ret;

	truncate_pagecache(inode, start);

	credits = ecfs_chunk_trans_extent(inode, 0);
	handle = ecfs_journal_start(inode, ECFS_HT_TRUNCATE, credits);
	if (IS_ERR(handle))
		return PTR_ERR(handle);

	ecfs_fc_mark_ineligible(sb, ECFS_FC_REASON_FALLOC_RANGE, handle);

	start_lblk = offset >> inode->i_blkbits;
	end_lblk = (offset + len) >> inode->i_blkbits;

	ecfs_check_map_extents_env(inode);

	down_write(&ECFS_I(inode)->i_data_sem);
	ecfs_discard_preallocations(inode);
	ecfs_es_remove_extent(inode, start_lblk, EXT_MAX_BLOCKS - start_lblk);

	ret = ecfs_ext_remove_space(inode, start_lblk, end_lblk - 1);
	if (ret) {
		up_write(&ECFS_I(inode)->i_data_sem);
		goto out_handle;
	}
	ecfs_discard_preallocations(inode);

	ret = ecfs_ext_shift_extents(inode, handle, end_lblk,
				     end_lblk - start_lblk, SHIFT_LEFT);
	if (ret) {
		up_write(&ECFS_I(inode)->i_data_sem);
		goto out_handle;
	}

	new_size = inode->i_size - len;
	i_size_write(inode, new_size);
	ECFS_I(inode)->i_disksize = new_size;

	up_write(&ECFS_I(inode)->i_data_sem);
	ret = ecfs_mark_inode_dirty(handle, inode);
	if (ret)
		goto out_handle;

	ecfs_update_inode_fsync_trans(handle, inode, 1);
	if (IS_SYNC(inode))
		ecfs_handle_sync(handle);

out_handle:
	ecfs_journal_stop(handle);
	return ret;
}

/*
 * ecfs_insert_range:
 * This function implements the FALLOC_FL_INSERT_RANGE flag of fallocate.
 * The data blocks starting from @offset to the EOF are shifted by @len
 * towards right to create a hole in the @inode. Inode size is increased
 * by len bytes.
 * Returns 0 on success, error otherwise.
 */
static int ecfs_insert_range(struct file *file, loff_t offset, loff_t len)
{
	struct inode *inode = file_inode(file);
	struct super_block *sb = inode->i_sb;
	struct address_space *mapping = inode->i_mapping;
	handle_t *handle;
	struct ecfs_ext_path *path;
	struct ecfs_extent *extent;
	ecfs_lblk_t start_lblk, len_lblk, ee_start_lblk = 0;
	unsigned int credits, ee_len;
	int ret, depth, split_flag = 0;
	loff_t start;

	trace_ecfs_insert_range(inode, offset, len);
	WARN_ON_ONCE(!inode_is_locked(inode));

	/* Currently just for extent based files */
	if (!ecfs_test_inode_flag(inode, ECFS_INODE_EXTENTS))
		return -EOPNOTSUPP;
	/* Insert range works only on fs cluster size aligned regions. */
	if (!IS_ALIGNED(offset | len, ECFS_CLUSTER_SIZE(sb)))
		return -EINVAL;
	/* Offset must be less than i_size */
	if (offset >= inode->i_size)
		return -EINVAL;
	/* Check whether the maximum file size would be exceeded */
	if (len > inode->i_sb->s_maxbytes - inode->i_size)
		return -EFBIG;

	/*
	 * Write out all dirty pages. Need to round down to align start offset
	 * to page size boundary for page size > block size.
	 */
	start = round_down(offset, PAGE_SIZE);
	ret = filemap_write_and_wait_range(mapping, start, LLONG_MAX);
	if (ret)
		return ret;

	truncate_pagecache(inode, start);

	credits = ecfs_chunk_trans_extent(inode, 0);
	handle = ecfs_journal_start(inode, ECFS_HT_TRUNCATE, credits);
	if (IS_ERR(handle))
		return PTR_ERR(handle);

	ecfs_fc_mark_ineligible(sb, ECFS_FC_REASON_FALLOC_RANGE, handle);

	/* Expand file to avoid data loss if there is error while shifting */
	inode->i_size += len;
	ECFS_I(inode)->i_disksize += len;
	ret = ecfs_mark_inode_dirty(handle, inode);
	if (ret)
		goto out_handle;

	start_lblk = offset >> inode->i_blkbits;
	len_lblk = len >> inode->i_blkbits;

	ecfs_check_map_extents_env(inode);

	down_write(&ECFS_I(inode)->i_data_sem);
	ecfs_discard_preallocations(inode);

	path = ecfs_find_extent(inode, start_lblk, NULL, 0);
	if (IS_ERR(path)) {
		up_write(&ECFS_I(inode)->i_data_sem);
		ret = PTR_ERR(path);
		goto out_handle;
	}

	depth = ext_depth(inode);
	extent = path[depth].p_ext;
	if (extent) {
		ee_start_lblk = le32_to_cpu(extent->ee_block);
		ee_len = ecfs_ext_get_actual_len(extent);

		/*
		 * If start_lblk is not the starting block of extent, split
		 * the extent @start_lblk
		 */
		if ((start_lblk > ee_start_lblk) &&
				(start_lblk < (ee_start_lblk + ee_len))) {
			if (ecfs_ext_is_unwritten(extent))
				split_flag = ECFS_EXT_MARK_UNWRIT1 |
					ECFS_EXT_MARK_UNWRIT2;
			path = ecfs_split_extent_at(handle, inode, path,
					start_lblk, split_flag,
					ECFS_EX_NOCACHE |
					ECFS_GET_BLOCKS_PRE_IO |
					ECFS_GET_BLOCKS_METADATA_NOFAIL);
		}

		if (IS_ERR(path)) {
			up_write(&ECFS_I(inode)->i_data_sem);
			ret = PTR_ERR(path);
			goto out_handle;
		}
	}

	ecfs_free_ext_path(path);
	ecfs_es_remove_extent(inode, start_lblk, EXT_MAX_BLOCKS - start_lblk);

	/*
	 * if start_lblk lies in a hole which is at start of file, use
	 * ee_start_lblk to shift extents
	 */
	ret = ecfs_ext_shift_extents(inode, handle,
		max(ee_start_lblk, start_lblk), len_lblk, SHIFT_RIGHT);
	up_write(&ECFS_I(inode)->i_data_sem);
	if (ret)
		goto out_handle;

	ecfs_update_inode_fsync_trans(handle, inode, 1);
	if (IS_SYNC(inode))
		ecfs_handle_sync(handle);

out_handle:
	ecfs_journal_stop(handle);
	return ret;
}

/**
 * ecfs_swap_extents() - Swap extents between two inodes
 * @handle: handle for this transaction
 * @inode1:	First inode
 * @inode2:	Second inode
 * @lblk1:	Start block for first inode
 * @lblk2:	Start block for second inode
 * @count:	Number of blocks to swap
 * @unwritten: Mark second inode's extents as unwritten after swap
 * @erp:	Pointer to save error value
 *
 * This helper routine does exactly what is promise "swap extents". All other
 * stuff such as page-cache locking consistency, bh mapping consistency or
 * extent's data copying must be performed by caller.
 * Locking:
 *		i_rwsem is held for both inodes
 * 		i_data_sem is locked for write for both inodes
 * Assumptions:
 *		All pages from requested range are locked for both inodes
 */
int
ecfs_swap_extents(handle_t *handle, struct inode *inode1,
		  struct inode *inode2, ecfs_lblk_t lblk1, ecfs_lblk_t lblk2,
		  ecfs_lblk_t count, int unwritten, int *erp)
{
	struct ecfs_ext_path *path1 = NULL;
	struct ecfs_ext_path *path2 = NULL;
	int replaced_count = 0;

	BUG_ON(!rwsem_is_locked(&ECFS_I(inode1)->i_data_sem));
	BUG_ON(!rwsem_is_locked(&ECFS_I(inode2)->i_data_sem));
	BUG_ON(!inode_is_locked(inode1));
	BUG_ON(!inode_is_locked(inode2));

	ecfs_es_remove_extent(inode1, lblk1, count);
	ecfs_es_remove_extent(inode2, lblk2, count);

	while (count) {
		struct ecfs_extent *ex1, *ex2, tmp_ex;
		ecfs_lblk_t e1_blk, e2_blk;
		int e1_len, e2_len, len;
		int split = 0;

		path1 = ecfs_find_extent(inode1, lblk1, path1, ECFS_EX_NOCACHE);
		if (IS_ERR(path1)) {
			*erp = PTR_ERR(path1);
			goto errout;
		}
		path2 = ecfs_find_extent(inode2, lblk2, path2, ECFS_EX_NOCACHE);
		if (IS_ERR(path2)) {
			*erp = PTR_ERR(path2);
			goto errout;
		}
		ex1 = path1[path1->p_depth].p_ext;
		ex2 = path2[path2->p_depth].p_ext;
		/* Do we have something to swap ? */
		if (unlikely(!ex2 || !ex1))
			goto errout;

		e1_blk = le32_to_cpu(ex1->ee_block);
		e2_blk = le32_to_cpu(ex2->ee_block);
		e1_len = ecfs_ext_get_actual_len(ex1);
		e2_len = ecfs_ext_get_actual_len(ex2);

		/* Hole handling */
		if (!in_range(lblk1, e1_blk, e1_len) ||
		    !in_range(lblk2, e2_blk, e2_len)) {
			ecfs_lblk_t next1, next2;

			/* if hole after extent, then go to next extent */
			next1 = ecfs_ext_next_allocated_block(path1);
			next2 = ecfs_ext_next_allocated_block(path2);
			/* If hole before extent, then shift to that extent */
			if (e1_blk > lblk1)
				next1 = e1_blk;
			if (e2_blk > lblk2)
				next2 = e2_blk;
			/* Do we have something to swap */
			if (next1 == EXT_MAX_BLOCKS || next2 == EXT_MAX_BLOCKS)
				goto errout;
			/* Move to the rightest boundary */
			len = next1 - lblk1;
			if (len < next2 - lblk2)
				len = next2 - lblk2;
			if (len > count)
				len = count;
			lblk1 += len;
			lblk2 += len;
			count -= len;
			continue;
		}

		/* Prepare left boundary */
		if (e1_blk < lblk1) {
			split = 1;
			path1 = ecfs_force_split_extent_at(handle, inode1,
							   path1, lblk1, 0);
			if (IS_ERR(path1)) {
				*erp = PTR_ERR(path1);
				goto errout;
			}
		}
		if (e2_blk < lblk2) {
			split = 1;
			path2 = ecfs_force_split_extent_at(handle, inode2,
							   path2, lblk2, 0);
			if (IS_ERR(path2)) {
				*erp = PTR_ERR(path2);
				goto errout;
			}
		}
		/* ecfs_split_extent_at() may result in leaf extent split,
		 * path must to be revalidated. */
		if (split)
			continue;

		/* Prepare right boundary */
		len = count;
		if (len > e1_blk + e1_len - lblk1)
			len = e1_blk + e1_len - lblk1;
		if (len > e2_blk + e2_len - lblk2)
			len = e2_blk + e2_len - lblk2;

		if (len != e1_len) {
			split = 1;
			path1 = ecfs_force_split_extent_at(handle, inode1,
							path1, lblk1 + len, 0);
			if (IS_ERR(path1)) {
				*erp = PTR_ERR(path1);
				goto errout;
			}
		}
		if (len != e2_len) {
			split = 1;
			path2 = ecfs_force_split_extent_at(handle, inode2,
							path2, lblk2 + len, 0);
			if (IS_ERR(path2)) {
				*erp = PTR_ERR(path2);
				goto errout;
			}
		}
		/* ecfs_split_extent_at() may result in leaf extent split,
		 * path must to be revalidated. */
		if (split)
			continue;

		BUG_ON(e2_len != e1_len);
		*erp = ecfs_ext_get_access(handle, inode1, path1 + path1->p_depth);
		if (unlikely(*erp))
			goto errout;
		*erp = ecfs_ext_get_access(handle, inode2, path2 + path2->p_depth);
		if (unlikely(*erp))
			goto errout;

		/* Both extents are fully inside boundaries. Swap it now */
		tmp_ex = *ex1;
		ecfs_ext_store_pblock(ex1, ecfs_ext_pblock(ex2));
		ecfs_ext_store_pblock(ex2, ecfs_ext_pblock(&tmp_ex));
		ex1->ee_len = cpu_to_le16(e2_len);
		ex2->ee_len = cpu_to_le16(e1_len);
		if (unwritten)
			ecfs_ext_mark_unwritten(ex2);
		if (ecfs_ext_is_unwritten(&tmp_ex))
			ecfs_ext_mark_unwritten(ex1);

		ecfs_ext_try_to_merge(handle, inode2, path2, ex2);
		ecfs_ext_try_to_merge(handle, inode1, path1, ex1);
		*erp = ecfs_ext_dirty(handle, inode2, path2 +
				      path2->p_depth);
		if (unlikely(*erp))
			goto errout;
		*erp = ecfs_ext_dirty(handle, inode1, path1 +
				      path1->p_depth);
		/*
		 * Looks scarry ah..? second inode already points to new blocks,
		 * and it was successfully dirtied. But luckily error may happen
		 * only due to journal error, so full transaction will be
		 * aborted anyway.
		 */
		if (unlikely(*erp))
			goto errout;

		lblk1 += len;
		lblk2 += len;
		replaced_count += len;
		count -= len;
	}

errout:
	ecfs_free_ext_path(path1);
	ecfs_free_ext_path(path2);
	return replaced_count;
}

/*
 * ecfs_clu_mapped - determine whether any block in a logical cluster has
 *                   been mapped to a physical cluster
 *
 * @inode - file containing the logical cluster
 * @lclu - logical cluster of interest
 *
 * Returns 1 if any block in the logical cluster is mapped, signifying
 * that a physical cluster has been allocated for it.  Otherwise,
 * returns 0.  Can also return negative error codes.  Derived from
 * ecfs_ext_map_blocks().
 */
int ecfs_clu_mapped(struct inode *inode, ecfs_lblk_t lclu)
{
	struct ecfs_sb_info *sbi = ECFS_SB(inode->i_sb);
	struct ecfs_ext_path *path;
	int depth, mapped = 0, err = 0;
	struct ecfs_extent *extent;
	ecfs_lblk_t first_lblk, first_lclu, last_lclu;

	/*
	 * if data can be stored inline, the logical cluster isn't
	 * mapped - no physical clusters have been allocated, and the
	 * file has no extents
	 */
	if (ecfs_test_inode_state(inode, ECFS_STATE_MAY_INLINE_DATA) ||
	    ecfs_has_inline_data(inode))
		return 0;

	/* search for the extent closest to the first block in the cluster */
	path = ecfs_find_extent(inode, ECFS_C2B(sbi, lclu), NULL, 0);
	if (IS_ERR(path))
		return PTR_ERR(path);

	depth = ext_depth(inode);

	/*
	 * A consistent leaf must not be empty.  This situation is possible,
	 * though, _during_ tree modification, and it's why an assert can't
	 * be put in ecfs_find_extent().
	 */
	if (unlikely(path[depth].p_ext == NULL && depth != 0)) {
		ECFS_ERROR_INODE(inode,
		    "bad extent address - lblock: %lu, depth: %d, pblock: %lld",
				 (unsigned long) ECFS_C2B(sbi, lclu),
				 depth, path[depth].p_block);
		err = -EFSCORRUPTED;
		goto out;
	}

	extent = path[depth].p_ext;

	/* can't be mapped if the extent tree is empty */
	if (extent == NULL)
		goto out;

	first_lblk = le32_to_cpu(extent->ee_block);
	first_lclu = ECFS_B2C(sbi, first_lblk);

	/*
	 * Three possible outcomes at this point - found extent spanning
	 * the target cluster, to the left of the target cluster, or to the
	 * right of the target cluster.  The first two cases are handled here.
	 * The last case indicates the target cluster is not mapped.
	 */
	if (lclu >= first_lclu) {
		last_lclu = ECFS_B2C(sbi, first_lblk +
				     ecfs_ext_get_actual_len(extent) - 1);
		if (lclu <= last_lclu) {
			mapped = 1;
		} else {
			first_lblk = ecfs_ext_next_allocated_block(path);
			first_lclu = ECFS_B2C(sbi, first_lblk);
			if (lclu == first_lclu)
				mapped = 1;
		}
	}

out:
	ecfs_free_ext_path(path);

	return err ? err : mapped;
}

/*
 * Updates physical block address and unwritten status of extent
 * starting at lblk start and of len. If such an extent doesn't exist,
 * this function splits the extent tree appropriately to create an
 * extent like this.  This function is called in the fast commit
 * replay path.  Returns 0 on success and error on failure.
 */
int ecfs_ext_replay_update_ex(struct inode *inode, ecfs_lblk_t start,
			      int len, int unwritten, ecfs_fsblk_t pblk)
{
	struct ecfs_ext_path *path;
	struct ecfs_extent *ex;
	int ret;

	path = ecfs_find_extent(inode, start, NULL, 0);
	if (IS_ERR(path))
		return PTR_ERR(path);
	ex = path[path->p_depth].p_ext;
	if (!ex) {
		ret = -EFSCORRUPTED;
		goto out;
	}

	if (le32_to_cpu(ex->ee_block) != start ||
		ecfs_ext_get_actual_len(ex) != len) {
		/* We need to split this extent to match our extent first */
		down_write(&ECFS_I(inode)->i_data_sem);
		path = ecfs_force_split_extent_at(NULL, inode, path, start, 1);
		up_write(&ECFS_I(inode)->i_data_sem);
		if (IS_ERR(path)) {
			ret = PTR_ERR(path);
			goto out;
		}

		path = ecfs_find_extent(inode, start, path, 0);
		if (IS_ERR(path))
			return PTR_ERR(path);

		ex = path[path->p_depth].p_ext;
		WARN_ON(le32_to_cpu(ex->ee_block) != start);

		if (ecfs_ext_get_actual_len(ex) != len) {
			down_write(&ECFS_I(inode)->i_data_sem);
			path = ecfs_force_split_extent_at(NULL, inode, path,
							  start + len, 1);
			up_write(&ECFS_I(inode)->i_data_sem);
			if (IS_ERR(path)) {
				ret = PTR_ERR(path);
				goto out;
			}

			path = ecfs_find_extent(inode, start, path, 0);
			if (IS_ERR(path))
				return PTR_ERR(path);
			ex = path[path->p_depth].p_ext;
		}
	}
	if (unwritten)
		ecfs_ext_mark_unwritten(ex);
	else
		ecfs_ext_mark_initialized(ex);
	ecfs_ext_store_pblock(ex, pblk);
	down_write(&ECFS_I(inode)->i_data_sem);
	ret = ecfs_ext_dirty(NULL, inode, &path[path->p_depth]);
	up_write(&ECFS_I(inode)->i_data_sem);
out:
	ecfs_free_ext_path(path);
	ecfs_mark_inode_dirty(NULL, inode);
	return ret;
}

/* Try to shrink the extent tree */
void ecfs_ext_replay_shrink_inode(struct inode *inode, ecfs_lblk_t end)
{
	struct ecfs_ext_path *path = NULL;
	struct ecfs_extent *ex;
	ecfs_lblk_t old_cur, cur = 0;

	while (cur < end) {
		path = ecfs_find_extent(inode, cur, NULL, 0);
		if (IS_ERR(path))
			return;
		ex = path[path->p_depth].p_ext;
		if (!ex) {
			ecfs_free_ext_path(path);
			ecfs_mark_inode_dirty(NULL, inode);
			return;
		}
		old_cur = cur;
		cur = le32_to_cpu(ex->ee_block) + ecfs_ext_get_actual_len(ex);
		if (cur <= old_cur)
			cur = old_cur + 1;
		ecfs_ext_try_to_merge(NULL, inode, path, ex);
		down_write(&ECFS_I(inode)->i_data_sem);
		ecfs_ext_dirty(NULL, inode, &path[path->p_depth]);
		up_write(&ECFS_I(inode)->i_data_sem);
		ecfs_mark_inode_dirty(NULL, inode);
		ecfs_free_ext_path(path);
	}
}

/* Check if *cur is a hole and if it is, skip it */
static int skip_hole(struct inode *inode, ecfs_lblk_t *cur)
{
	int ret;
	struct ecfs_map_blocks map;

	map.m_lblk = *cur;
	map.m_len = ((inode->i_size) >> inode->i_sb->s_blocksize_bits) - *cur;

	ret = ecfs_map_blocks(NULL, inode, &map, 0);
	if (ret < 0)
		return ret;
	if (ret != 0)
		return 0;
	*cur = *cur + map.m_len;
	return 0;
}

/* Count number of blocks used by this inode and update i_blocks */
int ecfs_ext_replay_set_iblocks(struct inode *inode)
{
	struct ecfs_ext_path *path = NULL, *path2 = NULL;
	struct ecfs_extent *ex;
	ecfs_lblk_t cur = 0, end;
	int numblks = 0, i, ret = 0;
	ecfs_fsblk_t cmp1, cmp2;
	struct ecfs_map_blocks map;

	/* Determin the size of the file first */
	path = ecfs_find_extent(inode, EXT_MAX_BLOCKS - 1, NULL,
					ECFS_EX_NOCACHE);
	if (IS_ERR(path))
		return PTR_ERR(path);
	ex = path[path->p_depth].p_ext;
	if (!ex)
		goto out;
	end = le32_to_cpu(ex->ee_block) + ecfs_ext_get_actual_len(ex);

	/* Count the number of data blocks */
	cur = 0;
	while (cur < end) {
		map.m_lblk = cur;
		map.m_len = end - cur;
		ret = ecfs_map_blocks(NULL, inode, &map, 0);
		if (ret < 0)
			break;
		if (ret > 0)
			numblks += ret;
		cur = cur + map.m_len;
	}

	/*
	 * Count the number of extent tree blocks. We do it by looking up
	 * two successive extents and determining the difference between
	 * their paths. When path is different for 2 successive extents
	 * we compare the blocks in the path at each level and increment
	 * iblocks by total number of differences found.
	 */
	cur = 0;
	ret = skip_hole(inode, &cur);
	if (ret < 0)
		goto out;
	path = ecfs_find_extent(inode, cur, path, 0);
	if (IS_ERR(path))
		goto out;
	numblks += path->p_depth;
	while (cur < end) {
		path = ecfs_find_extent(inode, cur, path, 0);
		if (IS_ERR(path))
			break;
		ex = path[path->p_depth].p_ext;
		if (!ex)
			goto cleanup;

		cur = max(cur + 1, le32_to_cpu(ex->ee_block) +
					ecfs_ext_get_actual_len(ex));
		ret = skip_hole(inode, &cur);
		if (ret < 0)
			break;

		path2 = ecfs_find_extent(inode, cur, path2, 0);
		if (IS_ERR(path2))
			break;

		for (i = 0; i <= max(path->p_depth, path2->p_depth); i++) {
			cmp1 = cmp2 = 0;
			if (i <= path->p_depth)
				cmp1 = path[i].p_bh ?
					path[i].p_bh->b_blocknr : 0;
			if (i <= path2->p_depth)
				cmp2 = path2[i].p_bh ?
					path2[i].p_bh->b_blocknr : 0;
			if (cmp1 != cmp2 && cmp2 != 0)
				numblks++;
		}
	}

out:
	inode->i_blocks = numblks << (inode->i_sb->s_blocksize_bits - 9);
	ecfs_mark_inode_dirty(NULL, inode);
cleanup:
	ecfs_free_ext_path(path);
	ecfs_free_ext_path(path2);
	return 0;
}

int ecfs_ext_clear_bb(struct inode *inode)
{
	struct ecfs_ext_path *path = NULL;
	struct ecfs_extent *ex;
	ecfs_lblk_t cur = 0, end;
	int j, ret = 0;
	struct ecfs_map_blocks map;

	if (ecfs_test_inode_flag(inode, ECFS_INODE_INLINE_DATA))
		return 0;

	/* Determin the size of the file first */
	path = ecfs_find_extent(inode, EXT_MAX_BLOCKS - 1, NULL,
					ECFS_EX_NOCACHE);
	if (IS_ERR(path))
		return PTR_ERR(path);
	ex = path[path->p_depth].p_ext;
	if (!ex)
		goto out;
	end = le32_to_cpu(ex->ee_block) + ecfs_ext_get_actual_len(ex);

	cur = 0;
	while (cur < end) {
		map.m_lblk = cur;
		map.m_len = end - cur;
		ret = ecfs_map_blocks(NULL, inode, &map, 0);
		if (ret < 0)
			break;
		if (ret > 0) {
			path = ecfs_find_extent(inode, map.m_lblk, path, 0);
			if (!IS_ERR(path)) {
				for (j = 0; j < path->p_depth; j++) {
					ecfs_mb_mark_bb(inode->i_sb,
							path[j].p_block, 1, false);
					ecfs_fc_record_regions(inode->i_sb, inode->i_ino,
							0, path[j].p_block, 1, 1);
				}
			} else {
				path = NULL;
			}
			ecfs_mb_mark_bb(inode->i_sb, map.m_pblk, map.m_len, false);
			ecfs_fc_record_regions(inode->i_sb, inode->i_ino,
					map.m_lblk, map.m_pblk, map.m_len, 1);
		}
		cur = cur + map.m_len;
	}

out:
	ecfs_free_ext_path(path);
	return 0;
}
