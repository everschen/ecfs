// SPDX-License-Identifier: GPL-2.0+
/*
 * ecfs_jbd2.h
 *
 * Written by Stephen C. Tweedie <sct@redhat.com>, 1999
 *
 * Copyright 1998--1999 Red Hat corp --- All Rights Reserved
 *
 * Ecfs-specific journaling extensions.
 */

#ifndef _ECFS_JBD2_H
#define _ECFS_JBD2_H

#include <linux/fs.h>
#include <linux/jbd2.h>
#include "ecfs.h"

#define ECFS_JOURNAL(inode)	(ECFS_SB((inode)->i_sb)->s_journal)

/* Define the number of blocks we need to account to a transaction to
 * modify one block of data.
 *
 * We may have to touch one inode, one bitmap buffer, up to three
 * indirection blocks, the group and superblock summaries, and the data
 * block to complete the transaction.
 *
 * For extents-enabled fs we may have to allocate and modify up to
 * 5 levels of tree, data block (for each of these we need bitmap + group
 * summaries), root which is stored in the inode, sb
 */

#define ECFS_SINGLEDATA_TRANS_BLOCKS(sb)				\
	(ecfs_has_feature_extents(sb) ? 20U : 8U)

/* Extended attribute operations touch at most two data buffers,
 * two bitmap buffers, and two group summaries, in addition to the inode
 * and the superblock, which are already accounted for. */

#define ECFS_XATTR_TRANS_BLOCKS		6U

/* Define the minimum size for a transaction which modifies data.  This
 * needs to take into account the fact that we may end up modifying two
 * quota files too (one for the group, one for the user quota).  The
 * superblock only gets updated once, of course, so don't bother
 * counting that again for the quota updates. */

#define ECFS_DATA_TRANS_BLOCKS(sb)	(ECFS_SINGLEDATA_TRANS_BLOCKS(sb) + \
					 ECFS_XATTR_TRANS_BLOCKS - 2 + \
					 ECFS_MAXQUOTAS_TRANS_BLOCKS(sb))

/*
 * Define the number of metadata blocks we need to account to modify data.
 *
 * This include super block, inode block, quota blocks and xattr blocks
 */
#define ECFS_META_TRANS_BLOCKS(sb)	(ECFS_XATTR_TRANS_BLOCKS + \
					ECFS_MAXQUOTAS_TRANS_BLOCKS(sb))

/* Define an arbitrary limit for the amount of data we will anticipate
 * writing to any given transaction.  For unbounded transactions such as
 * write(2) and truncate(2) we can write more than this, but we always
 * start off at the maximum transaction size and grow the transaction
 * optimistically as we go. */

#define ECFS_MAX_TRANS_DATA		64U

/* We break up a large truncate or write transaction once the handle's
 * buffer credits gets this low, we need either to extend the
 * transaction or to start a new one.  Reserve enough space here for
 * inode, bitmap, superblock, group and indirection updates for at least
 * one block, plus two quota updates.  Quota allocations are not
 * needed. */

#define ECFS_RESERVE_TRANS_BLOCKS	12U

/*
 * Number of credits needed if we need to insert an entry into a
 * directory.  For each new index block, we need 4 blocks (old index
 * block, new index block, bitmap block, bg summary).  For normal
 * htree directories there are 2 levels; if the largedir feature
 * enabled it's 3 levels.
 */
#define ECFS_INDEX_EXTRA_TRANS_BLOCKS	12U

#ifdef CONFIG_QUOTA
/* Amount of blocks needed for quota update - we know that the structure was
 * allocated so we need to update only data block */
#define ECFS_QUOTA_TRANS_BLOCKS(sb) ((ecfs_quota_capable(sb)) ? 1 : 0)
/* Amount of blocks needed for quota insert/delete - we do some block writes
 * but inode, sb and group updates are done only once */
#define ECFS_QUOTA_INIT_BLOCKS(sb) ((ecfs_quota_capable(sb)) ?\
		(DQUOT_INIT_ALLOC*(ECFS_SINGLEDATA_TRANS_BLOCKS(sb)-3)\
		 +3+DQUOT_INIT_REWRITE) : 0)

#define ECFS_QUOTA_DEL_BLOCKS(sb) ((ecfs_quota_capable(sb)) ?\
		(DQUOT_DEL_ALLOC*(ECFS_SINGLEDATA_TRANS_BLOCKS(sb)-3)\
		 +3+DQUOT_DEL_REWRITE) : 0)
#else
#define ECFS_QUOTA_TRANS_BLOCKS(sb) 0
#define ECFS_QUOTA_INIT_BLOCKS(sb) 0
#define ECFS_QUOTA_DEL_BLOCKS(sb) 0
#endif
#define ECFS_MAXQUOTAS_TRANS_BLOCKS(sb) (ECFS_MAXQUOTAS*ECFS_QUOTA_TRANS_BLOCKS(sb))
#define ECFS_MAXQUOTAS_INIT_BLOCKS(sb) (ECFS_MAXQUOTAS*ECFS_QUOTA_INIT_BLOCKS(sb))
#define ECFS_MAXQUOTAS_DEL_BLOCKS(sb) (ECFS_MAXQUOTAS*ECFS_QUOTA_DEL_BLOCKS(sb))

/*
 * Ecfs handle operation types -- for logging purposes
 */
#define ECFS_HT_MISC             0
#define ECFS_HT_INODE            1
#define ECFS_HT_WRITE_PAGE       2
#define ECFS_HT_MAP_BLOCKS       3
#define ECFS_HT_DIR              4
#define ECFS_HT_TRUNCATE         5
#define ECFS_HT_QUOTA            6
#define ECFS_HT_RESIZE           7
#define ECFS_HT_MIGRATE          8
#define ECFS_HT_MOVE_EXTENTS     9
#define ECFS_HT_XATTR           10
#define ECFS_HT_EXT_CONVERT     11
#define ECFS_HT_MAX             12

int
ecfs_mark_iloc_dirty(handle_t *handle,
		     struct inode *inode,
		     struct ecfs_iloc *iloc);

/*
 * On success, We end up with an outstanding reference count against
 * iloc->bh.  This _must_ be cleaned up later.
 */

int ecfs_reserve_inode_write(handle_t *handle, struct inode *inode,
			struct ecfs_iloc *iloc);

#define ecfs_mark_inode_dirty(__h, __i)					\
		__ecfs_mark_inode_dirty((__h), (__i), __func__, __LINE__)
int __ecfs_mark_inode_dirty(handle_t *handle, struct inode *inode,
				const char *func, unsigned int line);

int ecfs_expand_extra_isize(struct inode *inode,
			    unsigned int new_extra_isize,
			    struct ecfs_iloc *iloc);
/*
 * Wrapper functions with which ecfs calls into JBD.
 */
int __ecfs_journal_get_write_access(const char *where, unsigned int line,
				    handle_t *handle, struct super_block *sb,
				    struct buffer_head *bh,
				    enum ecfs_journal_trigger_type trigger_type);

int __ecfs_forget(const char *where, unsigned int line, handle_t *handle,
		  int is_metadata, struct inode *inode,
		  struct buffer_head *bh, ecfs_fsblk_t blocknr);

int __ecfs_journal_get_create_access(const char *where, unsigned int line,
				handle_t *handle, struct super_block *sb,
				struct buffer_head *bh,
				enum ecfs_journal_trigger_type trigger_type);

int __ecfs_handle_dirty_metadata(const char *where, unsigned int line,
				 handle_t *handle, struct inode *inode,
				 struct buffer_head *bh);

#define ecfs_journal_get_write_access(handle, sb, bh, trigger_type) \
	__ecfs_journal_get_write_access(__func__, __LINE__, (handle), (sb), \
					(bh), (trigger_type))
#define ecfs_forget(handle, is_metadata, inode, bh, block_nr) \
	__ecfs_forget(__func__, __LINE__, (handle), (is_metadata), (inode), \
		      (bh), (block_nr))
#define ecfs_journal_get_create_access(handle, sb, bh, trigger_type) \
	__ecfs_journal_get_create_access(__func__, __LINE__, (handle), (sb), \
					 (bh), (trigger_type))
#define ecfs_handle_dirty_metadata(handle, inode, bh) \
	__ecfs_handle_dirty_metadata(__func__, __LINE__, (handle), (inode), \
				     (bh))

handle_t *__ecfs_journal_start_sb(struct inode *inode, struct super_block *sb,
				  unsigned int line, int type, int blocks,
				  int rsv_blocks, int revoke_creds);
int __ecfs_journal_stop(const char *where, unsigned int line, handle_t *handle);

#define ECFS_NOJOURNAL_MAX_REF_COUNT ((unsigned long) 4096)

/* Note:  Do not use this for NULL handles.  This is only to determine if
 * a properly allocated handle is using a journal or not. */
static inline int ecfs_handle_valid(handle_t *handle)
{
	if ((unsigned long)handle < ECFS_NOJOURNAL_MAX_REF_COUNT)
		return 0;
	return 1;
}

static inline void ecfs_handle_sync(handle_t *handle)
{
	if (ecfs_handle_valid(handle))
		handle->h_sync = 1;
}

static inline int ecfs_handle_is_aborted(handle_t *handle)
{
	if (ecfs_handle_valid(handle))
		return is_handle_aborted(handle);
	return 0;
}

static inline int ecfs_free_metadata_revoke_credits(struct super_block *sb,
						    int blocks)
{
	/* Freeing each metadata block can result in freeing one cluster */
	return blocks * ECFS_SB(sb)->s_cluster_ratio;
}

static inline int ecfs_trans_default_revoke_credits(struct super_block *sb)
{
	return ecfs_free_metadata_revoke_credits(sb, 8);
}

#define ecfs_journal_start_sb(sb, type, nblocks)			\
	__ecfs_journal_start_sb(NULL, (sb), __LINE__, (type), (nblocks), 0,\
				ecfs_trans_default_revoke_credits(sb))

#define ecfs_journal_start(inode, type, nblocks)			\
	__ecfs_journal_start((inode), __LINE__, (type), (nblocks), 0,	\
			     ecfs_trans_default_revoke_credits((inode)->i_sb))

#define ecfs_journal_start_with_reserve(inode, type, blocks, rsv_blocks)\
	__ecfs_journal_start((inode), __LINE__, (type), (blocks), (rsv_blocks),\
			     ecfs_trans_default_revoke_credits((inode)->i_sb))

#define ecfs_journal_start_with_revoke(inode, type, blocks, revoke_creds) \
	__ecfs_journal_start((inode), __LINE__, (type), (blocks), 0,	\
			     (revoke_creds))

static inline handle_t *__ecfs_journal_start(struct inode *inode,
					     unsigned int line, int type,
					     int blocks, int rsv_blocks,
					     int revoke_creds)
{
	return __ecfs_journal_start_sb(inode, inode->i_sb, line, type, blocks,
				       rsv_blocks, revoke_creds);
}

#define ecfs_journal_stop(handle) \
	__ecfs_journal_stop(__func__, __LINE__, (handle))

#define ecfs_journal_start_reserved(handle, type) \
	__ecfs_journal_start_reserved((handle), __LINE__, (type))

handle_t *__ecfs_journal_start_reserved(handle_t *handle, unsigned int line,
					int type);

static inline handle_t *ecfs_journal_current_handle(void)
{
	return journal_current_handle();
}

static inline int ecfs_journal_extend(handle_t *handle, int nblocks, int revoke)
{
	if (ecfs_handle_valid(handle))
		return jbd2_journal_extend(handle, nblocks, revoke);
	return 0;
}

static inline int ecfs_journal_restart(handle_t *handle, int nblocks,
				       int revoke)
{
	if (ecfs_handle_valid(handle))
		return jbd2__journal_restart(handle, nblocks, revoke, GFP_NOFS);
	return 0;
}

int __ecfs_journal_ensure_credits(handle_t *handle, int check_cred,
				  int extend_cred, int revoke_cred);


/*
 * Ensure @handle has at least @check_creds credits available. If not,
 * transaction will be extended or restarted to contain at least @extend_cred
 * credits. Before restarting transaction @fn is executed to allow for cleanup
 * before the transaction is restarted.
 *
 * The return value is < 0 in case of error, 0 in case the handle has enough
 * credits or transaction extension succeeded, 1 in case transaction had to be
 * restarted.
 */
#define ecfs_journal_ensure_credits_fn(handle, check_cred, extend_cred,	\
				       revoke_cred, fn) \
({									\
	__label__ __ensure_end;						\
	int err = __ecfs_journal_ensure_credits((handle), (check_cred),	\
					(extend_cred), (revoke_cred));	\
									\
	if (err <= 0)							\
		goto __ensure_end;					\
	err = (fn);							\
	if (err < 0)							\
		goto __ensure_end;					\
	err = ecfs_journal_restart((handle), (extend_cred), (revoke_cred)); \
	if (err == 0)							\
		err = 1;						\
__ensure_end:								\
	err;								\
})

/*
 * Ensure given handle has at least requested amount of credits available,
 * possibly restarting transaction if needed. We also make sure the transaction
 * has space for at least ecfs_trans_default_revoke_credits(sb) revoke records
 * as freeing one or two blocks is very common pattern and requesting this is
 * very cheap.
 */
static inline int ecfs_journal_ensure_credits(handle_t *handle, int credits,
					      int revoke_creds)
{
	return ecfs_journal_ensure_credits_fn(handle, credits, credits,
				revoke_creds, 0);
}

static inline int ecfs_journal_blocks_per_folio(struct inode *inode)
{
	if (ECFS_JOURNAL(inode) != NULL)
		return jbd2_journal_blocks_per_folio(inode);
	return 0;
}

static inline int ecfs_journal_force_commit(journal_t *journal)
{
	if (journal)
		return jbd2_journal_force_commit(journal);
	return 0;
}

static inline int ecfs_jbd2_inode_add_write(handle_t *handle,
		struct inode *inode, loff_t start_byte, loff_t length)
{
	if (ecfs_handle_valid(handle))
		return jbd2_journal_inode_ranged_write(handle,
				ECFS_I(inode)->jinode, start_byte, length);
	return 0;
}

static inline int ecfs_jbd2_inode_add_wait(handle_t *handle,
		struct inode *inode, loff_t start_byte, loff_t length)
{
	if (ecfs_handle_valid(handle))
		return jbd2_journal_inode_ranged_wait(handle,
				ECFS_I(inode)->jinode, start_byte, length);
	return 0;
}

static inline void ecfs_update_inode_fsync_trans(handle_t *handle,
						 struct inode *inode,
						 int datasync)
{
	struct ecfs_inode_info *ei = ECFS_I(inode);

	if (ecfs_handle_valid(handle) && !is_handle_aborted(handle)) {
		ei->i_sync_tid = handle->h_transaction->t_tid;
		if (datasync)
			ei->i_datasync_tid = handle->h_transaction->t_tid;
	}
}

/* super.c */
int ecfs_force_commit(struct super_block *sb);

/*
 * Ecfs inode journal modes
 */
#define ECFS_INODE_JOURNAL_DATA_MODE	0x01 /* journal data mode */
#define ECFS_INODE_ORDERED_DATA_MODE	0x02 /* ordered data mode */
#define ECFS_INODE_WRITEBACK_DATA_MODE	0x04 /* writeback data mode */

int ecfs_inode_journal_mode(struct inode *inode);

static inline int ecfs_should_journal_data(struct inode *inode)
{
	return ecfs_inode_journal_mode(inode) & ECFS_INODE_JOURNAL_DATA_MODE;
}

static inline int ecfs_should_order_data(struct inode *inode)
{
	return ecfs_inode_journal_mode(inode) & ECFS_INODE_ORDERED_DATA_MODE;
}

static inline int ecfs_should_writeback_data(struct inode *inode)
{
	return ecfs_inode_journal_mode(inode) & ECFS_INODE_WRITEBACK_DATA_MODE;
}

static inline int ecfs_free_data_revoke_credits(struct inode *inode, int blocks)
{
	if (test_opt(inode->i_sb, DATA_FLAGS) == ECFS_MOUNT_JOURNAL_DATA)
		return 0;
	if (!ecfs_should_journal_data(inode))
		return 0;
	/*
	 * Data blocks in one extent are contiguous, just account for partial
	 * clusters at extent boundaries
	 */
	return blocks + 2*(ECFS_SB(inode->i_sb)->s_cluster_ratio - 1);
}

/*
 * This function controls whether or not we should try to go down the
 * dioread_nolock code paths, which makes it safe to avoid taking
 * i_rwsem for direct I/O reads.  This only works for extent-based
 * files, and it doesn't work if data journaling is enabled, since the
 * dioread_nolock code uses b_private to pass information back to the
 * I/O completion handler, and this conflicts with the jbd's use of
 * b_private.
 */
static inline int ecfs_should_dioread_nolock(struct inode *inode)
{
	if (!test_opt(inode->i_sb, DIOREAD_NOLOCK))
		return 0;
	if (!S_ISREG(inode->i_mode))
		return 0;
	if (!(ecfs_test_inode_flag(inode, ECFS_INODE_EXTENTS)))
		return 0;
	if (ecfs_should_journal_data(inode))
		return 0;
	/* temporary fix to prevent generic/422 test failures */
	if (!test_opt(inode->i_sb, DELALLOC))
		return 0;
	return 1;
}

/*
 * Pass journal explicitly as it may not be cached in the sbi->s_journal in some
 * cases
 */
static inline int ecfs_journal_destroy(struct ecfs_sb_info *sbi, journal_t *journal)
{
	int err = 0;

	/*
	 * At this point only two things can be operating on the journal.
	 * JBD2 thread performing transaction commit and s_sb_upd_work
	 * issuing sb update through the journal. Once we set
	 * ECFS_JOURNAL_DESTROY, new ecfs_handle_error() calls will not
	 * queue s_sb_upd_work and ecfs_force_commit() makes sure any
	 * ecfs_handle_error() calls from the running transaction commit are
	 * finished. Hence no new s_sb_upd_work can be queued after we
	 * flush it here.
	 */
	ecfs_set_mount_flag(sbi->s_sb, ECFS_MF_JOURNAL_DESTROY);

	ecfs_force_commit(sbi->s_sb);
	flush_work(&sbi->s_sb_upd_work);

	err = jbd2_journal_destroy(journal);
	sbi->s_journal = NULL;

	return err;
}

#endif	/* _ECFS_JBD2_H */
