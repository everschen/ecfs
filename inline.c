// SPDX-License-Identifier: LGPL-2.1
/*
 * Copyright (c) 2012 Taobao.
 * Written by Tao Ma <boyu.mt@taobao.com>
 */

#include <linux/iomap.h>
#include <linux/fiemap.h>
#include <linux/namei.h>
#include <linux/iversion.h>
#include <linux/sched/mm.h>

#include "ecfs_jbd2.h"
#include "ecfs.h"
#include "xattr.h"
#include "truncate.h"

#define ECFS_XATTR_SYSTEM_DATA	"data"
#define ECFS_MIN_INLINE_DATA_SIZE	((sizeof(__le32) * ECFS_N_BLOCKS))
#define ECFS_INLINE_DOTDOT_OFFSET	2
#define ECFS_INLINE_DOTDOT_SIZE		4


static int ecfs_da_convert_inline_data_to_extent(struct address_space *mapping,
						 struct inode *inode,
						 void **fsdata);

static int ecfs_get_inline_size(struct inode *inode)
{
	if (ECFS_I(inode)->i_inline_off)
		return ECFS_I(inode)->i_inline_size;

	return 0;
}

static int get_max_inline_xattr_value_size(struct inode *inode,
					   struct ecfs_iloc *iloc)
{
	struct ecfs_xattr_ibody_header *header;
	struct ecfs_xattr_entry *entry;
	struct ecfs_inode *raw_inode;
	void *end;
	int free, min_offs;

	if (!ECFS_INODE_HAS_XATTR_SPACE(inode))
		return 0;

	min_offs = ECFS_SB(inode->i_sb)->s_inode_size -
			ECFS_GOOD_OLD_INODE_SIZE -
			ECFS_I(inode)->i_extra_isize -
			sizeof(struct ecfs_xattr_ibody_header);

	/*
	 * We need to subtract another sizeof(__u32) since an in-inode xattr
	 * needs an empty 4 bytes to indicate the gap between the xattr entry
	 * and the name/value pair.
	 */
	if (!ecfs_test_inode_state(inode, ECFS_STATE_XATTR))
		return ECFS_XATTR_SIZE(min_offs -
			ECFS_XATTR_LEN(strlen(ECFS_XATTR_SYSTEM_DATA)) -
			ECFS_XATTR_ROUND - sizeof(__u32));

	raw_inode = ecfs_raw_inode(iloc);
	header = IHDR(inode, raw_inode);
	entry = IFIRST(header);
	end = (void *)raw_inode + ECFS_SB(inode->i_sb)->s_inode_size;

	/* Compute min_offs. */
	while (!IS_LAST_ENTRY(entry)) {
		void *next = ECFS_XATTR_NEXT(entry);

		if (next >= end) {
			ECFS_ERROR_INODE(inode,
					 "corrupt xattr in inline inode");
			return 0;
		}
		if (!entry->e_value_inum && entry->e_value_size) {
			size_t offs = le16_to_cpu(entry->e_value_offs);
			if (offs < min_offs)
				min_offs = offs;
		}
		entry = next;
	}
	free = min_offs -
		((void *)entry - (void *)IFIRST(header)) - sizeof(__u32);

	if (ECFS_I(inode)->i_inline_off) {
		entry = (struct ecfs_xattr_entry *)
			((void *)raw_inode + ECFS_I(inode)->i_inline_off);

		free += ECFS_XATTR_SIZE(le32_to_cpu(entry->e_value_size));
		goto out;
	}

	free -= ECFS_XATTR_LEN(strlen(ECFS_XATTR_SYSTEM_DATA));

	if (free > ECFS_XATTR_ROUND)
		free = ECFS_XATTR_SIZE(free - ECFS_XATTR_ROUND);
	else
		free = 0;

out:
	return free;
}

/*
 * Get the maximum size we now can store in an inode.
 * If we can't find the space for a xattr entry, don't use the space
 * of the extents since we have no space to indicate the inline data.
 */
int ecfs_get_max_inline_size(struct inode *inode)
{
	int error, max_inline_size;
	struct ecfs_iloc iloc;

	if (ECFS_I(inode)->i_extra_isize == 0)
		return 0;

	error = ecfs_get_inode_loc(inode, &iloc);
	if (error) {
		ecfs_error_inode_err(inode, __func__, __LINE__, 0, -error,
				     "can't get inode location %lu",
				     inode->i_ino);
		return 0;
	}

	down_read(&ECFS_I(inode)->xattr_sem);
	max_inline_size = get_max_inline_xattr_value_size(inode, &iloc);
	up_read(&ECFS_I(inode)->xattr_sem);

	brelse(iloc.bh);

	if (!max_inline_size)
		return 0;

	return max_inline_size + ECFS_MIN_INLINE_DATA_SIZE;
}

/*
 * this function does not take xattr_sem, which is OK because it is
 * currently only used in a code path coming form ecfs_iget, before
 * the new inode has been unlocked
 */
int ecfs_find_inline_data_nolock(struct inode *inode)
{
	struct ecfs_xattr_ibody_find is = {
		.s = { .not_found = -ENODATA, },
	};
	struct ecfs_xattr_info i = {
		.name_index = ECFS_XATTR_INDEX_SYSTEM,
		.name = ECFS_XATTR_SYSTEM_DATA,
	};
	int error;

	if (ECFS_I(inode)->i_extra_isize == 0)
		return 0;

	error = ecfs_get_inode_loc(inode, &is.iloc);
	if (error)
		return error;

	error = ecfs_xattr_ibody_find(inode, &i, &is);
	if (error)
		goto out;

	if (!is.s.not_found) {
		if (is.s.here->e_value_inum) {
			ECFS_ERROR_INODE(inode, "inline data xattr refers "
					 "to an external xattr inode");
			error = -EFSCORRUPTED;
			goto out;
		}
		ECFS_I(inode)->i_inline_off = (u16)((void *)is.s.here -
					(void *)ecfs_raw_inode(&is.iloc));
		ECFS_I(inode)->i_inline_size = ECFS_MIN_INLINE_DATA_SIZE +
				le32_to_cpu(is.s.here->e_value_size);
	}
out:
	brelse(is.iloc.bh);
	return error;
}

static int ecfs_read_inline_data(struct inode *inode, void *buffer,
				 unsigned int len,
				 struct ecfs_iloc *iloc)
{
	struct ecfs_xattr_entry *entry;
	struct ecfs_xattr_ibody_header *header;
	int cp_len = 0;
	struct ecfs_inode *raw_inode;

	if (!len)
		return 0;

	BUG_ON(len > ECFS_I(inode)->i_inline_size);

	cp_len = min_t(unsigned int, len, ECFS_MIN_INLINE_DATA_SIZE);

	raw_inode = ecfs_raw_inode(iloc);
	memcpy(buffer, (void *)(raw_inode->i_block), cp_len);

	len -= cp_len;
	buffer += cp_len;

	if (!len)
		goto out;

	header = IHDR(inode, raw_inode);
	entry = (struct ecfs_xattr_entry *)((void *)raw_inode +
					    ECFS_I(inode)->i_inline_off);
	len = min_t(unsigned int, len,
		    (unsigned int)le32_to_cpu(entry->e_value_size));

	memcpy(buffer,
	       (void *)IFIRST(header) + le16_to_cpu(entry->e_value_offs), len);
	cp_len += len;

out:
	return cp_len;
}

/*
 * write the buffer to the inline inode.
 * If 'create' is set, we don't need to do the extra copy in the xattr
 * value since it is already handled by ecfs_xattr_ibody_set.
 * That saves us one memcpy.
 */
static void ecfs_write_inline_data(struct inode *inode, struct ecfs_iloc *iloc,
				   void *buffer, loff_t pos, unsigned int len)
{
	struct ecfs_xattr_entry *entry;
	struct ecfs_xattr_ibody_header *header;
	struct ecfs_inode *raw_inode;
	int cp_len = 0;

	if (unlikely(ecfs_emergency_state(inode->i_sb)))
		return;

	BUG_ON(!ECFS_I(inode)->i_inline_off);
	BUG_ON(pos + len > ECFS_I(inode)->i_inline_size);

	raw_inode = ecfs_raw_inode(iloc);
	buffer += pos;

	if (pos < ECFS_MIN_INLINE_DATA_SIZE) {
		cp_len = pos + len > ECFS_MIN_INLINE_DATA_SIZE ?
			 ECFS_MIN_INLINE_DATA_SIZE - pos : len;
		memcpy((void *)raw_inode->i_block + pos, buffer, cp_len);

		len -= cp_len;
		buffer += cp_len;
		pos += cp_len;
	}

	if (!len)
		return;

	pos -= ECFS_MIN_INLINE_DATA_SIZE;
	header = IHDR(inode, raw_inode);
	entry = (struct ecfs_xattr_entry *)((void *)raw_inode +
					    ECFS_I(inode)->i_inline_off);

	memcpy((void *)IFIRST(header) + le16_to_cpu(entry->e_value_offs) + pos,
	       buffer, len);
}

static int ecfs_create_inline_data(handle_t *handle,
				   struct inode *inode, unsigned len)
{
	int error;
	void *value = NULL;
	struct ecfs_xattr_ibody_find is = {
		.s = { .not_found = -ENODATA, },
	};
	struct ecfs_xattr_info i = {
		.name_index = ECFS_XATTR_INDEX_SYSTEM,
		.name = ECFS_XATTR_SYSTEM_DATA,
	};

	error = ecfs_get_inode_loc(inode, &is.iloc);
	if (error)
		return error;

	BUFFER_TRACE(is.iloc.bh, "get_write_access");
	error = ecfs_journal_get_write_access(handle, inode->i_sb, is.iloc.bh,
					      ECFS_JTR_NONE);
	if (error)
		goto out;

	if (len > ECFS_MIN_INLINE_DATA_SIZE) {
		value = ECFS_ZERO_XATTR_VALUE;
		len -= ECFS_MIN_INLINE_DATA_SIZE;
	} else {
		value = "";
		len = 0;
	}

	/* Insert the xttr entry. */
	i.value = value;
	i.value_len = len;

	error = ecfs_xattr_ibody_find(inode, &i, &is);
	if (error)
		goto out;

	if (!is.s.not_found) {
		ECFS_ERROR_INODE(inode, "unexpected inline data xattr");
		error = -EFSCORRUPTED;
		goto out;
	}

	error = ecfs_xattr_ibody_set(handle, inode, &i, &is);
	if (error) {
		if (error == -ENOSPC)
			ecfs_clear_inode_state(inode,
					       ECFS_STATE_MAY_INLINE_DATA);
		goto out;
	}

	memset((void *)ecfs_raw_inode(&is.iloc)->i_block,
		0, ECFS_MIN_INLINE_DATA_SIZE);

	ECFS_I(inode)->i_inline_off = (u16)((void *)is.s.here -
				      (void *)ecfs_raw_inode(&is.iloc));
	ECFS_I(inode)->i_inline_size = len + ECFS_MIN_INLINE_DATA_SIZE;
	ecfs_clear_inode_flag(inode, ECFS_INODE_EXTENTS);
	ecfs_set_inode_flag(inode, ECFS_INODE_INLINE_DATA);
	get_bh(is.iloc.bh);
	error = ecfs_mark_iloc_dirty(handle, inode, &is.iloc);

out:
	brelse(is.iloc.bh);
	return error;
}

static int ecfs_update_inline_data(handle_t *handle, struct inode *inode,
				   unsigned int len)
{
	int error;
	void *value = NULL;
	struct ecfs_xattr_ibody_find is = {
		.s = { .not_found = -ENODATA, },
	};
	struct ecfs_xattr_info i = {
		.name_index = ECFS_XATTR_INDEX_SYSTEM,
		.name = ECFS_XATTR_SYSTEM_DATA,
	};

	/* If the old space is ok, write the data directly. */
	if (len <= ECFS_I(inode)->i_inline_size)
		return 0;

	error = ecfs_get_inode_loc(inode, &is.iloc);
	if (error)
		return error;

	error = ecfs_xattr_ibody_find(inode, &i, &is);
	if (error)
		goto out;

	if (is.s.not_found) {
		ECFS_ERROR_INODE(inode, "missing inline data xattr");
		error = -EFSCORRUPTED;
		goto out;
	}

	len -= ECFS_MIN_INLINE_DATA_SIZE;
	value = kzalloc(len, GFP_NOFS);
	if (!value) {
		error = -ENOMEM;
		goto out;
	}

	error = ecfs_xattr_ibody_get(inode, i.name_index, i.name,
				     value, len);
	if (error < 0)
		goto out;

	BUFFER_TRACE(is.iloc.bh, "get_write_access");
	error = ecfs_journal_get_write_access(handle, inode->i_sb, is.iloc.bh,
					      ECFS_JTR_NONE);
	if (error)
		goto out;

	/* Update the xattr entry. */
	i.value = value;
	i.value_len = len;

	error = ecfs_xattr_ibody_set(handle, inode, &i, &is);
	if (error)
		goto out;

	ECFS_I(inode)->i_inline_off = (u16)((void *)is.s.here -
				      (void *)ecfs_raw_inode(&is.iloc));
	ECFS_I(inode)->i_inline_size = ECFS_MIN_INLINE_DATA_SIZE +
				le32_to_cpu(is.s.here->e_value_size);
	ecfs_set_inode_state(inode, ECFS_STATE_MAY_INLINE_DATA);
	get_bh(is.iloc.bh);
	error = ecfs_mark_iloc_dirty(handle, inode, &is.iloc);

out:
	kfree(value);
	brelse(is.iloc.bh);
	return error;
}

static int ecfs_prepare_inline_data(handle_t *handle, struct inode *inode,
				    loff_t len)
{
	int ret, size, no_expand;
	struct ecfs_inode_info *ei = ECFS_I(inode);

	if (!ecfs_test_inode_state(inode, ECFS_STATE_MAY_INLINE_DATA))
		return -ENOSPC;

	size = ecfs_get_max_inline_size(inode);
	if (size < len)
		return -ENOSPC;

	ecfs_write_lock_xattr(inode, &no_expand);

	if (ei->i_inline_off)
		ret = ecfs_update_inline_data(handle, inode, len);
	else
		ret = ecfs_create_inline_data(handle, inode, len);

	ecfs_write_unlock_xattr(inode, &no_expand);
	return ret;
}

static int ecfs_destroy_inline_data_nolock(handle_t *handle,
					   struct inode *inode)
{
	struct ecfs_inode_info *ei = ECFS_I(inode);
	struct ecfs_xattr_ibody_find is = {
		.s = { .not_found = 0, },
	};
	struct ecfs_xattr_info i = {
		.name_index = ECFS_XATTR_INDEX_SYSTEM,
		.name = ECFS_XATTR_SYSTEM_DATA,
		.value = NULL,
		.value_len = 0,
	};
	int error;

	if (!ei->i_inline_off)
		return 0;

	error = ecfs_get_inode_loc(inode, &is.iloc);
	if (error)
		return error;

	error = ecfs_xattr_ibody_find(inode, &i, &is);
	if (error)
		goto out;

	BUFFER_TRACE(is.iloc.bh, "get_write_access");
	error = ecfs_journal_get_write_access(handle, inode->i_sb, is.iloc.bh,
					      ECFS_JTR_NONE);
	if (error)
		goto out;

	error = ecfs_xattr_ibody_set(handle, inode, &i, &is);
	if (error)
		goto out;

	memset((void *)ecfs_raw_inode(&is.iloc)->i_block,
		0, ECFS_MIN_INLINE_DATA_SIZE);
	memset(ei->i_data, 0, ECFS_MIN_INLINE_DATA_SIZE);

	if (ecfs_has_feature_extents(inode->i_sb)) {
		if (S_ISDIR(inode->i_mode) ||
		    S_ISREG(inode->i_mode) || S_ISLNK(inode->i_mode)) {
			ecfs_set_inode_flag(inode, ECFS_INODE_EXTENTS);
			ecfs_ext_tree_init(handle, inode);
		}
	}
	ecfs_clear_inode_flag(inode, ECFS_INODE_INLINE_DATA);

	get_bh(is.iloc.bh);
	error = ecfs_mark_iloc_dirty(handle, inode, &is.iloc);

	ECFS_I(inode)->i_inline_off = 0;
	ECFS_I(inode)->i_inline_size = 0;
	ecfs_clear_inode_state(inode, ECFS_STATE_MAY_INLINE_DATA);
out:
	brelse(is.iloc.bh);
	if (error == -ENODATA)
		error = 0;
	return error;
}

static int ecfs_read_inline_folio(struct inode *inode, struct folio *folio)
{
	void *kaddr;
	int ret = 0;
	size_t len;
	struct ecfs_iloc iloc;

	BUG_ON(!folio_test_locked(folio));
	BUG_ON(!ecfs_has_inline_data(inode));
	BUG_ON(folio->index);

	if (!ECFS_I(inode)->i_inline_off) {
		ecfs_warning(inode->i_sb, "inode %lu doesn't have inline data.",
			     inode->i_ino);
		goto out;
	}

	ret = ecfs_get_inode_loc(inode, &iloc);
	if (ret)
		goto out;

	len = min_t(size_t, ecfs_get_inline_size(inode), i_size_read(inode));
	BUG_ON(len > PAGE_SIZE);
	kaddr = kmap_local_folio(folio, 0);
	ret = ecfs_read_inline_data(inode, kaddr, len, &iloc);
	kaddr = folio_zero_tail(folio, len, kaddr + len);
	kunmap_local(kaddr);
	folio_mark_uptodate(folio);
	brelse(iloc.bh);

out:
	return ret;
}

int ecfs_readpage_inline(struct inode *inode, struct folio *folio)
{
	int ret = 0;

	down_read(&ECFS_I(inode)->xattr_sem);
	if (!ecfs_has_inline_data(inode)) {
		up_read(&ECFS_I(inode)->xattr_sem);
		return -EAGAIN;
	}

	/*
	 * Current inline data can only exist in the 1st page,
	 * So for all the other pages, just set them uptodate.
	 */
	if (!folio->index)
		ret = ecfs_read_inline_folio(inode, folio);
	else if (!folio_test_uptodate(folio)) {
		folio_zero_segment(folio, 0, folio_size(folio));
		folio_mark_uptodate(folio);
	}

	up_read(&ECFS_I(inode)->xattr_sem);

	folio_unlock(folio);
	return ret >= 0 ? 0 : ret;
}

static int ecfs_convert_inline_data_to_extent(struct address_space *mapping,
					      struct inode *inode)
{
	int ret, needed_blocks, no_expand;
	handle_t *handle = NULL;
	int retries = 0, sem_held = 0;
	struct folio *folio = NULL;
	unsigned from, to;
	struct ecfs_iloc iloc;

	if (!ecfs_has_inline_data(inode)) {
		/*
		 * clear the flag so that no new write
		 * will trap here again.
		 */
		ecfs_clear_inode_state(inode, ECFS_STATE_MAY_INLINE_DATA);
		return 0;
	}

	needed_blocks = ecfs_chunk_trans_extent(inode, 1);

	ret = ecfs_get_inode_loc(inode, &iloc);
	if (ret)
		return ret;

retry:
	handle = ecfs_journal_start(inode, ECFS_HT_WRITE_PAGE, needed_blocks);
	if (IS_ERR(handle)) {
		ret = PTR_ERR(handle);
		handle = NULL;
		goto out;
	}

	/* We cannot recurse into the filesystem as the transaction is already
	 * started */
	folio = __filemap_get_folio(mapping, 0, FGP_WRITEBEGIN | FGP_NOFS,
			mapping_gfp_mask(mapping));
	if (IS_ERR(folio)) {
		ret = PTR_ERR(folio);
		goto out_nofolio;
	}

	ecfs_write_lock_xattr(inode, &no_expand);
	sem_held = 1;
	/* If some one has already done this for us, just exit. */
	if (!ecfs_has_inline_data(inode)) {
		ret = 0;
		goto out;
	}

	from = 0;
	to = ecfs_get_inline_size(inode);
	if (!folio_test_uptodate(folio)) {
		ret = ecfs_read_inline_folio(inode, folio);
		if (ret < 0)
			goto out;
	}

	ecfs_fc_track_inode(handle, inode);
	ret = ecfs_destroy_inline_data_nolock(handle, inode);
	if (ret)
		goto out;

	if (ecfs_should_dioread_nolock(inode)) {
		ret = ecfs_block_write_begin(handle, folio, from, to,
					     ecfs_get_block_unwritten);
	} else
		ret = ecfs_block_write_begin(handle, folio, from, to,
					     ecfs_get_block);
	clear_buffer_new(folio_buffers(folio));

	if (!ret && ecfs_should_journal_data(inode)) {
		ret = ecfs_walk_page_buffers(handle, inode,
					     folio_buffers(folio), from, to,
					     NULL, ecfs_do_journal_get_write_access);
	}

	if (ret) {
		folio_unlock(folio);
		folio_put(folio);
		folio = NULL;
		ecfs_orphan_add(handle, inode);
		ecfs_write_unlock_xattr(inode, &no_expand);
		sem_held = 0;
		ecfs_journal_stop(handle);
		handle = NULL;
		ecfs_truncate_failed_write(inode);
		/*
		 * If truncate failed early the inode might
		 * still be on the orphan list; we need to
		 * make sure the inode is removed from the
		 * orphan list in that case.
		 */
		if (inode->i_nlink)
			ecfs_orphan_del(NULL, inode);
	}

	if (ret == -ENOSPC && ecfs_should_retry_alloc(inode->i_sb, &retries))
		goto retry;

	if (folio)
		block_commit_write(folio, from, to);
out:
	if (folio) {
		folio_unlock(folio);
		folio_put(folio);
	}
out_nofolio:
	if (sem_held)
		ecfs_write_unlock_xattr(inode, &no_expand);
	if (handle)
		ecfs_journal_stop(handle);
	brelse(iloc.bh);
	return ret;
}

/*
 * Prepare the write for the inline data.
 * If the data can be written into the inode, we just read
 * the page and make it uptodate, and start the journal.
 * Otherwise read the page, makes it dirty so that it can be
 * handle in writepages(the i_disksize update is left to the
 * normal ecfs_da_write_end).
 */
int ecfs_generic_write_inline_data(struct address_space *mapping,
					  struct inode *inode,
					  loff_t pos, unsigned len,
					  struct folio **foliop,
					  void **fsdata, bool da)
{
	int ret;
	handle_t *handle;
	struct folio *folio;
	struct ecfs_iloc iloc;
	int retries = 0;

	ret = ecfs_get_inode_loc(inode, &iloc);
	if (ret)
		return ret;

retry_journal:
	handle = ecfs_journal_start(inode, ECFS_HT_INODE, 1);
	if (IS_ERR(handle)) {
		ret = PTR_ERR(handle);
		goto out_release_bh;
	}

	ret = ecfs_prepare_inline_data(handle, inode, pos + len);
	if (ret && ret != -ENOSPC)
		goto out_stop_journal;

	if (ret == -ENOSPC) {
		ecfs_journal_stop(handle);
		if (!da) {
			brelse(iloc.bh);
			/* Retry inside */
			return ecfs_convert_inline_data_to_extent(mapping, inode);
		}

		ret = ecfs_da_convert_inline_data_to_extent(mapping, inode, fsdata);
		if (ret == -ENOSPC &&
		    ecfs_should_retry_alloc(inode->i_sb, &retries))
			goto retry_journal;
		goto out_release_bh;
	}

	folio = __filemap_get_folio(mapping, 0, FGP_WRITEBEGIN | FGP_NOFS,
					mapping_gfp_mask(mapping));
	if (IS_ERR(folio)) {
		ret = PTR_ERR(folio);
		goto out_stop_journal;
	}

	down_read(&ECFS_I(inode)->xattr_sem);
	/* Someone else had converted it to extent */
	if (!ecfs_has_inline_data(inode)) {
		ret = 0;
		goto out_release_folio;
	}

	if (!folio_test_uptodate(folio)) {
		ret = ecfs_read_inline_folio(inode, folio);
		if (ret < 0)
			goto out_release_folio;
	}

	ret = ecfs_journal_get_write_access(handle, inode->i_sb, iloc.bh, ECFS_JTR_NONE);
	if (ret)
		goto out_release_folio;
	*foliop = folio;
	up_read(&ECFS_I(inode)->xattr_sem);
	brelse(iloc.bh);
	return 1;

out_release_folio:
	up_read(&ECFS_I(inode)->xattr_sem);
	folio_unlock(folio);
	folio_put(folio);
out_stop_journal:
	ecfs_journal_stop(handle);
out_release_bh:
	brelse(iloc.bh);
	return ret;
}

/*
 * Try to write data in the inode.
 * If the inode has inline data, check whether the new write can be
 * in the inode also. If not, create the page the handle, move the data
 * to the page make it update and let the later codes create extent for it.
 */
int ecfs_try_to_write_inline_data(struct address_space *mapping,
				  struct inode *inode,
				  loff_t pos, unsigned len,
				  struct folio **foliop)
{
	if (pos + len > ecfs_get_max_inline_size(inode))
		return ecfs_convert_inline_data_to_extent(mapping, inode);
	return ecfs_generic_write_inline_data(mapping, inode, pos, len,
					      foliop, NULL, false);
}

int ecfs_write_inline_data_end(struct inode *inode, loff_t pos, unsigned len,
			       unsigned copied, struct folio *folio)
{
	handle_t *handle = ecfs_journal_current_handle();
	int no_expand;
	void *kaddr;
	struct ecfs_iloc iloc;
	int ret = 0, ret2;

	if (unlikely(copied < len) && !folio_test_uptodate(folio))
		copied = 0;

	if (likely(copied)) {
		ret = ecfs_get_inode_loc(inode, &iloc);
		if (ret) {
			folio_unlock(folio);
			folio_put(folio);
			ecfs_std_error(inode->i_sb, ret);
			goto out;
		}
		ecfs_write_lock_xattr(inode, &no_expand);
		BUG_ON(!ecfs_has_inline_data(inode));

		/*
		 * ei->i_inline_off may have changed since
		 * ecfs_write_begin() called
		 * ecfs_try_to_write_inline_data()
		 */
		(void) ecfs_find_inline_data_nolock(inode);

		kaddr = kmap_local_folio(folio, 0);
		ecfs_write_inline_data(inode, &iloc, kaddr, pos, copied);
		kunmap_local(kaddr);
		folio_mark_uptodate(folio);
		/* clear dirty flag so that writepages wouldn't work for us. */
		folio_clear_dirty(folio);

		ecfs_write_unlock_xattr(inode, &no_expand);
		brelse(iloc.bh);

		/*
		 * It's important to update i_size while still holding folio
		 * lock: page writeout could otherwise come in and zero
		 * beyond i_size.
		 */
		ecfs_update_inode_size(inode, pos + copied);
	}
	folio_unlock(folio);
	folio_put(folio);

	/*
	 * Don't mark the inode dirty under folio lock. First, it unnecessarily
	 * makes the holding time of folio lock longer. Second, it forces lock
	 * ordering of folio lock and transaction start for journaling
	 * filesystems.
	 */
	if (likely(copied))
		mark_inode_dirty(inode);
out:
	/*
	 * If we didn't copy as much data as expected, we need to trim back
	 * size of xattr containing inline data.
	 */
	if (pos + len > inode->i_size && ecfs_can_truncate(inode))
		ecfs_orphan_add(handle, inode);

	ret2 = ecfs_journal_stop(handle);
	if (!ret)
		ret = ret2;
	if (pos + len > inode->i_size) {
		ecfs_truncate_failed_write(inode);
		/*
		 * If truncate failed early the inode might still be
		 * on the orphan list; we need to make sure the inode
		 * is removed from the orphan list in that case.
		 */
		if (inode->i_nlink)
			ecfs_orphan_del(NULL, inode);
	}
	return ret ? ret : copied;
}

/*
 * Try to make the page cache and handle ready for the inline data case.
 * We can call this function in 2 cases:
 * 1. The inode is created and the first write exceeds inline size. We can
 *    clear the inode state safely.
 * 2. The inode has inline data, then we need to read the data, make it
 *    update and dirty so that ecfs_da_writepages can handle it. We don't
 *    need to start the journal since the file's metadata isn't changed now.
 */
static int ecfs_da_convert_inline_data_to_extent(struct address_space *mapping,
						 struct inode *inode,
						 void **fsdata)
{
	int ret = 0, inline_size;
	struct folio *folio;

	folio = __filemap_get_folio(mapping, 0, FGP_WRITEBEGIN,
					mapping_gfp_mask(mapping));
	if (IS_ERR(folio))
		return PTR_ERR(folio);

	down_read(&ECFS_I(inode)->xattr_sem);
	if (!ecfs_has_inline_data(inode)) {
		ecfs_clear_inode_state(inode, ECFS_STATE_MAY_INLINE_DATA);
		goto out;
	}

	inline_size = ecfs_get_inline_size(inode);

	if (!folio_test_uptodate(folio)) {
		ret = ecfs_read_inline_folio(inode, folio);
		if (ret < 0)
			goto out;
	}

	ret = ecfs_block_write_begin(NULL, folio, 0, inline_size,
				     ecfs_da_get_block_prep);
	if (ret) {
		up_read(&ECFS_I(inode)->xattr_sem);
		folio_unlock(folio);
		folio_put(folio);
		ecfs_truncate_failed_write(inode);
		return ret;
	}

	clear_buffer_new(folio_buffers(folio));
	folio_mark_dirty(folio);
	folio_mark_uptodate(folio);
	ecfs_clear_inode_state(inode, ECFS_STATE_MAY_INLINE_DATA);
	*fsdata = (void *)CONVERT_INLINE_DATA;

out:
	up_read(&ECFS_I(inode)->xattr_sem);
	if (folio) {
		folio_unlock(folio);
		folio_put(folio);
	}
	return ret;
}

#ifdef INLINE_DIR_DEBUG
void ecfs_show_inline_dir(struct inode *dir, struct buffer_head *bh,
			  void *inline_start, int inline_size)
{
	int offset;
	unsigned short de_len;
	struct ecfs_dir_entry_2 *de = inline_start;
	void *dlimit = inline_start + inline_size;

	trace_printk("inode %lu\n", dir->i_ino);
	offset = 0;
	while ((void *)de < dlimit) {
		de_len = ecfs_rec_len_from_disk(de->rec_len, inline_size);
		trace_printk("de: off %u rlen %u name %.*s nlen %u ino %u\n",
			     offset, de_len, de->name_len, de->name,
			     de->name_len, le64_to_cpu(de->inode));
		if (ecfs_check_dir_entry(dir, NULL, de, bh,
					 inline_start, inline_size, offset))
			BUG();

		offset += de_len;
		de = (struct ecfs_dir_entry_2 *) ((char *) de + de_len);
	}
}
#else
#define ecfs_show_inline_dir(dir, bh, inline_start, inline_size)
#endif

/*
 * Add a new entry into a inline dir.
 * It will return -ENOSPC if no space is available, and -EIO
 * and -EEXIST if directory entry already exists.
 */
static int ecfs_add_dirent_to_inline(handle_t *handle,
				     struct ecfs_filename *fname,
				     struct inode *dir,
				     struct inode *inode,
				     struct ecfs_iloc *iloc,
				     void *inline_start, int inline_size)
{
	int		err;
	struct ecfs_dir_entry_2 *de;

	err = ecfs_find_dest_de(dir, iloc->bh, inline_start,
				inline_size, fname, &de);
	if (err)
		return err;

	BUFFER_TRACE(iloc->bh, "get_write_access");
	err = ecfs_journal_get_write_access(handle, dir->i_sb, iloc->bh,
					    ECFS_JTR_NONE);
	if (err)
		return err;
	ecfs_insert_dentry(dir, inode, de, inline_size, fname);

	ecfs_show_inline_dir(dir, iloc->bh, inline_start, inline_size);

	/*
	 * XXX shouldn't update any times until successful
	 * completion of syscall, but too many callers depend
	 * on this.
	 *
	 * XXX similarly, too many callers depend on
	 * ecfs_new_inode() setting the times, but error
	 * recovery deletes the inode, so the worst that can
	 * happen is that the times are slightly out of date
	 * and/or different from the directory change time.
	 */
	inode_set_mtime_to_ts(dir, inode_set_ctime_current(dir));
	ecfs_update_dx_flag(dir);
	inode_inc_iversion(dir);
	return 1;
}

static void *ecfs_get_inline_xattr_pos(struct inode *inode,
				       struct ecfs_iloc *iloc)
{
	struct ecfs_xattr_entry *entry;
	struct ecfs_xattr_ibody_header *header;

	BUG_ON(!ECFS_I(inode)->i_inline_off);

	header = IHDR(inode, ecfs_raw_inode(iloc));
	entry = (struct ecfs_xattr_entry *)((void *)ecfs_raw_inode(iloc) +
					    ECFS_I(inode)->i_inline_off);

	return (void *)IFIRST(header) + le16_to_cpu(entry->e_value_offs);
}

/* Set the final de to cover the whole block. */
void ecfs_update_final_de(void *de_buf, int old_size, int new_size)
{
	struct ecfs_dir_entry_2 *de, *prev_de;
	void *limit;
	int de_len;

	de = de_buf;
	if (old_size) {
		limit = de_buf + old_size;
		do {
			prev_de = de;
			de_len = ecfs_rec_len_from_disk(de->rec_len, old_size);
			de_buf += de_len;
			de = de_buf;
		} while (de_buf < limit);

		prev_de->rec_len = ecfs_rec_len_to_disk(de_len + new_size -
							old_size, new_size);
	} else {
		/* this is just created, so create an empty entry. */
		de->inode = 0;
		de->rec_len = ecfs_rec_len_to_disk(new_size, new_size);
	}
}

static int ecfs_update_inline_dir(handle_t *handle, struct inode *dir,
				  struct ecfs_iloc *iloc)
{
	int ret;
	int old_size = ECFS_I(dir)->i_inline_size - ECFS_MIN_INLINE_DATA_SIZE;
	int new_size = get_max_inline_xattr_value_size(dir, iloc);

	if (new_size - old_size <= ecfs_dir_rec_len(1, NULL))
		return -ENOSPC;

	ret = ecfs_update_inline_data(handle, dir,
				      new_size + ECFS_MIN_INLINE_DATA_SIZE);
	if (ret)
		return ret;

	ecfs_update_final_de(ecfs_get_inline_xattr_pos(dir, iloc), old_size,
			     ECFS_I(dir)->i_inline_size -
						ECFS_MIN_INLINE_DATA_SIZE);
	dir->i_size = ECFS_I(dir)->i_disksize = ECFS_I(dir)->i_inline_size;
	return 0;
}

static void ecfs_restore_inline_data(handle_t *handle, struct inode *inode,
				     struct ecfs_iloc *iloc,
				     void *buf, int inline_size)
{
	int ret;

	ret = ecfs_create_inline_data(handle, inode, inline_size);
	if (ret) {
		ecfs_msg(inode->i_sb, KERN_EMERG,
			"error restoring inline_data for inode -- potential data loss! (inode %lu, error %d)",
			inode->i_ino, ret);
		return;
	}
	ecfs_write_inline_data(inode, iloc, buf, 0, inline_size);
	ecfs_set_inode_state(inode, ECFS_STATE_MAY_INLINE_DATA);
}

static int ecfs_convert_inline_data_nolock(handle_t *handle,
					   struct inode *inode,
					   struct ecfs_iloc *iloc)
{
	int error;
	void *buf = NULL;
	struct buffer_head *data_bh = NULL;
	struct ecfs_map_blocks map;
	int inline_size;

	inline_size = ecfs_get_inline_size(inode);
	buf = kmalloc(inline_size, GFP_NOFS);
	if (!buf) {
		error = -ENOMEM;
		goto out;
	}

	error = ecfs_read_inline_data(inode, buf, inline_size, iloc);
	if (error < 0)
		goto out;

	/*
	 * Make sure the inline directory entries pass checks before we try to
	 * convert them, so that we avoid touching stuff that needs fsck.
	 */
	if (S_ISDIR(inode->i_mode)) {
		error = ecfs_check_all_de(inode, iloc->bh,
					buf + ECFS_INLINE_DOTDOT_SIZE,
					inline_size - ECFS_INLINE_DOTDOT_SIZE);
		if (error)
			goto out;
	}

	error = ecfs_destroy_inline_data_nolock(handle, inode);
	if (error)
		goto out;

	map.m_lblk = 0;
	map.m_len = 1;
	map.m_flags = 0;
	error = ecfs_map_blocks(handle, inode, &map, ECFS_GET_BLOCKS_CREATE);
	if (error < 0)
		goto out_restore;
	if (!(map.m_flags & ECFS_MAP_MAPPED)) {
		error = -EIO;
		goto out_restore;
	}

	data_bh = sb_getblk(inode->i_sb, map.m_pblk);
	if (!data_bh) {
		error = -ENOMEM;
		goto out_restore;
	}

	lock_buffer(data_bh);
	error = ecfs_journal_get_create_access(handle, inode->i_sb, data_bh,
					       ECFS_JTR_NONE);
	if (error) {
		unlock_buffer(data_bh);
		error = -EIO;
		goto out_restore;
	}
	memset(data_bh->b_data, 0, inode->i_sb->s_blocksize);

	if (!S_ISDIR(inode->i_mode)) {
		memcpy(data_bh->b_data, buf, inline_size);
		set_buffer_uptodate(data_bh);
		unlock_buffer(data_bh);
		error = ecfs_handle_dirty_metadata(handle,
						   inode, data_bh);
	} else {
		unlock_buffer(data_bh);
		inode->i_size = inode->i_sb->s_blocksize;
		i_size_write(inode, inode->i_sb->s_blocksize);
		ECFS_I(inode)->i_disksize = inode->i_sb->s_blocksize;

		error = ecfs_init_dirblock(handle, inode, data_bh,
			  le64_to_cpu(((struct ecfs_dir_entry_2 *)buf)->inode),
			  buf + ECFS_INLINE_DOTDOT_SIZE,
			  inline_size - ECFS_INLINE_DOTDOT_SIZE);
		if (!error)
			error = ecfs_mark_inode_dirty(handle, inode);
	}

out_restore:
	if (error)
		ecfs_restore_inline_data(handle, inode, iloc, buf, inline_size);

out:
	brelse(data_bh);
	kfree(buf);
	return error;
}

/*
 * Try to add the new entry to the inline data.
 * If succeeds, return 0. If not, extended the inline dir and copied data to
 * the new created block.
 */
int ecfs_try_add_inline_entry(handle_t *handle, struct ecfs_filename *fname,
			      struct inode *dir, struct inode *inode)
{
	int ret, ret2, inline_size, no_expand;
	void *inline_start;
	struct ecfs_iloc iloc;

	ret = ecfs_get_inode_loc(dir, &iloc);
	if (ret)
		return ret;

	ecfs_write_lock_xattr(dir, &no_expand);
	if (!ecfs_has_inline_data(dir))
		goto out;

	inline_start = (void *)ecfs_raw_inode(&iloc)->i_block +
						 ECFS_INLINE_DOTDOT_SIZE;
	inline_size = ECFS_MIN_INLINE_DATA_SIZE - ECFS_INLINE_DOTDOT_SIZE;

	ret = ecfs_add_dirent_to_inline(handle, fname, dir, inode, &iloc,
					inline_start, inline_size);
	if (ret != -ENOSPC)
		goto out;

	/* check whether it can be inserted to inline xattr space. */
	inline_size = ECFS_I(dir)->i_inline_size -
			ECFS_MIN_INLINE_DATA_SIZE;
	if (!inline_size) {
		/* Try to use the xattr space.*/
		ret = ecfs_update_inline_dir(handle, dir, &iloc);
		if (ret && ret != -ENOSPC)
			goto out;

		inline_size = ECFS_I(dir)->i_inline_size -
				ECFS_MIN_INLINE_DATA_SIZE;
	}

	if (inline_size) {
		inline_start = ecfs_get_inline_xattr_pos(dir, &iloc);

		ret = ecfs_add_dirent_to_inline(handle, fname, dir,
						inode, &iloc, inline_start,
						inline_size);

		if (ret != -ENOSPC)
			goto out;
	}

	/*
	 * The inline space is filled up, so create a new block for it.
	 * As the extent tree will be created, we have to save the inline
	 * dir first.
	 */
	ret = ecfs_convert_inline_data_nolock(handle, dir, &iloc);

out:
	ecfs_write_unlock_xattr(dir, &no_expand);
	ret2 = ecfs_mark_inode_dirty(handle, dir);
	if (unlikely(ret2 && !ret))
		ret = ret2;
	brelse(iloc.bh);
	return ret;
}

/*
 * This function fills a red-black tree with information from an
 * inlined dir.  It returns the number directory entries loaded
 * into the tree.  If there is an error it is returned in err.
 */
int ecfs_inlinedir_to_tree(struct file *dir_file,
			   struct inode *dir, ecfs_lblk_t block,
			   struct dx_hash_info *hinfo,
			   __u32 start_hash, __u32 start_minor_hash,
			   int *has_inline_data)
{
	int err = 0, count = 0;
	unsigned int parent_ino;
	int pos;
	struct ecfs_dir_entry_2 *de;
	struct inode *inode = file_inode(dir_file);
	int ret, inline_size = 0;
	struct ecfs_iloc iloc;
	void *dir_buf = NULL;
	struct ecfs_dir_entry_2 fake;
	struct fscrypt_str tmp_str;

	ret = ecfs_get_inode_loc(inode, &iloc);
	if (ret)
		return ret;

	down_read(&ECFS_I(inode)->xattr_sem);
	if (!ecfs_has_inline_data(inode)) {
		up_read(&ECFS_I(inode)->xattr_sem);
		*has_inline_data = 0;
		goto out;
	}

	inline_size = ecfs_get_inline_size(inode);
	dir_buf = kmalloc(inline_size, GFP_NOFS);
	if (!dir_buf) {
		ret = -ENOMEM;
		up_read(&ECFS_I(inode)->xattr_sem);
		goto out;
	}

	ret = ecfs_read_inline_data(inode, dir_buf, inline_size, &iloc);
	up_read(&ECFS_I(inode)->xattr_sem);
	if (ret < 0)
		goto out;

	pos = 0;
	parent_ino = le64_to_cpu(((struct ecfs_dir_entry_2 *)dir_buf)->inode);
	while (pos < inline_size) {
		/*
		 * As inlined dir doesn't store any information about '.' and
		 * only the inode number of '..' is stored, we have to handle
		 * them differently.
		 */
		if (pos == 0) {
			fake.inode = cpu_to_le64(inode->i_ino);
			fake.name_len = 1;
			memcpy(fake.name, ".", 2);
			fake.rec_len = ecfs_rec_len_to_disk(
					  ecfs_dir_rec_len(fake.name_len, NULL),
					  inline_size);
			ecfs_set_de_type(inode->i_sb, &fake, S_IFDIR);
			de = &fake;
			pos = ECFS_INLINE_DOTDOT_OFFSET;
		} else if (pos == ECFS_INLINE_DOTDOT_OFFSET) {
			fake.inode = cpu_to_le64(parent_ino);
			fake.name_len = 2;
			memcpy(fake.name, "..", 3);
			fake.rec_len = ecfs_rec_len_to_disk(
					  ecfs_dir_rec_len(fake.name_len, NULL),
					  inline_size);
			ecfs_set_de_type(inode->i_sb, &fake, S_IFDIR);
			de = &fake;
			pos = ECFS_INLINE_DOTDOT_SIZE;
		} else {
			de = (struct ecfs_dir_entry_2 *)(dir_buf + pos);
			pos += ecfs_rec_len_from_disk(de->rec_len, inline_size);
			if (ecfs_check_dir_entry(inode, dir_file, de,
					 iloc.bh, dir_buf,
					 inline_size, pos)) {
				ret = count;
				goto out;
			}
		}

		if (ecfs_hash_in_dirent(dir)) {
			hinfo->hash = ECFS_DIRENT_HASH(de);
			hinfo->minor_hash = ECFS_DIRENT_MINOR_HASH(de);
		} else {
			err = ecfsfs_dirhash(dir, de->name, de->name_len, hinfo);
			if (err) {
				ret = err;
				goto out;
			}
		}
		if ((hinfo->hash < start_hash) ||
		    ((hinfo->hash == start_hash) &&
		     (hinfo->minor_hash < start_minor_hash)))
			continue;
		if (de->inode == 0)
			continue;
		tmp_str.name = de->name;
		tmp_str.len = de->name_len;
		err = ecfs_htree_store_dirent(dir_file, hinfo->hash,
					      hinfo->minor_hash, de, &tmp_str);
		if (err) {
			ret = err;
			goto out;
		}
		count++;
	}
	ret = count;
out:
	kfree(dir_buf);
	brelse(iloc.bh);
	return ret;
}

/*
 * So this function is called when the volume is mkfsed with
 * dir_index disabled. In order to keep f_pos persistent
 * after we convert from an inlined dir to a blocked based,
 * we just pretend that we are a normal dir and return the
 * offset as if '.' and '..' really take place.
 *
 */
int ecfs_read_inline_dir(struct file *file,
			 struct dir_context *ctx,
			 int *has_inline_data)
{
	unsigned int offset, parent_ino;
	int i;
	struct ecfs_dir_entry_2 *de;
	struct super_block *sb;
	struct inode *inode = file_inode(file);
	int ret, inline_size = 0;
	struct ecfs_iloc iloc;
	void *dir_buf = NULL;
	int dotdot_offset, dotdot_size, extra_offset, extra_size;
	struct dir_private_info *info = file->private_data;

	ret = ecfs_get_inode_loc(inode, &iloc);
	if (ret)
		return ret;

	down_read(&ECFS_I(inode)->xattr_sem);
	if (!ecfs_has_inline_data(inode)) {
		up_read(&ECFS_I(inode)->xattr_sem);
		*has_inline_data = 0;
		goto out;
	}

	inline_size = ecfs_get_inline_size(inode);
	dir_buf = kmalloc(inline_size, GFP_NOFS);
	if (!dir_buf) {
		ret = -ENOMEM;
		up_read(&ECFS_I(inode)->xattr_sem);
		goto out;
	}

	ret = ecfs_read_inline_data(inode, dir_buf, inline_size, &iloc);
	up_read(&ECFS_I(inode)->xattr_sem);
	if (ret < 0)
		goto out;

	ret = 0;
	sb = inode->i_sb;
	parent_ino = le64_to_cpu(((struct ecfs_dir_entry_2 *)dir_buf)->inode);
	offset = ctx->pos;

	/*
	 * dotdot_offset and dotdot_size is the real offset and
	 * size for ".." and "." if the dir is block based while
	 * the real size for them are only ECFS_INLINE_DOTDOT_SIZE.
	 * So we will use extra_offset and extra_size to indicate them
	 * during the inline dir iteration.
	 */
	dotdot_offset = ecfs_dir_rec_len(1, NULL);
	dotdot_size = dotdot_offset + ecfs_dir_rec_len(2, NULL);
	extra_offset = dotdot_size - ECFS_INLINE_DOTDOT_SIZE;
	extra_size = extra_offset + inline_size;

	/*
	 * If the cookie has changed since the last call to
	 * readdir(2), then we might be pointing to an invalid
	 * dirent right now.  Scan from the start of the inline
	 * dir to make sure.
	 */
	if (!inode_eq_iversion(inode, info->cookie)) {
		for (i = 0; i < extra_size && i < offset;) {
			/*
			 * "." is with offset 0 and
			 * ".." is dotdot_offset.
			 */
			if (!i) {
				i = dotdot_offset;
				continue;
			} else if (i == dotdot_offset) {
				i = dotdot_size;
				continue;
			}
			/* for other entry, the real offset in
			 * the buf has to be tuned accordingly.
			 */
			de = (struct ecfs_dir_entry_2 *)
				(dir_buf + i - extra_offset);
			/* It's too expensive to do a full
			 * dirent test each time round this
			 * loop, but we do have to test at
			 * least that it is non-zero.  A
			 * failure will be detected in the
			 * dirent test below. */
			if (ecfs_rec_len_from_disk(de->rec_len, extra_size)
				< ecfs_dir_rec_len(1, NULL))
				break;
			i += ecfs_rec_len_from_disk(de->rec_len,
						    extra_size);
		}
		offset = i;
		ctx->pos = offset;
		info->cookie = inode_query_iversion(inode);
	}

	while (ctx->pos < extra_size) {
		if (ctx->pos == 0) {
			if (!dir_emit(ctx, ".", 1, fid_get_ino(inode->i_ino), DT_DIR))
				goto out;
			ctx->pos = dotdot_offset;
			continue;
		}

		if (ctx->pos == dotdot_offset) {
			if (!dir_emit(ctx, "..", 2, fid_get_ino(parent_ino), DT_DIR))
				goto out;
			ctx->pos = dotdot_size;
			continue;
		}

		de = (struct ecfs_dir_entry_2 *)
			(dir_buf + ctx->pos - extra_offset);
		if (ecfs_check_dir_entry(inode, file, de, iloc.bh, dir_buf,
					 extra_size, ctx->pos))
			goto out;
		if (le64_to_cpu(de->inode)) {
			if (!dir_emit(ctx, de->name, de->name_len,
				      fid_get_ino(de->inode),
				      get_dtype(sb, de->file_type)))
				goto out;
		}
		ctx->pos += ecfs_rec_len_from_disk(de->rec_len, extra_size);
	}
out:
	kfree(dir_buf);
	brelse(iloc.bh);
	return ret;
}

void *ecfs_read_inline_link(struct inode *inode)
{
	struct ecfs_iloc iloc;
	int ret, inline_size;
	void *link;

	ret = ecfs_get_inode_loc(inode, &iloc);
	if (ret)
		return ERR_PTR(ret);

	ret = -ENOMEM;
	inline_size = ecfs_get_inline_size(inode);
	link = kmalloc(inline_size + 1, GFP_NOFS);
	if (!link)
		goto out;

	ret = ecfs_read_inline_data(inode, link, inline_size, &iloc);
	if (ret < 0) {
		kfree(link);
		goto out;
	}
	nd_terminate_link(link, inode->i_size, ret);
out:
	if (ret < 0)
		link = ERR_PTR(ret);
	brelse(iloc.bh);
	return link;
}

struct buffer_head *ecfs_get_first_inline_block(struct inode *inode,
					struct ecfs_dir_entry_2 **parent_de,
					int *retval)
{
	struct ecfs_iloc iloc;

	*retval = ecfs_get_inode_loc(inode, &iloc);
	if (*retval)
		return NULL;

	*parent_de = (struct ecfs_dir_entry_2 *)ecfs_raw_inode(&iloc)->i_block;

	return iloc.bh;
}

/*
 * Try to create the inline data for the new dir.
 * If it succeeds, return 0, otherwise return the error.
 * In case of ENOSPC, the caller should create the normal disk layout dir.
 */
int ecfs_try_create_inline_dir(handle_t *handle, struct inode *parent,
			       struct inode *inode)
{
	int ret, inline_size = ECFS_MIN_INLINE_DATA_SIZE;
	struct ecfs_iloc iloc;
	struct ecfs_dir_entry_2 *de;

	ret = ecfs_get_inode_loc(inode, &iloc);
	if (ret)
		return ret;

	ret = ecfs_prepare_inline_data(handle, inode, inline_size);
	if (ret)
		goto out;

	/*
	 * For inline dir, we only save the inode information for the ".."
	 * and create a fake dentry to cover the left space.
	 */
	de = (struct ecfs_dir_entry_2 *)ecfs_raw_inode(&iloc)->i_block;
	de->inode = cpu_to_le64(parent->i_ino);
	de = (struct ecfs_dir_entry_2 *)((void *)de + ECFS_INLINE_DOTDOT_SIZE);
	de->inode = 0;
	de->rec_len = ecfs_rec_len_to_disk(
				inline_size - ECFS_INLINE_DOTDOT_SIZE,
				inline_size);
	set_nlink(inode, 2);
	inode->i_size = ECFS_I(inode)->i_disksize = inline_size;
out:
	brelse(iloc.bh);
	return ret;
}

struct buffer_head *ecfs_find_inline_entry(struct inode *dir,
					struct ecfs_filename *fname,
					struct ecfs_dir_entry_2 **res_dir,
					int *has_inline_data)
{
	struct ecfs_xattr_ibody_find is = {
		.s = { .not_found = -ENODATA, },
	};
	struct ecfs_xattr_info i = {
		.name_index = ECFS_XATTR_INDEX_SYSTEM,
		.name = ECFS_XATTR_SYSTEM_DATA,
	};
	int ret;
	void *inline_start;
	int inline_size;

	ret = ecfs_get_inode_loc(dir, &is.iloc);
	if (ret)
		return ERR_PTR(ret);

	down_read(&ECFS_I(dir)->xattr_sem);

	ret = ecfs_xattr_ibody_find(dir, &i, &is);
	if (ret)
		goto out;

	if (!ecfs_has_inline_data(dir)) {
		*has_inline_data = 0;
		goto out;
	}

	inline_start = (void *)ecfs_raw_inode(&is.iloc)->i_block +
						ECFS_INLINE_DOTDOT_SIZE;
	inline_size = ECFS_MIN_INLINE_DATA_SIZE - ECFS_INLINE_DOTDOT_SIZE;
	ret = ecfs_search_dir(is.iloc.bh, inline_start, inline_size,
			      dir, fname, 0, res_dir);
	if (ret == 1)
		goto out_find;
	if (ret < 0)
		goto out;

	if (ecfs_get_inline_size(dir) == ECFS_MIN_INLINE_DATA_SIZE)
		goto out;

	inline_start = ecfs_get_inline_xattr_pos(dir, &is.iloc);
	inline_size = ecfs_get_inline_size(dir) - ECFS_MIN_INLINE_DATA_SIZE;

	ret = ecfs_search_dir(is.iloc.bh, inline_start, inline_size,
			      dir, fname, 0, res_dir);
	if (ret == 1)
		goto out_find;

out:
	brelse(is.iloc.bh);
	if (ret < 0)
		is.iloc.bh = ERR_PTR(ret);
	else
		is.iloc.bh = NULL;
out_find:
	up_read(&ECFS_I(dir)->xattr_sem);
	return is.iloc.bh;
}

int ecfs_delete_inline_entry(handle_t *handle,
			     struct inode *dir,
			     struct ecfs_dir_entry_2 *de_del,
			     struct buffer_head *bh,
			     int *has_inline_data)
{
	int err, inline_size, no_expand;
	struct ecfs_iloc iloc;
	void *inline_start;

	err = ecfs_get_inode_loc(dir, &iloc);
	if (err)
		return err;

	ecfs_write_lock_xattr(dir, &no_expand);
	if (!ecfs_has_inline_data(dir)) {
		*has_inline_data = 0;
		goto out;
	}

	if ((void *)de_del - ((void *)ecfs_raw_inode(&iloc)->i_block) <
		ECFS_MIN_INLINE_DATA_SIZE) {
		inline_start = (void *)ecfs_raw_inode(&iloc)->i_block +
					ECFS_INLINE_DOTDOT_SIZE;
		inline_size = ECFS_MIN_INLINE_DATA_SIZE -
				ECFS_INLINE_DOTDOT_SIZE;
	} else {
		inline_start = ecfs_get_inline_xattr_pos(dir, &iloc);
		inline_size = ecfs_get_inline_size(dir) -
				ECFS_MIN_INLINE_DATA_SIZE;
	}

	BUFFER_TRACE(bh, "get_write_access");
	err = ecfs_journal_get_write_access(handle, dir->i_sb, bh,
					    ECFS_JTR_NONE);
	if (err)
		goto out;

	err = ecfs_generic_delete_entry(dir, de_del, bh,
					inline_start, inline_size, 0);
	if (err)
		goto out;

	ecfs_show_inline_dir(dir, iloc.bh, inline_start, inline_size);
out:
	ecfs_write_unlock_xattr(dir, &no_expand);
	if (likely(err == 0))
		err = ecfs_mark_inode_dirty(handle, dir);
	brelse(iloc.bh);
	if (err != -ENOENT)
		ecfs_std_error(dir->i_sb, err);
	return err;
}

/*
 * Get the inline dentry at offset.
 */
static inline struct ecfs_dir_entry_2 *
ecfs_get_inline_entry(struct inode *inode,
		      struct ecfs_iloc *iloc,
		      unsigned int offset,
		      void **inline_start,
		      int *inline_size)
{
	void *inline_pos;

	BUG_ON(offset > ecfs_get_inline_size(inode));

	if (offset < ECFS_MIN_INLINE_DATA_SIZE) {
		inline_pos = (void *)ecfs_raw_inode(iloc)->i_block;
		*inline_size = ECFS_MIN_INLINE_DATA_SIZE;
	} else {
		inline_pos = ecfs_get_inline_xattr_pos(inode, iloc);
		offset -= ECFS_MIN_INLINE_DATA_SIZE;
		*inline_size = ecfs_get_inline_size(inode) -
				ECFS_MIN_INLINE_DATA_SIZE;
	}

	if (inline_start)
		*inline_start = inline_pos;
	return (struct ecfs_dir_entry_2 *)(inline_pos + offset);
}

bool ecfs_empty_inline_dir(struct inode *dir, int *has_inline_data)
{
	int err, inline_size;
	struct ecfs_iloc iloc;
	size_t inline_len;
	void *inline_pos;
	unsigned int offset;
	struct ecfs_dir_entry_2 *de;
	bool ret = false;

	err = ecfs_get_inode_loc(dir, &iloc);
	if (err) {
		ECFS_ERROR_INODE_ERR(dir, -err,
				     "error %d getting inode %lu block",
				     err, dir->i_ino);
		return false;
	}

	down_read(&ECFS_I(dir)->xattr_sem);
	if (!ecfs_has_inline_data(dir)) {
		*has_inline_data = 0;
		ret = true;
		goto out;
	}

	de = (struct ecfs_dir_entry_2 *)ecfs_raw_inode(&iloc)->i_block;
	if (!le64_to_cpu(de->inode)) {
		ecfs_warning(dir->i_sb,
			     "bad inline directory (dir #%lu) - no `..'",
			     dir->i_ino);
		goto out;
	}

	inline_len = ecfs_get_inline_size(dir);
	offset = ECFS_INLINE_DOTDOT_SIZE;
	while (offset < inline_len) {
		de = ecfs_get_inline_entry(dir, &iloc, offset,
					   &inline_pos, &inline_size);
		if (ecfs_check_dir_entry(dir, NULL, de,
					 iloc.bh, inline_pos,
					 inline_size, offset)) {
			ecfs_warning(dir->i_sb,
				     "bad inline directory (dir #%lu) - "
				     "inode %llu, rec_len %u, name_len %d"
				     "inline size %d",
				     dir->i_ino, le64_to_cpu(de->inode),
				     le16_to_cpu(de->rec_len), de->name_len,
				     inline_size);
			goto out;
		}
		if (le64_to_cpu(de->inode)) {
			goto out;
		}
		offset += ecfs_rec_len_from_disk(de->rec_len, inline_size);
	}

	ret = true;
out:
	up_read(&ECFS_I(dir)->xattr_sem);
	brelse(iloc.bh);
	return ret;
}

int ecfs_destroy_inline_data(handle_t *handle, struct inode *inode)
{
	int ret, no_expand;

	ecfs_write_lock_xattr(inode, &no_expand);
	ret = ecfs_destroy_inline_data_nolock(handle, inode);
	ecfs_write_unlock_xattr(inode, &no_expand);

	return ret;
}

int ecfs_inline_data_iomap(struct inode *inode, struct iomap *iomap)
{
	__u64 addr;
	int error = -EAGAIN;
	struct ecfs_iloc iloc;

	down_read(&ECFS_I(inode)->xattr_sem);
	if (!ecfs_has_inline_data(inode))
		goto out;

	error = ecfs_get_inode_loc(inode, &iloc);
	if (error)
		goto out;

	addr = (__u64)iloc.bh->b_blocknr << inode->i_sb->s_blocksize_bits;
	addr += (char *)ecfs_raw_inode(&iloc) - iloc.bh->b_data;
	addr += offsetof(struct ecfs_inode, i_block);

	brelse(iloc.bh);

	iomap->addr = addr;
	iomap->offset = 0;
	iomap->length = min_t(loff_t, ecfs_get_inline_size(inode),
			      i_size_read(inode));
	iomap->type = IOMAP_INLINE;
	iomap->flags = 0;

out:
	up_read(&ECFS_I(inode)->xattr_sem);
	return error;
}

int ecfs_inline_data_truncate(struct inode *inode, int *has_inline)
{
	handle_t *handle;
	int inline_size, value_len, needed_blocks, no_expand, err = 0;
	size_t i_size;
	void *value = NULL;
	struct ecfs_xattr_ibody_find is = {
		.s = { .not_found = -ENODATA, },
	};
	struct ecfs_xattr_info i = {
		.name_index = ECFS_XATTR_INDEX_SYSTEM,
		.name = ECFS_XATTR_SYSTEM_DATA,
	};


	needed_blocks = ecfs_chunk_trans_extent(inode, 1);
	handle = ecfs_journal_start(inode, ECFS_HT_INODE, needed_blocks);
	if (IS_ERR(handle))
		return PTR_ERR(handle);

	ecfs_write_lock_xattr(inode, &no_expand);
	if (!ecfs_has_inline_data(inode)) {
		ecfs_write_unlock_xattr(inode, &no_expand);
		*has_inline = 0;
		ecfs_journal_stop(handle);
		return 0;
	}

	if ((err = ecfs_orphan_add(handle, inode)) != 0)
		goto out;

	if ((err = ecfs_get_inode_loc(inode, &is.iloc)) != 0)
		goto out;

	down_write(&ECFS_I(inode)->i_data_sem);
	i_size = inode->i_size;
	inline_size = ecfs_get_inline_size(inode);
	ECFS_I(inode)->i_disksize = i_size;

	if (i_size < inline_size) {
		/*
		 * if there's inline data to truncate and this file was
		 * converted to extents after that inline data was written,
		 * the extent status cache must be cleared to avoid leaving
		 * behind stale delayed allocated extent entries
		 */
		if (!ecfs_test_inode_state(inode, ECFS_STATE_MAY_INLINE_DATA))
			ecfs_es_remove_extent(inode, 0, EXT_MAX_BLOCKS);

		/* Clear the content in the xattr space. */
		if (inline_size > ECFS_MIN_INLINE_DATA_SIZE) {
			if ((err = ecfs_xattr_ibody_find(inode, &i, &is)) != 0)
				goto out_error;

			if (is.s.not_found) {
				ECFS_ERROR_INODE(inode,
						 "missing inline data xattr");
				err = -EFSCORRUPTED;
				goto out_error;
			}

			value_len = le32_to_cpu(is.s.here->e_value_size);
			value = kmalloc(value_len, GFP_NOFS);
			if (!value) {
				err = -ENOMEM;
				goto out_error;
			}

			err = ecfs_xattr_ibody_get(inode, i.name_index,
						   i.name, value, value_len);
			if (err <= 0)
				goto out_error;

			i.value = value;
			i.value_len = i_size > ECFS_MIN_INLINE_DATA_SIZE ?
					i_size - ECFS_MIN_INLINE_DATA_SIZE : 0;
			err = ecfs_xattr_ibody_set(handle, inode, &i, &is);
			if (err)
				goto out_error;
		}

		/* Clear the content within i_blocks. */
		if (i_size < ECFS_MIN_INLINE_DATA_SIZE) {
			void *p = (void *) ecfs_raw_inode(&is.iloc)->i_block;
			memset(p + i_size, 0,
			       ECFS_MIN_INLINE_DATA_SIZE - i_size);
		}

		ECFS_I(inode)->i_inline_size = i_size <
					ECFS_MIN_INLINE_DATA_SIZE ?
					ECFS_MIN_INLINE_DATA_SIZE : i_size;
	}

out_error:
	up_write(&ECFS_I(inode)->i_data_sem);
out:
	brelse(is.iloc.bh);
	ecfs_write_unlock_xattr(inode, &no_expand);
	kfree(value);
	if (inode->i_nlink)
		ecfs_orphan_del(handle, inode);

	if (err == 0) {
		inode_set_mtime_to_ts(inode, inode_set_ctime_current(inode));
		err = ecfs_mark_inode_dirty(handle, inode);
		if (IS_SYNC(inode))
			ecfs_handle_sync(handle);
	}
	ecfs_journal_stop(handle);
	return err;
}

int ecfs_convert_inline_data(struct inode *inode)
{
	int error, needed_blocks, no_expand;
	handle_t *handle;
	struct ecfs_iloc iloc;

	if (!ecfs_has_inline_data(inode)) {
		ecfs_clear_inode_state(inode, ECFS_STATE_MAY_INLINE_DATA);
		return 0;
	} else if (!ecfs_test_inode_state(inode, ECFS_STATE_MAY_INLINE_DATA)) {
		/*
		 * Inode has inline data but ECFS_STATE_MAY_INLINE_DATA is
		 * cleared. This means we are in the middle of moving of
		 * inline data to delay allocated block. Just force writeout
		 * here to finish conversion.
		 */
		error = filemap_flush(inode->i_mapping);
		if (error)
			return error;
		if (!ecfs_has_inline_data(inode))
			return 0;
	}

	needed_blocks = ecfs_chunk_trans_extent(inode, 1);

	iloc.bh = NULL;
	error = ecfs_get_inode_loc(inode, &iloc);
	if (error)
		return error;

	handle = ecfs_journal_start(inode, ECFS_HT_WRITE_PAGE, needed_blocks);
	if (IS_ERR(handle)) {
		error = PTR_ERR(handle);
		goto out_free;
	}

	ecfs_write_lock_xattr(inode, &no_expand);
	if (ecfs_has_inline_data(inode))
		error = ecfs_convert_inline_data_nolock(handle, inode, &iloc);
	ecfs_write_unlock_xattr(inode, &no_expand);
	ecfs_journal_stop(handle);
out_free:
	brelse(iloc.bh);
	return error;
}
