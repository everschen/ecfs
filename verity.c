// SPDX-License-Identifier: GPL-2.0
/*
 * fs/ecfs/verity.c: fs-verity support for ecfs
 *
 * Copyright 2019 Google LLC
 */

/*
 * Implementation of fsverity_operations for ecfs.
 *
 * ecfs stores the verity metadata (Merkle tree and fsverity_descriptor) past
 * the end of the file, starting at the first 64K boundary beyond i_size.  This
 * approach works because (a) verity files are readonly, and (b) pages fully
 * beyond i_size aren't visible to userspace but can be read/written internally
 * by ecfs with only some relatively small changes to ecfs.  This approach
 * avoids having to depend on the EA_INODE feature and on rearchitecturing
 * ecfs's xattr support to support paging multi-gigabyte xattrs into memory, and
 * to support encrypting xattrs.  Note that the verity metadata *must* be
 * encrypted when the file is, since it contains hashes of the plaintext data.
 *
 * Using a 64K boundary rather than a 4K one keeps things ready for
 * architectures with 64K pages, and it doesn't necessarily waste space on-disk
 * since there can be a hole between i_size and the start of the Merkle tree.
 */

#include <linux/quotaops.h>

#include "ecfs.h"
#include "ecfs_extents.h"
#include "ecfs_jbd2.h"

static inline loff_t ecfs_verity_metadata_pos(const struct inode *inode)
{
	return round_up(inode->i_size, 65536);
}

/*
 * Read some verity metadata from the inode.  __vfs_read() can't be used because
 * we need to read beyond i_size.
 */
static int pagecache_read(struct inode *inode, void *buf, size_t count,
			  loff_t pos)
{
	while (count) {
		struct folio *folio;
		size_t n;

		folio = read_mapping_folio(inode->i_mapping, pos >> PAGE_SHIFT,
					 NULL);
		if (IS_ERR(folio))
			return PTR_ERR(folio);

		n = memcpy_from_file_folio(buf, folio, pos, count);
		folio_put(folio);

		buf += n;
		pos += n;
		count -= n;
	}
	return 0;
}

/*
 * Write some verity metadata to the inode for FS_IOC_ENABLE_VERITY.
 * kernel_write() can't be used because the file descriptor is readonly.
 */
static int pagecache_write(struct inode *inode, const void *buf, size_t count,
			   loff_t pos)
{
	struct address_space *mapping = inode->i_mapping;
	const struct address_space_operations *aops = mapping->a_ops;

	if (pos + count > inode->i_sb->s_maxbytes)
		return -EFBIG;

	while (count) {
		size_t n = min_t(size_t, count,
				 PAGE_SIZE - offset_in_page(pos));
		struct folio *folio;
		void *fsdata = NULL;
		int res;

		res = aops->write_begin(NULL, mapping, pos, n, &folio, &fsdata);
		if (res)
			return res;

		memcpy_to_folio(folio, offset_in_folio(folio, pos), buf, n);

		res = aops->write_end(NULL, mapping, pos, n, n, folio, fsdata);
		if (res < 0)
			return res;
		if (res != n)
			return -EIO;

		buf += n;
		pos += n;
		count -= n;
	}
	return 0;
}

static int ecfs_begin_enable_verity(struct file *filp)
{
	struct inode *inode = file_inode(filp);
	const int credits = 2; /* superblock and inode for ecfs_orphan_add() */
	handle_t *handle;
	int err;

	if (IS_DAX(inode) || ecfs_test_inode_flag(inode, ECFS_INODE_DAX))
		return -EINVAL;

	if (ecfs_verity_in_progress(inode))
		return -EBUSY;

	/*
	 * Since the file was opened readonly, we have to initialize the jbd
	 * inode and quotas here and not rely on ->open() doing it.  This must
	 * be done before evicting the inline data.
	 */

	err = ecfs_inode_attach_jinode(inode);
	if (err)
		return err;

	err = dquot_initialize(inode);
	if (err)
		return err;

	err = ecfs_convert_inline_data(inode);
	if (err)
		return err;

	if (!ecfs_test_inode_flag(inode, ECFS_INODE_EXTENTS)) {
		ecfs_warning_inode(inode,
				   "verity is only allowed on extent-based files");
		return -EOPNOTSUPP;
	}

	/*
	 * ecfs uses the last allocated block to find the verity descriptor, so
	 * we must remove any other blocks past EOF which might confuse things.
	 */
	err = ecfs_truncate(inode);
	if (err)
		return err;

	handle = ecfs_journal_start(inode, ECFS_HT_INODE, credits);
	if (IS_ERR(handle))
		return PTR_ERR(handle);

	err = ecfs_orphan_add(handle, inode);
	if (err == 0)
		ecfs_set_inode_state(inode, ECFS_STATE_VERITY_IN_PROGRESS);

	ecfs_journal_stop(handle);
	return err;
}

/*
 * ecfs stores the verity descriptor beginning on the next filesystem block
 * boundary after the Merkle tree.  Then, the descriptor size is stored in the
 * last 4 bytes of the last allocated filesystem block --- which is either the
 * block in which the descriptor ends, or the next block after that if there
 * weren't at least 4 bytes remaining.
 *
 * We can't simply store the descriptor in an xattr because it *must* be
 * encrypted when ecfs encryption is used, but ecfs encryption doesn't encrypt
 * xattrs.  Also, if the descriptor includes a large signature blob it may be
 * too large to store in an xattr without the EA_INODE feature.
 */
static int ecfs_write_verity_descriptor(struct inode *inode, const void *desc,
					size_t desc_size, u64 merkle_tree_size)
{
	const u64 desc_pos = round_up(ecfs_verity_metadata_pos(inode) +
				      merkle_tree_size, i_blocksize(inode));
	const u64 desc_end = desc_pos + desc_size;
	const __le32 desc_size_disk = cpu_to_le32(desc_size);
	const u64 desc_size_pos = round_up(desc_end + sizeof(desc_size_disk),
					   i_blocksize(inode)) -
				  sizeof(desc_size_disk);
	int err;

	err = pagecache_write(inode, desc, desc_size, desc_pos);
	if (err)
		return err;

	return pagecache_write(inode, &desc_size_disk, sizeof(desc_size_disk),
			       desc_size_pos);
}

static int ecfs_end_enable_verity(struct file *filp, const void *desc,
				  size_t desc_size, u64 merkle_tree_size)
{
	struct inode *inode = file_inode(filp);
	const int credits = 2; /* superblock and inode for ecfs_orphan_del() */
	handle_t *handle;
	struct ecfs_iloc iloc;
	int err = 0;

	/*
	 * If an error already occurred (which fs/verity/ signals by passing
	 * desc == NULL), then only clean-up is needed.
	 */
	if (desc == NULL)
		goto cleanup;

	/* Append the verity descriptor. */
	err = ecfs_write_verity_descriptor(inode, desc, desc_size,
					   merkle_tree_size);
	if (err)
		goto cleanup;

	/*
	 * Write all pages (both data and verity metadata).  Note that this must
	 * happen before clearing ECFS_STATE_VERITY_IN_PROGRESS; otherwise pages
	 * beyond i_size won't be written properly.  For crash consistency, this
	 * also must happen before the verity inode flag gets persisted.
	 */
	err = filemap_write_and_wait(inode->i_mapping);
	if (err)
		goto cleanup;

	/*
	 * Finally, set the verity inode flag and remove the inode from the
	 * orphan list (in a single transaction).
	 */

	handle = ecfs_journal_start(inode, ECFS_HT_INODE, credits);
	if (IS_ERR(handle)) {
		err = PTR_ERR(handle);
		goto cleanup;
	}

	err = ecfs_orphan_del(handle, inode);
	if (err)
		goto stop_and_cleanup;

	err = ecfs_reserve_inode_write(handle, inode, &iloc);
	if (err)
		goto stop_and_cleanup;

	ecfs_set_inode_flag(inode, ECFS_INODE_VERITY);
	ecfs_set_inode_flags(inode, false);
	err = ecfs_mark_iloc_dirty(handle, inode, &iloc);
	if (err)
		goto stop_and_cleanup;

	ecfs_journal_stop(handle);

	ecfs_clear_inode_state(inode, ECFS_STATE_VERITY_IN_PROGRESS);
	return 0;

stop_and_cleanup:
	ecfs_journal_stop(handle);
cleanup:
	/*
	 * Verity failed to be enabled, so clean up by truncating any verity
	 * metadata that was written beyond i_size (both from cache and from
	 * disk), removing the inode from the orphan list (if it wasn't done
	 * already), and clearing ECFS_STATE_VERITY_IN_PROGRESS.
	 */
	truncate_inode_pages(inode->i_mapping, inode->i_size);
	ecfs_truncate(inode);
	ecfs_orphan_del(NULL, inode);
	ecfs_clear_inode_state(inode, ECFS_STATE_VERITY_IN_PROGRESS);
	return err;
}

static int ecfs_get_verity_descriptor_location(struct inode *inode,
					       size_t *desc_size_ret,
					       u64 *desc_pos_ret)
{
	struct ecfs_ext_path *path;
	struct ecfs_extent *last_extent;
	u32 end_lblk;
	u64 desc_size_pos;
	__le32 desc_size_disk;
	u32 desc_size;
	u64 desc_pos;
	int err;

	/*
	 * Descriptor size is in last 4 bytes of last allocated block.
	 * See ecfs_write_verity_descriptor().
	 */

	if (!ecfs_test_inode_flag(inode, ECFS_INODE_EXTENTS)) {
		ECFS_ERROR_INODE(inode, "verity file doesn't use extents");
		return -EFSCORRUPTED;
	}

	path = ecfs_find_extent(inode, EXT_MAX_BLOCKS - 1, NULL, 0);
	if (IS_ERR(path))
		return PTR_ERR(path);

	last_extent = path[path->p_depth].p_ext;
	if (!last_extent) {
		ECFS_ERROR_INODE(inode, "verity file has no extents");
		ecfs_free_ext_path(path);
		return -EFSCORRUPTED;
	}

	end_lblk = le32_to_cpu(last_extent->ee_block) +
		   ecfs_ext_get_actual_len(last_extent);
	desc_size_pos = (u64)end_lblk << inode->i_blkbits;
	ecfs_free_ext_path(path);

	if (desc_size_pos < sizeof(desc_size_disk))
		goto bad;
	desc_size_pos -= sizeof(desc_size_disk);

	err = pagecache_read(inode, &desc_size_disk, sizeof(desc_size_disk),
			     desc_size_pos);
	if (err)
		return err;
	desc_size = le32_to_cpu(desc_size_disk);

	/*
	 * The descriptor is stored just before the desc_size_disk, but starting
	 * on a filesystem block boundary.
	 */

	if (desc_size > INT_MAX || desc_size > desc_size_pos)
		goto bad;

	desc_pos = round_down(desc_size_pos - desc_size, i_blocksize(inode));
	if (desc_pos < ecfs_verity_metadata_pos(inode))
		goto bad;

	*desc_size_ret = desc_size;
	*desc_pos_ret = desc_pos;
	return 0;

bad:
	ECFS_ERROR_INODE(inode, "verity file corrupted; can't find descriptor");
	return -EFSCORRUPTED;
}

static int ecfs_get_verity_descriptor(struct inode *inode, void *buf,
				      size_t buf_size)
{
	size_t desc_size = 0;
	u64 desc_pos = 0;
	int err;

	err = ecfs_get_verity_descriptor_location(inode, &desc_size, &desc_pos);
	if (err)
		return err;

	if (buf_size) {
		if (desc_size > buf_size)
			return -ERANGE;
		err = pagecache_read(inode, buf, desc_size, desc_pos);
		if (err)
			return err;
	}
	return desc_size;
}

static struct page *ecfs_read_merkle_tree_page(struct inode *inode,
					       pgoff_t index,
					       unsigned long num_ra_pages)
{
	struct folio *folio;

	index += ecfs_verity_metadata_pos(inode) >> PAGE_SHIFT;

	folio = __filemap_get_folio(inode->i_mapping, index, FGP_ACCESSED, 0);
	if (IS_ERR(folio) || !folio_test_uptodate(folio)) {
		DEFINE_READAHEAD(ractl, NULL, NULL, inode->i_mapping, index);

		if (!IS_ERR(folio))
			folio_put(folio);
		else if (num_ra_pages > 1)
			page_cache_ra_unbounded(&ractl, num_ra_pages, 0);
		folio = read_mapping_folio(inode->i_mapping, index, NULL);
		if (IS_ERR(folio))
			return ERR_CAST(folio);
	}
	return folio_file_page(folio, index);
}

static int ecfs_write_merkle_tree_block(struct inode *inode, const void *buf,
					u64 pos, unsigned int size)
{
	pos += ecfs_verity_metadata_pos(inode);

	return pagecache_write(inode, buf, size, pos);
}

const struct fsverity_operations ecfs_verityops = {
	.begin_enable_verity	= ecfs_begin_enable_verity,
	.end_enable_verity	= ecfs_end_enable_verity,
	.get_verity_descriptor	= ecfs_get_verity_descriptor,
	.read_merkle_tree_page	= ecfs_read_merkle_tree_page,
	.write_merkle_tree_block = ecfs_write_merkle_tree_block,
};
