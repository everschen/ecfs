// SPDX-License-Identifier: GPL-2.0+
/*
 * Copyright (C) 2017 Oracle.  All Rights Reserved.
 *
 * Author: Darrick J. Wong <darrick.wong@oracle.com>
 */
#include "ecfs.h"
#include <linux/fsmap.h>
#include "fsmap.h"
#include "mballoc.h"
#include <linux/sort.h>
#include <linux/list_sort.h>
#include <trace/events/ecfs.h>

/* Convert an ecfs_fsmap to an fsmap. */
void ecfs_fsmap_from_internal(struct super_block *sb, struct fsmap *dest,
			      struct ecfs_fsmap *src)
{
	dest->fmr_device = src->fmr_device;
	dest->fmr_flags = src->fmr_flags;
	dest->fmr_physical = src->fmr_physical << sb->s_blocksize_bits;
	dest->fmr_owner = src->fmr_owner;
	dest->fmr_offset = 0;
	dest->fmr_length = src->fmr_length << sb->s_blocksize_bits;
	dest->fmr_reserved[0] = 0;
	dest->fmr_reserved[1] = 0;
	dest->fmr_reserved[2] = 0;
}

/* Convert an fsmap to an ecfs_fsmap. */
void ecfs_fsmap_to_internal(struct super_block *sb, struct ecfs_fsmap *dest,
			    struct fsmap *src)
{
	dest->fmr_device = src->fmr_device;
	dest->fmr_flags = src->fmr_flags;
	dest->fmr_physical = src->fmr_physical >> sb->s_blocksize_bits;
	dest->fmr_owner = src->fmr_owner;
	dest->fmr_length = src->fmr_length >> sb->s_blocksize_bits;
}

/* getfsmap query state */
struct ecfs_getfsmap_info {
	struct ecfs_fsmap_head	*gfi_head;
	ecfs_fsmap_format_t	gfi_formatter;	/* formatting fn */
	void			*gfi_format_arg;/* format buffer */
	ecfs_fsblk_t		gfi_next_fsblk;	/* next fsblock we expect */
	u32			gfi_dev;	/* device id */
	ecfs_group_t		gfi_agno;	/* bg number, if applicable */
	struct ecfs_fsmap	gfi_low;	/* low rmap key */
	struct ecfs_fsmap	gfi_high;	/* high rmap key */
	struct ecfs_fsmap	gfi_lastfree;	/* free ext at end of last bg */
	struct list_head	gfi_meta_list;	/* fixed metadata list */
	bool			gfi_last;	/* last extent? */
};

/* Associate a device with a getfsmap handler. */
struct ecfs_getfsmap_dev {
	int			(*gfd_fn)(struct super_block *sb,
				      struct ecfs_fsmap *keys,
				      struct ecfs_getfsmap_info *info);
	u32			gfd_dev;
};

/* Compare two getfsmap device handlers. */
static int ecfs_getfsmap_dev_compare(const void *p1, const void *p2)
{
	const struct ecfs_getfsmap_dev *d1 = p1;
	const struct ecfs_getfsmap_dev *d2 = p2;

	return d1->gfd_dev - d2->gfd_dev;
}

/* Compare a record against our starting point */
static bool ecfs_getfsmap_rec_before_low_key(struct ecfs_getfsmap_info *info,
					     struct ecfs_fsmap *rec)
{
	return rec->fmr_physical < info->gfi_low.fmr_physical;
}

/*
 * Format a reverse mapping for getfsmap, having translated rm_startblock
 * into the appropriate daddr units.
 */
static int ecfs_getfsmap_helper(struct super_block *sb,
				struct ecfs_getfsmap_info *info,
				struct ecfs_fsmap *rec)
{
	struct ecfs_fsmap fmr;
	struct ecfs_sb_info *sbi = ECFS_SB(sb);
	ecfs_fsblk_t rec_fsblk = rec->fmr_physical;
	ecfs_group_t agno;
	ecfs_grpblk_t cno;
	int error;

	if (fatal_signal_pending(current))
		return -EINTR;

	/*
	 * Filter out records that start before our startpoint, if the
	 * caller requested that.
	 */
	if (ecfs_getfsmap_rec_before_low_key(info, rec)) {
		rec_fsblk += rec->fmr_length;
		if (info->gfi_next_fsblk < rec_fsblk)
			info->gfi_next_fsblk = rec_fsblk;
		return ECFS_QUERY_RANGE_CONTINUE;
	}

	/* Are we just counting mappings? */
	if (info->gfi_head->fmh_count == 0) {
		if (info->gfi_head->fmh_entries == UINT_MAX)
			return ECFS_QUERY_RANGE_ABORT;

		if (rec_fsblk > info->gfi_next_fsblk)
			info->gfi_head->fmh_entries++;

		if (info->gfi_last)
			return ECFS_QUERY_RANGE_CONTINUE;

		info->gfi_head->fmh_entries++;

		rec_fsblk += rec->fmr_length;
		if (info->gfi_next_fsblk < rec_fsblk)
			info->gfi_next_fsblk = rec_fsblk;
		return ECFS_QUERY_RANGE_CONTINUE;
	}

	/*
	 * If the record starts past the last physical block we saw,
	 * then we've found a gap.  Report the gap as being owned by
	 * whatever the caller specified is the missing owner.
	 */
	if (rec_fsblk > info->gfi_next_fsblk) {
		if (info->gfi_head->fmh_entries >= info->gfi_head->fmh_count)
			return ECFS_QUERY_RANGE_ABORT;

		ecfs_get_group_no_and_offset(sb, info->gfi_next_fsblk,
				&agno, &cno);
		trace_ecfs_fsmap_mapping(sb, info->gfi_dev, agno,
				ECFS_C2B(sbi, cno),
				rec_fsblk - info->gfi_next_fsblk,
				ECFS_FMR_OWN_UNKNOWN);

		fmr.fmr_device = info->gfi_dev;
		fmr.fmr_physical = info->gfi_next_fsblk;
		fmr.fmr_owner = ECFS_FMR_OWN_UNKNOWN;
		fmr.fmr_length = rec_fsblk - info->gfi_next_fsblk;
		fmr.fmr_flags = FMR_OF_SPECIAL_OWNER;
		error = info->gfi_formatter(&fmr, info->gfi_format_arg);
		if (error)
			return error;
		info->gfi_head->fmh_entries++;
	}

	if (info->gfi_last)
		goto out;

	/* Fill out the extent we found */
	if (info->gfi_head->fmh_entries >= info->gfi_head->fmh_count)
		return ECFS_QUERY_RANGE_ABORT;

	ecfs_get_group_no_and_offset(sb, rec_fsblk, &agno, &cno);
	trace_ecfs_fsmap_mapping(sb, info->gfi_dev, agno, ECFS_C2B(sbi, cno),
			rec->fmr_length, rec->fmr_owner);

	fmr.fmr_device = info->gfi_dev;
	fmr.fmr_physical = rec_fsblk;
	fmr.fmr_owner = rec->fmr_owner;
	fmr.fmr_flags = FMR_OF_SPECIAL_OWNER;
	fmr.fmr_length = rec->fmr_length;
	error = info->gfi_formatter(&fmr, info->gfi_format_arg);
	if (error)
		return error;
	info->gfi_head->fmh_entries++;

out:
	rec_fsblk += rec->fmr_length;
	if (info->gfi_next_fsblk < rec_fsblk)
		info->gfi_next_fsblk = rec_fsblk;
	return ECFS_QUERY_RANGE_CONTINUE;
}

static inline ecfs_fsblk_t ecfs_fsmap_next_pblk(struct ecfs_fsmap *fmr)
{
	return fmr->fmr_physical + fmr->fmr_length;
}

static int ecfs_getfsmap_meta_helper(struct super_block *sb,
				     ecfs_group_t agno, ecfs_grpblk_t start,
				     ecfs_grpblk_t len, void *priv)
{
	struct ecfs_getfsmap_info *info = priv;
	struct ecfs_fsmap *p;
	struct ecfs_fsmap *tmp;
	struct ecfs_sb_info *sbi = ECFS_SB(sb);
	ecfs_fsblk_t fsb, fs_start, fs_end;
	int error;

	fs_start = fsb = (ECFS_C2B(sbi, start) +
			  ecfs_group_first_block_no(sb, agno));
	fs_end = fs_start + ECFS_C2B(sbi, len);

	/* Return relevant extents from the meta_list */
	list_for_each_entry_safe(p, tmp, &info->gfi_meta_list, fmr_list) {
		if (p->fmr_physical < info->gfi_next_fsblk) {
			list_del(&p->fmr_list);
			kfree(p);
			continue;
		}
		if (p->fmr_physical <= fs_start ||
		    p->fmr_physical + p->fmr_length <= fs_end) {
			/* Emit the retained free extent record if present */
			if (info->gfi_lastfree.fmr_owner) {
				error = ecfs_getfsmap_helper(sb, info,
							&info->gfi_lastfree);
				if (error)
					return error;
				info->gfi_lastfree.fmr_owner = 0;
			}
			error = ecfs_getfsmap_helper(sb, info, p);
			if (error)
				return error;
			fsb = p->fmr_physical + p->fmr_length;
			if (info->gfi_next_fsblk < fsb)
				info->gfi_next_fsblk = fsb;
			list_del(&p->fmr_list);
			kfree(p);
			continue;
		}
	}
	if (info->gfi_next_fsblk < fsb)
		info->gfi_next_fsblk = fsb;

	return 0;
}


/* Transform a blockgroup's free record into a fsmap */
static int ecfs_getfsmap_datadev_helper(struct super_block *sb,
					ecfs_group_t agno, ecfs_grpblk_t start,
					ecfs_grpblk_t len, void *priv)
{
	struct ecfs_fsmap irec;
	struct ecfs_getfsmap_info *info = priv;
	struct ecfs_fsmap *p;
	struct ecfs_fsmap *tmp;
	struct ecfs_sb_info *sbi = ECFS_SB(sb);
	ecfs_fsblk_t fsb;
	ecfs_fsblk_t fslen;
	int error;

	fsb = (ECFS_C2B(sbi, start) + ecfs_group_first_block_no(sb, agno));
	fslen = ECFS_C2B(sbi, len);

	/* If the retained free extent record is set... */
	if (info->gfi_lastfree.fmr_owner) {
		/* ...and abuts this one, lengthen it and return. */
		if (ecfs_fsmap_next_pblk(&info->gfi_lastfree) == fsb) {
			info->gfi_lastfree.fmr_length += fslen;
			return 0;
		}

		/*
		 * There's a gap between the two free extents; emit the
		 * retained extent prior to merging the meta_list.
		 */
		error = ecfs_getfsmap_helper(sb, info, &info->gfi_lastfree);
		if (error)
			return error;
		info->gfi_lastfree.fmr_owner = 0;
	}

	/* Merge in any relevant extents from the meta_list */
	list_for_each_entry_safe(p, tmp, &info->gfi_meta_list, fmr_list) {
		if (p->fmr_physical + p->fmr_length <= info->gfi_next_fsblk) {
			list_del(&p->fmr_list);
			kfree(p);
		} else if (p->fmr_physical < fsb) {
			error = ecfs_getfsmap_helper(sb, info, p);
			if (error)
				return error;

			list_del(&p->fmr_list);
			kfree(p);
		}
	}

	irec.fmr_device = 0;
	irec.fmr_physical = fsb;
	irec.fmr_length = fslen;
	irec.fmr_owner = ECFS_FMR_OWN_FREE;
	irec.fmr_flags = 0;

	/* If this is a free extent at the end of a bg, buffer it. */
	if (ecfs_fsmap_next_pblk(&irec) ==
			ecfs_group_first_block_no(sb, agno + 1)) {
		info->gfi_lastfree = irec;
		return 0;
	}

	/* Otherwise, emit it */
	return ecfs_getfsmap_helper(sb, info, &irec);
}

/* Execute a getfsmap query against the log device. */
static int ecfs_getfsmap_logdev(struct super_block *sb, struct ecfs_fsmap *keys,
				struct ecfs_getfsmap_info *info)
{
	journal_t *journal = ECFS_SB(sb)->s_journal;
	struct ecfs_fsmap irec;

	/* Set up search keys */
	info->gfi_low = keys[0];
	info->gfi_low.fmr_length = 0;

	memset(&info->gfi_high, 0xFF, sizeof(info->gfi_high));

	trace_ecfs_fsmap_low_key(sb, info->gfi_dev, 0,
			info->gfi_low.fmr_physical,
			info->gfi_low.fmr_length,
			info->gfi_low.fmr_owner);

	trace_ecfs_fsmap_high_key(sb, info->gfi_dev, 0,
			info->gfi_high.fmr_physical,
			info->gfi_high.fmr_length,
			info->gfi_high.fmr_owner);

	if (keys[0].fmr_physical > 0)
		return 0;

	/* Fabricate an rmap entry for the external log device. */
	irec.fmr_physical = journal->j_blk_offset;
	irec.fmr_length = journal->j_total_len;
	irec.fmr_owner = ECFS_FMR_OWN_LOG;
	irec.fmr_flags = 0;

	return ecfs_getfsmap_helper(sb, info, &irec);
}

/* Helper to fill out an ecfs_fsmap. */
static inline int ecfs_getfsmap_fill(struct list_head *meta_list,
				     ecfs_fsblk_t fsb, ecfs_fsblk_t len,
				     uint64_t owner)
{
	struct ecfs_fsmap *fsm;

	fsm = kmalloc(sizeof(*fsm), GFP_NOFS);
	if (!fsm)
		return -ENOMEM;
	fsm->fmr_device = 0;
	fsm->fmr_flags = 0;
	fsm->fmr_physical = fsb;
	fsm->fmr_owner = owner;
	fsm->fmr_length = len;
	list_add_tail(&fsm->fmr_list, meta_list);

	return 0;
}

/*
 * This function returns the number of file system metadata blocks at
 * the beginning of a block group, including the reserved gdt blocks.
 */
static unsigned int ecfs_getfsmap_find_sb(struct super_block *sb,
					  ecfs_group_t agno,
					  struct list_head *meta_list)
{
	struct ecfs_sb_info *sbi = ECFS_SB(sb);
	ecfs_fsblk_t fsb = ecfs_group_first_block_no(sb, agno);
	ecfs_fsblk_t len;
	unsigned long first_meta_bg = le32_to_cpu(sbi->s_es->s_first_meta_bg);
	unsigned long metagroup = agno / ECFS_DESC_PER_BLOCK(sb);
	int error;

	/* Record the superblock. */
	if (ecfs_bg_has_super(sb, agno)) {
		error = ecfs_getfsmap_fill(meta_list, fsb, 1, ECFS_FMR_OWN_FS);
		if (error)
			return error;
		fsb++;
	}

	/* Record the group descriptors. */
	len = ecfs_bg_num_gdb(sb, agno);
	if (!len)
		return 0;
	error = ecfs_getfsmap_fill(meta_list, fsb, len,
				   ECFS_FMR_OWN_GDT);
	if (error)
		return error;
	fsb += len;

	/* Reserved GDT blocks */
	if (!ecfs_has_feature_meta_bg(sb) || metagroup < first_meta_bg) {
		len = le16_to_cpu(sbi->s_es->s_reserved_gdt_blocks);

		/*
		 * mkfs.ecfs can set s_reserved_gdt_blocks as 0 in some cases,
		 * check for that.
		 */
		if (!len)
			return 0;

		error = ecfs_getfsmap_fill(meta_list, fsb, len,
					   ECFS_FMR_OWN_RESV_GDT);
		if (error)
			return error;
	}

	return 0;
}

/* Compare two fsmap items. */
static int ecfs_getfsmap_compare(void *priv,
				 const struct list_head *a,
				 const struct list_head *b)
{
	struct ecfs_fsmap *fa;
	struct ecfs_fsmap *fb;

	fa = container_of(a, struct ecfs_fsmap, fmr_list);
	fb = container_of(b, struct ecfs_fsmap, fmr_list);
	if (fa->fmr_physical < fb->fmr_physical)
		return -1;
	else if (fa->fmr_physical > fb->fmr_physical)
		return 1;
	return 0;
}

/* Merge adjacent extents of fixed metadata. */
static void ecfs_getfsmap_merge_fixed_metadata(struct list_head *meta_list)
{
	struct ecfs_fsmap *p;
	struct ecfs_fsmap *prev = NULL;
	struct ecfs_fsmap *tmp;

	list_for_each_entry_safe(p, tmp, meta_list, fmr_list) {
		if (!prev) {
			prev = p;
			continue;
		}

		if (prev->fmr_owner == p->fmr_owner &&
		    prev->fmr_physical + prev->fmr_length == p->fmr_physical) {
			prev->fmr_length += p->fmr_length;
			list_del(&p->fmr_list);
			kfree(p);
		} else
			prev = p;
	}
}

/* Free a list of fixed metadata. */
static void ecfs_getfsmap_free_fixed_metadata(struct list_head *meta_list)
{
	struct ecfs_fsmap *p;
	struct ecfs_fsmap *tmp;

	list_for_each_entry_safe(p, tmp, meta_list, fmr_list) {
		list_del(&p->fmr_list);
		kfree(p);
	}
}

/* Find all the fixed metadata in the filesystem. */
static int ecfs_getfsmap_find_fixed_metadata(struct super_block *sb,
					     struct list_head *meta_list)
{
	struct ecfs_group_desc *gdp;
	ecfs_group_t agno;
	int error;

	INIT_LIST_HEAD(meta_list);

	/* Collect everything. */
	for (agno = 0; agno < ECFS_SB(sb)->s_groups_count; agno++) {
		gdp = ecfs_get_group_desc(sb, agno, NULL);
		if (!gdp) {
			error = -EFSCORRUPTED;
			goto err;
		}

		/* Superblock & GDT */
		error = ecfs_getfsmap_find_sb(sb, agno, meta_list);
		if (error)
			goto err;

		/* Block bitmap */
		error = ecfs_getfsmap_fill(meta_list,
					   ecfs_block_bitmap(sb, gdp), 1,
					   ECFS_FMR_OWN_BLKBM);
		if (error)
			goto err;

		/* Inode bitmap */
		error = ecfs_getfsmap_fill(meta_list,
					   ecfs_inode_bitmap(sb, gdp), 1,
					   ECFS_FMR_OWN_INOBM);
		if (error)
			goto err;

		/* Inodes */
		error = ecfs_getfsmap_fill(meta_list,
					   ecfs_inode_table(sb, gdp),
					   ECFS_SB(sb)->s_itb_per_group,
					   ECFS_FMR_OWN_INODES);
		if (error)
			goto err;
	}

	/* Sort the list */
	list_sort(NULL, meta_list, ecfs_getfsmap_compare);

	/* Merge adjacent extents */
	ecfs_getfsmap_merge_fixed_metadata(meta_list);

	return 0;
err:
	ecfs_getfsmap_free_fixed_metadata(meta_list);
	return error;
}

/* Execute a getfsmap query against the buddy bitmaps */
static int ecfs_getfsmap_datadev(struct super_block *sb,
				 struct ecfs_fsmap *keys,
				 struct ecfs_getfsmap_info *info)
{
	struct ecfs_sb_info *sbi = ECFS_SB(sb);
	ecfs_fsblk_t start_fsb;
	ecfs_fsblk_t end_fsb;
	ecfs_fsblk_t bofs;
	ecfs_fsblk_t eofs;
	ecfs_group_t start_ag;
	ecfs_group_t end_ag;
	ecfs_grpblk_t first_cluster;
	ecfs_grpblk_t last_cluster;
	struct ecfs_fsmap irec;
	int error = 0;

	bofs = le32_to_cpu(sbi->s_es->s_first_data_block);
	eofs = ecfs_blocks_count(sbi->s_es);
	if (keys[0].fmr_physical >= eofs)
		return 0;
	else if (keys[0].fmr_physical < bofs)
		keys[0].fmr_physical = bofs;
	if (keys[1].fmr_physical >= eofs)
		keys[1].fmr_physical = eofs - 1;
	if (keys[1].fmr_physical < keys[0].fmr_physical)
		return 0;
	start_fsb = keys[0].fmr_physical;
	end_fsb = keys[1].fmr_physical;

	/* Determine first and last group to examine based on start and end */
	ecfs_get_group_no_and_offset(sb, start_fsb, &start_ag, &first_cluster);
	ecfs_get_group_no_and_offset(sb, end_fsb, &end_ag, &last_cluster);

	/*
	 * Convert the fsmap low/high keys to bg based keys.  Initialize
	 * low to the fsmap low key and max out the high key to the end
	 * of the bg.
	 */
	info->gfi_low = keys[0];
	info->gfi_low.fmr_physical = ECFS_C2B(sbi, first_cluster);
	info->gfi_low.fmr_length = 0;

	memset(&info->gfi_high, 0xFF, sizeof(info->gfi_high));

	/* Assemble a list of all the fixed-location metadata. */
	error = ecfs_getfsmap_find_fixed_metadata(sb, &info->gfi_meta_list);
	if (error)
		goto err;

	/* Query each bg */
	for (info->gfi_agno = start_ag;
	     info->gfi_agno <= end_ag;
	     info->gfi_agno++) {
		/*
		 * Set the bg high key from the fsmap high key if this
		 * is the last bg that we're querying.
		 */
		if (info->gfi_agno == end_ag) {
			info->gfi_high = keys[1];
			info->gfi_high.fmr_physical = ECFS_C2B(sbi,
					last_cluster);
			info->gfi_high.fmr_length = 0;
		}

		trace_ecfs_fsmap_low_key(sb, info->gfi_dev, info->gfi_agno,
				info->gfi_low.fmr_physical,
				info->gfi_low.fmr_length,
				info->gfi_low.fmr_owner);

		trace_ecfs_fsmap_high_key(sb, info->gfi_dev, info->gfi_agno,
				info->gfi_high.fmr_physical,
				info->gfi_high.fmr_length,
				info->gfi_high.fmr_owner);

		error = ecfs_mballoc_query_range(sb, info->gfi_agno,
				ECFS_B2C(sbi, info->gfi_low.fmr_physical),
				ECFS_B2C(sbi, info->gfi_high.fmr_physical),
				ecfs_getfsmap_meta_helper,
				ecfs_getfsmap_datadev_helper, info);
		if (error)
			goto err;

		/*
		 * Set the bg low key to the start of the bg prior to
		 * moving on to the next bg.
		 */
		if (info->gfi_agno == start_ag)
			memset(&info->gfi_low, 0, sizeof(info->gfi_low));
	}

	/* Do we have a retained free extent? */
	if (info->gfi_lastfree.fmr_owner) {
		error = ecfs_getfsmap_helper(sb, info, &info->gfi_lastfree);
		if (error)
			goto err;
	}

	/*
	 * The dummy record below will cause ecfs_getfsmap_helper() to report
	 * any allocated blocks at the end of the range.
	 */
	irec.fmr_device = 0;
	irec.fmr_physical = end_fsb + 1;
	irec.fmr_length = 0;
	irec.fmr_owner = ECFS_FMR_OWN_FREE;
	irec.fmr_flags = 0;

	info->gfi_last = true;
	error = ecfs_getfsmap_helper(sb, info, &irec);
	if (error)
		goto err;

err:
	ecfs_getfsmap_free_fixed_metadata(&info->gfi_meta_list);
	return error;
}

/* Do we recognize the device? */
static bool ecfs_getfsmap_is_valid_device(struct super_block *sb,
					  struct ecfs_fsmap *fm)
{
	if (fm->fmr_device == 0 || fm->fmr_device == UINT_MAX ||
	    fm->fmr_device == new_encode_dev(sb->s_bdev->bd_dev))
		return true;
	if (ECFS_SB(sb)->s_journal_bdev_file &&
	    fm->fmr_device ==
	    new_encode_dev(file_bdev(ECFS_SB(sb)->s_journal_bdev_file)->bd_dev))
		return true;
	return false;
}

/* Ensure that the low key is less than the high key. */
static bool ecfs_getfsmap_check_keys(struct ecfs_fsmap *low_key,
				     struct ecfs_fsmap *high_key)
{
	if (low_key->fmr_device > high_key->fmr_device)
		return false;
	if (low_key->fmr_device < high_key->fmr_device)
		return true;

	if (low_key->fmr_physical > high_key->fmr_physical)
		return false;
	if (low_key->fmr_physical < high_key->fmr_physical)
		return true;

	if (low_key->fmr_owner > high_key->fmr_owner)
		return false;
	if (low_key->fmr_owner < high_key->fmr_owner)
		return true;

	return false;
}

#define ECFS_GETFSMAP_DEVS	2
/*
 * Get filesystem's extents as described in head, and format for
 * output.  Calls formatter to fill the user's buffer until all
 * extents are mapped, until the passed-in head->fmh_count slots have
 * been filled, or until the formatter short-circuits the loop, if it
 * is tracking filled-in extents on its own.
 *
 * Key to Confusion
 * ----------------
 * There are multiple levels of keys and counters at work here:
 * _fsmap_head.fmh_keys		-- low and high fsmap keys passed in;
 * 				   these reflect fs-wide block addrs.
 * dkeys			-- fmh_keys used to query each device;
 * 				   these are fmh_keys but w/ the low key
 * 				   bumped up by fmr_length.
 * _getfsmap_info.gfi_next_fsblk-- next fs block we expect to see; this
 *				   is how we detect gaps in the fsmap
 *				   records and report them.
 * _getfsmap_info.gfi_low/high	-- per-bg low/high keys computed from
 * 				   dkeys; used to query the free space.
 */
int ecfs_getfsmap(struct super_block *sb, struct ecfs_fsmap_head *head,
		  ecfs_fsmap_format_t formatter, void *arg)
{
	struct ecfs_fsmap dkeys[2];	/* per-dev keys */
	struct ecfs_getfsmap_dev handlers[ECFS_GETFSMAP_DEVS];
	struct ecfs_getfsmap_info info = { NULL };
	int i;
	int error = 0;

	if (head->fmh_iflags & ~FMH_IF_VALID)
		return -EINVAL;
	if (!ecfs_getfsmap_is_valid_device(sb, &head->fmh_keys[0]) ||
	    !ecfs_getfsmap_is_valid_device(sb, &head->fmh_keys[1]))
		return -EINVAL;

	head->fmh_entries = 0;

	/* Set up our device handlers. */
	memset(handlers, 0, sizeof(handlers));
	handlers[0].gfd_dev = new_encode_dev(sb->s_bdev->bd_dev);
	handlers[0].gfd_fn = ecfs_getfsmap_datadev;
	if (ECFS_SB(sb)->s_journal_bdev_file) {
		handlers[1].gfd_dev = new_encode_dev(
			file_bdev(ECFS_SB(sb)->s_journal_bdev_file)->bd_dev);
		handlers[1].gfd_fn = ecfs_getfsmap_logdev;
	}

	sort(handlers, ECFS_GETFSMAP_DEVS, sizeof(struct ecfs_getfsmap_dev),
			ecfs_getfsmap_dev_compare, NULL);

	/*
	 * To continue where we left off, we allow userspace to use the
	 * last mapping from a previous call as the low key of the next.
	 * This is identified by a non-zero length in the low key. We
	 * have to increment the low key in this scenario to ensure we
	 * don't return the same mapping again, and instead return the
	 * very next mapping.
	 *
	 * Bump the physical offset as there can be no other mapping for
	 * the same physical block range.
	 */
	dkeys[0] = head->fmh_keys[0];
	dkeys[0].fmr_physical += dkeys[0].fmr_length;
	dkeys[0].fmr_owner = 0;
	dkeys[0].fmr_length = 0;
	memset(&dkeys[1], 0xFF, sizeof(struct ecfs_fsmap));

	if (!ecfs_getfsmap_check_keys(dkeys, &head->fmh_keys[1]))
		return -EINVAL;

	info.gfi_next_fsblk = head->fmh_keys[0].fmr_physical +
			  head->fmh_keys[0].fmr_length;
	info.gfi_formatter = formatter;
	info.gfi_format_arg = arg;
	info.gfi_head = head;

	/* For each device we support... */
	for (i = 0; i < ECFS_GETFSMAP_DEVS; i++) {
		/* Is this device within the range the user asked for? */
		if (!handlers[i].gfd_fn)
			continue;
		if (head->fmh_keys[0].fmr_device > handlers[i].gfd_dev)
			continue;
		if (head->fmh_keys[1].fmr_device < handlers[i].gfd_dev)
			break;

		/*
		 * If this device number matches the high key, we have
		 * to pass the high key to the handler to limit the
		 * query results.  If the device number exceeds the
		 * low key, zero out the low key so that we get
		 * everything from the beginning.
		 */
		if (handlers[i].gfd_dev == head->fmh_keys[1].fmr_device)
			dkeys[1] = head->fmh_keys[1];
		if (handlers[i].gfd_dev > head->fmh_keys[0].fmr_device)
			memset(&dkeys[0], 0, sizeof(struct ecfs_fsmap));

		info.gfi_dev = handlers[i].gfd_dev;
		info.gfi_last = false;
		info.gfi_agno = -1;
		error = handlers[i].gfd_fn(sb, dkeys, &info);
		if (error)
			break;
		info.gfi_next_fsblk = 0;
	}

	head->fmh_oflags = FMH_OF_DEV_T;
	return error;
}
