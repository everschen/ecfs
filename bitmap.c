// SPDX-License-Identifier: GPL-2.0
/*
 *  linux/fs/ecfs/bitmap.c
 *
 * Copyright (C) 1992, 1993, 1994, 1995
 * Remy Card (card@masi.ibp.fr)
 * Laboratoire MASI - Institut Blaise Pascal
 * Universite Pierre et Marie Curie (Paris VI)
 */

#include <linux/buffer_head.h>
#include "ecfs.h"

unsigned int ecfs_count_free(char *bitmap, unsigned int numchars)
{
	return numchars * BITS_PER_BYTE - memweight(bitmap, numchars);
}

int ecfs_inode_bitmap_csum_verify(struct super_block *sb,
				  struct ecfs_group_desc *gdp,
				  struct buffer_head *bh)
{
	__u32 hi;
	__u32 provided, calculated;
	struct ecfs_sb_info *sbi = ECFS_SB(sb);
	int sz;

	if (!ecfs_has_feature_metadata_csum(sb))
		return 1;

	sz = ECFS_INODES_PER_GROUP(sb) >> 3;
	provided = le16_to_cpu(gdp->bg_inode_bitmap_csum_lo);
	calculated = ecfs_chksum(sbi->s_csum_seed, (__u8 *)bh->b_data, sz);
	if (sbi->s_desc_size >= ECFS_BG_INODE_BITMAP_CSUM_HI_END) {
		hi = le16_to_cpu(gdp->bg_inode_bitmap_csum_hi);
		provided |= (hi << 16);
	} else
		calculated &= 0xFFFF;

	return provided == calculated;
}

void ecfs_inode_bitmap_csum_set(struct super_block *sb,
				struct ecfs_group_desc *gdp,
				struct buffer_head *bh)
{
	__u32 csum;
	struct ecfs_sb_info *sbi = ECFS_SB(sb);
	int sz;

	if (!ecfs_has_feature_metadata_csum(sb))
		return;

	sz = ECFS_INODES_PER_GROUP(sb) >> 3;
	csum = ecfs_chksum(sbi->s_csum_seed, (__u8 *)bh->b_data, sz);
	gdp->bg_inode_bitmap_csum_lo = cpu_to_le16(csum & 0xFFFF);
	if (sbi->s_desc_size >= ECFS_BG_INODE_BITMAP_CSUM_HI_END)
		gdp->bg_inode_bitmap_csum_hi = cpu_to_le16(csum >> 16);
}

int ecfs_block_bitmap_csum_verify(struct super_block *sb,
				  struct ecfs_group_desc *gdp,
				  struct buffer_head *bh)
{
	__u32 hi;
	__u32 provided, calculated;
	struct ecfs_sb_info *sbi = ECFS_SB(sb);
	int sz = ECFS_CLUSTERS_PER_GROUP(sb) / 8;

	if (!ecfs_has_feature_metadata_csum(sb))
		return 1;

	provided = le16_to_cpu(gdp->bg_block_bitmap_csum_lo);
	calculated = ecfs_chksum(sbi->s_csum_seed, (__u8 *)bh->b_data, sz);
	if (sbi->s_desc_size >= ECFS_BG_BLOCK_BITMAP_CSUM_HI_END) {
		hi = le16_to_cpu(gdp->bg_block_bitmap_csum_hi);
		provided |= (hi << 16);
	} else
		calculated &= 0xFFFF;

	return provided == calculated;
}

void ecfs_block_bitmap_csum_set(struct super_block *sb,
				struct ecfs_group_desc *gdp,
				struct buffer_head *bh)
{
	int sz = ECFS_CLUSTERS_PER_GROUP(sb) / 8;
	__u32 csum;
	struct ecfs_sb_info *sbi = ECFS_SB(sb);

	if (!ecfs_has_feature_metadata_csum(sb))
		return;

	csum = ecfs_chksum(sbi->s_csum_seed, (__u8 *)bh->b_data, sz);
	gdp->bg_block_bitmap_csum_lo = cpu_to_le16(csum & 0xFFFF);
	if (sbi->s_desc_size >= ECFS_BG_BLOCK_BITMAP_CSUM_HI_END)
		gdp->bg_block_bitmap_csum_hi = cpu_to_le16(csum >> 16);
}
