// SPDX-License-Identifier: GPL-2.0+
/*
 * Copyright (C) 2017 Oracle.  All Rights Reserved.
 *
 * Author: Darrick J. Wong <darrick.wong@oracle.com>
 */
#ifndef __ECFS_FSMAP_H__
#define	__ECFS_FSMAP_H__

struct fsmap;

/* internal fsmap representation */
struct ecfs_fsmap {
	struct list_head	fmr_list;
	dev_t		fmr_device;	/* device id */
	uint32_t	fmr_flags;	/* mapping flags */
	uint64_t	fmr_physical;	/* device offset of segment */
	uint64_t	fmr_owner;	/* owner id */
	uint64_t	fmr_length;	/* length of segment, blocks */
};

struct ecfs_fsmap_head {
	uint32_t	fmh_iflags;	/* control flags */
	uint32_t	fmh_oflags;	/* output flags */
	unsigned int	fmh_count;	/* # of entries in array incl. input */
	unsigned int	fmh_entries;	/* # of entries filled in (output). */

	struct ecfs_fsmap fmh_keys[2];	/* low and high keys */
};

void ecfs_fsmap_from_internal(struct super_block *sb, struct fsmap *dest,
		struct ecfs_fsmap *src);
void ecfs_fsmap_to_internal(struct super_block *sb, struct ecfs_fsmap *dest,
		struct fsmap *src);

/* fsmap to userspace formatter - copy to user & advance pointer */
typedef int (*ecfs_fsmap_format_t)(struct ecfs_fsmap *, void *);

int ecfs_getfsmap(struct super_block *sb, struct ecfs_fsmap_head *head,
		ecfs_fsmap_format_t formatter, void *arg);

#define ECFS_QUERY_RANGE_ABORT		1
#define ECFS_QUERY_RANGE_CONTINUE	0

/*	fmr_owner special values for FS_IOC_GETFSMAP; some share w/ XFS */
#define ECFS_FMR_OWN_FREE	FMR_OWN_FREE      /* free space */
#define ECFS_FMR_OWN_UNKNOWN	FMR_OWN_UNKNOWN   /* unknown owner */
#define ECFS_FMR_OWN_FS		FMR_OWNER('X', 1) /* static fs metadata */
#define ECFS_FMR_OWN_LOG	FMR_OWNER('X', 2) /* journalling log */
#define ECFS_FMR_OWN_INODES	FMR_OWNER('X', 5) /* inodes */
#define ECFS_FMR_OWN_GDT	FMR_OWNER('f', 1) /* group descriptors */
#define ECFS_FMR_OWN_RESV_GDT	FMR_OWNER('f', 2) /* reserved gdt blocks */
#define ECFS_FMR_OWN_BLKBM	FMR_OWNER('f', 3) /* block bitmap */
#define ECFS_FMR_OWN_INOBM	FMR_OWNER('f', 4) /* inode bitmap */

#endif /* __ECFS_FSMAP_H__ */
