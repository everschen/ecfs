// SPDX-License-Identifier: GPL-2.0
/*
 *  ecfs.h
 *
 * Copyright (C) 1992, 1993, 1994, 1995
 * Remy Card (card@masi.ibp.fr)
 * Laboratoire MASI - Institut Blaise Pascal
 * Universite Pierre et Marie Curie (Paris VI)
 *
 *  from
 *
 *  linux/include/linux/minix_fs.h
 *
 *  Copyright (C) 1991, 1992  Linus Torvalds
 */

#ifndef _ECFS_H
#define _ECFS_H

#include <linux/refcount.h>
#include <linux/types.h>
#include <linux/blkdev.h>
#include <linux/magic.h>
#include <linux/jbd2.h>
#include <linux/quota.h>
#include <linux/rwsem.h>
#include <linux/rbtree.h>
#include <linux/seqlock.h>
#include <linux/mutex.h>
#include <linux/timer.h>
#include <linux/wait.h>
#include <linux/sched/signal.h>
#include <linux/blockgroup_lock.h>
#include <linux/percpu_counter.h>
#include <linux/ratelimit.h>
#include <linux/crc32c.h>
#include <linux/falloc.h>
#include <linux/percpu-rwsem.h>
#include <linux/fiemap.h>
#ifdef __KERNEL__
#include <linux/compat.h>
#endif
#include <uapi/linux/ecfs.h>

#include <linux/fscrypt.h>
#include <linux/fsverity.h>

#include <linux/compiler.h>

/*
 * The fourth extended filesystem constants/structures
 */

/*
 * with AGGRESSIVE_CHECK allocator runs consistency checks over
 * structures. these checks slow things down a lot
 */
#define AGGRESSIVE_CHECK__

/*
 * with DOUBLE_CHECK defined mballoc creates persistent in-core
 * bitmaps, maintains and uses them to check for double allocations
 */
#define DOUBLE_CHECK__

/*
 * Define ECFSFS_DEBUG to produce debug messages
 */
#undef ECFSFS_DEBUG

/*
 * Debug code
 */
#ifdef ECFSFS_DEBUG
#define ecfs_debug(f, a...)						\
	do {								\
		printk(KERN_DEBUG "ECFS-fs DEBUG (%s, %d): %s:",	\
			__FILE__, __LINE__, __func__);			\
		printk(KERN_DEBUG f, ## a);				\
	} while (0)
#else
#define ecfs_debug(fmt, ...)	no_printk(fmt, ##__VA_ARGS__)
#endif

 /*
  * Turn on EXT_DEBUG to enable ecfs_ext_show_path/leaf/move in extents.c
  */
#define EXT_DEBUG__

/*
 * Dynamic printk for controlled extents debugging.
 */
#ifdef CONFIG_ECFS_DEBUG
#define ext_debug(ino, fmt, ...)					\
	pr_debug("[%s/%d] ECFS-fs (%s): ino %lu: (%s, %d): %s:" fmt,	\
		 current->comm, task_pid_nr(current),			\
		 ino->i_sb->s_id, ino->i_ino, __FILE__, __LINE__,	\
		 __func__, ##__VA_ARGS__)
#else
#define ext_debug(ino, fmt, ...)	no_printk(fmt, ##__VA_ARGS__)
#endif

#define ASSERT(assert)						\
do {									\
	if (unlikely(!(assert))) {					\
		printk(KERN_EMERG					\
		       "Assertion failure in %s() at %s:%d: '%s'\n",	\
		       __func__, __FILE__, __LINE__, #assert);		\
		BUG();							\
	}								\
} while (0)

/* data type for block offset of block group */
typedef int ecfs_grpblk_t;

/* data type for filesystem-wide blocks number */
typedef unsigned long long ecfs_fsblk_t;

/* data type for file logical block number */
typedef __u32 ecfs_lblk_t;

/* data type for block group number */
typedef unsigned int ecfs_group_t;

enum SHIFT_DIRECTION {
	SHIFT_LEFT = 0,
	SHIFT_RIGHT,
};

/*
 * For each criteria, mballoc has slightly different way of finding
 * the required blocks nad usually, higher the criteria the slower the
 * allocation.  We start at lower criterias and keep falling back to
 * higher ones if we are not able to find any blocks.  Lower (earlier)
 * criteria are faster.
 */
enum criteria {
	/*
	 * Used when number of blocks needed is a power of 2. This
	 * doesn't trigger any disk IO except prefetch and is the
	 * fastest criteria.
	 */
	CR_POWER2_ALIGNED,

	/*
	 * Tries to lookup in-memory data structures to find the most
	 * suitable group that satisfies goal request. No disk IO
	 * except block prefetch.
	 */
	CR_GOAL_LEN_FAST,

        /*
	 * Same as CR_GOAL_LEN_FAST but is allowed to reduce the goal
         * length to the best available length for faster allocation.
	 */
	CR_BEST_AVAIL_LEN,

	/*
	 * Reads each block group sequentially, performing disk IO if
	 * necessary, to find suitable block group. Tries to
	 * allocate goal length but might trim the request if nothing
	 * is found after enough tries.
	 */
	CR_GOAL_LEN_SLOW,

	/*
	 * Finds the first free set of blocks and allocates
	 * those. This is only used in rare cases when
	 * CR_GOAL_LEN_SLOW also fails to allocate anything.
	 */
	CR_ANY_FREE,

	/*
	 * Number of criterias defined.
	 */
	ECFS_MB_NUM_CRS
};

/*
 * Flags used in mballoc's allocation_context flags field.
 *
 * Also used to show what's going on for debugging purposes when the
 * flag field is exported via the traceport interface
 */

/* prefer goal again. length */
#define ECFS_MB_HINT_MERGE		0x0001
/* first blocks in the file */
#define ECFS_MB_HINT_FIRST		0x0008
/* data is being allocated */
#define ECFS_MB_HINT_DATA		0x0020
/* don't preallocate (for tails) */
#define ECFS_MB_HINT_NOPREALLOC		0x0040
/* allocate for locality group */
#define ECFS_MB_HINT_GROUP_ALLOC	0x0080
/* allocate goal blocks or none */
#define ECFS_MB_HINT_GOAL_ONLY		0x0100
/* goal is meaningful */
#define ECFS_MB_HINT_TRY_GOAL		0x0200
/* blocks already pre-reserved by delayed allocation */
#define ECFS_MB_DELALLOC_RESERVED	0x0400
/* We are doing stream allocation */
#define ECFS_MB_STREAM_ALLOC		0x0800
/* Use reserved root blocks if needed */
#define ECFS_MB_USE_ROOT_BLOCKS		0x1000
/* Use blocks from reserved pool */
#define ECFS_MB_USE_RESERVED		0x2000
/* Do strict check for free blocks while retrying block allocation */
#define ECFS_MB_STRICT_CHECK		0x4000

struct ecfs_allocation_request {
	/* target inode for block we're allocating */
	struct inode *inode;
	/* how many blocks we want to allocate */
	unsigned int len;
	/* logical block in target inode */
	ecfs_lblk_t logical;
	/* the closest logical allocated block to the left */
	ecfs_lblk_t lleft;
	/* the closest logical allocated block to the right */
	ecfs_lblk_t lright;
	/* phys. target (a hint) */
	ecfs_fsblk_t goal;
	/* phys. block for the closest logical allocated block to the left */
	ecfs_fsblk_t pleft;
	/* phys. block for the closest logical allocated block to the right */
	ecfs_fsblk_t pright;
	/* flags. see above ECFS_MB_HINT_* */
	unsigned int flags;
};

/*
 * Logical to physical block mapping, used by ecfs_map_blocks()
 *
 * This structure is used to pass requests into ecfs_map_blocks() as
 * well as to store the information returned by ecfs_map_blocks().  It
 * takes less room on the stack than a struct buffer_head.
 */
#define ECFS_MAP_NEW		BIT(BH_New)
#define ECFS_MAP_MAPPED		BIT(BH_Mapped)
#define ECFS_MAP_UNWRITTEN	BIT(BH_Unwritten)
#define ECFS_MAP_BOUNDARY	BIT(BH_Boundary)
#define ECFS_MAP_DELAYED	BIT(BH_Delay)
/*
 * This is for use in ecfs_map_query_blocks() for a special case where we can
 * have a physically and logically contiguous blocks split across two leaf
 * nodes instead of a single extent. This is required in case of atomic writes
 * to know whether the returned extent is last in leaf. If yes, then lookup for
 * next in leaf block in ecfs_map_query_blocks_next_in_leaf().
 * - This is never going to be added to any buffer head state.
 * - We use the next available bit after BH_BITMAP_UPTODATE.
 */
#define ECFS_MAP_QUERY_LAST_IN_LEAF	BIT(BH_BITMAP_UPTODATE + 1)
#define ECFS_MAP_FLAGS		(ECFS_MAP_NEW | ECFS_MAP_MAPPED |\
				 ECFS_MAP_UNWRITTEN | ECFS_MAP_BOUNDARY |\
				 ECFS_MAP_DELAYED | ECFS_MAP_QUERY_LAST_IN_LEAF)

struct ecfs_map_blocks {
	ecfs_fsblk_t m_pblk;
	ecfs_lblk_t m_lblk;
	unsigned int m_len;
	unsigned int m_flags;
};

/*
 * Block validity checking, system zone rbtree.
 */
struct ecfs_system_blocks {
	struct rb_root root;
	struct rcu_head rcu;
};

/*
 * Flags for ecfs_io_end->flags
 */
#define ECFS_IO_END_UNWRITTEN	0x0001
#define ECFS_IO_END_FAILED	0x0002

#define ECFS_IO_END_DEFER_COMPLETION (ECFS_IO_END_UNWRITTEN | ECFS_IO_END_FAILED)

struct ecfs_io_end_vec {
	struct list_head list;		/* list of io_end_vec */
	loff_t offset;			/* offset in the file */
	ssize_t size;			/* size of the extent */
};

/*
 * For converting unwritten extents on a work queue. 'handle' is used for
 * buffered writeback.
 */
typedef struct ecfs_io_end {
	struct list_head	list;		/* per-file finished IO list */
	handle_t		*handle;	/* handle reserved for extent
						 * conversion */
	struct inode		*inode;		/* file being written to */
	struct bio		*bio;		/* Linked list of completed
						 * bios covering the extent */
	unsigned int		flag;		/* unwritten or not */
	refcount_t		count;		/* reference counter */
	struct list_head	list_vec;	/* list of ecfs_io_end_vec */
} ecfs_io_end_t;

struct ecfs_io_submit {
	struct writeback_control *io_wbc;
	struct bio		*io_bio;
	ecfs_io_end_t		*io_end;
	sector_t		io_next_block;
};

/*
 * Special inodes numbers
 */
#define	ECFS_BAD_INO		 1	/* Bad blocks inode */
#define ECFS_ROOT_INO		 2	/* Root inode */
#define ECFS_USR_QUOTA_INO	 3	/* User quota inode */
#define ECFS_GRP_QUOTA_INO	 4	/* Group quota inode */
#define ECFS_BOOT_LOADER_INO	 5	/* Boot loader inode */
#define ECFS_UNDEL_DIR_INO	 6	/* Undelete directory inode */
#define ECFS_RESIZE_INO		 7	/* Reserved group descriptors inode */
#define ECFS_JOURNAL_INO	 8	/* Journal inode */

/* First non-reserved inode for old ecfs filesystems */
#define ECFS_GOOD_OLD_FIRST_INO	11

#define INO_MASK 0x00000000FFFFFFFFULL /* local inode mask */
#define LOCAL_INO(ino)   ((ino) & INO_MASK)

/*
 * Maximal count of links to a file
 */
#define ECFS_LINK_MAX		65000

/*
 * Macro-instructions used to manage several block sizes
 */
#define ECFS_MIN_BLOCK_SIZE		1024
#define	ECFS_MAX_BLOCK_SIZE		65536
#define ECFS_MIN_BLOCK_LOG_SIZE		10
#define ECFS_MAX_BLOCK_LOG_SIZE		16
#define ECFS_MAX_CLUSTER_LOG_SIZE	30
#ifdef __KERNEL__
# define ECFS_BLOCK_SIZE(s)		((s)->s_blocksize)
#else
# define ECFS_BLOCK_SIZE(s)		(ECFS_MIN_BLOCK_SIZE << (s)->s_log_block_size)
#endif
#define	ECFS_ADDR_PER_BLOCK(s)		(ECFS_BLOCK_SIZE(s) / sizeof(__u32))
#define ECFS_CLUSTER_SIZE(s)		(ECFS_BLOCK_SIZE(s) << \
					 ECFS_SB(s)->s_cluster_bits)
#ifdef __KERNEL__
# define ECFS_BLOCK_SIZE_BITS(s)	((s)->s_blocksize_bits)
# define ECFS_CLUSTER_BITS(s)		(ECFS_SB(s)->s_cluster_bits)
#else
# define ECFS_BLOCK_SIZE_BITS(s)	((s)->s_log_block_size + 10)
#endif
#ifdef __KERNEL__
#define	ECFS_ADDR_PER_BLOCK_BITS(s)	(ECFS_SB(s)->s_addr_per_block_bits)
#define ECFS_INODE_SIZE(s)		(ECFS_SB(s)->s_inode_size)
#define ECFS_FIRST_INO(s)		(ECFS_SB(s)->s_first_ino)
#else
#define ECFS_INODE_SIZE(s)	(((s)->s_rev_level == ECFS_GOOD_OLD_REV) ? \
				 ECFS_GOOD_OLD_INODE_SIZE : \
				 (s)->s_inode_size)
#define ECFS_FIRST_INO(s)	(((s)->s_rev_level == ECFS_GOOD_OLD_REV) ? \
				 ECFS_GOOD_OLD_FIRST_INO : \
				 (s)->s_first_ino)
#endif
#define ECFS_BLOCK_ALIGN(size, blkbits)		ALIGN((size), (1 << (blkbits)))
#define ECFS_MAX_BLOCKS(size, offset, blkbits) \
	((ECFS_BLOCK_ALIGN(size + offset, blkbits) >> blkbits) - (offset >> \
								  blkbits))
#define ECFS_B_TO_LBLK(inode, offset) \
	(round_up((offset), i_blocksize(inode)) >> (inode)->i_blkbits)

/* Translate a block number to a cluster number */
#define ECFS_B2C(sbi, blk)	((blk) >> (sbi)->s_cluster_bits)
/* Translate a cluster number to a block number */
#define ECFS_C2B(sbi, cluster)	((cluster) << (sbi)->s_cluster_bits)
/* Translate # of blks to # of clusters */
#define ECFS_NUM_B2C(sbi, blks)	(((blks) + (sbi)->s_cluster_ratio - 1) >> \
				 (sbi)->s_cluster_bits)
/* Mask out the low bits to get the starting block of the cluster */
#define ECFS_PBLK_CMASK(s, pblk) ((pblk) &				\
				  ~((ecfs_fsblk_t) (s)->s_cluster_ratio - 1))
#define ECFS_LBLK_CMASK(s, lblk) ((lblk) &				\
				  ~((ecfs_lblk_t) (s)->s_cluster_ratio - 1))
/* Fill in the low bits to get the last block of the cluster */
#define ECFS_LBLK_CFILL(sbi, lblk) ((lblk) |				\
				    ((ecfs_lblk_t) (sbi)->s_cluster_ratio - 1))
/* Get the cluster offset */
#define ECFS_PBLK_COFF(s, pblk) ((pblk) &				\
				 ((ecfs_fsblk_t) (s)->s_cluster_ratio - 1))
#define ECFS_LBLK_COFF(s, lblk) ((lblk) &				\
				 ((ecfs_lblk_t) (s)->s_cluster_ratio - 1))

/*
 * Structure of a blocks group descriptor
 */
struct ecfs_group_desc
{
	__le32	bg_block_bitmap_lo;	/* Blocks bitmap block */
	__le32	bg_inode_bitmap_lo;	/* Inodes bitmap block */
	__le32	bg_inode_table_lo;	/* Inodes table block */
	__le16	bg_free_blocks_count_lo;/* Free blocks count */
	__le16	bg_free_inodes_count_lo;/* Free inodes count */
	__le16	bg_used_dirs_count_lo;	/* Directories count */
	__le16	bg_flags;		/* ECFS_BG_flags (INODE_UNINIT, etc) */
	__le32  bg_exclude_bitmap_lo;   /* Exclude bitmap for snapshots */
	__le16  bg_block_bitmap_csum_lo;/* crc32c(s_uuid+grp_num+bbitmap) LE */
	__le16  bg_inode_bitmap_csum_lo;/* crc32c(s_uuid+grp_num+ibitmap) LE */
	__le16  bg_itable_unused_lo;	/* Unused inodes count */
	__le16  bg_checksum;		/* crc16(sb_uuid+group+desc) */
	__le32	bg_block_bitmap_hi;	/* Blocks bitmap block MSB */
	__le32	bg_inode_bitmap_hi;	/* Inodes bitmap block MSB */
	__le32	bg_inode_table_hi;	/* Inodes table block MSB */
	__le16	bg_free_blocks_count_hi;/* Free blocks count MSB */
	__le16	bg_free_inodes_count_hi;/* Free inodes count MSB */
	__le16	bg_used_dirs_count_hi;	/* Directories count MSB */
	__le16  bg_itable_unused_hi;    /* Unused inodes count MSB */
	__le32  bg_exclude_bitmap_hi;   /* Exclude bitmap block MSB */
	__le16  bg_block_bitmap_csum_hi;/* crc32c(s_uuid+grp_num+bbitmap) BE */
	__le16  bg_inode_bitmap_csum_hi;/* crc32c(s_uuid+grp_num+ibitmap) BE */
	__u32   bg_reserved;
};

#define ECFS_BG_INODE_BITMAP_CSUM_HI_END	\
	(offsetof(struct ecfs_group_desc, bg_inode_bitmap_csum_hi) + \
	 sizeof(__le16))
#define ECFS_BG_BLOCK_BITMAP_CSUM_HI_END	\
	(offsetof(struct ecfs_group_desc, bg_block_bitmap_csum_hi) + \
	 sizeof(__le16))

/*
 * Structure of a flex block group info
 */

struct flex_groups {
	atomic64_t	free_clusters;
	atomic_t	free_inodes;
	atomic_t	used_dirs;
};

#define ECFS_BG_INODE_UNINIT	0x0001 /* Inode table/bitmap not in use */
#define ECFS_BG_BLOCK_UNINIT	0x0002 /* Block bitmap not in use */
#define ECFS_BG_INODE_ZEROED	0x0004 /* On-disk itable initialized to zero */

/*
 * Macro-instructions used to manage group descriptors
 */
#define ECFS_MIN_DESC_SIZE		32
#define ECFS_MIN_DESC_SIZE_64BIT	64
#define	ECFS_MAX_DESC_SIZE		ECFS_MIN_BLOCK_SIZE
#define ECFS_DESC_SIZE(s)		(ECFS_SB(s)->s_desc_size)
#ifdef __KERNEL__
# define ECFS_BLOCKS_PER_GROUP(s)	(ECFS_SB(s)->s_blocks_per_group)
# define ECFS_CLUSTERS_PER_GROUP(s)	(ECFS_SB(s)->s_clusters_per_group)
# define ECFS_DESC_PER_BLOCK(s)		(ECFS_SB(s)->s_desc_per_block)
# define ECFS_INODES_PER_GROUP(s)	(ECFS_SB(s)->s_inodes_per_group)
# define ECFS_DESC_PER_BLOCK_BITS(s)	(ECFS_SB(s)->s_desc_per_block_bits)
#else
# define ECFS_BLOCKS_PER_GROUP(s)	((s)->s_blocks_per_group)
# define ECFS_DESC_PER_BLOCK(s)		(ECFS_BLOCK_SIZE(s) / ECFS_DESC_SIZE(s))
# define ECFS_INODES_PER_GROUP(s)	((s)->s_inodes_per_group)
#endif

/*
 * Constants relative to the data blocks
 */
#define	ECFS_NDIR_BLOCKS		12
#define	ECFS_IND_BLOCK			ECFS_NDIR_BLOCKS
#define	ECFS_DIND_BLOCK			(ECFS_IND_BLOCK + 1)
#define	ECFS_TIND_BLOCK			(ECFS_DIND_BLOCK + 1)
#define	ECFS_N_BLOCKS			(ECFS_TIND_BLOCK + 1)

/*
 * Inode flags
 */
#define	ECFS_SECRM_FL			0x00000001 /* Secure deletion */
#define	ECFS_UNRM_FL			0x00000002 /* Undelete */
#define	ECFS_COMPR_FL			0x00000004 /* Compress file */
#define ECFS_SYNC_FL			0x00000008 /* Synchronous updates */
#define ECFS_IMMUTABLE_FL		0x00000010 /* Immutable file */
#define ECFS_APPEND_FL			0x00000020 /* writes to file may only append */
#define ECFS_NODUMP_FL			0x00000040 /* do not dump file */
#define ECFS_NOATIME_FL			0x00000080 /* do not update atime */
/* Reserved for compression usage... */
#define ECFS_DIRTY_FL			0x00000100
#define ECFS_COMPRBLK_FL		0x00000200 /* One or more compressed clusters */
#define ECFS_NOCOMPR_FL			0x00000400 /* Don't compress */
	/* nb: was previously EXT2_ECOMPR_FL */
#define ECFS_ENCRYPT_FL			0x00000800 /* encrypted file */
/* End compression flags --- maybe not all used */
#define ECFS_INDEX_FL			0x00001000 /* hash-indexed directory */
#define ECFS_IMAGIC_FL			0x00002000 /* AFS directory */
#define ECFS_JOURNAL_DATA_FL		0x00004000 /* file data should be journaled */
#define ECFS_NOTAIL_FL			0x00008000 /* file tail should not be merged */
#define ECFS_DIRSYNC_FL			0x00010000 /* dirsync behaviour (directories only) */
#define ECFS_TOPDIR_FL			0x00020000 /* Top of directory hierarchies*/
#define ECFS_HUGE_FILE_FL               0x00040000 /* Set to each huge file */
#define ECFS_EXTENTS_FL			0x00080000 /* Inode uses extents */
#define ECFS_VERITY_FL			0x00100000 /* Verity protected inode */
#define ECFS_EA_INODE_FL	        0x00200000 /* Inode used for large EA */
/* 0x00400000 was formerly ECFS_EOFBLOCKS_FL */

#define ECFS_DAX_FL			0x02000000 /* Inode is DAX */

#define ECFS_INLINE_DATA_FL		0x10000000 /* Inode has inline data. */
#define ECFS_PROJINHERIT_FL		0x20000000 /* Create with parents projid */
#define ECFS_CASEFOLD_FL		0x40000000 /* Casefolded directory */
#define ECFS_RESERVED_FL		0x80000000 /* reserved for ecfs lib */

/* User modifiable flags */
#define ECFS_FL_USER_MODIFIABLE		(ECFS_SECRM_FL | \
					 ECFS_UNRM_FL | \
					 ECFS_COMPR_FL | \
					 ECFS_SYNC_FL | \
					 ECFS_IMMUTABLE_FL | \
					 ECFS_APPEND_FL | \
					 ECFS_NODUMP_FL | \
					 ECFS_NOATIME_FL | \
					 ECFS_JOURNAL_DATA_FL | \
					 ECFS_NOTAIL_FL | \
					 ECFS_DIRSYNC_FL | \
					 ECFS_TOPDIR_FL | \
					 ECFS_EXTENTS_FL | \
					 0x00400000 /* ECFS_EOFBLOCKS_FL */ | \
					 ECFS_DAX_FL | \
					 ECFS_PROJINHERIT_FL | \
					 ECFS_CASEFOLD_FL)

/* User visible flags */
#define ECFS_FL_USER_VISIBLE		(ECFS_FL_USER_MODIFIABLE | \
					 ECFS_DIRTY_FL | \
					 ECFS_COMPRBLK_FL | \
					 ECFS_NOCOMPR_FL | \
					 ECFS_ENCRYPT_FL | \
					 ECFS_INDEX_FL | \
					 ECFS_VERITY_FL | \
					 ECFS_INLINE_DATA_FL)

/* Flags that should be inherited by new inodes from their parent. */
#define ECFS_FL_INHERITED (ECFS_SECRM_FL | ECFS_UNRM_FL | ECFS_COMPR_FL |\
			   ECFS_SYNC_FL | ECFS_NODUMP_FL | ECFS_NOATIME_FL |\
			   ECFS_NOCOMPR_FL | ECFS_JOURNAL_DATA_FL |\
			   ECFS_NOTAIL_FL | ECFS_DIRSYNC_FL |\
			   ECFS_PROJINHERIT_FL | ECFS_CASEFOLD_FL |\
			   ECFS_DAX_FL)

/* Flags that are appropriate for regular files (all but dir-specific ones). */
#define ECFS_REG_FLMASK (~(ECFS_DIRSYNC_FL | ECFS_TOPDIR_FL | ECFS_CASEFOLD_FL |\
			   ECFS_PROJINHERIT_FL))

/* Flags that are appropriate for non-directories/regular files. */
#define ECFS_OTHER_FLMASK (ECFS_NODUMP_FL | ECFS_NOATIME_FL)

/* The only flags that should be swapped */
#define ECFS_FL_SHOULD_SWAP (ECFS_HUGE_FILE_FL | ECFS_EXTENTS_FL)

/* Flags which are mutually exclusive to DAX */
#define ECFS_DAX_MUT_EXCL (ECFS_VERITY_FL | ECFS_ENCRYPT_FL |\
			   ECFS_JOURNAL_DATA_FL | ECFS_INLINE_DATA_FL)

/* Mask out flags that are inappropriate for the given type of inode. */
static inline __u32 ecfs_mask_flags(umode_t mode, __u32 flags)
{
	if (S_ISDIR(mode))
		return flags;
	else if (S_ISREG(mode))
		return flags & ECFS_REG_FLMASK;
	else
		return flags & ECFS_OTHER_FLMASK;
}

/*
 * Inode flags used for atomic set/get
 */
enum {
	ECFS_INODE_SECRM	= 0,	/* Secure deletion */
	ECFS_INODE_UNRM		= 1,	/* Undelete */
	ECFS_INODE_COMPR	= 2,	/* Compress file */
	ECFS_INODE_SYNC		= 3,	/* Synchronous updates */
	ECFS_INODE_IMMUTABLE	= 4,	/* Immutable file */
	ECFS_INODE_APPEND	= 5,	/* writes to file may only append */
	ECFS_INODE_NODUMP	= 6,	/* do not dump file */
	ECFS_INODE_NOATIME	= 7,	/* do not update atime */
/* Reserved for compression usage... */
	ECFS_INODE_DIRTY	= 8,
	ECFS_INODE_COMPRBLK	= 9,	/* One or more compressed clusters */
	ECFS_INODE_NOCOMPR	= 10,	/* Don't compress */
	ECFS_INODE_ENCRYPT	= 11,	/* Encrypted file */
/* End compression flags --- maybe not all used */
	ECFS_INODE_INDEX	= 12,	/* hash-indexed directory */
	ECFS_INODE_IMAGIC	= 13,	/* AFS directory */
	ECFS_INODE_JOURNAL_DATA	= 14,	/* file data should be journaled */
	ECFS_INODE_NOTAIL	= 15,	/* file tail should not be merged */
	ECFS_INODE_DIRSYNC	= 16,	/* dirsync behaviour (directories only) */
	ECFS_INODE_TOPDIR	= 17,	/* Top of directory hierarchies*/
	ECFS_INODE_HUGE_FILE	= 18,	/* Set to each huge file */
	ECFS_INODE_EXTENTS	= 19,	/* Inode uses extents */
	ECFS_INODE_VERITY	= 20,	/* Verity protected inode */
	ECFS_INODE_EA_INODE	= 21,	/* Inode used for large EA */
/* 22 was formerly ECFS_INODE_EOFBLOCKS */
	ECFS_INODE_DAX		= 25,	/* Inode is DAX */
	ECFS_INODE_INLINE_DATA	= 28,	/* Data in inode. */
	ECFS_INODE_PROJINHERIT	= 29,	/* Create with parents projid */
	ECFS_INODE_CASEFOLD	= 30,	/* Casefolded directory */
	ECFS_INODE_RESERVED	= 31,	/* reserved for ecfs lib */
};

/*
 * Since it's pretty easy to mix up bit numbers and hex values, we use a
 * build-time check to make sure that ECFS_XXX_FL is consistent with respect to
 * ECFS_INODE_XXX. If all is well, the macros will be dropped, so, it won't cost
 * any extra space in the compiled kernel image, otherwise, the build will fail.
 * It's important that these values are the same, since we are using
 * ECFS_INODE_XXX to test for flag values, but ECFS_XXX_FL must be consistent
 * with the values of FS_XXX_FL defined in include/linux/fs.h and the on-disk
 * values found in ext2, ext3 and ecfs filesystems, and of course the values
 * defined in e2fsprogs.
 *
 * It's not paranoia if the Murphy's Law really *is* out to get you.  :-)
 */
#define TEST_FLAG_VALUE(FLAG) (ECFS_##FLAG##_FL == (1U << ECFS_INODE_##FLAG))
#define CHECK_FLAG_VALUE(FLAG) BUILD_BUG_ON(!TEST_FLAG_VALUE(FLAG))

static inline void ecfs_check_flag_values(void)
{
	CHECK_FLAG_VALUE(SECRM);
	CHECK_FLAG_VALUE(UNRM);
	CHECK_FLAG_VALUE(COMPR);
	CHECK_FLAG_VALUE(SYNC);
	CHECK_FLAG_VALUE(IMMUTABLE);
	CHECK_FLAG_VALUE(APPEND);
	CHECK_FLAG_VALUE(NODUMP);
	CHECK_FLAG_VALUE(NOATIME);
	CHECK_FLAG_VALUE(DIRTY);
	CHECK_FLAG_VALUE(COMPRBLK);
	CHECK_FLAG_VALUE(NOCOMPR);
	CHECK_FLAG_VALUE(ENCRYPT);
	CHECK_FLAG_VALUE(INDEX);
	CHECK_FLAG_VALUE(IMAGIC);
	CHECK_FLAG_VALUE(JOURNAL_DATA);
	CHECK_FLAG_VALUE(NOTAIL);
	CHECK_FLAG_VALUE(DIRSYNC);
	CHECK_FLAG_VALUE(TOPDIR);
	CHECK_FLAG_VALUE(HUGE_FILE);
	CHECK_FLAG_VALUE(EXTENTS);
	CHECK_FLAG_VALUE(VERITY);
	CHECK_FLAG_VALUE(EA_INODE);
	CHECK_FLAG_VALUE(INLINE_DATA);
	CHECK_FLAG_VALUE(PROJINHERIT);
	CHECK_FLAG_VALUE(CASEFOLD);
	CHECK_FLAG_VALUE(RESERVED);
}

#if defined(__KERNEL__) && defined(CONFIG_COMPAT)
struct compat_ecfs_new_group_input {
	u32 group;
	compat_u64 block_bitmap;
	compat_u64 inode_bitmap;
	compat_u64 inode_table;
	u32 blocks_count;
	u16 reserved_blocks;
	u16 unused;
};
#endif

/* The struct ecfs_new_group_input in kernel space, with free_blocks_count */
struct ecfs_new_group_data {
	__u32 group;
	__u64 block_bitmap;
	__u64 inode_bitmap;
	__u64 inode_table;
	__u32 blocks_count;
	__u16 reserved_blocks;
	__u16 mdata_blocks;
	__u32 free_clusters_count;
};

/* Indexes used to index group tables in ecfs_new_group_data */
enum {
	BLOCK_BITMAP = 0,	/* block bitmap */
	INODE_BITMAP,		/* inode bitmap */
	INODE_TABLE,		/* inode tables */
	GROUP_TABLE_COUNT,
};

/*
 * Flags used by ecfs_map_blocks()
 */
	/* Allocate any needed blocks and/or convert an unwritten
	   extent to be an initialized ecfs */
#define ECFS_GET_BLOCKS_CREATE			0x0001
	/* Request the creation of an unwritten extent */
#define ECFS_GET_BLOCKS_UNWRIT_EXT		0x0002
#define ECFS_GET_BLOCKS_CREATE_UNWRIT_EXT	(ECFS_GET_BLOCKS_UNWRIT_EXT|\
						 ECFS_GET_BLOCKS_CREATE)
	/* Caller is from the delayed allocation writeout path
	 * finally doing the actual allocation of delayed blocks */
#define ECFS_GET_BLOCKS_DELALLOC_RESERVE	0x0004
	/* caller is from the direct IO path, request to creation of an
	unwritten extents if not allocated, split the unwritten
	extent if blocks has been preallocated already*/
#define ECFS_GET_BLOCKS_PRE_IO			0x0008
#define ECFS_GET_BLOCKS_CONVERT			0x0010
#define ECFS_GET_BLOCKS_IO_CREATE_EXT		(ECFS_GET_BLOCKS_PRE_IO|\
					 ECFS_GET_BLOCKS_CREATE_UNWRIT_EXT)
	/* Eventual metadata allocation (due to growing extent tree)
	 * should not fail, so try to use reserved blocks for that.*/
#define ECFS_GET_BLOCKS_METADATA_NOFAIL		0x0020
	/* Don't normalize allocation size (used for fallocate) */
#define ECFS_GET_BLOCKS_NO_NORMALIZE		0x0040
	/* Convert written extents to unwritten */
#define ECFS_GET_BLOCKS_CONVERT_UNWRITTEN	0x0100
	/* Write zeros to newly created written extents */
#define ECFS_GET_BLOCKS_ZERO			0x0200
#define ECFS_GET_BLOCKS_CREATE_ZERO		(ECFS_GET_BLOCKS_CREATE |\
					ECFS_GET_BLOCKS_ZERO)
	/* Caller is in the context of data submission, such as writeback,
	 * fsync, etc. Especially, in the generic writeback path, caller will
	 * submit data before dropping transaction handle. This allows jbd2
	 * to avoid submitting data before commit. */
#define ECFS_GET_BLOCKS_IO_SUBMIT		0x0400
	/* Convert extent to initialized after IO complete */
#define ECFS_GET_BLOCKS_IO_CONVERT_EXT		(ECFS_GET_BLOCKS_CONVERT |\
					 ECFS_GET_BLOCKS_CREATE_UNWRIT_EXT |\
					 ECFS_GET_BLOCKS_IO_SUBMIT)
	/* Caller is in the atomic contex, find extent if it has been cached */
#define ECFS_GET_BLOCKS_CACHED_NOWAIT		0x0800
/*
 * Atomic write caller needs this to query in the slow path of mixed mapping
 * case, when a contiguous extent can be split across two adjacent leaf nodes.
 * Look ECFS_MAP_QUERY_LAST_IN_LEAF.
 */
#define ECFS_GET_BLOCKS_QUERY_LAST_IN_LEAF	0x1000

/*
 * The bit position of these flags must not overlap with any of the
 * ECFS_GET_BLOCKS_*.  They are used by ecfs_find_extent(),
 * read_extent_tree_block(), ecfs_split_extent_at(),
 * ecfs_ext_insert_extent(), and ecfs_ext_create_new_leaf().
 * ECFS_EX_NOCACHE is used to indicate that the we shouldn't be
 * caching the extents when reading from the extent tree while a
 * truncate or punch hole operation is in progress.
 */
#define ECFS_EX_NOCACHE				0x40000000
#define ECFS_EX_FORCE_CACHE			0x20000000
#define ECFS_EX_NOFAIL				0x10000000
/*
 * ecfs_map_query_blocks() uses this filter mask to filter the flags needed to
 * pass while lookup/querying of on disk extent tree.
 */
#define ECFS_EX_QUERY_FILTER	(ECFS_EX_NOCACHE | ECFS_EX_FORCE_CACHE |\
				 ECFS_EX_NOFAIL |\
				 ECFS_GET_BLOCKS_QUERY_LAST_IN_LEAF)

/*
 * Flags used by ecfs_free_blocks
 */
#define ECFS_FREE_BLOCKS_METADATA		0x0001
#define ECFS_FREE_BLOCKS_FORGET			0x0002
#define ECFS_FREE_BLOCKS_VALIDATED		0x0004
#define ECFS_FREE_BLOCKS_NO_QUOT_UPDATE		0x0008
#define ECFS_FREE_BLOCKS_NOFREE_FIRST_CLUSTER	0x0010
#define ECFS_FREE_BLOCKS_NOFREE_LAST_CLUSTER	0x0020
#define ECFS_FREE_BLOCKS_RERESERVE_CLUSTER      0x0040

#if defined(__KERNEL__) && defined(CONFIG_COMPAT)
/*
 * ioctl commands in 32 bit emulation
 */
#define ECFS_IOC32_GETVERSION		_IOR('f', 3, int)
#define ECFS_IOC32_SETVERSION		_IOW('f', 4, int)
#define ECFS_IOC32_GETRSVSZ		_IOR('f', 5, int)
#define ECFS_IOC32_SETRSVSZ		_IOW('f', 6, int)
#define ECFS_IOC32_GROUP_EXTEND		_IOW('f', 7, unsigned int)
#define ECFS_IOC32_GROUP_ADD		_IOW('f', 8, struct compat_ecfs_new_group_input)
#define ECFS_IOC32_GETVERSION_OLD	FS_IOC32_GETVERSION
#define ECFS_IOC32_SETVERSION_OLD	FS_IOC32_SETVERSION
#endif

/* Max physical block we can address w/o extents */
#define ECFS_MAX_BLOCK_FILE_PHYS	0xFFFFFFFF

/* Max logical block we can support */
#define ECFS_MAX_LOGICAL_BLOCK		0xFFFFFFFE

/*
 * Structure of an inode on the disk
 */
struct ecfs_inode {
	__le16	i_mode;		/* File mode */
	__le16	i_uid;		/* Low 16 bits of Owner Uid */
	__le32	i_size_lo;	/* Size in bytes */
	__le32	i_atime;	/* Access time */
	__le32	i_ctime;	/* Inode Change time */
	__le32	i_mtime;	/* Modification time */
	__le32	i_dtime;	/* Deletion Time */
	__le16	i_gid;		/* Low 16 bits of Group Id */
	__le16	i_links_count;	/* Links count */
	__le32	i_blocks_lo;	/* Blocks count */
	__le32	i_flags;	/* File flags */
	union {
		struct {
			__le32  l_i_version;
		} linux1;
		struct {
			__u32  h_i_translator;
		} hurd1;
		struct {
			__u32  m_i_reserved1;
		} masix1;
	} osd1;				/* OS dependent 1 */
	__le32	i_block[ECFS_N_BLOCKS];/* Pointers to blocks */
	__le32	i_generation;	/* File version (for NFS) */
	__le32	i_file_acl_lo;	/* File ACL */
	__le32	i_size_high;
	__le32	i_obso_faddr;	/* Obsoleted fragment address */
	union {
		struct {
			__le16	l_i_blocks_high; /* were l_i_reserved1 */
			__le16	l_i_file_acl_high;
			__le16	l_i_uid_high;	/* these 2 fields */
			__le16	l_i_gid_high;	/* were reserved2[0] */
			__le16	l_i_checksum_lo;/* crc32c(uuid+inum+inode) LE */
			__le16	l_i_reserved;
		} linux2;
		struct {
			__le16	h_i_reserved1;	/* Obsoleted fragment number/size which are removed in ecfs */
			__u16	h_i_mode_high;
			__u16	h_i_uid_high;
			__u16	h_i_gid_high;
			__u32	h_i_author;
		} hurd2;
		struct {
			__le16	h_i_reserved1;	/* Obsoleted fragment number/size which are removed in ecfs */
			__le16	m_i_file_acl_high;
			__u32	m_i_reserved2[2];
		} masix2;
	} osd2;				/* OS dependent 2 */
	__le16	i_extra_isize;
	__le16	i_checksum_hi;	/* crc32c(uuid+inum+inode) BE */
	__le32  i_ctime_extra;  /* extra Change time      (nsec << 2 | epoch) */
	__le32  i_mtime_extra;  /* extra Modification time(nsec << 2 | epoch) */
	__le32  i_atime_extra;  /* extra Access time      (nsec << 2 | epoch) */
	__le32  i_crtime;       /* File Creation time */
	__le32  i_crtime_extra; /* extra FileCreationtime (nsec << 2 | epoch) */
	__le32  i_version_hi;	/* high 32 bits for 64-bit version */
	__le32	i_projid;	/* Project ID */
};

#define ECFS_EPOCH_BITS 2
#define ECFS_EPOCH_MASK ((1 << ECFS_EPOCH_BITS) - 1)
#define ECFS_NSEC_MASK  (~0UL << ECFS_EPOCH_BITS)

/*
 * Extended fields will fit into an inode if the filesystem was formatted
 * with large inodes (-I 256 or larger) and there are not currently any EAs
 * consuming all of the available space. For new inodes we always reserve
 * enough space for the kernel's known extended fields, but for inodes
 * created with an old kernel this might not have been the case. None of
 * the extended inode fields is critical for correct filesystem operation.
 * This macro checks if a certain field fits in the inode. Note that
 * inode-size = GOOD_OLD_INODE_SIZE + i_extra_isize
 */
#define ECFS_FITS_IN_INODE(ecfs_inode, einode, field)	\
	((offsetof(typeof(*ecfs_inode), field) +	\
	  sizeof((ecfs_inode)->field))			\
	<= (ECFS_GOOD_OLD_INODE_SIZE +			\
	    (einode)->i_extra_isize))			\

/*
 * We use an encoding that preserves the times for extra epoch "00":
 *
 * extra  msb of                         adjust for signed
 * epoch  32-bit                         32-bit tv_sec to
 * bits   time    decoded 64-bit tv_sec  64-bit tv_sec      valid time range
 * 0 0    1    -0x80000000..-0x00000001  0x000000000 1901-12-13..1969-12-31
 * 0 0    0    0x000000000..0x07fffffff  0x000000000 1970-01-01..2038-01-19
 * 0 1    1    0x080000000..0x0ffffffff  0x100000000 2038-01-19..2106-02-07
 * 0 1    0    0x100000000..0x17fffffff  0x100000000 2106-02-07..2174-02-25
 * 1 0    1    0x180000000..0x1ffffffff  0x200000000 2174-02-25..2242-03-16
 * 1 0    0    0x200000000..0x27fffffff  0x200000000 2242-03-16..2310-04-04
 * 1 1    1    0x280000000..0x2ffffffff  0x300000000 2310-04-04..2378-04-22
 * 1 1    0    0x300000000..0x37fffffff  0x300000000 2378-04-22..2446-05-10
 *
 * Note that previous versions of the kernel on 64-bit systems would
 * incorrectly use extra epoch bits 1,1 for dates between 1901 and
 * 1970.  e2fsck will correct this, assuming that it is run on the
 * affected filesystem before 2242.
 */

static inline __le32 ecfs_encode_extra_time(struct timespec64 ts)
{
	u32 extra = ((ts.tv_sec - (s32)ts.tv_sec) >> 32) & ECFS_EPOCH_MASK;
	return cpu_to_le32(extra | (ts.tv_nsec << ECFS_EPOCH_BITS));
}

static inline struct timespec64 ecfs_decode_extra_time(__le32 base,
						       __le32 extra)
{
	struct timespec64 ts = { .tv_sec = (signed)le32_to_cpu(base) };

	if (unlikely(extra & cpu_to_le32(ECFS_EPOCH_MASK)))
		ts.tv_sec += (u64)(le32_to_cpu(extra) & ECFS_EPOCH_MASK) << 32;
	ts.tv_nsec = (le32_to_cpu(extra) & ECFS_NSEC_MASK) >> ECFS_EPOCH_BITS;
	return ts;
}

#define ECFS_INODE_SET_XTIME_VAL(xtime, inode, raw_inode, ts)			\
do {										\
	if (ECFS_FITS_IN_INODE(raw_inode, ECFS_I(inode), xtime ## _extra)) {	\
		(raw_inode)->xtime = cpu_to_le32((ts).tv_sec);			\
		(raw_inode)->xtime ## _extra = ecfs_encode_extra_time(ts);	\
	} else									\
		(raw_inode)->xtime = cpu_to_le32(clamp_t(int32_t, (ts).tv_sec, S32_MIN, S32_MAX));	\
} while (0)

#define ECFS_INODE_SET_ATIME(inode, raw_inode)						\
	ECFS_INODE_SET_XTIME_VAL(i_atime, inode, raw_inode, inode_get_atime(inode))

#define ECFS_INODE_SET_MTIME(inode, raw_inode)						\
	ECFS_INODE_SET_XTIME_VAL(i_mtime, inode, raw_inode, inode_get_mtime(inode))

#define ECFS_INODE_SET_CTIME(inode, raw_inode)						\
	ECFS_INODE_SET_XTIME_VAL(i_ctime, inode, raw_inode, inode_get_ctime(inode))

#define ECFS_EINODE_SET_XTIME(xtime, einode, raw_inode)				\
	if (ECFS_FITS_IN_INODE(raw_inode, einode, xtime))			\
		ECFS_INODE_SET_XTIME_VAL(xtime, &((einode)->vfs_inode),		\
					 raw_inode, (einode)->xtime)

#define ECFS_INODE_GET_XTIME_VAL(xtime, inode, raw_inode)			\
	(ECFS_FITS_IN_INODE(raw_inode, ECFS_I(inode), xtime ## _extra) ?	\
		ecfs_decode_extra_time((raw_inode)->xtime,				\
				       (raw_inode)->xtime ## _extra) :		\
		(struct timespec64) {						\
			.tv_sec = (signed)le32_to_cpu((raw_inode)->xtime)	\
		})

#define ECFS_INODE_GET_ATIME(inode, raw_inode)					\
do {										\
	inode_set_atime_to_ts(inode,						\
		ECFS_INODE_GET_XTIME_VAL(i_atime, inode, raw_inode));		\
} while (0)

#define ECFS_INODE_GET_MTIME(inode, raw_inode)					\
do {										\
	inode_set_mtime_to_ts(inode,						\
		ECFS_INODE_GET_XTIME_VAL(i_mtime, inode, raw_inode));		\
} while (0)

#define ECFS_INODE_GET_CTIME(inode, raw_inode)					\
do {										\
	inode_set_ctime_to_ts(inode,						\
		ECFS_INODE_GET_XTIME_VAL(i_ctime, inode, raw_inode));		\
} while (0)

#define ECFS_EINODE_GET_XTIME(xtime, einode, raw_inode)				\
do {										\
	if (ECFS_FITS_IN_INODE(raw_inode, einode, xtime)) 			\
		(einode)->xtime =						\
			ECFS_INODE_GET_XTIME_VAL(xtime, &(einode->vfs_inode),	\
						 raw_inode);			\
	else									\
		(einode)->xtime = (struct timespec64){0, 0};			\
} while (0)

#define i_disk_version osd1.linux1.l_i_version

#if defined(__KERNEL__) || defined(__linux__)
#define i_reserved1	osd1.linux1.l_i_reserved1
#define i_file_acl_high	osd2.linux2.l_i_file_acl_high
#define i_blocks_high	osd2.linux2.l_i_blocks_high
#define i_uid_low	i_uid
#define i_gid_low	i_gid
#define i_uid_high	osd2.linux2.l_i_uid_high
#define i_gid_high	osd2.linux2.l_i_gid_high
#define i_checksum_lo	osd2.linux2.l_i_checksum_lo

#elif defined(__GNU__)

#define i_translator	osd1.hurd1.h_i_translator
#define i_uid_high	osd2.hurd2.h_i_uid_high
#define i_gid_high	osd2.hurd2.h_i_gid_high
#define i_author	osd2.hurd2.h_i_author

#elif defined(__masix__)

#define i_reserved1	osd1.masix1.m_i_reserved1
#define i_file_acl_high	osd2.masix2.m_i_file_acl_high
#define i_reserved2	osd2.masix2.m_i_reserved2

#endif /* defined(__KERNEL__) || defined(__linux__) */

#include "extents_status.h"
#include "fast_commit.h"

/*
 * Lock subclasses for i_data_sem in the ecfs_inode_info structure.
 *
 * These are needed to avoid lockdep false positives when we need to
 * allocate blocks to the quota inode during ecfs_map_blocks(), while
 * holding i_data_sem for a normal (non-quota) inode.  Since we don't
 * do quota tracking for the quota inode, this avoids deadlock (as
 * well as infinite recursion, since it isn't turtles all the way
 * down...)
 *
 *  I_DATA_SEM_NORMAL - Used for most inodes
 *  I_DATA_SEM_OTHER  - Used by move_inode.c for the second normal inode
 *			  where the second inode has larger inode number
 *			  than the first
 *  I_DATA_SEM_QUOTA  - Used for quota inodes only
 *  I_DATA_SEM_EA     - Used for ea_inodes only
 */
enum {
	I_DATA_SEM_NORMAL = 0,
	I_DATA_SEM_OTHER,
	I_DATA_SEM_QUOTA,
	I_DATA_SEM_EA
};


/*
 * fourth extended file system inode data in memory
 */
struct ecfs_inode_info {
	__le32	i_data[15];	/* unconverted */
	__u32	i_dtime;
	ecfs_fsblk_t	i_file_acl;

	/*
	 * i_block_group is the number of the block group which contains
	 * this file's inode.  Constant across the lifetime of the inode,
	 * it is used for making block allocation decisions - we try to
	 * place a file's data blocks near its inode block, and new inodes
	 * near to their parent directory's inode.
	 */
	ecfs_group_t	i_block_group;
	ecfs_lblk_t	i_dir_start_lookup;
#if (BITS_PER_LONG < 64)
	unsigned long	i_state_flags;		/* Dynamic state flags */
#endif
	unsigned long	i_flags;

	/*
	 * Extended attributes can be read independently of the main file
	 * data. Taking i_rwsem even when reading would cause contention
	 * between readers of EAs and writers of regular file data, so
	 * instead we synchronize on xattr_sem when reading or changing
	 * EAs.
	 */
	struct rw_semaphore xattr_sem;

	/*
	 * Inodes with ECFS_STATE_ORPHAN_FILE use i_orphan_idx. Otherwise
	 * i_orphan is used.
	 */
	union {
		struct list_head i_orphan;	/* unlinked but open inodes */
		unsigned int i_orphan_idx;	/* Index in orphan file */
	};

	/* Fast commit related info */

	/* For tracking dentry create updates */
	struct list_head i_fc_dilist;
	struct list_head i_fc_list;	/*
					 * inodes that need fast commit
					 * protected by sbi->s_fc_lock.
					 */

	/* Start of lblk range that needs to be committed in this fast commit */
	ecfs_lblk_t i_fc_lblk_start;

	/* End of lblk range that needs to be committed in this fast commit */
	ecfs_lblk_t i_fc_lblk_len;

	spinlock_t i_raw_lock;	/* protects updates to the raw inode */

	/* Fast commit wait queue for this inode */
	wait_queue_head_t i_fc_wait;

	/*
	 * Protect concurrent accesses on i_fc_lblk_start, i_fc_lblk_len
	 * and inode's ECFS_FC_STATE_COMMITTING state bit.
	 */
	spinlock_t i_fc_lock;

	/*
	 * i_disksize keeps track of what the inode size is ON DISK, not
	 * in memory.  During truncate, i_size is set to the new size by
	 * the VFS prior to calling ecfs_truncate(), but the filesystem won't
	 * set i_disksize to 0 until the truncate is actually under way.
	 *
	 * The intent is that i_disksize always represents the blocks which
	 * are used by this file.  This allows recovery to restart truncate
	 * on orphans if we crash during truncate.  We actually write i_disksize
	 * into the on-disk inode when writing inodes out, instead of i_size.
	 *
	 * The only time when i_disksize and i_size may be different is when
	 * a truncate is in progress.  The only things which change i_disksize
	 * are ecfs_get_block (growth) and ecfs_truncate (shrinkth).
	 */
	loff_t	i_disksize;

	/*
	 * i_data_sem is for serialising ecfs_truncate() against
	 * ecfs_getblock().  In the 2.4 ext2 design, great chunks of inode's
	 * data tree are chopped off during truncate. We can't do that in
	 * ecfs because whenever we perform intermediate commits during
	 * truncate, the inode and all the metadata blocks *must* be in a
	 * consistent state which allows truncation of the orphans to restart
	 * during recovery.  Hence we must fix the get_block-vs-truncate race
	 * by other means, so we have i_data_sem.
	 */
	struct rw_semaphore i_data_sem;
	struct inode vfs_inode;
	struct jbd2_inode *jinode;

	/*
	 * File creation time. Its function is same as that of
	 * struct timespec64 i_{a,c,m}time in the generic inode.
	 */
	struct timespec64 i_crtime;

	/* mballoc */
	atomic_t i_prealloc_active;

	/* allocation reservation info for delalloc */
	/* In case of bigalloc, this refer to clusters rather than blocks */
	unsigned int i_reserved_data_blocks;
	struct rb_root i_prealloc_node;
	rwlock_t i_prealloc_lock;

	/* extents status tree */
	struct ecfs_es_tree i_es_tree;
	rwlock_t i_es_lock;
	struct list_head i_es_list;
	unsigned int i_es_all_nr;	/* protected by i_es_lock */
	unsigned int i_es_shk_nr;	/* protected by i_es_lock */
	ecfs_lblk_t i_es_shrink_lblk;	/* Offset where we start searching for
					   extents to shrink. Protected by
					   i_es_lock  */

	/* ialloc */
	ecfs_group_t	i_last_alloc_group;

	/* pending cluster reservations for bigalloc file systems */
	struct ecfs_pending_tree i_pending_tree;

	/* on-disk additional length */
	__u16 i_extra_isize;

	/* Indicate the inline data space. */
	u16 i_inline_off;
	u16 i_inline_size;

#ifdef CONFIG_QUOTA
	/* quota space reservation, managed internally by quota code */
	qsize_t i_reserved_quota;
#endif
	spinlock_t i_block_reservation_lock;

	/* Lock protecting lists below */
	spinlock_t i_completed_io_lock;
	/*
	 * Completed IOs that need unwritten extents handling and have
	 * transaction reserved
	 */
	struct list_head i_rsv_conversion_list;
	struct work_struct i_rsv_conversion_work;

	/*
	 * Transactions that contain inode's metadata needed to complete
	 * fsync and fdatasync, respectively.
	 */
	tid_t i_sync_tid;
	tid_t i_datasync_tid;

#ifdef CONFIG_QUOTA
	struct dquot __rcu *i_dquot[MAXQUOTAS];
#endif

	/* Precomputed uuid+inum+igen checksum for seeding inode checksums */
	__u32 i_csum_seed;

	kprojid_t i_projid;
};

/*
 * File system states
 */
#define	ECFS_VALID_FS			0x0001	/* Unmounted cleanly */
#define	ECFS_ERROR_FS			0x0002	/* Errors detected */
#define	ECFS_ORPHAN_FS			0x0004	/* Orphans being recovered */
#define ECFS_FC_REPLAY			0x0020	/* Fast commit replay ongoing */

/*
 * Misc. filesystem flags
 */
#define EXT2_FLAGS_SIGNED_HASH		0x0001  /* Signed dirhash in use */
#define EXT2_FLAGS_UNSIGNED_HASH	0x0002  /* Unsigned dirhash in use */
#define EXT2_FLAGS_TEST_FILESYS		0x0004	/* to test development code */

/*
 * Mount flags set via mount options or defaults
 */
#define ECFS_MOUNT_NO_MBCACHE		0x00001 /* Do not use mbcache */
#define ECFS_MOUNT_GRPID		0x00004	/* Create files with directory's group */
#define ECFS_MOUNT_DEBUG		0x00008	/* Some debugging messages */
#define ECFS_MOUNT_ERRORS_CONT		0x00010	/* Continue on errors */
#define ECFS_MOUNT_ERRORS_RO		0x00020	/* Remount fs ro on errors */
#define ECFS_MOUNT_ERRORS_PANIC		0x00040	/* Panic on errors */
#define ECFS_MOUNT_ERRORS_MASK		0x00070
#define ECFS_MOUNT_MINIX_DF		0x00080	/* Mimics the Minix statfs */
#define ECFS_MOUNT_NOLOAD		0x00100	/* Don't use existing journal*/
#ifdef CONFIG_FS_DAX
#define ECFS_MOUNT_DAX_ALWAYS		0x00200	/* Direct Access */
#else
#define ECFS_MOUNT_DAX_ALWAYS		0
#endif
#define ECFS_MOUNT_DATA_FLAGS		0x00C00	/* Mode for data writes: */
#define ECFS_MOUNT_JOURNAL_DATA		0x00400	/* Write data to journal */
#define ECFS_MOUNT_ORDERED_DATA		0x00800	/* Flush data before commit */
#define ECFS_MOUNT_WRITEBACK_DATA	0x00C00	/* No data ordering */
#define ECFS_MOUNT_UPDATE_JOURNAL	0x01000	/* Update the journal format */
#define ECFS_MOUNT_NO_UID32		0x02000  /* Disable 32-bit UIDs */
#define ECFS_MOUNT_XATTR_USER		0x04000	/* Extended user attributes */
#define ECFS_MOUNT_POSIX_ACL		0x08000	/* POSIX Access Control Lists */
#define ECFS_MOUNT_NO_AUTO_DA_ALLOC	0x10000	/* No auto delalloc mapping */
#define ECFS_MOUNT_BARRIER		0x20000 /* Use block barriers */
#define ECFS_MOUNT_QUOTA		0x40000 /* Some quota option set */
#define ECFS_MOUNT_USRQUOTA		0x80000 /* "old" user quota,
						 * enable enforcement for hidden
						 * quota files */
#define ECFS_MOUNT_GRPQUOTA		0x100000 /* "old" group quota, enable
						  * enforcement for hidden quota
						  * files */
#define ECFS_MOUNT_PRJQUOTA		0x200000 /* Enable project quota
						  * enforcement */
#define ECFS_MOUNT_DIOREAD_NOLOCK	0x400000 /* Enable support for dio read nolocking */
#define ECFS_MOUNT_JOURNAL_CHECKSUM	0x800000 /* Journal checksums */
#define ECFS_MOUNT_JOURNAL_ASYNC_COMMIT	0x1000000 /* Journal Async Commit */
#define ECFS_MOUNT_WARN_ON_ERROR	0x2000000 /* Trigger WARN_ON on error */
#define ECFS_MOUNT_NO_PREFETCH_BLOCK_BITMAPS 0x4000000
#define ECFS_MOUNT_DELALLOC		0x8000000 /* Delalloc support */
#define ECFS_MOUNT_DATA_ERR_ABORT	0x10000000 /* Abort on file data write */
#define ECFS_MOUNT_BLOCK_VALIDITY	0x20000000 /* Block validity checking */
#define ECFS_MOUNT_DISCARD		0x40000000 /* Issue DISCARD requests */
#define ECFS_MOUNT_INIT_INODE_TABLE	0x80000000 /* Initialize uninitialized itables */

/*
 * Mount flags set either automatically (could not be set by mount option)
 * based on per file system feature or property or in special cases such as
 * distinguishing between explicit mount option definition and default.
 */
#define ECFS_MOUNT2_EXPLICIT_DELALLOC	0x00000001 /* User explicitly
						      specified delalloc */
#define ECFS_MOUNT2_STD_GROUP_SIZE	0x00000002 /* We have standard group
						      size of blocksize * 8
						      blocks */
#define ECFS_MOUNT2_HURD_COMPAT		0x00000004 /* Support HURD-castrated
						      file systems */
#define ECFS_MOUNT2_EXPLICIT_JOURNAL_CHECKSUM	0x00000008 /* User explicitly
						specified journal checksum */

#define ECFS_MOUNT2_JOURNAL_FAST_COMMIT	0x00000010 /* Journal fast commit */
#define ECFS_MOUNT2_DAX_NEVER		0x00000020 /* Do not allow Direct Access */
#define ECFS_MOUNT2_DAX_INODE		0x00000040 /* For printing options only */
#define ECFS_MOUNT2_MB_OPTIMIZE_SCAN	0x00000080 /* Optimize group
						    * scanning in mballoc
						    */
#define ECFS_MOUNT2_ABORT		0x00000100 /* Abort filesystem */

#define clear_opt(sb, opt)		ECFS_SB(sb)->s_mount_opt &= \
						~ECFS_MOUNT_##opt
#define set_opt(sb, opt)		ECFS_SB(sb)->s_mount_opt |= \
						ECFS_MOUNT_##opt
#define test_opt(sb, opt)		(ECFS_SB(sb)->s_mount_opt & \
					 ECFS_MOUNT_##opt)

#define clear_opt2(sb, opt)		ECFS_SB(sb)->s_mount_opt2 &= \
						~ECFS_MOUNT2_##opt
#define set_opt2(sb, opt)		ECFS_SB(sb)->s_mount_opt2 |= \
						ECFS_MOUNT2_##opt
#define test_opt2(sb, opt)		(ECFS_SB(sb)->s_mount_opt2 & \
					 ECFS_MOUNT2_##opt)

#define ecfs_test_and_set_bit		__test_and_set_bit_le
#define ecfs_set_bit			__set_bit_le
#define ecfs_test_and_clear_bit		__test_and_clear_bit_le
#define ecfs_clear_bit			__clear_bit_le
#define ecfs_test_bit			test_bit_le
#define ecfs_find_next_zero_bit		find_next_zero_bit_le
#define ecfs_find_next_bit		find_next_bit_le

extern void ecfs_mb_set_bits(void *bm, int cur, int len);

/*
 * Maximal mount counts between two filesystem checks
 */
#define ECFS_DFL_MAX_MNT_COUNT		20	/* Allow 20 mounts */
#define ECFS_DFL_CHECKINTERVAL		0	/* Don't use interval check */

/*
 * Behaviour when detecting errors
 */
#define ECFS_ERRORS_CONTINUE		1	/* Continue execution */
#define ECFS_ERRORS_RO			2	/* Remount fs read-only */
#define ECFS_ERRORS_PANIC		3	/* Panic */
#define ECFS_ERRORS_DEFAULT		ECFS_ERRORS_CONTINUE

/* Metadata checksum algorithm codes */
#define ECFS_CRC32C_CHKSUM		1

#define ECFS_LABEL_MAX			16

/*
 * Structure of the super block
 */
struct ecfs_super_block {
/*00*/	__le32	s_inodes_count;		/* Inodes count */
	__le32	s_blocks_count_lo;	/* Blocks count */
	__le32	s_r_blocks_count_lo;	/* Reserved blocks count */
	__le32	s_free_blocks_count_lo;	/* Free blocks count */
/*10*/	__le32	s_free_inodes_count;	/* Free inodes count */
	__le32	s_first_data_block;	/* First Data Block */
	__le32	s_log_block_size;	/* Block size */
	__le32	s_log_cluster_size;	/* Allocation cluster size */
/*20*/	__le32	s_blocks_per_group;	/* # Blocks per group */
	__le32	s_clusters_per_group;	/* # Clusters per group */
	__le32	s_inodes_per_group;	/* # Inodes per group */
	__le32	s_mtime;		/* Mount time */
/*30*/	__le32	s_wtime;		/* Write time */
	__le16	s_mnt_count;		/* Mount count */
	__le16	s_max_mnt_count;	/* Maximal mount count */
	__le16	s_magic;		/* Magic signature */
	__le16	s_state;		/* File system state */
	__le16	s_errors;		/* Behaviour when detecting errors */
	__le16	s_minor_rev_level;	/* minor revision level */
/*40*/	__le32	s_lastcheck;		/* time of last check */
	__le32	s_checkinterval;	/* max. time between checks */
	__le32	s_creator_os;		/* OS */
	__le32	s_rev_level;		/* Revision level */
/*50*/	__le16	s_def_resuid;		/* Default uid for reserved blocks */
	__le16	s_def_resgid;		/* Default gid for reserved blocks */
	/*
	 * These fields are for ECFS_DYNAMIC_REV superblocks only.
	 *
	 * Note: the difference between the compatible feature set and
	 * the incompatible feature set is that if there is a bit set
	 * in the incompatible feature set that the kernel doesn't
	 * know about, it should refuse to mount the filesystem.
	 *
	 * e2fsck's requirements are more strict; if it doesn't know
	 * about a feature in either the compatible or incompatible
	 * feature set, it must abort and not try to meddle with
	 * things it doesn't understand...
	 */
	__le32	s_first_ino;		/* First non-reserved inode */
	__le16  s_inode_size;		/* size of inode structure */
	__le16	s_block_group_nr;	/* block group # of this superblock */
	__le32	s_feature_compat;	/* compatible feature set */
/*60*/	__le32	s_feature_incompat;	/* incompatible feature set */
	__le32	s_feature_ro_compat;	/* readonly-compatible feature set */
/*68*/	__u8	s_uuid[16];		/* 128-bit uuid for volume */
/*78*/	char	s_volume_name[ECFS_LABEL_MAX] __nonstring; /* volume name */
/*88*/	char	s_last_mounted[64] __nonstring;	/* directory where last mounted */
/*C8*/	__le32	s_algorithm_usage_bitmap; /* For compression */
	/*
	 * Performance hints.  Directory preallocation should only
	 * happen if the ECFS_FEATURE_COMPAT_DIR_PREALLOC flag is on.
	 */
	__u8	s_prealloc_blocks;	/* Nr of blocks to try to preallocate*/
	__u8	s_prealloc_dir_blocks;	/* Nr to preallocate for dirs */
	__le16	s_reserved_gdt_blocks;	/* Per group desc for online growth */
	/*
	 * Journaling support valid if ECFS_FEATURE_COMPAT_HAS_JOURNAL set.
	 */
/*D0*/	__u8	s_journal_uuid[16];	/* uuid of journal superblock */
/*E0*/	__le32	s_journal_inum;		/* inode number of journal file */
	__le32	s_journal_dev;		/* device number of journal file */
	__le32	s_last_orphan;		/* start of list of inodes to delete */
	__le32	s_hash_seed[4];		/* HTREE hash seed */
	__u8	s_def_hash_version;	/* Default hash version to use */
	__u8	s_jnl_backup_type;
	__le16  s_desc_size;		/* size of group descriptor */
/*100*/	__le32	s_default_mount_opts;
	__le32	s_first_meta_bg;	/* First metablock block group */
	__le32	s_mkfs_time;		/* When the filesystem was created */
	__le32	s_jnl_blocks[17];	/* Backup of the journal inode */
	/* 64bit support valid if ECFS_FEATURE_INCOMPAT_64BIT */
/*150*/	__le32	s_blocks_count_hi;	/* Blocks count */
	__le32	s_r_blocks_count_hi;	/* Reserved blocks count */
	__le32	s_free_blocks_count_hi;	/* Free blocks count */
	__le16	s_min_extra_isize;	/* All inodes have at least # bytes */
	__le16	s_want_extra_isize; 	/* New inodes should reserve # bytes */
	__le32	s_flags;		/* Miscellaneous flags */
	__le16  s_raid_stride;		/* RAID stride */
	__le16  s_mmp_update_interval;  /* # seconds to wait in MMP checking */
	__le64  s_mmp_block;            /* Block for multi-mount protection */
	__le32  s_raid_stripe_width;    /* blocks on all data disks (N*stride)*/
	__u8	s_log_groups_per_flex;  /* FLEX_BG group size */
	__u8	s_checksum_type;	/* metadata checksum algorithm used */
	__u8	s_encryption_level;	/* versioning level for encryption */
	__u8	s_reserved_pad;		/* Padding to next 32bits */
	__le64	s_kbytes_written;	/* nr of lifetime kilobytes written */
	__le32	s_snapshot_inum;	/* Inode number of active snapshot */
	__le32	s_snapshot_id;		/* sequential ID of active snapshot */
	__le64	s_snapshot_r_blocks_count; /* reserved blocks for active
					      snapshot's future use */
	__le32	s_snapshot_list;	/* inode number of the head of the
					   on-disk snapshot list */
#define ECFS_S_ERR_START offsetof(struct ecfs_super_block, s_error_count)
	__le32	s_error_count;		/* number of fs errors */
	__le32	s_first_error_time;	/* first time an error happened */
	__le32	s_first_error_ino;	/* inode involved in first error */
	__le64	s_first_error_block;	/* block involved of first error */
	__u8	s_first_error_func[32] __nonstring;	/* function where the error happened */
	__le32	s_first_error_line;	/* line number where error happened */
	__le32	s_last_error_time;	/* most recent time of an error */
	__le32	s_last_error_ino;	/* inode involved in last error */
	__le32	s_last_error_line;	/* line number where error happened */
	__le64	s_last_error_block;	/* block involved of last error */
	__u8	s_last_error_func[32] __nonstring;	/* function where the error happened */
#define ECFS_S_ERR_END offsetof(struct ecfs_super_block, s_mount_opts)
	__u8	s_mount_opts[64];
	__le32	s_usr_quota_inum;	/* inode for tracking user quota */
	__le32	s_grp_quota_inum;	/* inode for tracking group quota */
	__le32	s_overhead_clusters;	/* overhead blocks/clusters in fs */
	__le32	s_backup_bgs[2];	/* groups with sparse_super2 SBs */
	__u8	s_encrypt_algos[4];	/* Encryption algorithms in use  */
	__u8	s_encrypt_pw_salt[16];	/* Salt used for string2key algorithm */
	__le32	s_lpf_ino;		/* Location of the lost+found inode */
	__le32	s_prj_quota_inum;	/* inode for tracking project quota */
	__le32	s_checksum_seed;	/* crc32c(uuid) if csum_seed set */
	__u8	s_wtime_hi;
	__u8	s_mtime_hi;
	__u8	s_mkfs_time_hi;
	__u8	s_lastcheck_hi;
	__u8	s_first_error_time_hi;
	__u8	s_last_error_time_hi;
	__u8	s_first_error_errcode;
	__u8    s_last_error_errcode;
	__le16  s_encoding;		/* Filename charset encoding */
	__le16  s_encoding_flags;	/* Filename charset encoding flags */
	__le32  s_orphan_file_inum;	/* Inode for tracking orphan inodes */
	__le32  s_node_id;	/* node id, start from 1 */
	__le32  s_disk_id;	/* disk id, start form 0 */
	__le32	s_reserved[92];		/* Padding to the end of the block */
	__le32	s_checksum;		/* crc32c(superblock) */
};

#define ECFS_S_ERR_LEN (ECFS_S_ERR_END - ECFS_S_ERR_START)

#ifdef __KERNEL__

/* Number of quota types we support */
#define ECFS_MAXQUOTAS 3

#define ECFS_ENC_UTF8_12_1	1

/* Types of ecfs journal triggers */
enum ecfs_journal_trigger_type {
	ECFS_JTR_ORPHAN_FILE,
	ECFS_JTR_NONE	/* This must be the last entry for indexing to work! */
};

#define ECFS_JOURNAL_TRIGGER_COUNT ECFS_JTR_NONE

struct ecfs_journal_trigger {
	struct jbd2_buffer_trigger_type tr_triggers;
	struct super_block *sb;
};

static inline struct ecfs_journal_trigger *ECFS_TRIGGER(
				struct jbd2_buffer_trigger_type *trigger)
{
	return container_of(trigger, struct ecfs_journal_trigger, tr_triggers);
}

#define ECFS_ORPHAN_BLOCK_MAGIC 0x0b10ca04

/* Structure at the tail of orphan block */
struct ecfs_orphan_block_tail {
	__le32 ob_magic;
	__le32 ob_checksum;
};

static inline int ecfs_inodes_per_orphan_block(struct super_block *sb)
{
	return (sb->s_blocksize - sizeof(struct ecfs_orphan_block_tail)) /
			sizeof(u32);
}

struct ecfs_orphan_block {
	atomic_t ob_free_entries;	/* Number of free orphan entries in block */
	struct buffer_head *ob_bh;	/* Buffer for orphan block */
};

/*
 * Info about orphan file.
 */
struct ecfs_orphan_info {
	int of_blocks;			/* Number of orphan blocks in a file */
	__u32 of_csum_seed;		/* Checksum seed for orphan file */
	struct ecfs_orphan_block *of_binfo;	/* Array with info about orphan
						 * file blocks */
};

/*
 * fourth extended-fs super-block data in memory
 */
struct ecfs_sb_info {
	unsigned long s_desc_size;	/* Size of a group descriptor in bytes */
	unsigned long s_inodes_per_block;/* Number of inodes per block */
	unsigned long s_blocks_per_group;/* Number of blocks in a group */
	unsigned long s_clusters_per_group; /* Number of clusters in a group */
	unsigned long s_inodes_per_group;/* Number of inodes in a group */
	unsigned long s_itb_per_group;	/* Number of inode table blocks per group */
	unsigned long s_gdb_count;	/* Number of group descriptor blocks */
	unsigned long s_desc_per_block;	/* Number of group descriptors per block */
	ecfs_group_t s_groups_count;	/* Number of groups in the fs */
	ecfs_group_t s_blockfile_groups;/* Groups acceptable for non-extent files */
	unsigned long s_overhead;  /* # of fs overhead clusters */
	unsigned int s_cluster_ratio;	/* Number of blocks per cluster */
	unsigned int s_cluster_bits;	/* log2 of s_cluster_ratio */
	loff_t s_bitmap_maxbytes;	/* max bytes for bitmap files */
	struct buffer_head * s_sbh;	/* Buffer containing the super block */
	struct ecfs_super_block *s_es;	/* Pointer to the super block in the buffer */
	/* Array of bh's for the block group descriptors */
	struct buffer_head * __rcu *s_group_desc;
	unsigned int s_mount_opt;
	unsigned int s_mount_opt2;
	unsigned long s_mount_flags;
	unsigned int s_def_mount_opt;
	unsigned int s_def_mount_opt2;
	ecfs_fsblk_t s_sb_block;
	atomic64_t s_resv_clusters;
	kuid_t s_resuid;
	kgid_t s_resgid;
	unsigned short s_mount_state;
	unsigned short s_pad;
	int s_addr_per_block_bits;
	int s_desc_per_block_bits;
	int s_inode_size;
	int s_first_ino;
	unsigned int s_inode_readahead_blks;
	unsigned int s_inode_goal;
	u32 s_hash_seed[4];
	int s_def_hash_version;
	int s_hash_unsigned;	/* 3 if hash should be unsigned, 0 if not */
	struct percpu_counter s_freeclusters_counter;
	struct percpu_counter s_freeinodes_counter;
	struct percpu_counter s_dirs_counter;
	struct percpu_counter s_dirtyclusters_counter;
	struct percpu_counter s_sra_exceeded_retry_limit;
	struct blockgroup_lock *s_blockgroup_lock;
	struct proc_dir_entry *s_proc;
	struct kobject s_kobj;
	struct completion s_kobj_unregister;
	struct super_block *s_sb;
	struct buffer_head *s_mmp_bh;
	unsigned int s_node_id;
	unsigned int s_disk_id;

	/* Journaling */
	struct journal_s *s_journal;
	unsigned long s_ecfs_flags;		/* Ecfs superblock flags */
	struct mutex s_orphan_lock;	/* Protects on disk list changes */
	struct list_head s_orphan;	/* List of orphaned inodes in on disk
					   list */
	struct ecfs_orphan_info s_orphan_info;
	unsigned long s_commit_interval;
	u32 s_max_batch_time;
	u32 s_min_batch_time;
	struct file *s_journal_bdev_file;
#ifdef CONFIG_QUOTA
	/* Names of quota files with journalled quota */
	char __rcu *s_qf_names[ECFS_MAXQUOTAS];
	int s_jquota_fmt;			/* Format of quota to use */
#endif
	unsigned int s_want_extra_isize; /* New inodes should reserve # bytes */
	struct ecfs_system_blocks __rcu *s_system_blks;

#ifdef EXTENTS_STATS
	/* ecfs extents stats */
	unsigned long s_ext_min;
	unsigned long s_ext_max;
	unsigned long s_depth_max;
	spinlock_t s_ext_stats_lock;
	unsigned long s_ext_blocks;
	unsigned long s_ext_extents;
#endif

	/* for buddy allocator */
	struct ecfs_group_info ** __rcu *s_group_info;
	struct inode *s_buddy_cache;
	spinlock_t s_md_lock;
	unsigned short *s_mb_offsets;
	unsigned int *s_mb_maxs;
	unsigned int s_group_info_size;
	atomic_t s_mb_free_pending;
	struct list_head s_freed_data_list[2];	/* List of blocks to be freed
						   after commit completed */
	struct list_head s_discard_list;
	struct work_struct s_discard_work;
	atomic_t s_retry_alloc_pending;
	struct xarray *s_mb_avg_fragment_size;
	struct xarray *s_mb_largest_free_orders;

	/* tunables */
	unsigned long s_stripe;
	unsigned int s_mb_max_linear_groups;
	unsigned int s_mb_stream_request;
	unsigned int s_mb_max_to_scan;
	unsigned int s_mb_min_to_scan;
	unsigned int s_mb_stats;
	unsigned int s_mb_order2_reqs;
	unsigned int s_mb_group_prealloc;
	unsigned int s_max_dir_size_kb;
	unsigned int s_mb_prefetch;
	unsigned int s_mb_prefetch_limit;
	unsigned int s_mb_best_avail_max_trim_order;
	unsigned int s_sb_update_sec;
	unsigned int s_sb_update_kb;

	/* where last allocation was done - for stream allocation */
	ecfs_group_t *s_mb_last_groups;
	unsigned int s_mb_nr_global_goals;

	/* stats for buddy allocator */
	atomic_t s_bal_reqs;	/* number of reqs with len > 1 */
	atomic_t s_bal_success;	/* we found long enough chunks */
	atomic_t s_bal_allocated;	/* in blocks */
	atomic_t s_bal_ex_scanned;	/* total extents scanned */
	atomic_t s_bal_cX_ex_scanned[ECFS_MB_NUM_CRS];	/* total extents scanned */
	atomic_t s_bal_groups_scanned;	/* number of groups scanned */
	atomic_t s_bal_goals;	/* goal hits */
	atomic_t s_bal_stream_goals;	/* stream allocation global goal hits */
	atomic_t s_bal_len_goals;	/* len goal hits */
	atomic_t s_bal_breaks;	/* too long searches */
	atomic_t s_bal_2orders;	/* 2^order hits */
	atomic64_t s_bal_cX_groups_considered[ECFS_MB_NUM_CRS];
	atomic64_t s_bal_cX_hits[ECFS_MB_NUM_CRS];
	atomic64_t s_bal_cX_failed[ECFS_MB_NUM_CRS];		/* cX loop didn't find blocks */
	atomic_t s_mb_buddies_generated;	/* number of buddies generated */
	atomic64_t s_mb_generation_time;
	atomic_t s_mb_lost_chunks;
	atomic_t s_mb_preallocated;
	atomic_t s_mb_discarded;
	atomic_t s_lock_busy;

	/* locality groups */
	struct ecfs_locality_group __percpu *s_locality_groups;

	/* for write statistics */
	unsigned long s_sectors_written_start;
	u64 s_kbytes_written;

	/* the size of zero-out chunk */
	unsigned int s_extent_max_zeroout_kb;

	unsigned int s_log_groups_per_flex;
	struct flex_groups * __rcu *s_flex_groups;
	ecfs_group_t s_flex_groups_allocated;

	/* workqueue for reserved extent conversions (buffered io) */
	struct workqueue_struct *rsv_conversion_wq;

	/* timer for periodic error stats printing */
	struct timer_list s_err_report;

	/* Lazy inode table initialization info */
	struct ecfs_li_request *s_li_request;
	/* Wait multiplier for lazy initialization thread */
	unsigned int s_li_wait_mult;

	/* Kernel thread for multiple mount protection */
	struct task_struct *s_mmp_tsk;

	/* record the last minlen when FITRIM is called. */
	unsigned long s_last_trim_minblks;

	/* Precomputed FS UUID checksum for seeding other checksums */
	__u32 s_csum_seed;

	/* Reclaim extents from extent status tree */
	struct shrinker *s_es_shrinker;
	struct list_head s_es_list;	/* List of inodes with reclaimable extents */
	long s_es_nr_inode;
	struct ecfs_es_stats s_es_stats;
	struct mb_cache *s_ea_block_cache;
	struct mb_cache *s_ea_inode_cache;
	spinlock_t s_es_lock ____cacheline_aligned_in_smp;

	/* Journal triggers for checksum computation */
	struct ecfs_journal_trigger s_journal_triggers[ECFS_JOURNAL_TRIGGER_COUNT];

	/* Ratelimit ecfs messages. */
	struct ratelimit_state s_err_ratelimit_state;
	struct ratelimit_state s_warning_ratelimit_state;
	struct ratelimit_state s_msg_ratelimit_state;
	atomic_t s_warning_count;
	atomic_t s_msg_count;

	/* Encryption policy for '-o test_dummy_encryption' */
	struct fscrypt_dummy_policy s_dummy_enc_policy;

	/*
	 * Barrier between writepages ops and changing any inode's JOURNAL_DATA
	 * or EXTENTS flag or between writepages ops and changing DELALLOC or
	 * DIOREAD_NOLOCK mount options on remount.
	 */
	struct percpu_rw_semaphore s_writepages_rwsem;
	struct dax_device *s_daxdev;
	u64 s_dax_part_off;
#ifdef CONFIG_ECFS_DEBUG
	unsigned long s_simulate_fail;
#endif
	/* Record the errseq of the backing block device */
	errseq_t s_bdev_wb_err;
	spinlock_t s_bdev_wb_lock;

	/* Information about errors that happened during this mount */
	spinlock_t s_error_lock;
	int s_add_error_count;
	int s_first_error_code;
	__u32 s_first_error_line;
	__u32 s_first_error_ino;
	__u64 s_first_error_block;
	const char *s_first_error_func;
	time64_t s_first_error_time;
	int s_last_error_code;
	__u32 s_last_error_line;
	__u32 s_last_error_ino;
	__u64 s_last_error_block;
	const char *s_last_error_func;
	time64_t s_last_error_time;
	/*
	 * If we are in a context where we cannot update the on-disk
	 * superblock, we queue the work here.  This is used to update
	 * the error information in the superblock, and for periodic
	 * updates of the superblock called from the commit callback
	 * function.
	 */
	struct work_struct s_sb_upd_work;

	/* Atomic write unit values in bytes */
	unsigned int s_awu_min;
	unsigned int s_awu_max;

	/* Ecfs fast commit sub transaction ID */
	atomic_t s_fc_subtid;

	/*
	 * After commit starts, the main queue gets locked, and the further
	 * updates get added in the staging queue.
	 */
#define FC_Q_MAIN	0
#define FC_Q_STAGING	1
	struct list_head s_fc_q[2];	/* Inodes staged for fast commit
					 * that have data changes in them.
					 */
	struct list_head s_fc_dentry_q[2];	/* directory entry updates */
	unsigned int s_fc_bytes;
	/*
	 * Main fast commit lock. This lock protects accesses to the
	 * following fields:
	 * ei->i_fc_list, s_fc_dentry_q, s_fc_q, s_fc_bytes, s_fc_bh.
	 */
	struct mutex s_fc_lock;
	struct buffer_head *s_fc_bh;
	struct ecfs_fc_stats s_fc_stats;
	tid_t s_fc_ineligible_tid;
#ifdef CONFIG_ECFS_DEBUG
	int s_fc_debug_max_replay;
#endif
	struct ecfs_fc_replay_state s_fc_replay_state;
};

static inline struct ecfs_sb_info *ECFS_SB(struct super_block *sb)
{
	return sb->s_fs_info;
}
static inline struct ecfs_inode_info *ECFS_I(struct inode *inode)
{
	return container_of(inode, struct ecfs_inode_info, vfs_inode);
}

static inline int ecfs_writepages_down_read(struct super_block *sb)
{
	percpu_down_read(&ECFS_SB(sb)->s_writepages_rwsem);
	return memalloc_nofs_save();
}

static inline void ecfs_writepages_up_read(struct super_block *sb, int ctx)
{
	memalloc_nofs_restore(ctx);
	percpu_up_read(&ECFS_SB(sb)->s_writepages_rwsem);
}

static inline int ecfs_writepages_down_write(struct super_block *sb)
{
	percpu_down_write(&ECFS_SB(sb)->s_writepages_rwsem);
	return memalloc_nofs_save();
}

static inline void ecfs_writepages_up_write(struct super_block *sb, int ctx)
{
	memalloc_nofs_restore(ctx);
	percpu_up_write(&ECFS_SB(sb)->s_writepages_rwsem);
}

static inline int ecfs_valid_inum(struct super_block *sb, unsigned long ino)
{
	return ino == ECFS_ROOT_INO ||
		(ino >= ECFS_FIRST_INO(sb) &&
		 ino <= le32_to_cpu(ECFS_SB(sb)->s_es->s_inodes_count));
}

/*
 * Returns: sbi->field[index]
 * Used to access an array element from the following sbi fields which require
 * rcu protection to avoid dereferencing an invalid pointer due to reassignment
 * - s_group_desc
 * - s_group_info
 * - s_flex_group
 */
#define sbi_array_rcu_deref(sbi, field, index)				   \
({									   \
	typeof(*((sbi)->field)) _v;					   \
	rcu_read_lock();						   \
	_v = ((typeof(_v)*)rcu_dereference((sbi)->field))[index];	   \
	rcu_read_unlock();						   \
	_v;								   \
})

/*
 * run-time mount flags
 */
enum {
	ECFS_MF_MNTDIR_SAMPLED,
	ECFS_MF_FC_INELIGIBLE,	/* Fast commit ineligible */
	ECFS_MF_JOURNAL_DESTROY	/* Journal is in process of destroying */
};

static inline void ecfs_set_mount_flag(struct super_block *sb, int bit)
{
	set_bit(bit, &ECFS_SB(sb)->s_mount_flags);
}

static inline void ecfs_clear_mount_flag(struct super_block *sb, int bit)
{
	clear_bit(bit, &ECFS_SB(sb)->s_mount_flags);
}

static inline int ecfs_test_mount_flag(struct super_block *sb, int bit)
{
	return test_bit(bit, &ECFS_SB(sb)->s_mount_flags);
}


/*
 * Simulate_fail codes
 */
#define ECFS_SIM_BBITMAP_EIO	1
#define ECFS_SIM_BBITMAP_CRC	2
#define ECFS_SIM_IBITMAP_EIO	3
#define ECFS_SIM_IBITMAP_CRC	4
#define ECFS_SIM_INODE_EIO	5
#define ECFS_SIM_INODE_CRC	6
#define ECFS_SIM_DIRBLOCK_EIO	7
#define ECFS_SIM_DIRBLOCK_CRC	8

static inline bool ecfs_simulate_fail(struct super_block *sb,
				     unsigned long code)
{
#ifdef CONFIG_ECFS_DEBUG
	struct ecfs_sb_info *sbi = ECFS_SB(sb);

	if (unlikely(sbi->s_simulate_fail == code)) {
		sbi->s_simulate_fail = 0;
		return true;
	}
#endif
	return false;
}

/*
 * Error number codes for s_{first,last}_error_errno
 *
 * Linux errno numbers are architecture specific, so we need to translate
 * them into something which is architecture independent.   We don't define
 * codes for all errno's; just the ones which are most likely to be the cause
 * of an ecfs_error() call.
 */
#define ECFS_ERR_UNKNOWN	 1
#define ECFS_ERR_EIO		 2
#define ECFS_ERR_ENOMEM		 3
#define ECFS_ERR_EFSBADCRC	 4
#define ECFS_ERR_EFSCORRUPTED	 5
#define ECFS_ERR_ENOSPC		 6
#define ECFS_ERR_ENOKEY		 7
#define ECFS_ERR_EROFS		 8
#define ECFS_ERR_EFBIG		 9
#define ECFS_ERR_EEXIST		10
#define ECFS_ERR_ERANGE		11
#define ECFS_ERR_EOVERFLOW	12
#define ECFS_ERR_EBUSY		13
#define ECFS_ERR_ENOTDIR	14
#define ECFS_ERR_ENOTEMPTY	15
#define ECFS_ERR_ESHUTDOWN	16
#define ECFS_ERR_EFAULT		17

/*
 * Inode dynamic state flags
 */
enum {
	ECFS_STATE_NEW,			/* inode is newly created */
	ECFS_STATE_XATTR,		/* has in-inode xattrs */
	ECFS_STATE_NO_EXPAND,		/* No space for expansion */
	ECFS_STATE_DA_ALLOC_CLOSE,	/* Alloc DA blks on close */
	ECFS_STATE_EXT_MIGRATE,		/* Inode is migrating */
	ECFS_STATE_NEWENTRY,		/* File just added to dir */
	ECFS_STATE_MAY_INLINE_DATA,	/* may have in-inode data */
	ECFS_STATE_EXT_PRECACHED,	/* extents have been precached */
	ECFS_STATE_LUSTRE_EA_INODE,	/* Lustre-style ea_inode */
	ECFS_STATE_VERITY_IN_PROGRESS,	/* building fs-verity Merkle tree */
	ECFS_STATE_FC_COMMITTING,	/* Fast commit ongoing */
	ECFS_STATE_FC_FLUSHING_DATA,	/* Fast commit flushing data */
	ECFS_STATE_ORPHAN_FILE,		/* Inode orphaned in orphan file */
};

#define ECFS_INODE_BIT_FNS(name, field, offset)				\
static inline int ecfs_test_inode_##name(struct inode *inode, int bit)	\
{									\
	return test_bit(bit + (offset), &ECFS_I(inode)->i_##field);	\
}									\
static inline void ecfs_set_inode_##name(struct inode *inode, int bit)	\
{									\
	set_bit(bit + (offset), &ECFS_I(inode)->i_##field);		\
}									\
static inline void ecfs_clear_inode_##name(struct inode *inode, int bit) \
{									\
	clear_bit(bit + (offset), &ECFS_I(inode)->i_##field);		\
}

/* Add these declarations here only so that these functions can be
 * found by name.  Otherwise, they are very hard to locate. */
static inline int ecfs_test_inode_flag(struct inode *inode, int bit);
static inline void ecfs_set_inode_flag(struct inode *inode, int bit);
static inline void ecfs_clear_inode_flag(struct inode *inode, int bit);
ECFS_INODE_BIT_FNS(flag, flags, 0)

/* Add these declarations here only so that these functions can be
 * found by name.  Otherwise, they are very hard to locate. */
static inline int ecfs_test_inode_state(struct inode *inode, int bit);
static inline void ecfs_set_inode_state(struct inode *inode, int bit);
static inline void ecfs_clear_inode_state(struct inode *inode, int bit);
#if (BITS_PER_LONG < 64)
ECFS_INODE_BIT_FNS(state, state_flags, 0)

static inline void ecfs_clear_state_flags(struct ecfs_inode_info *ei)
{
	(ei)->i_state_flags = 0;
}
#else
ECFS_INODE_BIT_FNS(state, flags, 32)

static inline void ecfs_clear_state_flags(struct ecfs_inode_info *ei)
{
	/* We depend on the fact that callers will set i_flags */
}
#endif
#else
/* Assume that user mode programs are passing in an ecfsfs superblock, not
 * a kernel struct super_block.  This will allow us to call the feature-test
 * macros from user land. */
#define ECFS_SB(sb)	(sb)
#endif

static inline bool ecfs_verity_in_progress(struct inode *inode)
{
	return IS_ENABLED(CONFIG_FS_VERITY) &&
	       ecfs_test_inode_state(inode, ECFS_STATE_VERITY_IN_PROGRESS);
}

#define NEXT_ORPHAN(inode) ECFS_I(inode)->i_dtime

/*
 * Codes for operating systems
 */
#define ECFS_OS_LINUX		0
#define ECFS_OS_HURD		1
#define ECFS_OS_MASIX		2
#define ECFS_OS_FREEBSD		3
#define ECFS_OS_LITES		4

/*
 * Revision levels
 */
#define ECFS_GOOD_OLD_REV	0	/* The good old (original) format */
#define ECFS_DYNAMIC_REV	1	/* V2 format w/ dynamic inode sizes */

#define ECFS_MAX_SUPP_REV	ECFS_DYNAMIC_REV

#define ECFS_GOOD_OLD_INODE_SIZE 128

#define ECFS_EXTRA_TIMESTAMP_MAX	(((s64)1 << 34) - 1  + S32_MIN)
#define ECFS_NON_EXTRA_TIMESTAMP_MAX	S32_MAX
#define ECFS_TIMESTAMP_MIN		S32_MIN

/*
 * Feature set definitions
 */

#define ECFS_FEATURE_COMPAT_DIR_PREALLOC	0x0001
#define ECFS_FEATURE_COMPAT_IMAGIC_INODES	0x0002
#define ECFS_FEATURE_COMPAT_HAS_JOURNAL		0x0004
#define ECFS_FEATURE_COMPAT_EXT_ATTR		0x0008
#define ECFS_FEATURE_COMPAT_RESIZE_INODE	0x0010
#define ECFS_FEATURE_COMPAT_DIR_INDEX		0x0020
#define ECFS_FEATURE_COMPAT_SPARSE_SUPER2	0x0200
/*
 * The reason why "FAST_COMMIT" is a compat feature is that, FS becomes
 * incompatible only if fast commit blocks are present in the FS. Since we
 * clear the journal (and thus the fast commit blocks), we don't mark FS as
 * incompatible. We also have a JBD2 incompat feature, which gets set when
 * there are fast commit blocks present in the journal.
 */
#define ECFS_FEATURE_COMPAT_FAST_COMMIT		0x0400
#define ECFS_FEATURE_COMPAT_STABLE_INODES	0x0800
#define ECFS_FEATURE_COMPAT_ORPHAN_FILE		0x1000	/* Orphan file exists */

#define ECFS_FEATURE_RO_COMPAT_SPARSE_SUPER	0x0001
#define ECFS_FEATURE_RO_COMPAT_LARGE_FILE	0x0002
#define ECFS_FEATURE_RO_COMPAT_BTREE_DIR	0x0004
#define ECFS_FEATURE_RO_COMPAT_HUGE_FILE        0x0008
#define ECFS_FEATURE_RO_COMPAT_GDT_CSUM		0x0010
#define ECFS_FEATURE_RO_COMPAT_DIR_NLINK	0x0020
#define ECFS_FEATURE_RO_COMPAT_EXTRA_ISIZE	0x0040
#define ECFS_FEATURE_RO_COMPAT_QUOTA		0x0100
#define ECFS_FEATURE_RO_COMPAT_BIGALLOC		0x0200
/*
 * METADATA_CSUM also enables group descriptor checksums (GDT_CSUM).  When
 * METADATA_CSUM is set, group descriptor checksums use the same algorithm as
 * all other data structures' checksums.  However, the METADATA_CSUM and
 * GDT_CSUM bits are mutually exclusive.
 */
#define ECFS_FEATURE_RO_COMPAT_METADATA_CSUM	0x0400
#define ECFS_FEATURE_RO_COMPAT_READONLY		0x1000
#define ECFS_FEATURE_RO_COMPAT_PROJECT		0x2000
#define ECFS_FEATURE_RO_COMPAT_VERITY		0x8000
#define ECFS_FEATURE_RO_COMPAT_ORPHAN_PRESENT	0x10000 /* Orphan file may be
							   non-empty */

#define ECFS_FEATURE_INCOMPAT_COMPRESSION	0x0001
#define ECFS_FEATURE_INCOMPAT_FILETYPE		0x0002
#define ECFS_FEATURE_INCOMPAT_RECOVER		0x0004 /* Needs recovery */
#define ECFS_FEATURE_INCOMPAT_JOURNAL_DEV	0x0008 /* Journal device */
#define ECFS_FEATURE_INCOMPAT_META_BG		0x0010
#define ECFS_FEATURE_INCOMPAT_EXTENTS		0x0040 /* extents support */
#define ECFS_FEATURE_INCOMPAT_64BIT		0x0080
#define ECFS_FEATURE_INCOMPAT_MMP               0x0100
#define ECFS_FEATURE_INCOMPAT_FLEX_BG		0x0200
#define ECFS_FEATURE_INCOMPAT_EA_INODE		0x0400 /* EA in inode */
#define ECFS_FEATURE_INCOMPAT_DIRDATA		0x1000 /* data in dirent */
#define ECFS_FEATURE_INCOMPAT_CSUM_SEED		0x2000
#define ECFS_FEATURE_INCOMPAT_LARGEDIR		0x4000 /* >2GB or 3-lvl htree */
#define ECFS_FEATURE_INCOMPAT_INLINE_DATA	0x8000 /* data in inode */
#define ECFS_FEATURE_INCOMPAT_ENCRYPT		0x10000
#define ECFS_FEATURE_INCOMPAT_CASEFOLD		0x20000

extern void ecfs_update_dynamic_rev(struct super_block *sb);

#define ECFS_FEATURE_COMPAT_FUNCS(name, flagname) \
static inline bool ecfs_has_feature_##name(struct super_block *sb) \
{ \
	return ((ECFS_SB(sb)->s_es->s_feature_compat & \
		cpu_to_le32(ECFS_FEATURE_COMPAT_##flagname)) != 0); \
} \
static inline void ecfs_set_feature_##name(struct super_block *sb) \
{ \
	ecfs_update_dynamic_rev(sb); \
	ECFS_SB(sb)->s_es->s_feature_compat |= \
		cpu_to_le32(ECFS_FEATURE_COMPAT_##flagname); \
} \
static inline void ecfs_clear_feature_##name(struct super_block *sb) \
{ \
	ECFS_SB(sb)->s_es->s_feature_compat &= \
		~cpu_to_le32(ECFS_FEATURE_COMPAT_##flagname); \
}

#define ECFS_FEATURE_RO_COMPAT_FUNCS(name, flagname) \
static inline bool ecfs_has_feature_##name(struct super_block *sb) \
{ \
	return ((ECFS_SB(sb)->s_es->s_feature_ro_compat & \
		cpu_to_le32(ECFS_FEATURE_RO_COMPAT_##flagname)) != 0); \
} \
static inline void ecfs_set_feature_##name(struct super_block *sb) \
{ \
	ecfs_update_dynamic_rev(sb); \
	ECFS_SB(sb)->s_es->s_feature_ro_compat |= \
		cpu_to_le32(ECFS_FEATURE_RO_COMPAT_##flagname); \
} \
static inline void ecfs_clear_feature_##name(struct super_block *sb) \
{ \
	ECFS_SB(sb)->s_es->s_feature_ro_compat &= \
		~cpu_to_le32(ECFS_FEATURE_RO_COMPAT_##flagname); \
}

#define ECFS_FEATURE_INCOMPAT_FUNCS(name, flagname) \
static inline bool ecfs_has_feature_##name(struct super_block *sb) \
{ \
	return ((ECFS_SB(sb)->s_es->s_feature_incompat & \
		cpu_to_le32(ECFS_FEATURE_INCOMPAT_##flagname)) != 0); \
} \
static inline void ecfs_set_feature_##name(struct super_block *sb) \
{ \
	ecfs_update_dynamic_rev(sb); \
	ECFS_SB(sb)->s_es->s_feature_incompat |= \
		cpu_to_le32(ECFS_FEATURE_INCOMPAT_##flagname); \
} \
static inline void ecfs_clear_feature_##name(struct super_block *sb) \
{ \
	ECFS_SB(sb)->s_es->s_feature_incompat &= \
		~cpu_to_le32(ECFS_FEATURE_INCOMPAT_##flagname); \
}

ECFS_FEATURE_COMPAT_FUNCS(dir_prealloc,		DIR_PREALLOC)
ECFS_FEATURE_COMPAT_FUNCS(imagic_inodes,	IMAGIC_INODES)
ECFS_FEATURE_COMPAT_FUNCS(journal,		HAS_JOURNAL)
ECFS_FEATURE_COMPAT_FUNCS(xattr,		EXT_ATTR)
ECFS_FEATURE_COMPAT_FUNCS(resize_inode,		RESIZE_INODE)
ECFS_FEATURE_COMPAT_FUNCS(dir_index,		DIR_INDEX)
ECFS_FEATURE_COMPAT_FUNCS(sparse_super2,	SPARSE_SUPER2)
ECFS_FEATURE_COMPAT_FUNCS(fast_commit,		FAST_COMMIT)
ECFS_FEATURE_COMPAT_FUNCS(stable_inodes,	STABLE_INODES)
ECFS_FEATURE_COMPAT_FUNCS(orphan_file,		ORPHAN_FILE)

ECFS_FEATURE_RO_COMPAT_FUNCS(sparse_super,	SPARSE_SUPER)
ECFS_FEATURE_RO_COMPAT_FUNCS(large_file,	LARGE_FILE)
ECFS_FEATURE_RO_COMPAT_FUNCS(btree_dir,		BTREE_DIR)
ECFS_FEATURE_RO_COMPAT_FUNCS(huge_file,		HUGE_FILE)
ECFS_FEATURE_RO_COMPAT_FUNCS(gdt_csum,		GDT_CSUM)
ECFS_FEATURE_RO_COMPAT_FUNCS(dir_nlink,		DIR_NLINK)
ECFS_FEATURE_RO_COMPAT_FUNCS(extra_isize,	EXTRA_ISIZE)
ECFS_FEATURE_RO_COMPAT_FUNCS(quota,		QUOTA)
ECFS_FEATURE_RO_COMPAT_FUNCS(bigalloc,		BIGALLOC)
ECFS_FEATURE_RO_COMPAT_FUNCS(metadata_csum,	METADATA_CSUM)
ECFS_FEATURE_RO_COMPAT_FUNCS(readonly,		READONLY)
ECFS_FEATURE_RO_COMPAT_FUNCS(project,		PROJECT)
ECFS_FEATURE_RO_COMPAT_FUNCS(verity,		VERITY)
ECFS_FEATURE_RO_COMPAT_FUNCS(orphan_present,	ORPHAN_PRESENT)

ECFS_FEATURE_INCOMPAT_FUNCS(compression,	COMPRESSION)
ECFS_FEATURE_INCOMPAT_FUNCS(filetype,		FILETYPE)
ECFS_FEATURE_INCOMPAT_FUNCS(journal_needs_recovery,	RECOVER)
ECFS_FEATURE_INCOMPAT_FUNCS(journal_dev,	JOURNAL_DEV)
ECFS_FEATURE_INCOMPAT_FUNCS(meta_bg,		META_BG)
ECFS_FEATURE_INCOMPAT_FUNCS(extents,		EXTENTS)
ECFS_FEATURE_INCOMPAT_FUNCS(64bit,		64BIT)
ECFS_FEATURE_INCOMPAT_FUNCS(mmp,		MMP)
ECFS_FEATURE_INCOMPAT_FUNCS(flex_bg,		FLEX_BG)
ECFS_FEATURE_INCOMPAT_FUNCS(ea_inode,		EA_INODE)
ECFS_FEATURE_INCOMPAT_FUNCS(dirdata,		DIRDATA)
ECFS_FEATURE_INCOMPAT_FUNCS(csum_seed,		CSUM_SEED)
ECFS_FEATURE_INCOMPAT_FUNCS(largedir,		LARGEDIR)
ECFS_FEATURE_INCOMPAT_FUNCS(inline_data,	INLINE_DATA)
ECFS_FEATURE_INCOMPAT_FUNCS(encrypt,		ENCRYPT)
ECFS_FEATURE_INCOMPAT_FUNCS(casefold,		CASEFOLD)

#define EXT2_FEATURE_COMPAT_SUPP	ECFS_FEATURE_COMPAT_EXT_ATTR
#define EXT2_FEATURE_INCOMPAT_SUPP	(ECFS_FEATURE_INCOMPAT_FILETYPE| \
					 ECFS_FEATURE_INCOMPAT_META_BG)
#define EXT2_FEATURE_RO_COMPAT_SUPP	(ECFS_FEATURE_RO_COMPAT_SPARSE_SUPER| \
					 ECFS_FEATURE_RO_COMPAT_LARGE_FILE| \
					 ECFS_FEATURE_RO_COMPAT_BTREE_DIR)

#define EXT3_FEATURE_COMPAT_SUPP	ECFS_FEATURE_COMPAT_EXT_ATTR
#define EXT3_FEATURE_INCOMPAT_SUPP	(ECFS_FEATURE_INCOMPAT_FILETYPE| \
					 ECFS_FEATURE_INCOMPAT_RECOVER| \
					 ECFS_FEATURE_INCOMPAT_META_BG)
#define EXT3_FEATURE_RO_COMPAT_SUPP	(ECFS_FEATURE_RO_COMPAT_SPARSE_SUPER| \
					 ECFS_FEATURE_RO_COMPAT_LARGE_FILE| \
					 ECFS_FEATURE_RO_COMPAT_BTREE_DIR)

#define ECFS_FEATURE_COMPAT_SUPP	(ECFS_FEATURE_COMPAT_EXT_ATTR| \
					 ECFS_FEATURE_COMPAT_ORPHAN_FILE)
#define ECFS_FEATURE_INCOMPAT_SUPP	(ECFS_FEATURE_INCOMPAT_FILETYPE| \
					 ECFS_FEATURE_INCOMPAT_RECOVER| \
					 ECFS_FEATURE_INCOMPAT_META_BG| \
					 ECFS_FEATURE_INCOMPAT_EXTENTS| \
					 ECFS_FEATURE_INCOMPAT_64BIT| \
					 ECFS_FEATURE_INCOMPAT_FLEX_BG| \
					 ECFS_FEATURE_INCOMPAT_EA_INODE| \
					 ECFS_FEATURE_INCOMPAT_MMP | \
					 ECFS_FEATURE_INCOMPAT_INLINE_DATA | \
					 ECFS_FEATURE_INCOMPAT_ENCRYPT | \
					 ECFS_FEATURE_INCOMPAT_CASEFOLD | \
					 ECFS_FEATURE_INCOMPAT_CSUM_SEED | \
					 ECFS_FEATURE_INCOMPAT_LARGEDIR)
#define ECFS_FEATURE_RO_COMPAT_SUPP	(ECFS_FEATURE_RO_COMPAT_SPARSE_SUPER| \
					 ECFS_FEATURE_RO_COMPAT_LARGE_FILE| \
					 ECFS_FEATURE_RO_COMPAT_GDT_CSUM| \
					 ECFS_FEATURE_RO_COMPAT_DIR_NLINK | \
					 ECFS_FEATURE_RO_COMPAT_EXTRA_ISIZE | \
					 ECFS_FEATURE_RO_COMPAT_BTREE_DIR |\
					 ECFS_FEATURE_RO_COMPAT_HUGE_FILE |\
					 ECFS_FEATURE_RO_COMPAT_BIGALLOC |\
					 ECFS_FEATURE_RO_COMPAT_METADATA_CSUM|\
					 ECFS_FEATURE_RO_COMPAT_QUOTA |\
					 ECFS_FEATURE_RO_COMPAT_PROJECT |\
					 ECFS_FEATURE_RO_COMPAT_VERITY |\
					 ECFS_FEATURE_RO_COMPAT_ORPHAN_PRESENT)

//#define EXTN_FEATURE_FUNCS(ver) 
static inline bool ecfs_has_unknown_ecfs_compat_features(struct super_block *sb) \
{ \
	return ((ECFS_SB(sb)->s_es->s_feature_compat & \
		cpu_to_le32(~ECFS_FEATURE_COMPAT_SUPP)) != 0); \
} \
static inline bool ecfs_has_unknown_ecfs_ro_compat_features(struct super_block *sb) \
{ \
	return ((ECFS_SB(sb)->s_es->s_feature_ro_compat & \
		cpu_to_le32(~ECFS_FEATURE_RO_COMPAT_SUPP)) != 0); \
} \
static inline bool ecfs_has_unknown_ecfs_incompat_features(struct super_block *sb) \
{ \
	return ((ECFS_SB(sb)->s_es->s_feature_incompat & \
		cpu_to_le32(~ECFS_FEATURE_INCOMPAT_SUPP)) != 0); \
}

// EXTN_FEATURE_FUNCS(2)
// EXTN_FEATURE_FUNCS(3)
// EXTN_FEATURE_FUNCS(4)

static inline bool ecfs_has_compat_features(struct super_block *sb)
{
	return (ECFS_SB(sb)->s_es->s_feature_compat != 0);
}
static inline bool ecfs_has_ro_compat_features(struct super_block *sb)
{
	return (ECFS_SB(sb)->s_es->s_feature_ro_compat != 0);
}
static inline bool ecfs_has_incompat_features(struct super_block *sb)
{
	return (ECFS_SB(sb)->s_es->s_feature_incompat != 0);
}

extern int ecfs_feature_set_ok(struct super_block *sb, int readonly);

/*
 * Superblock flags
 */
enum {
	ECFS_FLAGS_RESIZING,	/* Avoid superblock update and resize race */
	ECFS_FLAGS_SHUTDOWN,	/* Prevent access to the file system */
	ECFS_FLAGS_BDEV_IS_DAX,	/* Current block device support DAX */
	ECFS_FLAGS_EMERGENCY_RO,/* Emergency read-only due to fs errors */
};

static inline int ecfs_forced_shutdown(struct super_block *sb)
{
	return test_bit(ECFS_FLAGS_SHUTDOWN, &ECFS_SB(sb)->s_ecfs_flags);
}

static inline int ecfs_emergency_ro(struct super_block *sb)
{
	return test_bit(ECFS_FLAGS_EMERGENCY_RO, &ECFS_SB(sb)->s_ecfs_flags);
}

static inline int ecfs_emergency_state(struct super_block *sb)
{
	if (unlikely(ecfs_forced_shutdown(sb)))
		return -EIO;
	if (unlikely(ecfs_emergency_ro(sb)))
		return -EROFS;
	return 0;
}

/*
 * Default values for user and/or group using reserved blocks
 */
#define	ECFS_DEF_RESUID		0
#define	ECFS_DEF_RESGID		0

/*
 * Default project ID
 */
#define	ECFS_DEF_PROJID		0

#define ECFS_DEF_INODE_READAHEAD_BLKS	32

/*
 * Default mount options
 */
#define ECFS_DEFM_DEBUG		0x0001
#define ECFS_DEFM_BSDGROUPS	0x0002
#define ECFS_DEFM_XATTR_USER	0x0004
#define ECFS_DEFM_ACL		0x0008
#define ECFS_DEFM_UID16		0x0010
#define ECFS_DEFM_JMODE		0x0060
#define ECFS_DEFM_JMODE_DATA	0x0020
#define ECFS_DEFM_JMODE_ORDERED	0x0040
#define ECFS_DEFM_JMODE_WBACK	0x0060
#define ECFS_DEFM_NOBARRIER	0x0100
#define ECFS_DEFM_BLOCK_VALIDITY 0x0200
#define ECFS_DEFM_DISCARD	0x0400
#define ECFS_DEFM_NODELALLOC	0x0800

/*
 * Default journal batch times and ioprio.
 */
#define ECFS_DEF_MIN_BATCH_TIME	0
#define ECFS_DEF_MAX_BATCH_TIME	15000 /* 15ms */
#define ECFS_DEF_JOURNAL_IOPRIO (IOPRIO_PRIO_VALUE(IOPRIO_CLASS_BE, 3))


/*
 * Default values for superblock update
 */
#define ECFS_DEF_SB_UPDATE_INTERVAL_SEC (3600) /* seconds (1 hour) */
#define ECFS_DEF_SB_UPDATE_INTERVAL_KB (16384) /* kilobytes (16MB) */


/*
 * Minimum number of groups in a flexgroup before we separate out
 * directories into the first block group of a flexgroup
 */
#define ECFS_FLEX_SIZE_DIR_ALLOC_SCHEME	4

/*
 * Structure of a directory entry
 */
#define ECFS_NAME_LEN 255
/*
 * Base length of the ecfs directory entry excluding the name length
 */
#define ECFS_BASE_DIR_LEN (sizeof(struct ecfs_dir_entry_2) - ECFS_NAME_LEN)

struct ecfs_dir_entry {
	__le64	inode;			/* Inode number */
	__le16	rec_len;		/* Directory entry length */
	__le16	name_len;		/* Name length */
	char	name[ECFS_NAME_LEN];	/* File name */
};


/*
 * Encrypted Casefolded entries require saving the hash on disk. This structure
 * followed ecfs_dir_entry_2's name[name_len] at the next 4 byte aligned
 * boundary.
 */
struct ecfs_dir_entry_hash {
	__le32 hash;
	__le32 minor_hash;
};

/*
 * The new version of the directory entry.  Since ECFS structures are
 * stored in intel byte order, and the name_len field could never be
 * bigger than 255 chars, it's safe to reclaim the extra byte for the
 * file_type field.
 */
struct ecfs_dir_entry_2 {
	__le64	inode;			/* Inode number */
	__le16	rec_len;		/* Directory entry length */
	__u8	name_len;		/* Name length */
	__u8	file_type;		/* See file type macros ECFS_FT_* below */
	char	name[ECFS_NAME_LEN];	/* File name */
};

/*
 * Access the hashes at the end of ecfs_dir_entry_2
 */
#define ECFS_DIRENT_HASHES(entry) \
	((struct ecfs_dir_entry_hash *) \
		(((void *)(entry)) + \
		((8 + (entry)->name_len + ECFS_DIR_ROUND) & ~ECFS_DIR_ROUND)))
#define ECFS_DIRENT_HASH(entry) le32_to_cpu(ECFS_DIRENT_HASHES(entry)->hash)
#define ECFS_DIRENT_MINOR_HASH(entry) \
		le32_to_cpu(ECFS_DIRENT_HASHES(entry)->minor_hash)

static inline bool ecfs_hash_in_dirent(const struct inode *inode)
{
	return IS_CASEFOLDED(inode) && IS_ENCRYPTED(inode);
}

/*
 * This is a bogus directory entry at the end of each leaf block that
 * records checksums.
 */
struct ecfs_dir_entry_tail {
	__le32	det_reserved_zero1;	/* Pretend to be unused */
	__le16	det_rec_len;		/* 12 */
	__u8	det_reserved_zero2;	/* Zero name length */
	__u8	det_reserved_ft;	/* 0xDE, fake file type */
	__le32	det_checksum;		/* crc32c(uuid+inum+dirblock) */
};

#define ECFS_DIRENT_TAIL(block, blocksize) \
	((struct ecfs_dir_entry_tail *)(((void *)(block)) + \
					((blocksize) - \
					 sizeof(struct ecfs_dir_entry_tail))))

/*
 * Ecfs directory file types.  Only the low 3 bits are used.  The
 * other bits are reserved for now.
 */
#define ECFS_FT_UNKNOWN		0
#define ECFS_FT_REG_FILE	1
#define ECFS_FT_DIR		2
#define ECFS_FT_CHRDEV		3
#define ECFS_FT_BLKDEV		4
#define ECFS_FT_FIFO		5
#define ECFS_FT_SOCK		6
#define ECFS_FT_SYMLINK		7

#define ECFS_FT_MAX		8

#define ECFS_FT_DIR_CSUM	0xDE

/*
 * ECFS_DIR_PAD defines the directory entries boundaries
 *
 * NOTE: It must be a multiple of 4
 */
#define ECFS_DIR_PAD			4
#define ECFS_DIR_ROUND			(ECFS_DIR_PAD - 1)
#define ECFS_MAX_REC_LEN		((1<<16)-1)

/*
 * The rec_len is dependent on the type of directory. Directories that are
 * casefolded and encrypted need to store the hash as well, so we add room for
 * ecfs_extended_dir_entry_2. For all entries related to '.' or '..' you should
 * pass NULL for dir, as those entries do not use the extra fields.
 */
static inline unsigned int ecfs_dir_rec_len(__u8 name_len,
						const struct inode *dir)
{
	int rec_len = (name_len + 8 + ECFS_DIR_ROUND);

	if (dir && ecfs_hash_in_dirent(dir))
		rec_len += sizeof(struct ecfs_dir_entry_hash);
	return (rec_len & ~ECFS_DIR_ROUND);
}

/*
 * If we ever get support for fs block sizes > page_size, we'll need
 * to remove the #if statements in the next two functions...
 */
static inline unsigned int
ecfs_rec_len_from_disk(__le16 dlen, unsigned blocksize)
{
	unsigned len = le16_to_cpu(dlen);

#if (PAGE_SIZE >= 65536)
	if (len == ECFS_MAX_REC_LEN || len == 0)
		return blocksize;
	return (len & 65532) | ((len & 3) << 16);
#else
	return len;
#endif
}

static inline __le16 ecfs_rec_len_to_disk(unsigned len, unsigned blocksize)
{
	BUG_ON((len > blocksize) || (blocksize > (1 << 18)) || (len & 3));
#if (PAGE_SIZE >= 65536)
	if (len < 65536)
		return cpu_to_le16(len);
	if (len == blocksize) {
		if (blocksize == 65536)
			return cpu_to_le16(ECFS_MAX_REC_LEN);
		else
			return cpu_to_le16(0);
	}
	return cpu_to_le16((len & 65532) | ((len >> 16) & 3));
#else
	return cpu_to_le16(len);
#endif
}

/*
 * Hash Tree Directory indexing
 * (c) Daniel Phillips, 2001
 */

#define is_dx(dir) (ecfs_has_feature_dir_index((dir)->i_sb) && \
		    ecfs_test_inode_flag((dir), ECFS_INODE_INDEX))
#define ECFS_DIR_LINK_MAX(dir) unlikely((dir)->i_nlink >= ECFS_LINK_MAX && \
		    !(ecfs_has_feature_dir_nlink((dir)->i_sb) && is_dx(dir)))
#define ECFS_DIR_LINK_EMPTY(dir) ((dir)->i_nlink == 2 || (dir)->i_nlink == 1)

/* Legal values for the dx_root hash_version field: */

#define DX_HASH_LEGACY			0
#define DX_HASH_HALF_MD4		1
#define DX_HASH_TEA			2
#define DX_HASH_LEGACY_UNSIGNED		3
#define DX_HASH_HALF_MD4_UNSIGNED	4
#define DX_HASH_TEA_UNSIGNED		5
#define DX_HASH_SIPHASH			6
#define DX_HASH_LAST 			DX_HASH_SIPHASH

static inline u32 ecfs_chksum(u32 crc, const void *address, unsigned int length)
{
	return crc32c(crc, address, length);
}

#ifdef __KERNEL__

/* hash info structure used by the directory hash */
struct dx_hash_info
{
	u32		hash;
	u32		minor_hash;
	int		hash_version;
	u32		*seed;
};


/* 32 and 64 bit signed EOF for dx directories */
#define ECFS_HTREE_EOF_32BIT   ((1UL  << (32 - 1)) - 1)
#define ECFS_HTREE_EOF_64BIT   ((1ULL << (64 - 1)) - 1)


/*
 * Control parameters used by ecfs_htree_next_block
 */
#define HASH_NB_ALWAYS		1

struct ecfs_filename {
	const struct qstr *usr_fname;
	struct fscrypt_str disk_name;
	struct dx_hash_info hinfo;
#ifdef CONFIG_FS_ENCRYPTION
	struct fscrypt_str crypto_buf;
#endif
#if IS_ENABLED(CONFIG_UNICODE)
	struct qstr cf_name;
#endif
};

#define fname_name(p) ((p)->disk_name.name)
#define fname_usr_name(p) ((p)->usr_fname->name)
#define fname_len(p)  ((p)->disk_name.len)

/*
 * Describe an inode's exact location on disk and in memory
 */
struct ecfs_iloc
{
	struct buffer_head *bh;
	unsigned long offset;
	ecfs_group_t block_group;
};

static inline struct ecfs_inode *ecfs_raw_inode(struct ecfs_iloc *iloc)
{
	return (struct ecfs_inode *) (iloc->bh->b_data + iloc->offset);
}

static inline bool ecfs_is_quota_file(struct inode *inode)
{
	return IS_NOQUOTA(inode) &&
	       !(ECFS_I(inode)->i_flags & ECFS_EA_INODE_FL);
}

/*
 * This structure is stuffed into the struct file's private_data field
 * for directories.  It is where we put information so that we can do
 * readdir operations in hash tree order.
 */
struct dir_private_info {
	struct rb_root	root;
	struct rb_node	*curr_node;
	struct fname	*extra_fname;
	loff_t		last_pos;
	__u32		curr_hash;
	__u32		curr_minor_hash;
	__u32		next_hash;
	u64		cookie;
	bool		initialized;
};

/* calculate the first block number of the group */
static inline ecfs_fsblk_t
ecfs_group_first_block_no(struct super_block *sb, ecfs_group_t group_no)
{
	return group_no * (ecfs_fsblk_t)ECFS_BLOCKS_PER_GROUP(sb) +
		le32_to_cpu(ECFS_SB(sb)->s_es->s_first_data_block);
}

/*
 * Special error return code only used by dx_probe() and its callers.
 */
#define ERR_BAD_DX_DIR	(-(MAX_ERRNO - 1))

/* htree levels for ecfs */
#define	ECFS_HTREE_LEVEL_COMPAT	2
#define	ECFS_HTREE_LEVEL	3

static inline int ecfs_dir_htree_level(struct super_block *sb)
{
	return ecfs_has_feature_largedir(sb) ?
		ECFS_HTREE_LEVEL : ECFS_HTREE_LEVEL_COMPAT;
}

/*
 * Timeout and state flag for lazy initialization inode thread.
 */
#define ECFS_DEF_LI_WAIT_MULT			10
#define ECFS_DEF_LI_MAX_START_DELAY		5
#define ECFS_LAZYINIT_QUIT			0x0001
#define ECFS_LAZYINIT_RUNNING			0x0002

/*
 * Lazy inode table initialization info
 */
struct ecfs_lazy_init {
	unsigned long		li_state;
	struct list_head	li_request_list;
	struct mutex		li_list_mtx;
};

enum ecfs_li_mode {
	ECFS_LI_MODE_PREFETCH_BBITMAP,
	ECFS_LI_MODE_ITABLE,
};

struct ecfs_li_request {
	struct super_block	*lr_super;
	enum ecfs_li_mode	lr_mode;
	ecfs_group_t		lr_first_not_zeroed;
	ecfs_group_t		lr_next_group;
	struct list_head	lr_request;
	unsigned long		lr_next_sched;
	unsigned long		lr_timeout;
};

struct ecfs_features {
	struct kobject f_kobj;
	struct completion f_kobj_unregister;
};

/*
 * This structure will be used for multiple mount protection. It will be
 * written into the block number saved in the s_mmp_block field in the
 * superblock. Programs that check MMP should assume that if
 * SEQ_FSCK (or any unknown code above SEQ_MAX) is present then it is NOT safe
 * to use the filesystem, regardless of how old the timestamp is.
 */
#define ECFS_MMP_MAGIC     0x004D4D50U /* ASCII for MMP */
#define ECFS_MMP_SEQ_CLEAN 0xFF4D4D50U /* mmp_seq value for clean unmount */
#define ECFS_MMP_SEQ_FSCK  0xE24D4D50U /* mmp_seq value when being fscked */
#define ECFS_MMP_SEQ_MAX   0xE24D4D4FU /* maximum valid mmp_seq value */

struct mmp_struct {
	__le32	mmp_magic;		/* Magic number for MMP */
	__le32	mmp_seq;		/* Sequence no. updated periodically */

	/*
	 * mmp_time, mmp_nodename & mmp_bdevname are only used for information
	 * purposes and do not affect the correctness of the algorithm
	 */
	__le64	mmp_time;		/* Time last updated */
	char	mmp_nodename[64];	/* Node which last updated MMP block */
	char	mmp_bdevname[32];	/* Bdev which last updated MMP block */

	/*
	 * mmp_check_interval is used to verify if the MMP block has been
	 * updated on the block device. The value is updated based on the
	 * maximum time to write the MMP block during an update cycle.
	 */
	__le16	mmp_check_interval;

	__le16	mmp_pad1;
	__le32	mmp_pad2[226];
	__le32	mmp_checksum;		/* crc32c(uuid+mmp_block) */
};

/* arguments passed to the mmp thread */
struct mmpd_data {
	struct buffer_head *bh; /* bh from initial read_mmp_block() */
	struct super_block *sb;  /* super block of the fs */
};

/*
 * Check interval multiplier
 * The MMP block is written every update interval and initially checked every
 * update interval x the multiplier (the value is then adapted based on the
 * write latency). The reason is that writes can be delayed under load and we
 * don't want readers to incorrectly assume that the filesystem is no longer
 * in use.
 */
#define ECFS_MMP_CHECK_MULT		2UL

/*
 * Minimum interval for MMP checking in seconds.
 */
#define ECFS_MMP_MIN_CHECK_INTERVAL	5UL

/*
 * Maximum interval for MMP checking in seconds.
 */
#define ECFS_MMP_MAX_CHECK_INTERVAL	300UL

/*
 * Function prototypes
 */

/*
 * Ok, these declarations are also in <linux/kernel.h> but none of the
 * ecfs source programs needs to include it so they are duplicated here.
 */
# define NORET_TYPE	/**/
# define ATTRIB_NORET	__attribute__((noreturn))
# define NORET_AND	noreturn,

/* bitmap.c */
extern unsigned int ecfs_count_free(char *bitmap, unsigned numchars);
void ecfs_inode_bitmap_csum_set(struct super_block *sb,
				struct ecfs_group_desc *gdp,
				struct buffer_head *bh);
int ecfs_inode_bitmap_csum_verify(struct super_block *sb,
				  struct ecfs_group_desc *gdp,
				  struct buffer_head *bh);
void ecfs_block_bitmap_csum_set(struct super_block *sb,
				struct ecfs_group_desc *gdp,
				struct buffer_head *bh);
int ecfs_block_bitmap_csum_verify(struct super_block *sb,
				  struct ecfs_group_desc *gdp,
				  struct buffer_head *bh);

/* balloc.c */
extern void ecfs_get_group_no_and_offset(struct super_block *sb,
					 ecfs_fsblk_t blocknr,
					 ecfs_group_t *blockgrpp,
					 ecfs_grpblk_t *offsetp);
extern ecfs_group_t ecfs_get_group_number(struct super_block *sb,
					  ecfs_fsblk_t block);

extern int ecfs_bg_has_super(struct super_block *sb, ecfs_group_t group);
extern unsigned long ecfs_bg_num_gdb(struct super_block *sb,
			ecfs_group_t group);
extern ecfs_fsblk_t ecfs_new_meta_blocks(handle_t *handle, struct inode *inode,
					 ecfs_fsblk_t goal,
					 unsigned int flags,
					 unsigned long *count,
					 int *errp);
extern int ecfs_claim_free_clusters(struct ecfs_sb_info *sbi,
				    s64 nclusters, unsigned int flags);
extern ecfs_fsblk_t ecfs_count_free_clusters(struct super_block *);
extern struct ecfs_group_desc * ecfs_get_group_desc(struct super_block * sb,
						    ecfs_group_t block_group,
						    struct buffer_head ** bh);
extern struct ecfs_group_info *ecfs_get_group_info(struct super_block *sb,
						   ecfs_group_t group);
extern int ecfs_should_retry_alloc(struct super_block *sb, int *retries);

extern struct buffer_head *ecfs_read_block_bitmap_nowait(struct super_block *sb,
						ecfs_group_t block_group,
						bool ignore_locked);
extern int ecfs_wait_block_bitmap(struct super_block *sb,
				  ecfs_group_t block_group,
				  struct buffer_head *bh);
extern struct buffer_head *ecfs_read_block_bitmap(struct super_block *sb,
						  ecfs_group_t block_group);
extern unsigned ecfs_free_clusters_after_init(struct super_block *sb,
					      ecfs_group_t block_group,
					      struct ecfs_group_desc *gdp);
ecfs_fsblk_t ecfs_inode_to_goal_block(struct inode *);

#if IS_ENABLED(CONFIG_UNICODE)
extern int ecfs_fname_setup_ci_filename(struct inode *dir,
					const struct qstr *iname,
					struct ecfs_filename *fname);

static inline void ecfs_fname_free_ci_filename(struct ecfs_filename *fname)
{
	kfree(fname->cf_name.name);
	fname->cf_name.name = NULL;
}
#else
static inline int ecfs_fname_setup_ci_filename(struct inode *dir,
					       const struct qstr *iname,
					       struct ecfs_filename *fname)
{
	return 0;
}

static inline void ecfs_fname_free_ci_filename(struct ecfs_filename *fname)
{
}
#endif

/* ecfs encryption related stuff goes here crypto.c */
#ifdef CONFIG_FS_ENCRYPTION
extern const struct fscrypt_operations ecfs_cryptops;

int ecfs_fname_setup_filename(struct inode *dir, const struct qstr *iname,
			      int lookup, struct ecfs_filename *fname);

int ecfs_fname_prepare_lookup(struct inode *dir, struct dentry *dentry,
			      struct ecfs_filename *fname);

void ecfs_fname_free_filename(struct ecfs_filename *fname);

int ecfs_ioctl_get_encryption_pwsalt(struct file *filp, void __user *arg);

#else /* !CONFIG_FS_ENCRYPTION */
static inline int ecfs_fname_setup_filename(struct inode *dir,
					    const struct qstr *iname,
					    int lookup,
					    struct ecfs_filename *fname)
{
	fname->usr_fname = iname;
	fname->disk_name.name = (unsigned char *) iname->name;
	fname->disk_name.len = iname->len;

	return ecfs_fname_setup_ci_filename(dir, iname, fname);
}

static inline int ecfs_fname_prepare_lookup(struct inode *dir,
					    struct dentry *dentry,
					    struct ecfs_filename *fname)
{
	return ecfs_fname_setup_filename(dir, &dentry->d_name, 1, fname);
}

static inline void ecfs_fname_free_filename(struct ecfs_filename *fname)
{
	ecfs_fname_free_ci_filename(fname);
}

static inline int ecfs_ioctl_get_encryption_pwsalt(struct file *filp,
						   void __user *arg)
{
	return -EOPNOTSUPP;
}
#endif /* !CONFIG_FS_ENCRYPTION */

/* dir.c */
extern int __ecfs_check_dir_entry(const char *, unsigned int, struct inode *,
				  struct file *,
				  struct ecfs_dir_entry_2 *,
				  struct buffer_head *, char *, int,
				  unsigned int);
#define ecfs_check_dir_entry(dir, filp, de, bh, buf, size, offset) \
	unlikely(__ecfs_check_dir_entry(__func__, __LINE__, (dir), (filp), \
				(de), (bh), (buf), (size), (offset)))
extern int ecfs_htree_store_dirent(struct file *dir_file, __u32 hash,
				__u32 minor_hash,
				struct ecfs_dir_entry_2 *dirent,
				struct fscrypt_str *ent_name);
extern void ecfs_htree_free_dir_info(struct dir_private_info *p);
extern int ecfs_find_dest_de(struct inode *dir, struct buffer_head *bh,
			     void *buf, int buf_size,
			     struct ecfs_filename *fname,
			     struct ecfs_dir_entry_2 **dest_de);
void ecfs_insert_dentry(struct inode *dir, struct inode *inode,
			struct ecfs_dir_entry_2 *de,
			int buf_size,
			struct ecfs_filename *fname);
static inline void ecfs_update_dx_flag(struct inode *inode)
{
	if (!ecfs_has_feature_dir_index(inode->i_sb) &&
	    ecfs_test_inode_flag(inode, ECFS_INODE_INDEX)) {
		/* ecfs_iget() should have caught this... */
		WARN_ON_ONCE(ecfs_has_feature_metadata_csum(inode->i_sb));
		ecfs_clear_inode_flag(inode, ECFS_INODE_INDEX);
	}
}
static const unsigned char ecfs_filetype_table[] = {
	DT_UNKNOWN, DT_REG, DT_DIR, DT_CHR, DT_BLK, DT_FIFO, DT_SOCK, DT_LNK
};

static inline  unsigned char get_dtype(struct super_block *sb, int filetype)
{
	if (!ecfs_has_feature_filetype(sb) || filetype >= ECFS_FT_MAX)
		return DT_UNKNOWN;

	return ecfs_filetype_table[filetype];
}
extern int ecfs_check_all_de(struct inode *dir, struct buffer_head *bh,
			     void *buf, int buf_size);

/* fsync.c */
extern int ecfs_sync_file(struct file *, loff_t, loff_t, int);

/* hash.c */
extern int ecfsfs_dirhash(const struct inode *dir, const char *name, int len,
			  struct dx_hash_info *hinfo);

/* ialloc.c */
extern int ecfs_mark_inode_used(struct super_block *sb, int ino);
extern struct inode *__ecfs_new_inode(struct mnt_idmap *, handle_t *,
				      struct inode *, umode_t,
				      const struct qstr *qstr, __u32 goal,
				      uid_t *owner, __u32 i_flags,
				      int handle_type, unsigned int line_no,
				      int nblocks);

#define ecfs_new_inode(handle, dir, mode, qstr, goal, owner, i_flags)          \
	__ecfs_new_inode(&nop_mnt_idmap, (handle), (dir), (mode), (qstr),      \
			 (goal), (owner), i_flags, 0, 0, 0)
#define ecfs_new_inode_start_handle(idmap, dir, mode, qstr, goal, owner, \
				    type, nblocks)		    \
	__ecfs_new_inode((idmap), NULL, (dir), (mode), (qstr), (goal), (owner), \
			 0, (type), __LINE__, (nblocks))


extern void ecfs_free_inode(handle_t *, struct inode *);
extern struct inode * ecfs_orphan_get(struct super_block *, unsigned long);
extern unsigned long ecfs_count_free_inodes(struct super_block *);
extern unsigned long ecfs_count_dirs(struct super_block *);
extern void ecfs_mark_bitmap_end(int start_bit, int end_bit, char *bitmap);
extern int ecfs_init_inode_table(struct super_block *sb,
				 ecfs_group_t group, int barrier);
extern void ecfs_end_bitmap_read(struct buffer_head *bh, int uptodate);

/* fast_commit.c */
int ecfs_fc_info_show(struct seq_file *seq, void *v);
void ecfs_fc_init(struct super_block *sb, journal_t *journal);
void ecfs_fc_init_inode(struct inode *inode);
void ecfs_fc_track_range(handle_t *handle, struct inode *inode, ecfs_lblk_t start,
			 ecfs_lblk_t end);
void __ecfs_fc_track_unlink(handle_t *handle, struct inode *inode,
	struct dentry *dentry);
void __ecfs_fc_track_link(handle_t *handle, struct inode *inode,
	struct dentry *dentry);
void ecfs_fc_track_unlink(handle_t *handle, struct dentry *dentry);
void ecfs_fc_track_link(handle_t *handle, struct dentry *dentry);
void __ecfs_fc_track_create(handle_t *handle, struct inode *inode,
			    struct dentry *dentry);
void ecfs_fc_track_create(handle_t *handle, struct dentry *dentry);
void ecfs_fc_track_inode(handle_t *handle, struct inode *inode);
void ecfs_fc_mark_ineligible(struct super_block *sb, int reason, handle_t *handle);
void ecfs_fc_del(struct inode *inode);
bool ecfs_fc_replay_check_excluded(struct super_block *sb, ecfs_fsblk_t block);
void ecfs_fc_replay_cleanup(struct super_block *sb);
int ecfs_fc_commit(journal_t *journal, tid_t commit_tid);
int __init ecfs_fc_init_dentry_cache(void);
void ecfs_fc_destroy_dentry_cache(void);
int ecfs_fc_record_regions(struct super_block *sb, int ino,
			   ecfs_lblk_t lblk, ecfs_fsblk_t pblk,
			   int len, int replay);

/* mballoc.c */
extern const struct seq_operations ecfs_mb_seq_groups_ops;
extern const struct seq_operations ecfs_mb_seq_structs_summary_ops;
extern int ecfs_seq_mb_stats_show(struct seq_file *seq, void *offset);
extern int ecfs_mb_init(struct super_block *);
extern void ecfs_mb_release(struct super_block *);
extern ecfs_fsblk_t ecfs_mb_new_blocks(handle_t *,
				struct ecfs_allocation_request *, int *);
extern void ecfs_discard_preallocations(struct inode *);
extern int __init ecfs_init_mballoc(void);
extern void ecfs_exit_mballoc(void);
extern ecfs_group_t ecfs_mb_prefetch(struct super_block *sb,
				     ecfs_group_t group,
				     unsigned int nr, int *cnt);
extern void ecfs_mb_prefetch_fini(struct super_block *sb, ecfs_group_t group,
				  unsigned int nr);

extern void ecfs_free_blocks(handle_t *handle, struct inode *inode,
			     struct buffer_head *bh, ecfs_fsblk_t block,
			     unsigned long count, int flags);
extern int ecfs_mb_alloc_groupinfo(struct super_block *sb,
				   ecfs_group_t ngroups);
extern int ecfs_mb_add_groupinfo(struct super_block *sb,
		ecfs_group_t i, struct ecfs_group_desc *desc);
extern int ecfs_group_add_blocks(handle_t *handle, struct super_block *sb,
				ecfs_fsblk_t block, unsigned long count);
extern int ecfs_trim_fs(struct super_block *, struct fstrim_range *);
extern void ecfs_process_freed_data(struct super_block *sb, tid_t commit_tid);
extern void ecfs_mb_mark_bb(struct super_block *sb, ecfs_fsblk_t block,
			    int len, bool state);
static inline bool ecfs_mb_cr_expensive(enum criteria cr)
{
	return cr >= CR_GOAL_LEN_SLOW;
}

/* inode.c */
void ecfs_inode_csum_set(struct inode *inode, struct ecfs_inode *raw,
			 struct ecfs_inode_info *ei);
int ecfs_inode_is_fast_symlink(struct inode *inode);
void ecfs_check_map_extents_env(struct inode *inode);
struct buffer_head *ecfs_getblk(handle_t *, struct inode *, ecfs_lblk_t, int);
struct buffer_head *ecfs_bread(handle_t *, struct inode *, ecfs_lblk_t, int);
int ecfs_bread_batch(struct inode *inode, ecfs_lblk_t block, int bh_count,
		     bool wait, struct buffer_head **bhs);
int ecfs_get_block_unwritten(struct inode *inode, sector_t iblock,
			     struct buffer_head *bh_result, int create);
int ecfs_get_block(struct inode *inode, sector_t iblock,
		   struct buffer_head *bh_result, int create);
int ecfs_da_get_block_prep(struct inode *inode, sector_t iblock,
			   struct buffer_head *bh, int create);
int ecfs_walk_page_buffers(handle_t *handle,
			   struct inode *inode,
			   struct buffer_head *head,
			   unsigned from,
			   unsigned to,
			   int *partial,
			   int (*fn)(handle_t *handle, struct inode *inode,
				     struct buffer_head *bh));
int ecfs_do_journal_get_write_access(handle_t *handle, struct inode *inode,
				struct buffer_head *bh);
void ecfs_set_inode_mapping_order(struct inode *inode);
#define FALL_BACK_TO_NONDELALLOC 1
#define CONVERT_INLINE_DATA	 2

typedef enum {
	ECFS_IGET_NORMAL =	0,
	ECFS_IGET_SPECIAL =	0x0001, /* OK to iget a system inode */
	ECFS_IGET_HANDLE = 	0x0002,	/* Inode # is from a handle */
	ECFS_IGET_BAD =		0x0004, /* Allow to iget a bad inode */
	ECFS_IGET_EA_INODE =	0x0008	/* Inode should contain an EA value */
} ecfs_iget_flags;

extern struct inode *__ecfs_iget(struct super_block *sb, unsigned long ino,
				 ecfs_iget_flags flags, const char *function,
				 unsigned int line);

#define ecfs_iget(sb, ino, flags) \
	__ecfs_iget((sb), (ino), (flags), __func__, __LINE__)

extern int  ecfs_write_inode(struct inode *, struct writeback_control *);
extern int  ecfs_setattr(struct mnt_idmap *, struct dentry *,
			 struct iattr *);
extern u32  ecfs_dio_alignment(struct inode *inode);
extern int  ecfs_getattr(struct mnt_idmap *, const struct path *,
			 struct kstat *, u32, unsigned int);
extern void ecfs_evict_inode(struct inode *);
extern void ecfs_clear_inode(struct inode *);
extern int  ecfs_file_getattr(struct mnt_idmap *, const struct path *,
			      struct kstat *, u32, unsigned int);
extern void ecfs_dirty_inode(struct inode *, int);
extern int ecfs_change_inode_journal_flag(struct inode *, int);
extern int ecfs_get_inode_loc(struct inode *, struct ecfs_iloc *);
extern int ecfs_get_fc_inode_loc(struct super_block *sb, unsigned long ino,
			  struct ecfs_iloc *iloc);
extern int ecfs_inode_attach_jinode(struct inode *inode);
extern int ecfs_can_truncate(struct inode *inode);
extern int ecfs_truncate(struct inode *);
extern int ecfs_break_layouts(struct inode *);
extern int ecfs_truncate_page_cache_block_range(struct inode *inode,
						loff_t start, loff_t end);
extern int ecfs_punch_hole(struct file *file, loff_t offset, loff_t length);
extern void ecfs_set_inode_flags(struct inode *, bool init);
extern int ecfs_alloc_da_blocks(struct inode *inode);
extern void ecfs_set_aops(struct inode *inode);
extern int ecfs_normal_submit_inode_data_buffers(struct jbd2_inode *jinode);
extern int ecfs_chunk_trans_blocks(struct inode *, int nrblocks);
extern int ecfs_chunk_trans_extent(struct inode *inode, int nrblocks);
extern int ecfs_meta_trans_blocks(struct inode *inode, int lblocks,
				  int pextents);
extern int ecfs_zero_partial_blocks(handle_t *handle, struct inode *inode,
			     loff_t lstart, loff_t lend);
extern vm_fault_t ecfs_page_mkwrite(struct vm_fault *vmf);
extern qsize_t *ecfs_get_reserved_space(struct inode *inode);
extern int ecfs_get_projid(struct inode *inode, kprojid_t *projid);
extern void ecfs_da_release_space(struct inode *inode, int to_free);
extern void ecfs_da_update_reserve_space(struct inode *inode,
					int used, int quota_claim);
extern int ecfs_issue_zeroout(struct inode *inode, ecfs_lblk_t lblk,
			      ecfs_fsblk_t pblk, ecfs_lblk_t len);

static inline bool is_special_ino(struct super_block *sb, unsigned long ino)
{
	struct ecfs_super_block *es = ECFS_SB(sb)->s_es;

	return (ino < ECFS_FIRST_INO(sb) && ino != ECFS_ROOT_INO) ||
		ino == le32_to_cpu(es->s_usr_quota_inum) ||
		ino == le32_to_cpu(es->s_grp_quota_inum) ||
		ino == le32_to_cpu(es->s_prj_quota_inum) ||
		ino == le32_to_cpu(es->s_orphan_file_inum);
}

/* indirect.c */
extern int ecfs_ind_map_blocks(handle_t *handle, struct inode *inode,
				struct ecfs_map_blocks *map, int flags);
extern int ecfs_ind_trans_blocks(struct inode *inode, int nrblocks);
extern void ecfs_ind_truncate(handle_t *, struct inode *inode);
extern int ecfs_ind_remove_space(handle_t *handle, struct inode *inode,
				 ecfs_lblk_t start, ecfs_lblk_t end);

/* ioctl.c */
extern long ecfs_ioctl(struct file *, unsigned int, unsigned long);
extern long ecfs_compat_ioctl(struct file *, unsigned int, unsigned long);
int ecfs_fileattr_set(struct mnt_idmap *idmap,
		      struct dentry *dentry, struct file_kattr *fa);
int ecfs_fileattr_get(struct dentry *dentry, struct file_kattr *fa);
extern void ecfs_reset_inode_seed(struct inode *inode);
int ecfs_update_overhead(struct super_block *sb, bool force);
int ecfs_force_shutdown(struct super_block *sb, u32 flags);

/* migrate.c */
extern int ecfs_ext_migrate(struct inode *);
extern int ecfs_ind_migrate(struct inode *inode);

/* namei.c */
extern int ecfs_init_new_dir(handle_t *handle, struct inode *dir,
			     struct inode *inode);
extern int ecfs_dirblock_csum_verify(struct inode *inode,
				     struct buffer_head *bh);
extern int ecfs_htree_fill_tree(struct file *dir_file, __u32 start_hash,
				__u32 start_minor_hash, __u32 *next_hash);
extern int ecfs_search_dir(struct buffer_head *bh,
			   char *search_buf,
			   int buf_size,
			   struct inode *dir,
			   struct ecfs_filename *fname,
			   unsigned int offset,
			   struct ecfs_dir_entry_2 **res_dir);
extern int ecfs_generic_delete_entry(struct inode *dir,
				     struct ecfs_dir_entry_2 *de_del,
				     struct buffer_head *bh,
				     void *entry_buf,
				     int buf_size,
				     int csum_size);
extern bool ecfs_empty_dir(struct inode *inode);

/* resize.c */
extern void ecfs_kvfree_array_rcu(void *to_free);
extern int ecfs_group_add(struct super_block *sb,
				struct ecfs_new_group_data *input);
extern int ecfs_group_extend(struct super_block *sb,
				struct ecfs_super_block *es,
				ecfs_fsblk_t n_blocks_count);
extern int ecfs_resize_fs(struct super_block *sb, ecfs_fsblk_t n_blocks_count);
extern unsigned int ecfs_list_backups(struct super_block *sb,
				      unsigned int *three, unsigned int *five,
				      unsigned int *seven);

/* super.c */
extern struct buffer_head *ecfs_sb_bread(struct super_block *sb,
					 sector_t block, blk_opf_t op_flags);
extern struct buffer_head *ecfs_sb_bread_unmovable(struct super_block *sb,
						   sector_t block);
extern void ecfs_read_bh_nowait(struct buffer_head *bh, blk_opf_t op_flags,
				bh_end_io_t *end_io, bool simu_fail);
extern int ecfs_read_bh(struct buffer_head *bh, blk_opf_t op_flags,
			bh_end_io_t *end_io, bool simu_fail);
extern int ecfs_read_bh_lock(struct buffer_head *bh, blk_opf_t op_flags, bool wait);
extern void ecfs_sb_breadahead_unmovable(struct super_block *sb, sector_t block);
extern int ecfs_seq_options_show(struct seq_file *seq, void *offset);
extern int ecfs_calculate_overhead(struct super_block *sb);
extern __le32 ecfs_superblock_csum(struct ecfs_super_block *es);
extern void ecfs_superblock_csum_set(struct super_block *sb);
extern int ecfs_alloc_flex_bg_array(struct super_block *sb,
				    ecfs_group_t ngroup);
extern const char *ecfs_decode_error(struct super_block *sb, int errno,
				     char nbuf[16]);
extern void ecfs_mark_group_bitmap_corrupted(struct super_block *sb,
					     ecfs_group_t block_group,
					     unsigned int flags);
extern unsigned int ecfs_num_base_meta_blocks(struct super_block *sb,
					      ecfs_group_t block_group);

extern __printf(7, 8)
void __ecfs_error(struct super_block *, const char *, unsigned int, bool,
		  int, __u64, const char *, ...);
extern __printf(6, 7)
void __ecfs_error_inode(struct inode *, const char *, unsigned int,
			ecfs_fsblk_t, int, const char *, ...);
extern __printf(5, 6)
void __ecfs_error_file(struct file *, const char *, unsigned int, ecfs_fsblk_t,
		     const char *, ...);
extern void __ecfs_std_error(struct super_block *, const char *,
			     unsigned int, int);
extern __printf(4, 5)
void __ecfs_warning(struct super_block *, const char *, unsigned int,
		    const char *, ...);
extern __printf(4, 5)
void __ecfs_warning_inode(const struct inode *inode, const char *function,
			  unsigned int line, const char *fmt, ...);
extern __printf(3, 4)
void __ecfs_msg(struct super_block *, const char *, const char *, ...);
extern void __ecfs_dump_mmp_msg(struct super_block *, struct mmp_struct *mmp,
			   const char *, unsigned int, const char *);
extern __printf(7, 8)
void __ecfs_grp_locked_error(const char *, unsigned int,
			     struct super_block *, ecfs_group_t,
			     unsigned long, ecfs_fsblk_t,
			     const char *, ...);

#define ECFS_ERROR_INODE(inode, fmt, a...) \
	ecfs_error_inode((inode), __func__, __LINE__, 0, (fmt), ## a)

#define ECFS_ERROR_INODE_ERR(inode, err, fmt, a...)			\
	__ecfs_error_inode((inode), __func__, __LINE__, 0, (err), (fmt), ## a)

#define ecfs_error_inode_block(inode, block, err, fmt, a...)		\
	__ecfs_error_inode((inode), __func__, __LINE__, (block), (err),	\
			   (fmt), ## a)

#define ECFS_ERROR_FILE(file, block, fmt, a...)				\
	ecfs_error_file((file), __func__, __LINE__, (block), (fmt), ## a)

#define ecfs_abort(sb, err, fmt, a...)					\
	__ecfs_error((sb), __func__, __LINE__, true, (err), 0, (fmt), ## a)

#ifdef CONFIG_PRINTK

#define ecfs_error_inode(inode, func, line, block, fmt, ...)		\
	__ecfs_error_inode(inode, func, line, block, 0, fmt, ##__VA_ARGS__)
#define ecfs_error_inode_err(inode, func, line, block, err, fmt, ...)	\
	__ecfs_error_inode((inode), (func), (line), (block), 		\
			   (err), (fmt), ##__VA_ARGS__)
#define ecfs_error_file(file, func, line, block, fmt, ...)		\
	__ecfs_error_file(file, func, line, block, fmt, ##__VA_ARGS__)
#define ecfs_error(sb, fmt, ...)					\
	__ecfs_error((sb), __func__, __LINE__, false, 0, 0, (fmt),	\
		##__VA_ARGS__)
#define ecfs_error_err(sb, err, fmt, ...)				\
	__ecfs_error((sb), __func__, __LINE__, false, (err), 0, (fmt),	\
		##__VA_ARGS__)
#define ecfs_warning(sb, fmt, ...)					\
	__ecfs_warning(sb, __func__, __LINE__, fmt, ##__VA_ARGS__)
#define ecfs_warning_inode(inode, fmt, ...)				\
	__ecfs_warning_inode(inode, __func__, __LINE__, fmt, ##__VA_ARGS__)
#define ecfs_msg(sb, level, fmt, ...)				\
	__ecfs_msg(sb, level, fmt, ##__VA_ARGS__)
#define dump_mmp_msg(sb, mmp, msg)					\
	__ecfs_dump_mmp_msg(sb, mmp, __func__, __LINE__, msg)
#define ecfs_grp_locked_error(sb, grp, ino, block, fmt, ...)		\
	__ecfs_grp_locked_error(__func__, __LINE__, sb, grp, ino, block, \
				fmt, ##__VA_ARGS__)

#else

#define ecfs_error_inode(inode, func, line, block, fmt, ...)		\
do {									\
	no_printk(fmt, ##__VA_ARGS__);					\
	__ecfs_error_inode(inode, "", 0, block, 0, " ");		\
} while (0)
#define ecfs_error_inode_err(inode, func, line, block, err, fmt, ...)	\
do {									\
	no_printk(fmt, ##__VA_ARGS__);					\
	__ecfs_error_inode(inode, "", 0, block, err, " ");		\
} while (0)
#define ecfs_error_file(file, func, line, block, fmt, ...)		\
do {									\
	no_printk(fmt, ##__VA_ARGS__);					\
	__ecfs_error_file(file, "", 0, block, " ");			\
} while (0)
#define ecfs_error(sb, fmt, ...)					\
do {									\
	no_printk(fmt, ##__VA_ARGS__);					\
	__ecfs_error(sb, "", 0, false, 0, 0, " ");			\
} while (0)
#define ecfs_error_err(sb, err, fmt, ...)				\
do {									\
	no_printk(fmt, ##__VA_ARGS__);					\
	__ecfs_error(sb, "", 0, false, err, 0, " ");			\
} while (0)
#define ecfs_warning(sb, fmt, ...)					\
do {									\
	no_printk(fmt, ##__VA_ARGS__);					\
	__ecfs_warning(sb, "", 0, " ");					\
} while (0)
#define ecfs_warning_inode(inode, fmt, ...)				\
do {									\
	no_printk(fmt, ##__VA_ARGS__);					\
	__ecfs_warning_inode(inode, "", 0, " ");			\
} while (0)
#define ecfs_msg(sb, level, fmt, ...)					\
do {									\
	no_printk(fmt, ##__VA_ARGS__);					\
	__ecfs_msg(sb, "", " ");					\
} while (0)
#define dump_mmp_msg(sb, mmp, msg)					\
	__ecfs_dump_mmp_msg(sb, mmp, "", 0, "")
#define ecfs_grp_locked_error(sb, grp, ino, block, fmt, ...)		\
do {									\
	no_printk(fmt, ##__VA_ARGS__);				\
	__ecfs_grp_locked_error("", 0, sb, grp, ino, block, " ");	\
} while (0)

#endif

extern ecfs_fsblk_t ecfs_block_bitmap(struct super_block *sb,
				      struct ecfs_group_desc *bg);
extern ecfs_fsblk_t ecfs_inode_bitmap(struct super_block *sb,
				      struct ecfs_group_desc *bg);
extern ecfs_fsblk_t ecfs_inode_table(struct super_block *sb,
				     struct ecfs_group_desc *bg);
extern __u32 ecfs_free_group_clusters(struct super_block *sb,
				      struct ecfs_group_desc *bg);
extern __u32 ecfs_free_inodes_count(struct super_block *sb,
				 struct ecfs_group_desc *bg);
extern __u32 ecfs_used_dirs_count(struct super_block *sb,
				struct ecfs_group_desc *bg);
extern __u32 ecfs_itable_unused_count(struct super_block *sb,
				   struct ecfs_group_desc *bg);
extern void ecfs_block_bitmap_set(struct super_block *sb,
				  struct ecfs_group_desc *bg, ecfs_fsblk_t blk);
extern void ecfs_inode_bitmap_set(struct super_block *sb,
				  struct ecfs_group_desc *bg, ecfs_fsblk_t blk);
extern void ecfs_inode_table_set(struct super_block *sb,
				 struct ecfs_group_desc *bg, ecfs_fsblk_t blk);
extern void ecfs_free_group_clusters_set(struct super_block *sb,
					 struct ecfs_group_desc *bg,
					 __u32 count);
extern void ecfs_free_inodes_set(struct super_block *sb,
				struct ecfs_group_desc *bg, __u32 count);
extern void ecfs_used_dirs_set(struct super_block *sb,
				struct ecfs_group_desc *bg, __u32 count);
extern void ecfs_itable_unused_set(struct super_block *sb,
				   struct ecfs_group_desc *bg, __u32 count);
extern int ecfs_group_desc_csum_verify(struct super_block *sb, __u32 group,
				       struct ecfs_group_desc *gdp);
extern void ecfs_group_desc_csum_set(struct super_block *sb, __u32 group,
				     struct ecfs_group_desc *gdp);
extern int ecfs_register_li_request(struct super_block *sb,
				    ecfs_group_t first_not_zeroed);

static inline int ecfs_has_group_desc_csum(struct super_block *sb)
{
	return ecfs_has_feature_gdt_csum(sb) ||
	       ecfs_has_feature_metadata_csum(sb);
}

#define ecfs_read_incompat_64bit_val(es, name) \
	(((es)->s_feature_incompat & cpu_to_le32(ECFS_FEATURE_INCOMPAT_64BIT) \
		? (ecfs_fsblk_t)le32_to_cpu(es->name##_hi) << 32 : 0) | \
		le32_to_cpu(es->name##_lo))

static inline ecfs_fsblk_t ecfs_blocks_count(struct ecfs_super_block *es)
{
	return ecfs_read_incompat_64bit_val(es, s_blocks_count);
}

static inline ecfs_fsblk_t ecfs_r_blocks_count(struct ecfs_super_block *es)
{
	return ecfs_read_incompat_64bit_val(es, s_r_blocks_count);
}

static inline ecfs_fsblk_t ecfs_free_blocks_count(struct ecfs_super_block *es)
{
	return ecfs_read_incompat_64bit_val(es, s_free_blocks_count);
}

static inline void ecfs_blocks_count_set(struct ecfs_super_block *es,
					 ecfs_fsblk_t blk)
{
	es->s_blocks_count_lo = cpu_to_le32((u32)blk);
	es->s_blocks_count_hi = cpu_to_le32(blk >> 32);
}

static inline void ecfs_free_blocks_count_set(struct ecfs_super_block *es,
					      ecfs_fsblk_t blk)
{
	es->s_free_blocks_count_lo = cpu_to_le32((u32)blk);
	es->s_free_blocks_count_hi = cpu_to_le32(blk >> 32);
}

static inline void ecfs_r_blocks_count_set(struct ecfs_super_block *es,
					   ecfs_fsblk_t blk)
{
	es->s_r_blocks_count_lo = cpu_to_le32((u32)blk);
	es->s_r_blocks_count_hi = cpu_to_le32(blk >> 32);
}

static inline loff_t ecfs_isize(struct super_block *sb,
				struct ecfs_inode *raw_inode)
{
	if (ecfs_has_feature_largedir(sb) ||
	    S_ISREG(le16_to_cpu(raw_inode->i_mode)))
		return ((loff_t)le32_to_cpu(raw_inode->i_size_high) << 32) |
			le32_to_cpu(raw_inode->i_size_lo);

	return (loff_t) le32_to_cpu(raw_inode->i_size_lo);
}

static inline void ecfs_isize_set(struct ecfs_inode *raw_inode, loff_t i_size)
{
	raw_inode->i_size_lo = cpu_to_le32(i_size);
	raw_inode->i_size_high = cpu_to_le32(i_size >> 32);
}

/*
 * Reading s_groups_count requires using smp_rmb() afterwards.  See
 * the locking protocol documented in the comments of ecfs_group_add()
 * in resize.c
 */
static inline ecfs_group_t ecfs_get_groups_count(struct super_block *sb)
{
	ecfs_group_t	ngroups = ECFS_SB(sb)->s_groups_count;

	smp_rmb();
	return ngroups;
}

static inline ecfs_group_t ecfs_flex_group(struct ecfs_sb_info *sbi,
					     ecfs_group_t block_group)
{
	return block_group >> sbi->s_log_groups_per_flex;
}

static inline unsigned int ecfs_flex_bg_size(struct ecfs_sb_info *sbi)
{
	return 1 << sbi->s_log_groups_per_flex;
}

static inline loff_t ecfs_get_maxbytes(struct inode *inode)
{
	if (ecfs_test_inode_flag(inode, ECFS_INODE_EXTENTS))
		return inode->i_sb->s_maxbytes;
	return ECFS_SB(inode->i_sb)->s_bitmap_maxbytes;
}

#define ecfs_std_error(sb, errno)				\
do {								\
	if ((errno))						\
		__ecfs_std_error((sb), __func__, __LINE__, (errno));	\
} while (0)

#ifdef CONFIG_SMP
/* Each CPU can accumulate percpu_counter_batch clusters in their local
 * counters. So we need to make sure we have free clusters more
 * than percpu_counter_batch  * nr_cpu_ids. Also add a window of 4 times.
 */
#define ECFS_FREECLUSTERS_WATERMARK (4 * (percpu_counter_batch * nr_cpu_ids))
#else
#define ECFS_FREECLUSTERS_WATERMARK 0
#endif

/* Update i_disksize. Requires i_rwsem to avoid races with truncate */
static inline void ecfs_update_i_disksize(struct inode *inode, loff_t newsize)
{
	WARN_ON_ONCE(S_ISREG(inode->i_mode) &&
		     !inode_is_locked(inode));
	down_write(&ECFS_I(inode)->i_data_sem);
	if (newsize > ECFS_I(inode)->i_disksize)
		WRITE_ONCE(ECFS_I(inode)->i_disksize, newsize);
	up_write(&ECFS_I(inode)->i_data_sem);
}

/* Update i_size, i_disksize. Requires i_rwsem to avoid races with truncate */
static inline int ecfs_update_inode_size(struct inode *inode, loff_t newsize)
{
	int changed = 0;

	if (newsize > inode->i_size) {
		i_size_write(inode, newsize);
		changed = 1;
	}
	if (newsize > ECFS_I(inode)->i_disksize) {
		ecfs_update_i_disksize(inode, newsize);
		changed |= 2;
	}
	return changed;
}

int ecfs_update_disksize_before_punch(struct inode *inode, loff_t offset,
				      loff_t len);

struct ecfs_group_info {
	unsigned long   bb_state;
#ifdef AGGRESSIVE_CHECK
	unsigned long	bb_check_counter;
#endif
	struct rb_root  bb_free_root;
	ecfs_grpblk_t	bb_first_free;	/* first free block */
	ecfs_grpblk_t	bb_free;	/* total free blocks */
	ecfs_grpblk_t	bb_fragments;	/* nr of freespace fragments */
	int		bb_avg_fragment_size_order;	/* order of average
							   fragment in BG */
	ecfs_grpblk_t	bb_largest_free_order;/* order of largest frag in BG */
	ecfs_group_t	bb_group;	/* Group number */
	struct          list_head bb_prealloc_list;
#ifdef DOUBLE_CHECK
	void            *bb_bitmap;
#endif
	struct rw_semaphore alloc_sem;
	ecfs_grpblk_t	bb_counters[];	/* Nr of free power-of-two-block
					 * regions, index is order.
					 * bb_counters[3] = 5 means
					 * 5 free 8-block regions. */
};

#define ECFS_GROUP_INFO_NEED_INIT_BIT		0
#define ECFS_GROUP_INFO_WAS_TRIMMED_BIT		1
#define ECFS_GROUP_INFO_BBITMAP_CORRUPT_BIT	2
#define ECFS_GROUP_INFO_IBITMAP_CORRUPT_BIT	3
#define ECFS_GROUP_INFO_BBITMAP_CORRUPT		\
	(1 << ECFS_GROUP_INFO_BBITMAP_CORRUPT_BIT)
#define ECFS_GROUP_INFO_IBITMAP_CORRUPT		\
	(1 << ECFS_GROUP_INFO_IBITMAP_CORRUPT_BIT)
#define ECFS_GROUP_INFO_BBITMAP_READ_BIT	4

#define ECFS_MB_GRP_NEED_INIT(grp)	\
	(test_bit(ECFS_GROUP_INFO_NEED_INIT_BIT, &((grp)->bb_state)))
#define ECFS_MB_GRP_BBITMAP_CORRUPT(grp)	\
	(test_bit(ECFS_GROUP_INFO_BBITMAP_CORRUPT_BIT, &((grp)->bb_state)))
#define ECFS_MB_GRP_IBITMAP_CORRUPT(grp)	\
	(test_bit(ECFS_GROUP_INFO_IBITMAP_CORRUPT_BIT, &((grp)->bb_state)))

#define ECFS_MB_GRP_WAS_TRIMMED(grp)	\
	(test_bit(ECFS_GROUP_INFO_WAS_TRIMMED_BIT, &((grp)->bb_state)))
#define ECFS_MB_GRP_SET_TRIMMED(grp)	\
	(set_bit(ECFS_GROUP_INFO_WAS_TRIMMED_BIT, &((grp)->bb_state)))
#define ECFS_MB_GRP_CLEAR_TRIMMED(grp)	\
	(clear_bit(ECFS_GROUP_INFO_WAS_TRIMMED_BIT, &((grp)->bb_state)))
#define ECFS_MB_GRP_TEST_AND_SET_READ(grp)	\
	(test_and_set_bit(ECFS_GROUP_INFO_BBITMAP_READ_BIT, &((grp)->bb_state)))

#define ECFS_MAX_CONTENTION		8
#define ECFS_CONTENTION_THRESHOLD	2

static inline spinlock_t *ecfs_group_lock_ptr(struct super_block *sb,
					      ecfs_group_t group)
{
	return bgl_lock_ptr(ECFS_SB(sb)->s_blockgroup_lock, group);
}

/*
 * Returns true if the filesystem is busy enough that attempts to
 * access the block group locks has run into contention.
 */
static inline int ecfs_fs_is_busy(struct ecfs_sb_info *sbi)
{
	return (atomic_read(&sbi->s_lock_busy) > ECFS_CONTENTION_THRESHOLD);
}

static inline bool ecfs_try_lock_group(struct super_block *sb, ecfs_group_t group)
{
	if (!spin_trylock(ecfs_group_lock_ptr(sb, group)))
		return false;
	/*
	 * We're able to grab the lock right away, so drop the lock
	 * contention counter.
	 */
	atomic_add_unless(&ECFS_SB(sb)->s_lock_busy, -1, 0);
	return true;
}

static inline void ecfs_lock_group(struct super_block *sb, ecfs_group_t group)
{
	if (!ecfs_try_lock_group(sb, group)) {
		/*
		 * The lock is busy, so bump the contention counter,
		 * and then wait on the spin lock.
		 */
		atomic_add_unless(&ECFS_SB(sb)->s_lock_busy, 1,
				  ECFS_MAX_CONTENTION);
		spin_lock(ecfs_group_lock_ptr(sb, group));
	}
}

static inline void ecfs_unlock_group(struct super_block *sb,
					ecfs_group_t group)
{
	spin_unlock(ecfs_group_lock_ptr(sb, group));
}

#ifdef CONFIG_QUOTA
static inline bool ecfs_quota_capable(struct super_block *sb)
{
	return (test_opt(sb, QUOTA) || ecfs_has_feature_quota(sb));
}

static inline bool ecfs_is_quota_journalled(struct super_block *sb)
{
	struct ecfs_sb_info *sbi = ECFS_SB(sb);

	return (ecfs_has_feature_quota(sb) ||
		sbi->s_qf_names[USRQUOTA] || sbi->s_qf_names[GRPQUOTA]);
}
int ecfs_enable_quotas(struct super_block *sb);
#endif

/*
 * Block validity checking
 */
#define ecfs_check_indirect_blockref(inode, bh)				\
	ecfs_check_blockref(__func__, __LINE__, inode,			\
			    (__le32 *)(bh)->b_data,			\
			    ECFS_ADDR_PER_BLOCK((inode)->i_sb))

#define ecfs_ind_check_inode(inode)					\
	ecfs_check_blockref(__func__, __LINE__, inode,			\
			    ECFS_I(inode)->i_data,			\
			    ECFS_NDIR_BLOCKS)

/*
 * Inodes and files operations
 */

/* dir.c */
extern const struct file_operations ecfs_dir_operations;

/* file.c */
extern const struct inode_operations ecfs_file_inode_operations;
extern const struct file_operations ecfs_file_operations;
extern loff_t ecfs_llseek(struct file *file, loff_t offset, int origin);

/* inline.c */
extern int ecfs_get_max_inline_size(struct inode *inode);
extern int ecfs_find_inline_data_nolock(struct inode *inode);
extern int ecfs_destroy_inline_data(handle_t *handle, struct inode *inode);
extern void ecfs_update_final_de(void *de_buf, int old_size, int new_size);

int ecfs_readpage_inline(struct inode *inode, struct folio *folio);
extern int ecfs_try_to_write_inline_data(struct address_space *mapping,
					 struct inode *inode,
					 loff_t pos, unsigned len,
					 struct folio **foliop);
int ecfs_write_inline_data_end(struct inode *inode, loff_t pos, unsigned len,
			       unsigned copied, struct folio *folio);
extern int ecfs_generic_write_inline_data(struct address_space *mapping,
					  struct inode *inode,
					  loff_t pos, unsigned len,
					  struct folio **foliop,
					  void **fsdata, bool da);
extern int ecfs_try_add_inline_entry(handle_t *handle,
				     struct ecfs_filename *fname,
				     struct inode *dir, struct inode *inode);
extern int ecfs_try_create_inline_dir(handle_t *handle,
				      struct inode *parent,
				      struct inode *inode);
extern int ecfs_read_inline_dir(struct file *filp,
				struct dir_context *ctx,
				int *has_inline_data);
extern int ecfs_inlinedir_to_tree(struct file *dir_file,
				  struct inode *dir, ecfs_lblk_t block,
				  struct dx_hash_info *hinfo,
				  __u32 start_hash, __u32 start_minor_hash,
				  int *has_inline_data);
extern struct buffer_head *ecfs_find_inline_entry(struct inode *dir,
					struct ecfs_filename *fname,
					struct ecfs_dir_entry_2 **res_dir,
					int *has_inline_data);
extern int ecfs_delete_inline_entry(handle_t *handle,
				    struct inode *dir,
				    struct ecfs_dir_entry_2 *de_del,
				    struct buffer_head *bh,
				    int *has_inline_data);
extern bool ecfs_empty_inline_dir(struct inode *dir, int *has_inline_data);
extern struct buffer_head *ecfs_get_first_inline_block(struct inode *inode,
					struct ecfs_dir_entry_2 **parent_de,
					int *retval);
extern void *ecfs_read_inline_link(struct inode *inode);

struct iomap;
extern int ecfs_inline_data_iomap(struct inode *inode, struct iomap *iomap);

extern int ecfs_inline_data_truncate(struct inode *inode, int *has_inline);

extern int ecfs_convert_inline_data(struct inode *inode);

static inline int ecfs_has_inline_data(struct inode *inode)
{
	return ecfs_test_inode_flag(inode, ECFS_INODE_INLINE_DATA) &&
	       ECFS_I(inode)->i_inline_off;
}

/* namei.c */
extern const struct inode_operations ecfs_dir_inode_operations;
extern const struct inode_operations ecfs_special_inode_operations;
extern struct dentry *ecfs_get_parent(struct dentry *child);
extern int ecfs_init_dirblock(handle_t *handle, struct inode *inode,
			      struct buffer_head *dir_block,
			      unsigned int parent_ino, void *inline_buf,
			      int inline_size);
extern void ecfs_initialize_dirent_tail(struct buffer_head *bh,
					unsigned int blocksize);
extern int ecfs_handle_dirty_dirblock(handle_t *handle, struct inode *inode,
				      struct buffer_head *bh);
extern int __ecfs_unlink(struct inode *dir, const struct qstr *d_name,
			 struct inode *inode, struct dentry *dentry);
extern int __ecfs_link(struct inode *dir, struct inode *inode,
		       struct dentry *dentry);

#define S_SHIFT 12
static const unsigned char ecfs_type_by_mode[(S_IFMT >> S_SHIFT) + 1] = {
	[S_IFREG >> S_SHIFT]	= ECFS_FT_REG_FILE,
	[S_IFDIR >> S_SHIFT]	= ECFS_FT_DIR,
	[S_IFCHR >> S_SHIFT]	= ECFS_FT_CHRDEV,
	[S_IFBLK >> S_SHIFT]	= ECFS_FT_BLKDEV,
	[S_IFIFO >> S_SHIFT]	= ECFS_FT_FIFO,
	[S_IFSOCK >> S_SHIFT]	= ECFS_FT_SOCK,
	[S_IFLNK >> S_SHIFT]	= ECFS_FT_SYMLINK,
};

static inline void ecfs_set_de_type(struct super_block *sb,
				struct ecfs_dir_entry_2 *de,
				umode_t mode) {
	if (ecfs_has_feature_filetype(sb))
		de->file_type = ecfs_type_by_mode[(mode & S_IFMT)>>S_SHIFT];
}

/* readpages.c */
extern int ecfs_mpage_readpages(struct inode *inode,
		struct readahead_control *rac, struct folio *folio);
extern int __init ecfs_init_post_read_processing(void);
extern void ecfs_exit_post_read_processing(void);

/* symlink.c */
extern const struct inode_operations ecfs_encrypted_symlink_inode_operations;
extern const struct inode_operations ecfs_symlink_inode_operations;
extern const struct inode_operations ecfs_fast_symlink_inode_operations;

/* sysfs.c */
extern void ecfs_notify_error_sysfs(struct ecfs_sb_info *sbi);
extern int ecfs_register_sysfs(struct super_block *sb);
extern void ecfs_unregister_sysfs(struct super_block *sb);
extern int __init ecfs_init_sysfs(void);
extern void ecfs_exit_sysfs(void);

/* block_validity */
extern void ecfs_release_system_zone(struct super_block *sb);
extern int ecfs_setup_system_zone(struct super_block *sb);
extern int __init ecfs_init_system_zone(void);
extern void ecfs_exit_system_zone(void);
extern int ecfs_inode_block_valid(struct inode *inode,
				  ecfs_fsblk_t start_blk,
				  unsigned int count);
extern int ecfs_check_blockref(const char *, unsigned int,
			       struct inode *, __le32 *, unsigned int);
extern int ecfs_sb_block_valid(struct super_block *sb, struct inode *inode,
				ecfs_fsblk_t start_blk, unsigned int count);


/* extents.c */
struct ecfs_ext_path;
struct ecfs_extent;

/*
 * Maximum number of logical blocks in a file; ecfs_extent's ee_block is
 * __le32.
 */
#define EXT_MAX_BLOCKS	0xffffffff

extern void ecfs_ext_tree_init(handle_t *handle, struct inode *inode);
extern int ecfs_ext_index_trans_blocks(struct inode *inode, int extents);
extern int ecfs_ext_map_blocks(handle_t *handle, struct inode *inode,
			       struct ecfs_map_blocks *map, int flags);
extern int ecfs_ext_truncate(handle_t *, struct inode *);
extern int ecfs_ext_remove_space(struct inode *inode, ecfs_lblk_t start,
				 ecfs_lblk_t end);
extern void ecfs_ext_init(struct super_block *);
extern void ecfs_ext_release(struct super_block *);
extern long ecfs_fallocate(struct file *file, int mode, loff_t offset,
			  loff_t len);
extern int ecfs_convert_unwritten_extents(handle_t *handle, struct inode *inode,
					  loff_t offset, ssize_t len);
extern int ecfs_convert_unwritten_extents_atomic(handle_t *handle,
			struct inode *inode, loff_t offset, ssize_t len);
extern int ecfs_convert_unwritten_io_end_vec(handle_t *handle,
					     ecfs_io_end_t *io_end);
extern int ecfs_map_blocks(handle_t *handle, struct inode *inode,
			   struct ecfs_map_blocks *map, int flags);
extern int ecfs_ext_calc_credits_for_single_extent(struct inode *inode,
						   int num,
						   struct ecfs_ext_path *path);
extern struct ecfs_ext_path *ecfs_ext_insert_extent(
				handle_t *handle, struct inode *inode,
				struct ecfs_ext_path *path,
				struct ecfs_extent *newext, int gb_flags);
extern struct ecfs_ext_path *ecfs_find_extent(struct inode *, ecfs_lblk_t,
					      struct ecfs_ext_path *,
					      int flags);
extern void ecfs_free_ext_path(struct ecfs_ext_path *);
extern int ecfs_ext_check_inode(struct inode *inode);
extern ecfs_lblk_t ecfs_ext_next_allocated_block(struct ecfs_ext_path *path);
extern int ecfs_fiemap(struct inode *inode, struct fiemap_extent_info *fieinfo,
			__u64 start, __u64 len);
extern int ecfs_get_es_cache(struct inode *inode,
			     struct fiemap_extent_info *fieinfo,
			     __u64 start, __u64 len);
extern int ecfs_ext_precache(struct inode *inode);
extern int ecfs_swap_extents(handle_t *handle, struct inode *inode1,
				struct inode *inode2, ecfs_lblk_t lblk1,
			     ecfs_lblk_t lblk2,  ecfs_lblk_t count,
			     int mark_unwritten,int *err);
extern int ecfs_clu_mapped(struct inode *inode, ecfs_lblk_t lclu);
extern int ecfs_datasem_ensure_credits(handle_t *handle, struct inode *inode,
				       int check_cred, int restart_cred,
				       int revoke_cred);
extern void ecfs_ext_replay_shrink_inode(struct inode *inode, ecfs_lblk_t end);
extern int ecfs_ext_replay_set_iblocks(struct inode *inode);
extern int ecfs_ext_replay_update_ex(struct inode *inode, ecfs_lblk_t start,
		int len, int unwritten, ecfs_fsblk_t pblk);
extern int ecfs_ext_clear_bb(struct inode *inode);


/* move_extent.c */
extern void ecfs_double_down_write_data_sem(struct inode *first,
					    struct inode *second);
extern void ecfs_double_up_write_data_sem(struct inode *orig_inode,
					  struct inode *donor_inode);
extern int ecfs_move_extents(struct file *o_filp, struct file *d_filp,
			     __u64 start_orig, __u64 start_donor,
			     __u64 len, __u64 *moved_len);

/* page-io.c */
extern int __init ecfs_init_pageio(void);
extern void ecfs_exit_pageio(void);
extern ecfs_io_end_t *ecfs_init_io_end(struct inode *inode, gfp_t flags);
extern ecfs_io_end_t *ecfs_get_io_end(ecfs_io_end_t *io_end);
extern int ecfs_put_io_end(ecfs_io_end_t *io_end);
extern void ecfs_put_io_end_defer(ecfs_io_end_t *io_end);
extern void ecfs_io_submit_init(struct ecfs_io_submit *io,
				struct writeback_control *wbc);
extern void ecfs_end_io_rsv_work(struct work_struct *work);
extern void ecfs_io_submit(struct ecfs_io_submit *io);
int ecfs_bio_write_folio(struct ecfs_io_submit *io, struct folio *page,
		size_t len);
extern struct ecfs_io_end_vec *ecfs_alloc_io_end_vec(ecfs_io_end_t *io_end);
extern struct ecfs_io_end_vec *ecfs_last_io_end_vec(ecfs_io_end_t *io_end);

/* mmp.c */
extern int ecfs_multi_mount_protect(struct super_block *, ecfs_fsblk_t);

/* mmp.c */
extern void ecfs_stop_mmpd(struct ecfs_sb_info *sbi);

/* verity.c */
extern const struct fsverity_operations ecfs_verityops;

/* orphan.c */
extern int ecfs_orphan_add(handle_t *, struct inode *);
extern int ecfs_orphan_del(handle_t *, struct inode *);
extern void ecfs_orphan_cleanup(struct super_block *sb,
				struct ecfs_super_block *es);
extern void ecfs_release_orphan_info(struct super_block *sb);
extern int ecfs_init_orphan_info(struct super_block *sb);
extern int ecfs_orphan_file_empty(struct super_block *sb);
extern void ecfs_orphan_file_block_trigger(
				struct jbd2_buffer_trigger_type *triggers,
				struct buffer_head *bh,
				void *data, size_t size);

/*
 * Add new method to test whether block and inode bitmaps are properly
 * initialized. With uninit_bg reading the block from disk is not enough
 * to mark the bitmap uptodate. We need to also zero-out the bitmap
 */
#define BH_BITMAP_UPTODATE BH_JBDPrivateStart

static inline int bitmap_uptodate(struct buffer_head *bh)
{
	return (buffer_uptodate(bh) &&
			test_bit(BH_BITMAP_UPTODATE, &(bh)->b_state));
}
static inline void set_bitmap_uptodate(struct buffer_head *bh)
{
	set_bit(BH_BITMAP_UPTODATE, &(bh)->b_state);
}

extern int ecfs_resize_begin(struct super_block *sb);
extern int ecfs_resize_end(struct super_block *sb, bool update_backups);

static inline void ecfs_set_io_unwritten_flag(struct ecfs_io_end *io_end)
{
	if (!(io_end->flag & ECFS_IO_END_UNWRITTEN))
		io_end->flag |= ECFS_IO_END_UNWRITTEN;
}

static inline void ecfs_clear_io_unwritten_flag(ecfs_io_end_t *io_end)
{
	if (io_end->flag & ECFS_IO_END_UNWRITTEN)
		io_end->flag &= ~ECFS_IO_END_UNWRITTEN;
}

extern const struct iomap_ops ecfs_iomap_ops;
extern const struct iomap_ops ecfs_iomap_overwrite_ops;
extern const struct iomap_ops ecfs_iomap_report_ops;

static inline int ecfs_buffer_uptodate(struct buffer_head *bh)
{
	/*
	 * If the buffer has the write error flag, we have failed
	 * to write out data in the block.  In this  case, we don't
	 * have to read the block because we may read the old data
	 * successfully.
	 */
	if (buffer_write_io_error(bh))
		set_buffer_uptodate(bh);
	return buffer_uptodate(bh);
}

static inline bool ecfs_inode_can_atomic_write(struct inode *inode)
{

	return S_ISREG(inode->i_mode) &&
		ecfs_test_inode_flag(inode, ECFS_INODE_EXTENTS) &&
		ECFS_SB(inode->i_sb)->s_awu_min > 0;
}

extern int ecfs_block_write_begin(handle_t *handle, struct folio *folio,
				  loff_t pos, unsigned len,
				  get_block_t *get_block);
#endif	/* __KERNEL__ */

#define EFSBADCRC	EBADMSG		/* Bad CRC detected */
#define EFSCORRUPTED	EUCLEAN		/* Filesystem is corrupted */

#endif	/* _ECFS_H */
