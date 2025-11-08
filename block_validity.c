// SPDX-License-Identifier: GPL-2.0
/*
 *  linux/fs/ecfs/block_validity.c
 *
 * Copyright (C) 2009
 * Theodore Ts'o (tytso@mit.edu)
 *
 * Track which blocks in the filesystem are metadata blocks that
 * should never be used as data blocks by files or directories.
 */

#include <linux/time.h>
#include <linux/fs.h>
#include <linux/namei.h>
#include <linux/quotaops.h>
#include <linux/buffer_head.h>
#include <linux/swap.h>
#include <linux/pagemap.h>
#include <linux/blkdev.h>
#include <linux/slab.h>
#include "ecfs.h"

struct ecfs_system_zone {
	struct rb_node	node;
	ecfs_fsblk_t	start_blk;
	unsigned int	count;
	u32		ino;
};

static struct kmem_cache *ecfs_system_zone_cachep;

int __init ecfs_init_system_zone(void)
{
	ecfs_system_zone_cachep = KMEM_CACHE(ecfs_system_zone, 0);
	if (ecfs_system_zone_cachep == NULL)
		return -ENOMEM;
	return 0;
}

void ecfs_exit_system_zone(void)
{
	rcu_barrier();
	kmem_cache_destroy(ecfs_system_zone_cachep);
}

static inline int can_merge(struct ecfs_system_zone *entry1,
		     struct ecfs_system_zone *entry2)
{
	if ((entry1->start_blk + entry1->count) == entry2->start_blk &&
	    entry1->ino == entry2->ino)
		return 1;
	return 0;
}

static void release_system_zone(struct ecfs_system_blocks *system_blks)
{
	struct ecfs_system_zone	*entry, *n;

	rbtree_postorder_for_each_entry_safe(entry, n,
				&system_blks->root, node)
		kmem_cache_free(ecfs_system_zone_cachep, entry);
}

/*
 * Mark a range of blocks as belonging to the "system zone" --- that
 * is, filesystem metadata blocks which should never be used by
 * inodes.
 */
static int add_system_zone(struct ecfs_system_blocks *system_blks,
			   ecfs_fsblk_t start_blk,
			   unsigned int count, u32 ino)
{
	struct ecfs_system_zone *new_entry, *entry;
	struct rb_node **n = &system_blks->root.rb_node, *node;
	struct rb_node *parent = NULL, *new_node;

	while (*n) {
		parent = *n;
		entry = rb_entry(parent, struct ecfs_system_zone, node);
		if (start_blk < entry->start_blk)
			n = &(*n)->rb_left;
		else if (start_blk >= (entry->start_blk + entry->count))
			n = &(*n)->rb_right;
		else	/* Unexpected overlap of system zones. */
			return -EFSCORRUPTED;
	}

	new_entry = kmem_cache_alloc(ecfs_system_zone_cachep,
				     GFP_KERNEL);
	if (!new_entry)
		return -ENOMEM;
	new_entry->start_blk = start_blk;
	new_entry->count = count;
	new_entry->ino = ino;
	new_node = &new_entry->node;

	rb_link_node(new_node, parent, n);
	rb_insert_color(new_node, &system_blks->root);

	/* Can we merge to the left? */
	node = rb_prev(new_node);
	if (node) {
		entry = rb_entry(node, struct ecfs_system_zone, node);
		if (can_merge(entry, new_entry)) {
			new_entry->start_blk = entry->start_blk;
			new_entry->count += entry->count;
			rb_erase(node, &system_blks->root);
			kmem_cache_free(ecfs_system_zone_cachep, entry);
		}
	}

	/* Can we merge to the right? */
	node = rb_next(new_node);
	if (node) {
		entry = rb_entry(node, struct ecfs_system_zone, node);
		if (can_merge(new_entry, entry)) {
			new_entry->count += entry->count;
			rb_erase(node, &system_blks->root);
			kmem_cache_free(ecfs_system_zone_cachep, entry);
		}
	}
	return 0;
}

static void debug_print_tree(struct ecfs_sb_info *sbi)
{
	struct rb_node *node;
	struct ecfs_system_zone *entry;
	struct ecfs_system_blocks *system_blks;
	int first = 1;

	printk(KERN_INFO "System zones: ");
	rcu_read_lock();
	system_blks = rcu_dereference(sbi->s_system_blks);
	node = rb_first(&system_blks->root);
	while (node) {
		entry = rb_entry(node, struct ecfs_system_zone, node);
		printk(KERN_CONT "%s%llu-%llu", first ? "" : ", ",
		       entry->start_blk, entry->start_blk + entry->count - 1);
		first = 0;
		node = rb_next(node);
	}
	rcu_read_unlock();
	printk(KERN_CONT "\n");
}

static int ecfs_protect_reserved_inode(struct super_block *sb,
				       struct ecfs_system_blocks *system_blks,
				       u32 ino)
{
	struct inode *inode;
	struct ecfs_sb_info *sbi = ECFS_SB(sb);
	struct ecfs_map_blocks map;
	u32 i = 0, num;
	int err = 0, n;

	if ((ino < ECFS_ROOT_INO) ||
	    (ino > le32_to_cpu(sbi->s_es->s_inodes_count)))
		return -EINVAL;
	inode = ecfs_iget(sb, ino, ECFS_IGET_SPECIAL);
	if (IS_ERR(inode))
		return PTR_ERR(inode);
	num = (inode->i_size + sb->s_blocksize - 1) >> sb->s_blocksize_bits;
	while (i < num) {
		cond_resched();
		map.m_lblk = i;
		map.m_len = num - i;
		n = ecfs_map_blocks(NULL, inode, &map, 0);
		if (n < 0) {
			err = n;
			break;
		}
		if (n == 0) {
			i++;
		} else {
			err = add_system_zone(system_blks, map.m_pblk, n, ino);
			if (err < 0) {
				if (err == -EFSCORRUPTED) {
					ECFS_ERROR_INODE_ERR(inode, -err,
						"blocks %llu-%llu from inode overlap system zone",
						map.m_pblk,
						map.m_pblk + map.m_len - 1);
				}
				break;
			}
			i += n;
		}
	}
	iput(inode);
	return err;
}

static void ecfs_destroy_system_zone(struct rcu_head *rcu)
{
	struct ecfs_system_blocks *system_blks;

	system_blks = container_of(rcu, struct ecfs_system_blocks, rcu);
	release_system_zone(system_blks);
	kfree(system_blks);
}

/*
 * Build system zone rbtree which is used for block validity checking.
 *
 * The update of system_blks pointer in this function is protected by
 * sb->s_umount semaphore. However we have to be careful as we can be
 * racing with ecfs_inode_block_valid() calls reading system_blks rbtree
 * protected only by RCU. That's why we first build the rbtree and then
 * swap it in place.
 */
int ecfs_setup_system_zone(struct super_block *sb)
{
	ecfs_group_t ngroups = ecfs_get_groups_count(sb);
	struct ecfs_sb_info *sbi = ECFS_SB(sb);
	struct ecfs_system_blocks *system_blks;
	struct ecfs_group_desc *gdp;
	ecfs_group_t i;
	int ret;

	system_blks = kzalloc(sizeof(*system_blks), GFP_KERNEL);
	if (!system_blks)
		return -ENOMEM;

	for (i=0; i < ngroups; i++) {
		unsigned int meta_blks = ecfs_num_base_meta_blocks(sb, i);

		cond_resched();
		if (meta_blks != 0) {
			ret = add_system_zone(system_blks,
					ecfs_group_first_block_no(sb, i),
					meta_blks, 0);
			if (ret)
				goto err;
		}
		gdp = ecfs_get_group_desc(sb, i, NULL);
		ret = add_system_zone(system_blks,
				ecfs_block_bitmap(sb, gdp), 1, 0);
		if (ret)
			goto err;
		ret = add_system_zone(system_blks,
				ecfs_inode_bitmap(sb, gdp), 1, 0);
		if (ret)
			goto err;
		ret = add_system_zone(system_blks,
				ecfs_inode_table(sb, gdp),
				sbi->s_itb_per_group, 0);
		if (ret)
			goto err;
	}
	if (ecfs_has_feature_journal(sb) && sbi->s_es->s_journal_inum) {
		ret = ecfs_protect_reserved_inode(sb, system_blks,
				le32_to_cpu(sbi->s_es->s_journal_inum));
		if (ret)
			goto err;
	}

	/*
	 * System blks rbtree complete, announce it once to prevent racing
	 * with ecfs_inode_block_valid() accessing the rbtree at the same
	 * time.
	 */
	rcu_assign_pointer(sbi->s_system_blks, system_blks);

	if (test_opt(sb, DEBUG))
		debug_print_tree(sbi);
	return 0;
err:
	release_system_zone(system_blks);
	kfree(system_blks);
	return ret;
}

/*
 * Called when the filesystem is unmounted or when remounting it with
 * noblock_validity specified.
 *
 * The update of system_blks pointer in this function is protected by
 * sb->s_umount semaphore. However we have to be careful as we can be
 * racing with ecfs_inode_block_valid() calls reading system_blks rbtree
 * protected only by RCU. So we first clear the system_blks pointer and
 * then free the rbtree only after RCU grace period expires.
 */
void ecfs_release_system_zone(struct super_block *sb)
{
	struct ecfs_system_blocks *system_blks;

	system_blks = rcu_dereference_protected(ECFS_SB(sb)->s_system_blks,
					lockdep_is_held(&sb->s_umount));
	rcu_assign_pointer(ECFS_SB(sb)->s_system_blks, NULL);

	if (system_blks)
		call_rcu(&system_blks->rcu, ecfs_destroy_system_zone);
}

int ecfs_sb_block_valid(struct super_block *sb, struct inode *inode,
				ecfs_fsblk_t start_blk, unsigned int count)
{
	struct ecfs_sb_info *sbi = ECFS_SB(sb);
	struct ecfs_system_blocks *system_blks;
	struct ecfs_system_zone *entry;
	struct rb_node *n;
	int ret = 1;

	if ((start_blk <= le32_to_cpu(sbi->s_es->s_first_data_block)) ||
	    (start_blk + count < start_blk) ||
	    (start_blk + count > ecfs_blocks_count(sbi->s_es)))
		return 0;

	/*
	 * Lock the system zone to prevent it being released concurrently
	 * when doing a remount which inverse current "[no]block_validity"
	 * mount option.
	 */
	rcu_read_lock();
	system_blks = rcu_dereference(sbi->s_system_blks);
	if (system_blks == NULL)
		goto out_rcu;

	n = system_blks->root.rb_node;
	while (n) {
		entry = rb_entry(n, struct ecfs_system_zone, node);
		if (start_blk + count - 1 < entry->start_blk)
			n = n->rb_left;
		else if (start_blk >= (entry->start_blk + entry->count))
			n = n->rb_right;
		else {
			ret = 0;
			if (inode)
				ret = (entry->ino == inode->i_ino);
			break;
		}
	}
out_rcu:
	rcu_read_unlock();
	return ret;
}

/*
 * Returns 1 if the passed-in block region (start_blk,
 * start_blk+count) is valid; 0 if some part of the block region
 * overlaps with some other filesystem metadata blocks.
 */
int ecfs_inode_block_valid(struct inode *inode, ecfs_fsblk_t start_blk,
			  unsigned int count)
{
	return ecfs_sb_block_valid(inode->i_sb, inode, start_blk, count);
}

int ecfs_check_blockref(const char *function, unsigned int line,
			struct inode *inode, __le32 *p, unsigned int max)
{
	__le32 *bref = p;
	unsigned int blk;
	journal_t *journal = ECFS_SB(inode->i_sb)->s_journal;

	if (journal && inode == journal->j_inode)
		return 0;

	while (bref < p+max) {
		blk = le32_to_cpu(*bref++);
		if (blk &&
		    unlikely(!ecfs_inode_block_valid(inode, blk, 1))) {
			ecfs_error_inode(inode, function, line, blk,
					 "invalid block");
			return -EFSCORRUPTED;
		}
	}
	return 0;
}

