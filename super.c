// super.c
#include <linux/slab.h>
#include "super.h"
#include "inode.h"
#include "meta/raft.h"
#include "net/net.h"

const struct super_operations ecfs_sops = {
    .alloc_inode    = ecfs_alloc_inode,
    .destroy_inode  = ecfs_destroy_inode,
    .statfs         = simple_statfs,
};

int ecfs_fill_super(struct super_block *sb, void *data, int silent)
{
    struct inode *root_inode;
    struct ecfs_super_block *esb;

    sb->s_magic = 0xECF5;
    sb->s_op = &ecfs_sops;
    sb->s_fs_info = kzalloc(sizeof(struct ecfs_super_block), GFP_KERNEL);
    if (!sb->s_fs_info)
        return -ENOMEM;

    esb = sb->s_fs_info;
    esb->magic = 0xECF5;
    esb->node_id = ecfs_net_get_node_id();
    spin_lock_init(&esb->lock);

    // 初始化 Raft
    if (ecfs_raft_join(sb)) {
        kfree(sb->s_fs_info);
        return -EIO;
    }

    // 创建根 inode
    root_inode = ecfs_new_inode(sb, NULL, S_IFDIR | 0755);
    if (!root_inode) {
        ecfs_raft_leave(sb);
        kfree(sb->s_fs_info);
        return -ENOMEM;
    }

    sb->s_root = d_make_root(root_inode);
    if (!sb->s_root) {
        ecfs_raft_leave(sb);
        kfree(sb->s_fs_info);
        return -ENOMEM;
    }

    printk(KERN_INFO "ECFS: superblock filled, root created\n");
    return 0;
}