// super.h
#ifndef ECFS_SUPER_H
#define ECFS_SUPER_H

#include <linux/fs.h>

struct ecfs_super_block {
    u64 magic;
    u64 node_id;
    spinlock_t lock;
};

extern const struct super_operations ecfs_sops;
extern const struct inode_operations ecfs_inode_ops;
extern const struct inode_operations ecfs_dir_inode_ops;
extern const struct file_operations ecfs_file_ops;
extern const struct file_operations ecfs_dir_ops;

int ecfs_fill_super(struct super_block *sb, void *data, int silent);

#endif