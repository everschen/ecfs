// inode.h
#ifndef ECFS_INODE_H
#define ECFS_INODE_H

#include <linux/fs.h>

struct ecfs_inode {
    struct inode vfs_inode;
    u64 ino;
    u64 parent_ino;
    u32 mode;
    u64 size;
    struct rw_semaphore lock;
};

// 必须导出
extern int ecfs_inode_cache_create(void);
extern void ecfs_inode_cache_destroy(void);

struct inode *ecfs_new_inode(struct super_block *sb, struct inode *parent, umode_t mode);
struct inode *ecfs_alloc_inode(struct super_block *sb);
void ecfs_destroy_inode(struct inode *inode);

#endif