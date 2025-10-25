// inode.c
#include <linux/slab.h>
#include <linux/fs.h>
#include "inode.h"
#include "super.h"

static struct kmem_cache *ecfs_inode_cache;

// 导出函数
int ecfs_inode_cache_create(void)
{
    ecfs_inode_cache = kmem_cache_create("ecfs_inode_cache",
                                         sizeof(struct ecfs_inode), 0,
                                         SLAB_RECLAIM_ACCOUNT, NULL);
    if (!ecfs_inode_cache)
        return -ENOMEM;
    printk(KERN_INFO "ECFS: inode cache created\n");
    return 0;
}
EXPORT_SYMBOL(ecfs_inode_cache_create);

void ecfs_inode_cache_destroy(void)
{
    if (ecfs_inode_cache) {
        kmem_cache_destroy(ecfs_inode_cache);
        printk(KERN_INFO "ECFS: inode cache destroyed\n");
    }
}
EXPORT_SYMBOL(ecfs_inode_cache_destroy);

struct inode *ecfs_alloc_inode(struct super_block *sb)
{
    struct ecfs_inode *ei = kmem_cache_alloc(ecfs_inode_cache, GFP_KERNEL);
    if (!ei)
        return NULL;
    return &ei->vfs_inode;  // 修复：ecfs_inode
}

void ecfs_destroy_inode(struct inode *inode)
{
    struct ecfs_inode *ei = container_of(inode, struct ecfs_inode, vfs_inode);
    kmem_cache_free(ecfs_inode_cache, ei);
}

struct inode *ecfs_new_inode(struct super_block *sb, struct inode *parent, umode_t mode)
{
    struct inode *inode = new_inode(sb);
    if (!inode)
        return NULL;

    inode->i_ino = get_next_ino();
    inode->i_mode = mode;

    // 修复：去掉多余的 'c'
    inode_update_time(inode, S_ATIME | S_MTIME | S_CTIME);

    if (S_ISDIR(mode)) {
        inode->i_op = &ecfs_dir_inode_ops;   // 修复：使用 ecfs_dir_inode_ops
        inode->i_fop = &ecfs_dir_ops;
        inc_nlink(inode);
    } else if (S_ISREG(mode)) {
        inode->i_op = &ecfs_inode_ops;
        inode->i_fop = &ecfs_file_ops;
    }

    return inode;
}

// inode.c 底部添加
const struct inode_operations ecfs_inode_ops = {
    .lookup = simple_lookup,
};
