// ecfs_main.c
#include <linux/module.h>
#include <linux/fs.h>
#include <linux/printk.h>
#include "super.h"
#include "inode.h"      // 必须包含！
#include "net/net.h"
#include "meta/meta.h"
#include "meta/raft.h"
#include "net/rdma.h"

extern int ecfs_meta_init(void);
extern void ecfs_meta_exit(void);

static struct dentry *ecfs_mount(struct file_system_type *fs_type, int flags,
                                const char *dev_name, void *data)
{
    return mount_bdev(fs_type, flags, dev_name, data, ecfs_fill_super);
}

static struct file_system_type ecfs_fs_type = {
    .owner      = THIS_MODULE,
    .name       = "ecfs",
    .mount      = ecfs_mount,
    .kill_sb    = kill_block_super,
    .fs_flags   = FS_REQUIRES_DEV | FS_USERNS_MOUNT,
};

static int __init ecfs_init(void)
{
    int ret;

    ret = ecfs_inode_cache_create();
    if (ret) return ret;

    ret = ecfs_net_init();
    if (ret) goto err_cache;

    ret = ecfs_meta_init();   // 新增
    if (ret) goto err_net;

    ret = ecfs_raft_init();
    if (ret) goto err_meta;

    ret = register_filesystem(&ecfs_fs_type);
    if (ret) goto err_raft;

    printk(KERN_INFO "ECFS: loaded on Linux 6.17.0\n");
    return 0;

err_raft:
    ecfs_raft_exit();
err_meta:
    ecfs_meta_exit();
err_net:
    ecfs_net_exit();
err_cache:
    ecfs_inode_cache_destroy();
    return ret;
}

// 退出
static void __exit ecfs_exit(void)
{
    unregister_filesystem(&ecfs_fs_type);
    ecfs_raft_exit();
    ecfs_meta_exit();         // 新增
    ecfs_net_exit();
    ecfs_inode_cache_destroy();
    printk(KERN_INFO "ECFS: unloaded\n");
}

module_init(ecfs_init);
module_exit(ecfs_exit);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("ECFS Team");
MODULE_DESCRIPTION("Enterprise Cloud File System - Kernel Distributed FS");