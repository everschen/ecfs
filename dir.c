// dir.c
#include <linux/fs.h>
#include <linux/slab.h>
#include <linux/cred.h>
#include "inode.h"
#include "dir.h"
#include "super.h"

static struct dentry *ecfs_mkdir(struct mnt_idmap *idmap, struct inode *dir,
                                struct dentry *dentry, umode_t mode)
{
    struct inode *inode;
    struct dentry *ret;

    // 1. 创建 inode
    inode = ecfs_new_inode(dir->i_sb, dir, S_IFDIR | (mode & 0777));
    if (!inode)
        return ERR_PTR(-ENOMEM);

    // 2. 增加链接计数
    inc_nlink(dir);
    inc_nlink(inode);

    // 3. 调用 vfs_mkdir，它返回 dentry（成功返回原 dentry）
    ret = vfs_mkdir(idmap, dir, dentry, mode & 0777);
    if (IS_ERR(ret)) {
        int err = PTR_ERR(ret);
        drop_nlink(inode);
        drop_nlink(dir);
        iput(inode);
        return ERR_PTR(err);
    }

    // 4. 绑定 inode
    d_instantiate(dentry, inode);
    return NULL;  // 成功
}

static int ecfs_create(struct mnt_idmap *idmap, struct inode *dir,
                       struct dentry *dentry, umode_t mode, bool excl)
{
    struct inode *inode = ecfs_new_inode(dir->i_sb, dir, mode);
    if (!inode)
        return -ENOMEM;

    d_instantiate(dentry, inode);
    return 0;
}

const struct inode_operations ecfs_dir_inode_ops = {
    .create = ecfs_create,   // 返回 int
    .mkdir  = ecfs_mkdir,    // 返回 struct dentry *
    .lookup = simple_lookup,
};

const struct file_operations ecfs_dir_ops = {
    .open           = simple_open,
    .iterate_shared = iterate_dir,
    .llseek         = generic_file_llseek,
};