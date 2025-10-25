// dir.c
#include <linux/fs.h>
#include <linux/slab.h>
#include <linux/cred.h>
#include "inode.h"
#include "dir.h"
#include "super.h"

static int ecfs_readdir(struct file *file, struct dir_context *ctx)
{
    struct inode *inode = file_inode(file);
    struct ecfs_inode *ei = inode->i_private;

    if (ctx->pos == 0) {
        if (!dir_emit_dot(file, ctx))
            return 0;
        ctx->pos = 1;
    }

    if (ctx->pos == 1) {
        ino_t parent_ino = ei->parent_ino ? ei->parent_ino : inode->i_ino;
        if (!dir_emit(ctx, "..", 2, parent_ino, DT_DIR))
            return 0;
        ctx->pos = 2;
    }

    return 0;
}

static struct dentry *ecfs_lookup(struct inode *dir, struct dentry *dentry, unsigned int flags)
{
    struct inode *inode = NULL;

    if (strcmp(dentry->d_name.name, "mydir") == 0) {
        inode = ecfs_new_inode(dir->i_sb, dir, S_IFDIR | 0755);
    } else if (strcmp(dentry->d_name.name, "file.txt") == 0) {
        inode = ecfs_new_inode(dir->i_sb, dir, S_IFREG | 0644);
    }

    if (!inode)
        return ERR_PTR(-ENOENT);

    d_add(dentry, inode);
    return NULL;
}

static struct dentry * ecfs_mkdir(struct mnt_idmap *idmap, struct inode *dir, struct dentry *dentry, umode_t mode)
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

static int ecfs_unlink(struct inode *dir, struct dentry *dentry)
{
    struct inode *inode = d_inode(dentry);
    drop_nlink(inode);
    d_delete(dentry);
    dput(dentry);
    return 0;
}

static int ecfs_rmdir(struct inode *dir, struct dentry *dentry)
{
    struct inode *inode = d_inode(dentry);
    if (!S_ISDIR(inode->i_mode)) return -ENOTDIR;
    if (inode->i_nlink > 2) return -ENOTEMPTY;
    drop_nlink(inode);
    drop_nlink(dir);
    d_delete(dentry);
    dput(dentry);
    return 0;
}

// 关键：使用 iterate_shared
const struct file_operations ecfs_dir_ops = {
    .llseek         = generic_file_llseek,
    .read           = generic_read_dir,
    .iterate_shared = ecfs_readdir,
    .fsync          = noop_fsync,
};

const struct inode_operations ecfs_dir_inode_ops = {
    .lookup         = ecfs_lookup,
    .mkdir          = ecfs_mkdir,
    .rmdir          = ecfs_rmdir,
    .create         = ecfs_create,
    .unlink         = ecfs_unlink,
};
