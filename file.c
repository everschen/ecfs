// file.c
#include <linux/fs.h>
#include <linux/uio.h>
#include <linux/slab.h>
#include "inode.h"
#include "file.h"
#include "super.h"
#include "ec/reed_solomon.h"

static ssize_t ecfs_file_read_iter(struct kiocb *iocb, struct iov_iter *iter)
{
    struct inode *inode = file_inode(iocb->ki_filp);
    struct ecfs_inode *ei = container_of(inode, struct ecfs_inode, vfs_inode);
    loff_t pos = iocb->ki_pos;
    size_t count = iov_iter_count(iter);
    char *buf;
    ssize_t ret;

    if (!count)
        return 0;

    buf = kzalloc(count, GFP_KERNEL);
    if (!buf)
        return -ENOMEM;

    // 模拟：从内存中读取（实际应从网络/纠删码）
    ret = simple_read_from_buffer(buf, count, &pos, "ECFS stub data", 14);
    if (ret > 0)
        ret = copy_to_iter(buf, ret, iter);

    kfree(buf);
    if (ret > 0)
        iocb->ki_pos += ret;

    return ret;
}

static ssize_t ecfs_file_write_iter(struct kiocb *iocb, struct iov_iter *iter)
{
    struct inode *inode = file_inode(iocb->ki_filp);
    struct ecfs_inode *ei = container_of(inode, struct ecfs_inode, vfs_inode);
    loff_t pos = iocb->ki_pos;
    size_t count = iov_iter_count(iter);
    char *buf;
    ssize_t ret;

    if (!count)
        return 0;

    buf = kzalloc(count, GFP_KERNEL);
    if (!buf)
        return -ENOMEM;

    ret = copy_from_iter(buf, count, iter);
    if (ret <= 0) {
        kfree(buf);
        return ret;
    }

    // 模拟：写入内存（实际应写到网络 + 纠删码）
    printk(KERN_INFO "ECFS write: %.*s\n", (int)ret, buf);

    kfree(buf);
    iocb->ki_pos += ret;
    inode->i_size = max(inode->i_size, pos + ret);
    inode_update_time(inode, S_MTIME | S_CTIME);

    return ret;
}

const struct file_operations ecfs_file_ops = {
    .read_iter     = ecfs_file_read_iter,
    .write_iter    = ecfs_file_write_iter,
    .llseek        = generic_file_llseek,
    .open          = simple_open,
};