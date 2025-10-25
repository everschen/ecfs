// dir.h
#ifndef ECFS_DIR_H
#define ECFS_DIR_H

#include <linux/fs.h>

extern const struct inode_operations ecfs_dir_inode_ops;
extern const struct file_operations ecfs_dir_ops;

#endif