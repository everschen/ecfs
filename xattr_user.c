// SPDX-License-Identifier: GPL-2.0
/*
 * linux/fs/ecfs/xattr_user.c
 * Handler for extended user attributes.
 *
 * Copyright (C) 2001 by Andreas Gruenbacher, <a.gruenbacher@computer.org>
 */

#include <linux/string.h>
#include <linux/fs.h>
#include "ecfs_jbd2.h"
#include "ecfs.h"
#include "xattr.h"

static bool
ecfs_xattr_user_list(struct dentry *dentry)
{
	return test_opt(dentry->d_sb, XATTR_USER);
}

static int
ecfs_xattr_user_get(const struct xattr_handler *handler,
		    struct dentry *unused, struct inode *inode,
		    const char *name, void *buffer, size_t size)
{
	if (!test_opt(inode->i_sb, XATTR_USER))
		return -EOPNOTSUPP;
	return ecfs_xattr_get(inode, ECFS_XATTR_INDEX_USER,
			      name, buffer, size);
}

static int
ecfs_xattr_user_set(const struct xattr_handler *handler,
		    struct mnt_idmap *idmap,
		    struct dentry *unused, struct inode *inode,
		    const char *name, const void *value,
		    size_t size, int flags)
{
	if (!test_opt(inode->i_sb, XATTR_USER))
		return -EOPNOTSUPP;
	return ecfs_xattr_set(inode, ECFS_XATTR_INDEX_USER,
			      name, value, size, flags);
}

const struct xattr_handler ecfs_xattr_user_handler = {
	.prefix	= XATTR_USER_PREFIX,
	.list	= ecfs_xattr_user_list,
	.get	= ecfs_xattr_user_get,
	.set	= ecfs_xattr_user_set,
};
