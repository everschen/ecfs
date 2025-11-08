// SPDX-License-Identifier: GPL-2.0
/*
 * linux/fs/ecfs/xattr_trusted.c
 * Handler for trusted extended attributes.
 *
 * Copyright (C) 2003 by Andreas Gruenbacher, <a.gruenbacher@computer.org>
 */

#include <linux/string.h>
#include <linux/capability.h>
#include <linux/fs.h>
#include "ecfs_jbd2.h"
#include "ecfs.h"
#include "xattr.h"

static bool
ecfs_xattr_trusted_list(struct dentry *dentry)
{
	return capable(CAP_SYS_ADMIN);
}

static int
ecfs_xattr_trusted_get(const struct xattr_handler *handler,
		       struct dentry *unused, struct inode *inode,
		       const char *name, void *buffer, size_t size)
{
	return ecfs_xattr_get(inode, ECFS_XATTR_INDEX_TRUSTED,
			      name, buffer, size);
}

static int
ecfs_xattr_trusted_set(const struct xattr_handler *handler,
		       struct mnt_idmap *idmap,
		       struct dentry *unused, struct inode *inode,
		       const char *name, const void *value,
		       size_t size, int flags)
{
	return ecfs_xattr_set(inode, ECFS_XATTR_INDEX_TRUSTED,
			      name, value, size, flags);
}

const struct xattr_handler ecfs_xattr_trusted_handler = {
	.prefix	= XATTR_TRUSTED_PREFIX,
	.list	= ecfs_xattr_trusted_list,
	.get	= ecfs_xattr_trusted_get,
	.set	= ecfs_xattr_trusted_set,
};
