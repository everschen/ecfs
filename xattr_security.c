// SPDX-License-Identifier: GPL-2.0
/*
 * linux/fs/ecfs/xattr_security.c
 * Handler for storing security labels as extended attributes.
 */

#include <linux/string.h>
#include <linux/fs.h>
#include <linux/security.h>
#include <linux/slab.h>
#include "ecfs_jbd2.h"
#include "ecfs.h"
#include "xattr.h"

static int
ecfs_xattr_security_get(const struct xattr_handler *handler,
			struct dentry *unused, struct inode *inode,
			const char *name, void *buffer, size_t size)
{
	return ecfs_xattr_get(inode, ECFS_XATTR_INDEX_SECURITY,
			      name, buffer, size);
}

static int
ecfs_xattr_security_set(const struct xattr_handler *handler,
			struct mnt_idmap *idmap,
			struct dentry *unused, struct inode *inode,
			const char *name, const void *value,
			size_t size, int flags)
{
	return ecfs_xattr_set(inode, ECFS_XATTR_INDEX_SECURITY,
			      name, value, size, flags);
}

static int
ecfs_initxattrs(struct inode *inode, const struct xattr *xattr_array,
		void *fs_info)
{
	const struct xattr *xattr;
	handle_t *handle = fs_info;
	int err = 0;

	for (xattr = xattr_array; xattr->name != NULL; xattr++) {
		err = ecfs_xattr_set_handle(handle, inode,
					    ECFS_XATTR_INDEX_SECURITY,
					    xattr->name, xattr->value,
					    xattr->value_len, XATTR_CREATE);
		if (err < 0)
			break;
	}
	return err;
}

int
ecfs_init_security(handle_t *handle, struct inode *inode, struct inode *dir,
		   const struct qstr *qstr)
{
	return security_inode_init_security(inode, dir, qstr,
					    &ecfs_initxattrs, handle);
}

const struct xattr_handler ecfs_xattr_security_handler = {
	.prefix	= XATTR_SECURITY_PREFIX,
	.get	= ecfs_xattr_security_get,
	.set	= ecfs_xattr_security_set,
};
