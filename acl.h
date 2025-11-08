// SPDX-License-Identifier: GPL-2.0
/*
  File: fs/ecfs/acl.h

  (C) 2001 Andreas Gruenbacher, <a.gruenbacher@computer.org>
*/

#include <linux/posix_acl_xattr.h>

#define ECFS_ACL_VERSION	0x0001

typedef struct {
	__le16		e_tag;
	__le16		e_perm;
	__le32		e_id;
} ecfs_acl_entry;

typedef struct {
	__le16		e_tag;
	__le16		e_perm;
} ecfs_acl_entry_short;

typedef struct {
	__le32		a_version;
} ecfs_acl_header;

static inline size_t ecfs_acl_size(int count)
{
	if (count <= 4) {
		return sizeof(ecfs_acl_header) +
		       count * sizeof(ecfs_acl_entry_short);
	} else {
		return sizeof(ecfs_acl_header) +
		       4 * sizeof(ecfs_acl_entry_short) +
		       (count - 4) * sizeof(ecfs_acl_entry);
	}
}

static inline int ecfs_acl_count(size_t size)
{
	ssize_t s;
	size -= sizeof(ecfs_acl_header);
	s = size - 4 * sizeof(ecfs_acl_entry_short);
	if (s < 0) {
		if (size % sizeof(ecfs_acl_entry_short))
			return -1;
		return size / sizeof(ecfs_acl_entry_short);
	} else {
		if (s % sizeof(ecfs_acl_entry))
			return -1;
		return s / sizeof(ecfs_acl_entry) + 4;
	}
}

#ifdef CONFIG_ECFS_FS_POSIX_ACL

/* acl.c */
struct posix_acl *ecfs_get_acl(struct inode *inode, int type, bool rcu);
int ecfs_set_acl(struct mnt_idmap *idmap, struct dentry *dentry,
		 struct posix_acl *acl, int type);
extern int ecfs_init_acl(handle_t *, struct inode *, struct inode *);

#else  /* CONFIG_ECFS_FS_POSIX_ACL */
#include <linux/sched.h>
#define ecfs_get_acl NULL
#define ecfs_set_acl NULL

static inline int
ecfs_init_acl(handle_t *handle, struct inode *inode, struct inode *dir)
{
	return 0;
}
#endif  /* CONFIG_ECFS_FS_POSIX_ACL */

