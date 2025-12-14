# SPDX-License-Identifier: GPL-2.0
#
# Makefile for the linux ecfs-filesystem routines.
#

ifneq ($(KERNELRELEASE),)

obj-m += ecfs.o

ecfs-objs	:= balloc.o bitmap.o block_validity.o dir.o ecfs_jbd2.o extents.o \
		extents_status.o file.o fsmap.o fsync.o hash.o ialloc.o \
		indirect.o inline.o inode.o ioctl.o mballoc.o migrate.o \
		mmp.o move_extent.o namei.o page-io.o readpage.o resize.o \
		super.o symlink.o sysfs.o xattr.o xattr_hurd.o xattr_trusted.o \
		xattr_user.o fast_commit.o orphan.o

ccflags-y += -I$(src)/../../include

ecfs-objs += \
	$(if $(CONFIG_ECFS_FS_POSIX_ACL),acl.o) \
	$(if $(CONFIG_ECFS_FS_SECURITY),xattr_security.o) \
	$(if $(CONFIG_FS_VERITY),verity.o) \
	$(if $(CONFIG_FS_ENCRYPTION),crypto.o)

# ecfs-$(CONFIG_ECFS_FS_POSIX_ACL)	+= acl.o
# ecfs-$(CONFIG_ECFS_FS_SECURITY)		+= xattr_security.o
# ecfs-inode-test-objs			+= inode-test.o
# obj-$(CONFIG_ECFS_KUNIT_TESTS)		+= ecfs-inode-test.o
# ecfs-$(CONFIG_FS_VERITY)		+= verity.o
# ecfs-$(CONFIG_FS_ENCRYPTION)		+= crypto.o

# CONFIG_KUNIT=y
# obj-m += ecfs-inode-test.o
# ecfs-inode-test-objs := inode-test.o

else
# ------------------- 外部构建阶段 -------------------

KDIR := /lib/modules/$(shell uname -r)/build
PWD  := $(shell pwd)

all:
	$(MAKE) -C $(KDIR) M=$(PWD) modules

clean:
	$(MAKE) -C $(KDIR) M=$(PWD) clean
	rm -f modules.order

endif
