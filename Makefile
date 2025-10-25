# Makefile
obj-m += ecfs.o

ecfs-objs := ecfs_main.o \
             super.o \
             inode.o \
             file.o \
             dir.o \
             net/net.o \
             net/rdma.o \
             meta/raft.o \
             meta/meta.o \
             ec/reed_solomon.o \
             crypto/aes_gcm.o

KDIR ?= /lib/modules/$(shell uname -r)/build

all:
	$(MAKE) -C $(KDIR) M=$(PWD) modules

clean:
	$(MAKE) -C $(KDIR) M=$(PWD) clean