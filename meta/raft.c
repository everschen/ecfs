// meta/raft.c
#include "raft.h"
#include <linux/printk.h>

int ecfs_raft_init(void) {
    printk(KERN_INFO "ECFS Raft: initialized (stub)\n");
    return 0;
}

void ecfs_raft_exit() {
    printk(KERN_INFO "ECFS Raft: exit\n");
}

void ecfs_raft_leave(struct super_block *sb) {
    printk(KERN_INFO "ECFS Raft: shutdown\n");
}

int ecfs_raft_join(struct super_block *sb) {
    return 0;
}

int ecfs_raft_log_create(u64 parent, const char *name, u64 ino, u32 mode) {
    printk(KERN_INFO "Raft log: create %s ino=%llu\n", name, ino);
    return 0;
}