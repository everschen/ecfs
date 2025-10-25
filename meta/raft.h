// meta/raft.h
#ifndef ECFS_RAFT_H
#define ECFS_RAFT_H

#include <linux/types.h>

struct super_block;

int ecfs_raft_init(void);
void ecfs_raft_exit(void);
int ecfs_raft_join(struct super_block *sb);
void ecfs_raft_leave(struct super_block *sb);
int ecfs_raft_log_create(u64 parent, const char *name, u64 ino, u32 mode);

#endif