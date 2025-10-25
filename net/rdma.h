// net/rdma.h
#ifndef ECFS_RDMA_H
#define ECFS_RDMA_H

#include <linux/types.h>       // 必须！u64, size_t

int ecfs_rdma_write(u64 node_id, void *buf, size_t len, u64 remote_addr);
#endif