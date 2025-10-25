// net/rdma.c
#include <linux/types.h>       // 必须！提供 u64, size_t
#include <linux/printk.h>
#include "rdma.h"

int ecfs_rdma_write(u64 node_id, void *buf, size_t len, u64 remote_addr)
{
    printk(KERN_INFO "ECFS RDMA stub: write to node %llu, addr %llu, len %zu\n",
           node_id, remote_addr, len);
    // 模拟成功
    return 0;
}