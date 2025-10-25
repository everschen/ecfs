// net/net.c
#include <linux/types.h>
#include <linux/printk.h>
#include "net.h"

int ecfs_net_init(void) {
    printk(KERN_INFO "ECFS NET: initialized (stub)\n");
    return 0;
}

void ecfs_net_exit(void) {
    printk(KERN_INFO "ECFS NET: shutdown\n");
}

u64 ecfs_net_get_node_id(void) {
    return 1; // 模拟节点 ID
}

int ecfs_net_send(u64 node_id, void *data, size_t len) {
    return 0; // 模拟成功
}