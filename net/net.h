// net/net.h
#ifndef ECFS_NET_H
#define ECFS_NET_H

#include <linux/types.h>

int ecfs_net_init(void);
void ecfs_net_exit(void);
u64 ecfs_net_get_node_id(void);
int ecfs_net_send(u64 node_id, void *data, size_t len);

#endif