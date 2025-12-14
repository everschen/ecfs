#ifndef _LINUX_ECFS_H
#define _LINUX_ECFS_H

#include <linux/fs.h>
#include <linux/net.h>
#include <linux/in.h>
#include <linux/socket.h>
#include <linux/mutex.h>
#include <linux/workqueue.h>

struct ecfs_sb_info {
    struct socket *ctrl_sock;
    struct mutex meta_lock;
};

int ecfs_init_meta(void);
void ecfs_exit_meta(void);
int ecfs_send_net_msg(const char *msg, size_t len);
int ecfs_register_fs(void);
void ecfs_unregister_fs(void);

#endif
