// ec/reed_solomon.h
#ifndef ECFS_RS_H
#define ECFS_RS_H

#include <linux/types.h>

ssize_t ecfs_rs_encode(void *data, size_t len);
ssize_t ecfs_rs_decode(void *data, size_t len, char *buf);

#endif