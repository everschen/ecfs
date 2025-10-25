// ec/reed_solomon.c
#include <linux/types.h>
#include <linux/string.h>
#include <linux/printk.h>
#include "reed_solomon.h"

// 最小 stub：模拟纠删码编码/解码
ssize_t ecfs_rs_encode(void *data, size_t len)
{
    printk(KERN_INFO "ECFS RS: encode %zu bytes (stub)\n", len);
    return len;  // 成功
}

ssize_t ecfs_rs_decode(void *data, size_t len, char *buf)
{
    printk(KERN_INFO "ECFS RS: decode %zu bytes (stub)\n", len);
    memcpy(buf, data, len);
    return len;  // 成功
}