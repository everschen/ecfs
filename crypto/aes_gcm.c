// crypto/aes_gcm.c
#include <linux/types.h>
#include <linux/printk.h>
#include "aes_gcm.h"

// 最小 stub：模拟 AES-GCM 加密/解密
int ecfs_aes_encrypt(void *data, size_t len)
{
    printk(KERN_INFO "ECFS AES-GCM: encrypt %zu bytes (stub)\n", len);
    // 模拟：直接返回成功
    return 0;
}

int ecfs_aes_decrypt(void *data, size_t len)
{
    printk(KERN_INFO "ECFS AES-GCM: decrypt %zu bytes (stub)\n", len);
    // 模拟：直接返回成功
    return 0;
}