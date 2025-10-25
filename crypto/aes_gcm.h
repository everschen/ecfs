// crypto/aes_gcm.h
#ifndef ECFS_CRYPTO_H
#define ECFS_CRYPTO_H

#include <linux/types.h>   // 必须！定义 size_t

int ecfs_aes_encrypt(void *data, size_t len);
int ecfs_aes_decrypt(void *data, size_t len);

#endif