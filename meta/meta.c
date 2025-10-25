// meta/meta.c
#include <linux/printk.h>
#include <linux/types.h>
#include "meta.h"

int ecfs_meta_init(void)
{
    printk(KERN_INFO "ECFS Meta: initialized\n");
    return 0;
}

void ecfs_meta_exit(void)
{
    printk(KERN_INFO "ECFS Meta: exited\n");
}