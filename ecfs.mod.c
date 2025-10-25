#include <linux/module.h>
#include <linux/export-internal.h>
#include <linux/compiler.h>

MODULE_INFO(name, KBUILD_MODNAME);

__visible struct module __this_module
__section(".gnu.linkonce.this_module") = {
	.name = KBUILD_MODNAME,
	.init = init_module,
#ifdef CONFIG_MODULE_UNLOAD
	.exit = cleanup_module,
#endif
	.arch = MODULE_ARCH_INIT,
};

KSYMTAB_FUNC(ecfs_inode_cache_create, "", "");
KSYMTAB_FUNC(ecfs_inode_cache_destroy, "", "");

SYMBOL_CRC(ecfs_inode_cache_create, 0x7851be11, "");
SYMBOL_CRC(ecfs_inode_cache_destroy, 0xd272d446, "");

static const struct modversion_info ____versions[]
__used __section("__versions") = {
	{ 0xa61fd7aa, "__check_object_size" },
	{ 0x3f221523, "d_instantiate" },
	{ 0x611ca149, "_copy_to_iter" },
	{ 0xd710adbf, "__kmalloc_noprof" },
	{ 0xbf8c476a, "new_inode" },
	{ 0x49a42492, "unregister_filesystem" },
	{ 0xcb3690fb, "iterate_dir" },
	{ 0xd5aa961b, "simple_statfs" },
	{ 0xb74a498a, "d_make_root" },
	{ 0xcb8b6ec6, "kfree" },
	{ 0x26417f80, "iput" },
	{ 0xd2c7d4a1, "get_next_ino" },
	{ 0x49a42492, "register_filesystem" },
	{ 0xd272d446, "__fentry__" },
	{ 0x3d855eb2, "vfs_mkdir" },
	{ 0xee58b086, "kill_block_super" },
	{ 0xe8213e80, "_printk" },
	{ 0xbd03ed67, "__ref_stack_chk_guard" },
	{ 0xd272d446, "__stack_chk_fail" },
	{ 0x09f09a8e, "simple_open" },
	{ 0xbd03ed67, "random_kmalloc_seed" },
	{ 0xb8d25b0c, "kmem_cache_free" },
	{ 0xd272d446, "__x86_return_thunk" },
	{ 0x8c5d7c40, "kmem_cache_alloc_noprof" },
	{ 0x53a74968, "inode_update_time" },
	{ 0x3d576eac, "__kmem_cache_create_args" },
	{ 0x129538ce, "mount_bdev" },
	{ 0x26417f80, "inc_nlink" },
	{ 0x2a327652, "__kmalloc_cache_noprof" },
	{ 0x546c19d9, "validate_usercopy_range" },
	{ 0xd9990e7f, "_copy_from_iter" },
	{ 0x3d3011aa, "simple_lookup" },
	{ 0xed2f3700, "generic_file_llseek" },
	{ 0x437e81c7, "simple_read_from_buffer" },
	{ 0x26417f80, "drop_nlink" },
	{ 0x30622947, "kmalloc_caches" },
	{ 0xc46acdad, "kmem_cache_destroy" },
	{ 0x4749ded2, "module_layout" },
};

static const u32 ____version_ext_crcs[]
__used __section("__version_ext_crcs") = {
	0xa61fd7aa,
	0x3f221523,
	0x611ca149,
	0xd710adbf,
	0xbf8c476a,
	0x49a42492,
	0xcb3690fb,
	0xd5aa961b,
	0xb74a498a,
	0xcb8b6ec6,
	0x26417f80,
	0xd2c7d4a1,
	0x49a42492,
	0xd272d446,
	0x3d855eb2,
	0xee58b086,
	0xe8213e80,
	0xbd03ed67,
	0xd272d446,
	0x09f09a8e,
	0xbd03ed67,
	0xb8d25b0c,
	0xd272d446,
	0x8c5d7c40,
	0x53a74968,
	0x3d576eac,
	0x129538ce,
	0x26417f80,
	0x2a327652,
	0x546c19d9,
	0xd9990e7f,
	0x3d3011aa,
	0xed2f3700,
	0x437e81c7,
	0x26417f80,
	0x30622947,
	0xc46acdad,
	0x4749ded2,
};
static const char ____version_ext_names[]
__used __section("__version_ext_names") =
	"__check_object_size\0"
	"d_instantiate\0"
	"_copy_to_iter\0"
	"__kmalloc_noprof\0"
	"new_inode\0"
	"unregister_filesystem\0"
	"iterate_dir\0"
	"simple_statfs\0"
	"d_make_root\0"
	"kfree\0"
	"iput\0"
	"get_next_ino\0"
	"register_filesystem\0"
	"__fentry__\0"
	"vfs_mkdir\0"
	"kill_block_super\0"
	"_printk\0"
	"__ref_stack_chk_guard\0"
	"__stack_chk_fail\0"
	"simple_open\0"
	"random_kmalloc_seed\0"
	"kmem_cache_free\0"
	"__x86_return_thunk\0"
	"kmem_cache_alloc_noprof\0"
	"inode_update_time\0"
	"__kmem_cache_create_args\0"
	"mount_bdev\0"
	"inc_nlink\0"
	"__kmalloc_cache_noprof\0"
	"validate_usercopy_range\0"
	"_copy_from_iter\0"
	"simple_lookup\0"
	"generic_file_llseek\0"
	"simple_read_from_buffer\0"
	"drop_nlink\0"
	"kmalloc_caches\0"
	"kmem_cache_destroy\0"
	"module_layout\0"
;

MODULE_INFO(depends, "");


MODULE_INFO(srcversion, "F9F2F21EBBB5E6D8BAF76E0");
