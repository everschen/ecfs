// SPDX-License-Identifier: GPL-2.0
/*
 *  linux/fs/ecfs/sysfs.c
 *
 * Copyright (C) 1992, 1993, 1994, 1995
 * Remy Card (card@masi.ibp.fr)
 * Theodore Ts'o (tytso@mit.edu)
 *
 */

#include <linux/time.h>
#include <linux/fs.h>
#include <linux/seq_file.h>
#include <linux/slab.h>
#include <linux/proc_fs.h>
#include <linux/part_stat.h>

#include "ecfs.h"
#include "ecfs_jbd2.h"

typedef enum {
	attr_noop,
	attr_delayed_allocation_blocks,
	attr_session_write_kbytes,
	attr_lifetime_write_kbytes,
	attr_reserved_clusters,
	attr_sra_exceeded_retry_limit,
	attr_inode_readahead,
	attr_trigger_test_error,
	attr_first_error_time,
	attr_last_error_time,
	attr_clusters_in_group,
	attr_mb_order,
	attr_feature,
	attr_pointer_pi,
	attr_pointer_ui,
	attr_pointer_ul,
	attr_pointer_u64,
	attr_pointer_u8,
	attr_pointer_string,
	attr_pointer_atomic,
	attr_journal_task,
} attr_id_t;

typedef enum {
	ptr_explicit,
	ptr_ecfs_sb_info_offset,
	ptr_ecfs_super_block_offset,
} attr_ptr_t;

static const char proc_dirname[] = "fs/ecfs";
static struct proc_dir_entry *ecfs_proc_root;

struct ecfs_attr {
	struct attribute attr;
	short attr_id;
	short attr_ptr;
	unsigned short attr_size;
	union {
		int offset;
		void *explicit_ptr;
	} u;
};

static ssize_t session_write_kbytes_show(struct ecfs_sb_info *sbi, char *buf)
{
	struct super_block *sb = sbi->s_buddy_cache->i_sb;

	return sysfs_emit(buf, "%lu\n",
			(part_stat_read(sb->s_bdev, sectors[STAT_WRITE]) -
			 sbi->s_sectors_written_start) >> 1);
}

static ssize_t lifetime_write_kbytes_show(struct ecfs_sb_info *sbi, char *buf)
{
	struct super_block *sb = sbi->s_buddy_cache->i_sb;

	return sysfs_emit(buf, "%llu\n",
			(unsigned long long)(sbi->s_kbytes_written +
			((part_stat_read(sb->s_bdev, sectors[STAT_WRITE]) -
			  ECFS_SB(sb)->s_sectors_written_start) >> 1)));
}

static ssize_t inode_readahead_blks_store(struct ecfs_sb_info *sbi,
					  const char *buf, size_t count)
{
	unsigned long t;
	int ret;

	ret = kstrtoul(skip_spaces(buf), 0, &t);
	if (ret)
		return ret;

	if (t && (!is_power_of_2(t) || t > 0x40000000))
		return -EINVAL;

	sbi->s_inode_readahead_blks = t;
	return count;
}

static ssize_t reserved_clusters_store(struct ecfs_sb_info *sbi,
				   const char *buf, size_t count)
{
	unsigned long long val;
	ecfs_fsblk_t clusters = (ecfs_blocks_count(sbi->s_es) >>
				 sbi->s_cluster_bits);
	int ret;

	ret = kstrtoull(skip_spaces(buf), 0, &val);
	if (ret || val >= clusters || (s64)val < 0)
		return -EINVAL;

	atomic64_set(&sbi->s_resv_clusters, val);
	return count;
}

static ssize_t trigger_test_error(struct ecfs_sb_info *sbi,
				  const char *buf, size_t count)
{
	int len = count;

	if (!capable(CAP_SYS_ADMIN))
		return -EPERM;

	if (len && buf[len-1] == '\n')
		len--;

	if (len)
		ecfs_error(sbi->s_sb, "%.*s", len, buf);
	return count;
}

static ssize_t journal_task_show(struct ecfs_sb_info *sbi, char *buf)
{
	if (!sbi->s_journal)
		return sysfs_emit(buf, "<none>\n");
	return sysfs_emit(buf, "%d\n",
			task_pid_vnr(sbi->s_journal->j_task));
}

#define ECFS_ATTR(_name,_mode,_id)					\
static struct ecfs_attr ecfs_attr_##_name = {				\
	.attr = {.name = __stringify(_name), .mode = _mode },		\
	.attr_id = attr_##_id,						\
}

#define ECFS_ATTR_FUNC(_name,_mode)  ECFS_ATTR(_name,_mode,_name)

#define ECFS_ATTR_FEATURE(_name)   ECFS_ATTR(_name, 0444, feature)

#define ECFS_ATTR_OFFSET(_name,_mode,_id,_struct,_elname)	\
static struct ecfs_attr ecfs_attr_##_name = {			\
	.attr = {.name = __stringify(_name), .mode = _mode },	\
	.attr_id = attr_##_id,					\
	.attr_ptr = ptr_##_struct##_offset,			\
	.u = {							\
		.offset = offsetof(struct _struct, _elname),\
	},							\
}

#define ECFS_ATTR_STRING(_name,_mode,_size,_struct,_elname)	\
static struct ecfs_attr ecfs_attr_##_name = {			\
	.attr = {.name = __stringify(_name), .mode = _mode },	\
	.attr_id = attr_pointer_string,				\
	.attr_size = _size,					\
	.attr_ptr = ptr_##_struct##_offset,			\
	.u = {							\
		.offset = offsetof(struct _struct, _elname),\
	},							\
}

#define ECFS_RO_ATTR_ES_UI(_name,_elname)				\
	ECFS_ATTR_OFFSET(_name, 0444, pointer_ui, ecfs_super_block, _elname)

#define ECFS_RO_ATTR_ES_U8(_name,_elname)				\
	ECFS_ATTR_OFFSET(_name, 0444, pointer_u8, ecfs_super_block, _elname)

#define ECFS_RO_ATTR_ES_U64(_name,_elname)				\
	ECFS_ATTR_OFFSET(_name, 0444, pointer_u64, ecfs_super_block, _elname)

#define ECFS_RO_ATTR_ES_STRING(_name,_elname,_size)			\
	ECFS_ATTR_STRING(_name, 0444, _size, ecfs_super_block, _elname)

#define ECFS_RW_ATTR_SBI_PI(_name,_elname)      \
	ECFS_ATTR_OFFSET(_name, 0644, pointer_pi, ecfs_sb_info, _elname)

#define ECFS_RW_ATTR_SBI_UI(_name,_elname)	\
	ECFS_ATTR_OFFSET(_name, 0644, pointer_ui, ecfs_sb_info, _elname)

#define ECFS_RW_ATTR_SBI_UL(_name,_elname)	\
	ECFS_ATTR_OFFSET(_name, 0644, pointer_ul, ecfs_sb_info, _elname)

#define ECFS_RO_ATTR_SBI_ATOMIC(_name,_elname)	\
	ECFS_ATTR_OFFSET(_name, 0444, pointer_atomic, ecfs_sb_info, _elname)

#define ECFS_ATTR_PTR(_name,_mode,_id,_ptr) \
static struct ecfs_attr ecfs_attr_##_name = {			\
	.attr = {.name = __stringify(_name), .mode = _mode },	\
	.attr_id = attr_##_id,					\
	.attr_ptr = ptr_explicit,				\
	.u = {							\
		.explicit_ptr = _ptr,				\
	},							\
}

#define ATTR_LIST(name) &ecfs_attr_##name.attr

ECFS_ATTR_FUNC(delayed_allocation_blocks, 0444);
ECFS_ATTR_FUNC(session_write_kbytes, 0444);
ECFS_ATTR_FUNC(lifetime_write_kbytes, 0444);
ECFS_ATTR_FUNC(reserved_clusters, 0644);
ECFS_ATTR_FUNC(sra_exceeded_retry_limit, 0444);

ECFS_ATTR_OFFSET(inode_readahead_blks, 0644, inode_readahead,
		 ecfs_sb_info, s_inode_readahead_blks);
ECFS_ATTR_OFFSET(mb_group_prealloc, 0644, clusters_in_group,
		 ecfs_sb_info, s_mb_group_prealloc);
ECFS_ATTR_OFFSET(mb_best_avail_max_trim_order, 0644, mb_order,
		 ecfs_sb_info, s_mb_best_avail_max_trim_order);
ECFS_RW_ATTR_SBI_UI(inode_goal, s_inode_goal);
ECFS_RW_ATTR_SBI_UI(mb_stats, s_mb_stats);
ECFS_RW_ATTR_SBI_UI(mb_max_to_scan, s_mb_max_to_scan);
ECFS_RW_ATTR_SBI_UI(mb_min_to_scan, s_mb_min_to_scan);
ECFS_RW_ATTR_SBI_UI(mb_order2_req, s_mb_order2_reqs);
ECFS_RW_ATTR_SBI_UI(mb_stream_req, s_mb_stream_request);
ECFS_RW_ATTR_SBI_UI(mb_max_linear_groups, s_mb_max_linear_groups);
ECFS_RW_ATTR_SBI_UI(extent_max_zeroout_kb, s_extent_max_zeroout_kb);
ECFS_ATTR(trigger_fs_error, 0200, trigger_test_error);
ECFS_RW_ATTR_SBI_PI(err_ratelimit_interval_ms, s_err_ratelimit_state.interval);
ECFS_RW_ATTR_SBI_PI(err_ratelimit_burst, s_err_ratelimit_state.burst);
ECFS_RW_ATTR_SBI_PI(warning_ratelimit_interval_ms, s_warning_ratelimit_state.interval);
ECFS_RW_ATTR_SBI_PI(warning_ratelimit_burst, s_warning_ratelimit_state.burst);
ECFS_RW_ATTR_SBI_PI(msg_ratelimit_interval_ms, s_msg_ratelimit_state.interval);
ECFS_RW_ATTR_SBI_PI(msg_ratelimit_burst, s_msg_ratelimit_state.burst);
#ifdef CONFIG_ECFS_DEBUG
ECFS_RW_ATTR_SBI_UL(simulate_fail, s_simulate_fail);
#endif
ECFS_RO_ATTR_SBI_ATOMIC(warning_count, s_warning_count);
ECFS_RO_ATTR_SBI_ATOMIC(msg_count, s_msg_count);
ECFS_RO_ATTR_ES_UI(errors_count, s_error_count);
ECFS_RO_ATTR_ES_U8(first_error_errcode, s_first_error_errcode);
ECFS_RO_ATTR_ES_U8(last_error_errcode, s_last_error_errcode);
ECFS_RO_ATTR_ES_UI(first_error_ino, s_first_error_ino);
ECFS_RO_ATTR_ES_UI(last_error_ino, s_last_error_ino);
ECFS_RO_ATTR_ES_U64(first_error_block, s_first_error_block);
ECFS_RO_ATTR_ES_U64(last_error_block, s_last_error_block);
ECFS_RO_ATTR_ES_UI(first_error_line, s_first_error_line);
ECFS_RO_ATTR_ES_UI(last_error_line, s_last_error_line);
ECFS_RO_ATTR_ES_STRING(first_error_func, s_first_error_func, 32);
ECFS_RO_ATTR_ES_STRING(last_error_func, s_last_error_func, 32);
ECFS_ATTR(first_error_time, 0444, first_error_time);
ECFS_ATTR(last_error_time, 0444, last_error_time);
ECFS_ATTR(journal_task, 0444, journal_task);
ECFS_RW_ATTR_SBI_UI(mb_prefetch, s_mb_prefetch);
ECFS_RW_ATTR_SBI_UI(mb_prefetch_limit, s_mb_prefetch_limit);
ECFS_RW_ATTR_SBI_UL(last_trim_minblks, s_last_trim_minblks);
ECFS_RW_ATTR_SBI_UI(sb_update_sec, s_sb_update_sec);
ECFS_RW_ATTR_SBI_UI(sb_update_kb, s_sb_update_kb);

static unsigned int old_bump_val = 128;
ECFS_ATTR_PTR(max_writeback_mb_bump, 0444, pointer_ui, &old_bump_val);

static struct attribute *ecfs_attrs[] = {
	ATTR_LIST(delayed_allocation_blocks),
	ATTR_LIST(session_write_kbytes),
	ATTR_LIST(lifetime_write_kbytes),
	ATTR_LIST(reserved_clusters),
	ATTR_LIST(sra_exceeded_retry_limit),
	ATTR_LIST(inode_readahead_blks),
	ATTR_LIST(inode_goal),
	ATTR_LIST(mb_stats),
	ATTR_LIST(mb_max_to_scan),
	ATTR_LIST(mb_min_to_scan),
	ATTR_LIST(mb_order2_req),
	ATTR_LIST(mb_stream_req),
	ATTR_LIST(mb_group_prealloc),
	ATTR_LIST(mb_max_linear_groups),
	ATTR_LIST(max_writeback_mb_bump),
	ATTR_LIST(extent_max_zeroout_kb),
	ATTR_LIST(trigger_fs_error),
	ATTR_LIST(err_ratelimit_interval_ms),
	ATTR_LIST(err_ratelimit_burst),
	ATTR_LIST(warning_ratelimit_interval_ms),
	ATTR_LIST(warning_ratelimit_burst),
	ATTR_LIST(msg_ratelimit_interval_ms),
	ATTR_LIST(msg_ratelimit_burst),
	ATTR_LIST(mb_best_avail_max_trim_order),
	ATTR_LIST(errors_count),
	ATTR_LIST(warning_count),
	ATTR_LIST(msg_count),
	ATTR_LIST(first_error_ino),
	ATTR_LIST(last_error_ino),
	ATTR_LIST(first_error_block),
	ATTR_LIST(last_error_block),
	ATTR_LIST(first_error_line),
	ATTR_LIST(last_error_line),
	ATTR_LIST(first_error_func),
	ATTR_LIST(last_error_func),
	ATTR_LIST(first_error_errcode),
	ATTR_LIST(last_error_errcode),
	ATTR_LIST(first_error_time),
	ATTR_LIST(last_error_time),
	ATTR_LIST(journal_task),
#ifdef CONFIG_ECFS_DEBUG
	ATTR_LIST(simulate_fail),
#endif
	ATTR_LIST(mb_prefetch),
	ATTR_LIST(mb_prefetch_limit),
	ATTR_LIST(last_trim_minblks),
	ATTR_LIST(sb_update_sec),
	ATTR_LIST(sb_update_kb),
	NULL,
};
ATTRIBUTE_GROUPS(ecfs);

/* Features this copy of ecfs supports */
ECFS_ATTR_FEATURE(lazy_itable_init);
ECFS_ATTR_FEATURE(batched_discard);
ECFS_ATTR_FEATURE(meta_bg_resize);
#ifdef CONFIG_FS_ENCRYPTION
ECFS_ATTR_FEATURE(encryption);
ECFS_ATTR_FEATURE(test_dummy_encryption_v2);
#endif
#if IS_ENABLED(CONFIG_UNICODE)
ECFS_ATTR_FEATURE(casefold);
#endif
#ifdef CONFIG_FS_VERITY
ECFS_ATTR_FEATURE(verity);
#endif
ECFS_ATTR_FEATURE(metadata_csum_seed);
ECFS_ATTR_FEATURE(fast_commit);
#if IS_ENABLED(CONFIG_UNICODE) && defined(CONFIG_FS_ENCRYPTION)
ECFS_ATTR_FEATURE(encrypted_casefold);
#endif

static struct attribute *ecfs_feat_attrs[] = {
	ATTR_LIST(lazy_itable_init),
	ATTR_LIST(batched_discard),
	ATTR_LIST(meta_bg_resize),
#ifdef CONFIG_FS_ENCRYPTION
	ATTR_LIST(encryption),
	ATTR_LIST(test_dummy_encryption_v2),
#endif
#if IS_ENABLED(CONFIG_UNICODE)
	ATTR_LIST(casefold),
#endif
#ifdef CONFIG_FS_VERITY
	ATTR_LIST(verity),
#endif
	ATTR_LIST(metadata_csum_seed),
	ATTR_LIST(fast_commit),
#if IS_ENABLED(CONFIG_UNICODE) && defined(CONFIG_FS_ENCRYPTION)
	ATTR_LIST(encrypted_casefold),
#endif
	NULL,
};
ATTRIBUTE_GROUPS(ecfs_feat);

static void *calc_ptr(struct ecfs_attr *a, struct ecfs_sb_info *sbi)
{
	switch (a->attr_ptr) {
	case ptr_explicit:
		return a->u.explicit_ptr;
	case ptr_ecfs_sb_info_offset:
		return (void *) (((char *) sbi) + a->u.offset);
	case ptr_ecfs_super_block_offset:
		return (void *) (((char *) sbi->s_es) + a->u.offset);
	}
	return NULL;
}

static ssize_t __print_tstamp(char *buf, __le32 lo, __u8 hi)
{
	return sysfs_emit(buf, "%lld\n",
			((time64_t)hi << 32) + le32_to_cpu(lo));
}

#define print_tstamp(buf, es, tstamp) \
	__print_tstamp(buf, (es)->tstamp, (es)->tstamp ## _hi)

static ssize_t ecfs_generic_attr_show(struct ecfs_attr *a,
				      struct ecfs_sb_info *sbi, char *buf)
{
	void *ptr = calc_ptr(a, sbi);

	if (!ptr)
		return 0;

	switch (a->attr_id) {
	case attr_inode_readahead:
	case attr_clusters_in_group:
	case attr_mb_order:
	case attr_pointer_pi:
	case attr_pointer_ui:
		if (a->attr_ptr == ptr_ecfs_super_block_offset)
			return sysfs_emit(buf, "%u\n", le32_to_cpup(ptr));
		return sysfs_emit(buf, "%u\n", *((unsigned int *) ptr));
	case attr_pointer_ul:
		return sysfs_emit(buf, "%lu\n", *((unsigned long *) ptr));
	case attr_pointer_u8:
		return sysfs_emit(buf, "%u\n", *((unsigned char *) ptr));
	case attr_pointer_u64:
		if (a->attr_ptr == ptr_ecfs_super_block_offset)
			return sysfs_emit(buf, "%llu\n", le64_to_cpup(ptr));
		return sysfs_emit(buf, "%llu\n", *((unsigned long long *) ptr));
	case attr_pointer_string:
		return sysfs_emit(buf, "%.*s\n", a->attr_size, (char *) ptr);
	case attr_pointer_atomic:
		return sysfs_emit(buf, "%d\n", atomic_read((atomic_t *) ptr));
	}
	return 0;
}

static ssize_t ecfs_attr_show(struct kobject *kobj,
			      struct attribute *attr, char *buf)
{
	struct ecfs_sb_info *sbi = container_of(kobj, struct ecfs_sb_info,
						s_kobj);
	struct ecfs_attr *a = container_of(attr, struct ecfs_attr, attr);

	switch (a->attr_id) {
	case attr_delayed_allocation_blocks:
		return sysfs_emit(buf, "%llu\n",
				(s64) ECFS_C2B(sbi,
		       percpu_counter_sum(&sbi->s_dirtyclusters_counter)));
	case attr_session_write_kbytes:
		return session_write_kbytes_show(sbi, buf);
	case attr_lifetime_write_kbytes:
		return lifetime_write_kbytes_show(sbi, buf);
	case attr_reserved_clusters:
		return sysfs_emit(buf, "%llu\n",
				(unsigned long long)
				atomic64_read(&sbi->s_resv_clusters));
	case attr_sra_exceeded_retry_limit:
		return sysfs_emit(buf, "%llu\n",
				(unsigned long long)
			percpu_counter_sum(&sbi->s_sra_exceeded_retry_limit));
	case attr_feature:
		return sysfs_emit(buf, "supported\n");
	case attr_first_error_time:
		return print_tstamp(buf, sbi->s_es, s_first_error_time);
	case attr_last_error_time:
		return print_tstamp(buf, sbi->s_es, s_last_error_time);
	case attr_journal_task:
		return journal_task_show(sbi, buf);
	default:
		return ecfs_generic_attr_show(a, sbi, buf);
	}
}

static ssize_t ecfs_generic_attr_store(struct ecfs_attr *a,
				       struct ecfs_sb_info *sbi,
				       const char *buf, size_t len)
{
	int ret;
	unsigned int t;
	unsigned long lt;
	void *ptr = calc_ptr(a, sbi);

	if (!ptr)
		return 0;

	switch (a->attr_id) {
	case attr_pointer_pi:
		ret = kstrtouint(skip_spaces(buf), 0, &t);
		if (ret)
			return ret;
		if ((int)t < 0)
			return -EINVAL;
		*((unsigned int *) ptr) = t;
		return len;
	case attr_pointer_ui:
		ret = kstrtouint(skip_spaces(buf), 0, &t);
		if (ret)
			return ret;
		if (a->attr_ptr == ptr_ecfs_super_block_offset)
			*((__le32 *) ptr) = cpu_to_le32(t);
		else
			*((unsigned int *) ptr) = t;
		return len;
	case attr_mb_order:
		ret = kstrtouint(skip_spaces(buf), 0, &t);
		if (ret)
			return ret;
		if (t > 64)
			return -EINVAL;
		*((unsigned int *) ptr) = t;
		return len;
	case attr_clusters_in_group:
		ret = kstrtouint(skip_spaces(buf), 0, &t);
		if (ret)
			return ret;
		if (t > sbi->s_clusters_per_group)
			return -EINVAL;
		*((unsigned int *) ptr) = t;
		return len;
	case attr_pointer_ul:
		ret = kstrtoul(skip_spaces(buf), 0, &lt);
		if (ret)
			return ret;
		*((unsigned long *) ptr) = lt;
		return len;
	}
	return 0;
}

static ssize_t ecfs_attr_store(struct kobject *kobj,
			       struct attribute *attr,
			       const char *buf, size_t len)
{
	struct ecfs_sb_info *sbi = container_of(kobj, struct ecfs_sb_info,
						s_kobj);
	struct ecfs_attr *a = container_of(attr, struct ecfs_attr, attr);

	switch (a->attr_id) {
	case attr_reserved_clusters:
		return reserved_clusters_store(sbi, buf, len);
	case attr_inode_readahead:
		return inode_readahead_blks_store(sbi, buf, len);
	case attr_trigger_test_error:
		return trigger_test_error(sbi, buf, len);
	default:
		return ecfs_generic_attr_store(a, sbi, buf, len);
	}
}

static void ecfs_sb_release(struct kobject *kobj)
{
	struct ecfs_sb_info *sbi = container_of(kobj, struct ecfs_sb_info,
						s_kobj);
	complete(&sbi->s_kobj_unregister);
}

static void ecfs_feat_release(struct kobject *kobj)
{
	kfree(kobj);
}

static const struct sysfs_ops ecfs_attr_ops = {
	.show	= ecfs_attr_show,
	.store	= ecfs_attr_store,
};

static const struct kobj_type ecfs_sb_ktype = {
	.default_groups = ecfs_groups,
	.sysfs_ops	= &ecfs_attr_ops,
	.release	= ecfs_sb_release,
};

static const struct kobj_type ecfs_feat_ktype = {
	.default_groups = ecfs_feat_groups,
	.sysfs_ops	= &ecfs_attr_ops,
	.release	= ecfs_feat_release,
};

void ecfs_notify_error_sysfs(struct ecfs_sb_info *sbi)
{
	sysfs_notify(&sbi->s_kobj, NULL, "errors_count");
}

static struct kobject *ecfs_root;

static struct kobject *ecfs_feat;

int ecfs_register_sysfs(struct super_block *sb)
{
	struct ecfs_sb_info *sbi = ECFS_SB(sb);
	int err;

	init_completion(&sbi->s_kobj_unregister);
	err = kobject_init_and_add(&sbi->s_kobj, &ecfs_sb_ktype, ecfs_root,
				   "%s", sb->s_id);
	if (err) {
		kobject_put(&sbi->s_kobj);
		wait_for_completion(&sbi->s_kobj_unregister);
		return err;
	}

	if (ecfs_proc_root)
		sbi->s_proc = proc_mkdir(sb->s_id, ecfs_proc_root);
	if (sbi->s_proc) {
		proc_create_single_data("options", S_IRUGO, sbi->s_proc,
				ecfs_seq_options_show, sb);
		proc_create_single_data("es_shrinker_info", S_IRUGO,
				sbi->s_proc, ecfs_seq_es_shrinker_info_show,
				sb);
		proc_create_single_data("fc_info", 0444, sbi->s_proc,
					ecfs_fc_info_show, sb);
		proc_create_seq_data("mb_groups", S_IRUGO, sbi->s_proc,
				&ecfs_mb_seq_groups_ops, sb);
		proc_create_single_data("mb_stats", 0444, sbi->s_proc,
				ecfs_seq_mb_stats_show, sb);
		proc_create_seq_data("mb_structs_summary", 0444, sbi->s_proc,
				&ecfs_mb_seq_structs_summary_ops, sb);
	}
	return 0;
}

void ecfs_unregister_sysfs(struct super_block *sb)
{
	struct ecfs_sb_info *sbi = ECFS_SB(sb);

	if (sbi->s_proc)
		remove_proc_subtree(sb->s_id, ecfs_proc_root);
	kobject_del(&sbi->s_kobj);
}

int __init ecfs_init_sysfs(void)
{
	int ret;

	ecfs_root = kobject_create_and_add("ecfs", fs_kobj);
	if (!ecfs_root)
		return -ENOMEM;

	ecfs_feat = kzalloc(sizeof(*ecfs_feat), GFP_KERNEL);
	if (!ecfs_feat) {
		ret = -ENOMEM;
		goto root_err;
	}

	ret = kobject_init_and_add(ecfs_feat, &ecfs_feat_ktype,
				   ecfs_root, "features");
	if (ret)
		goto feat_err;

	ecfs_proc_root = proc_mkdir(proc_dirname, NULL);
	return ret;

feat_err:
	kobject_put(ecfs_feat);
	ecfs_feat = NULL;
root_err:
	kobject_put(ecfs_root);
	ecfs_root = NULL;
	return ret;
}

void ecfs_exit_sysfs(void)
{
	kobject_put(ecfs_feat);
	ecfs_feat = NULL;
	kobject_put(ecfs_root);
	ecfs_root = NULL;
	remove_proc_entry(proc_dirname, NULL);
	ecfs_proc_root = NULL;
}

