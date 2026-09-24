/* SPDX-License-Identifier: GPL-2.0 */
/* Copyright (c) 2019 Facebook */
#ifndef _LINUX_BTF_H
#define _LINUX_BTF_H

#include <linux/types.h>
#include <uapi/linux/btf.h>

struct btf;

#ifdef CONFIG_BPF_JIT
#define BPF_MAX_ID	100000

struct btf *btf_alloc(u32 data_size, u32 data_len, u32 str_size, u32 str_len);
void btf_put(struct btf *btf);
struct btf *btf_get(u32 id);
const struct btf_type *btf_type_by_id(const struct btf *btf, u32 id);
const char *btf_name(const struct btf *btf, u32 name_off);
int btf_validate(const struct btf *btf);
int btf_find_by_name_kind(const struct btf *btf, u32 start_type_id,
			  const char *name, u8 kind);
int bpf_btf_load(union bpf_attr *attr);
int bpf_btf_get_fd_by_id(union bpf_attr *attr);
struct btf *btf_get_by_fd(u32 fd);
int btf_get_by_fd_info(struct btf *btf, struct file *btf_file,
		       union bpf_attr *uattr);
void __init btf_init(void);
int btf_sysfs_init(void);
void btf_module_exit(void);

static inline bool btf_vmlinux(void)
{
	return true;
}

#else
static inline struct btf *btf_alloc(u32 data_size, u32 data_len,
				    u32 str_size, u32 str_len)
{
	return ERR_PTR(-EOPNOTSUPP);
}

static inline void btf_put(struct btf *btf) {}
static inline struct btf *btf_get(u32 id)
{
	return ERR_PTR(-EOPNOTSUPP);
}

static inline const struct btf_type *btf_type_by_id(const struct btf *btf,
						    u32 id)
{
	return NULL;
}

static inline const char *btf_name(const struct btf *btf, u32 name_off)
{
	return "<no-btf>";
}

static inline int btf_validate(const struct btf *btf)
{
	return 0;
}

static inline int btf_find_by_name_kind(const struct btf *btf,
					u32 start_type_id,
					const char *name, u8 kind)
{
	return 0;
}

static inline int bpf_btf_load(union bpf_attr *attr)
{
	return -EOPNOTSUPP;
}

static inline int bpf_btf_get_fd_by_id(union bpf_attr *attr)
{
	return -EOPNOTSUPP;
}

static inline struct btf *btf_get_by_fd(u32 fd)
{
	return ERR_PTR(-EOPNOTSUPP);
}

static inline int btf_get_by_fd_info(struct btf *btf, struct file *btf_file,
				     union bpf_attr *uattr)
{
	return -EOPNOTSUPP;
}

static inline void btf_init(void) {}
static inline int btf_sysfs_init(void) { return 0; }
static inline void btf_module_exit(void) {}

static inline bool btf_vmlinux(void)
{
	return false;
}
#endif

#endif /* _LINUX_BTF_H */
