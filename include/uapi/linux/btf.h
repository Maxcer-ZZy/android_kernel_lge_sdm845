/* SPDX-License-Identifier: GPL-2.0 WITH Linux-syscall-note */
#ifndef _UAPI__LINUX_BTF_H__
#define _UAPI__LINUX_BTF_H__

#include <linux/types.h>

/* BTF header */
struct btf_header {
	__u16	magic;
	__u8	version;
	__u8	flags;
	__u32	hdr_len;
	__u32	type_off;
	__u32	type_len;
	__u32	str_off;
	__u32	str_len;
};

/* BTF type kinds */
#define BTF_KIND_UNKN		0
#define BTF_KIND_INT		1
#define BTF_KIND_PTR		2
#define BTF_KIND_ARRAY		3
#define BTF_KIND_STRUCT		4
#define BTF_KIND_UNION		5
#define BTF_KIND_ENUM		6
#define BTF_KIND_FWD		7
#define BTF_KIND_TYPEDEF	8
#define BTF_KIND_VOLATILE	9
#define BTF_KIND_CONST		10
#define BTF_KIND_RESTRICT	11
#define BTF_KIND_FUNC		12
#define BTF_KIND_FUNC_PROTO	13
#define BTF_KIND_VAR		14
#define BTF_KIND_DATASEC	15
#define BTF_KIND_MAX		16

/* BTF info encoding */
#define BTF_INFO_KIND(t)	(((t) >> 24) & 0x0f)
#define BTF_INFO_VLEN(t)	((t) & 0xffff)
#define BTF_INFO_FLAG(t)	(((t) >> 16) & 0xff)

/* BTF int encoding */
#define BTF_INT_SIGNED	(1 << 0)
#define BTF_INT_CHAR	(1 << 1)
#define BTF_INT_BOOL	(1 << 2)

/* BTF header flags */
#define BTF_F_COMPRESSED	(1 << 0)

/* BTF structs */
struct btf_type {
	__u32	name_off;
	__u32	info;
	__u32	size_or_var;
};

struct btf_int {
	__u32	array;
	__u32	base_type;
	__u32	value_offset;
};

struct btf_array {
	__u32	type;
	__u32	index_type;
	__u32.nelems;
};

struct btf_member {
	__u32	name_off;
	__u32	type;
	__u32	offset;
};

struct btf_enum {
	__u32	name_off;
	__s32	val;
};

struct btf_param {
	__u32	name_off;
	__u32	type;
};

struct btf_var {
	__u32 linkage;
};

struct btf_var_secinfo {
	__u32	type;
	__u32	offset;
	__u32	size;
};

#endif /* _UAPI__LINUX_BTF_H__ */
