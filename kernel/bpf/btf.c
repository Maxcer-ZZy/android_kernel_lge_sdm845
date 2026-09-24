// SPDX-License-Identifier: GPL-2.0
/*
 * BTF (BPF Type Format) - simplified implementation for 4.9 backport
 * Adapted from upstream Linux 5.10 kernel/bpf/btf.c
 */
#include <uapi/linux/btf.h>
#include <linux/btf.h>
#include <linux/bpf.h>
#include <linux/syscalls.h>
#include <linux/uaccess.h>
#include <linux/slab.h>
#include <linux/string.h>
#include <linux/errno.h>
#include <linux/rwsem.h>
#include <linux/idr.h>
#include <linux/capability.h>

static DEFINE_MUTEX(btf_mutex);
static DEFINE_IDR(btf_idr);
static DEFINE_SPINLOCK(btf_id_lock);

#define BTF_MAGIC	0xEB9F
#define BTF_VERSION	1
#define BTF_MAX_KINDS	16

struct btf {
	void *data;
	struct btf *base;
	u32 data_size;
	u32 data_len;
	u32 str_size;
	u32 str_len;
	u32 id;
	u32 num_types;
	u32 str_off;
	atomic64_t refcnt;
};

struct btf *btf_alloc(u32 data_size, u32 data_len, u32 str_size, u32 str_len)
{
	struct btf *btf;

	btf = kzalloc(sizeof(*btf), GFP_KERNEL);
	if (!btf)
		return ERR_PTR(-ENOMEM);

	btf->data = kvmalloc(data_len, GFP_KERNEL);
	if (!btf->data) {
		kfree(btf);
		return ERR_PTR(-ENOMEM);
	}

	btf->data_size = data_size;
	btf->data_len = data_len;
	btf->str_size = str_size;
	btf->str_len = str_len;
	atomic64_set(&btf->refcnt, 1);

	return btf;
}

void btf_put(struct btf *btf)
{
	if (!btf)
		return;

	if (atomic64_dec_and_test(&btf->refcnt)) {
		kvfree(btf->data);
		kfree(btf);
	}
}

struct btf *btf_get(u32 id)
{
	struct btf *btf;

	spin_lock_bh(&btf_id_lock);
	btf = idr_find(&btf_idr, id);
	if (btf)
		atomic64_inc(&btf->refcnt);
	spin_unlock_bh(&btf_id_lock);

	return btf;
}

const char *btf_name(const struct btf *btf, u32 name_off)
{
	if (!btf || name_off >= btf->str_len)
		return "<invalid>";

	return &btf->data[btf->str_off + name_off];
}

const struct btf_type *btf_type_by_id(const struct btf *btf, u32 id)
{
	const struct btf_type *t;

	if (id == 0 || id >= btf->num_types)
		return NULL;

	t = (const struct btf_type *)(btf->data +
		sizeof(struct btf_header) + id * sizeof(struct btf_type));

	return t;
}

int btf_validate(const struct btf *btf)
{
	const struct btf_type *t;
	u32 i;

	for (i = 1; i < btf->num_types; i++) {
		t = btf_type_by_id(btf, i);
		if (!t)
			return -EINVAL;
		if (BTF_INFO_KIND(t->info) >= BTF_MAX_KINDS)
			return -EINVAL;
	}

	return 0;
}

int btf_find_by_name_kind(const struct btf *btf, u32 start_type_id,
			  const char *name, u8 kind)
{
	u32 i;

	for (i = start_type_id; i < btf->num_types; i++) {
		const struct btf_type *t = btf_type_by_id(btf, i);
		const char *tname;

		if (BTF_INFO_KIND(t->info) != kind)
			continue;

		tname = btf_name(btf, t->name_off);
		if (strcmp(tname, name) == 0)
			return i;
	}

	return 0;
}

static int btf_load(void __user *btf_data, u32 btf_data_size)
{
	struct btf_header hdr;
	struct btf *btf;
	void *data;
	int err;

	if (btf_data_size < sizeof(hdr))
		return -EINVAL;

	if (copy_from_user(&hdr, btf_data, sizeof(hdr)))
		return -EFAULT;

	if (hdr.magic != BTF_MAGIC)
		return -EINVAL;

	if (hdr.version != BTF_VERSION)
		return -EINVAL;

	data = kvmalloc(btf_data_size, GFP_KERNEL);
	if (!data)
		return -ENOMEM;

	if (copy_from_user(data, btf_data, btf_data_size)) {
		kvfree(data);
		return -EFAULT;
	}

	btf = kzalloc(sizeof(*btf), GFP_KERNEL);
	if (!btf) {
		kvfree(data);
		return -ENOMEM;
	}

	btf->data = data;
	btf->data_size = btf_data_size;
	btf->str_off = sizeof(hdr) + le32_to_cpu(hdr.type_off);
	btf->str_len = le32_to_cpu(hdr.str_len);
	btf->data_len = sizeof(hdr) + le32_to_cpu(hdr.type_off) +
			le32_to_cpu(hdr.type_len) + le32_to_cpu(hdr.str_len);

	err = btf_validate(btf);
	if (err) {
		kvfree(data);
		kfree(btf);
		return err;
	}

	mutex_lock(&btf_mutex);
	err = idr_alloc(&btf_idr, btf, 1, INT_MAX, GFP_KERNEL);
	if (err < 0) {
		mutex_unlock(&btf_mutex);
		kvfree(data);
		kfree(btf);
		return err;
	}
	btf->id = err;
	mutex_unlock(&btf_mutex);

	return btf->id;
}

int bpf_btf_load(union bpf_attr *attr)
{
	void __user *ubuf;

	if (attr->btf_size == 0)
		return -EINVAL;

	if (!capable(CAP_SYS_ADMIN))
		return -EPERM;

	ubuf = u64_to_user_ptr(attr->btf);
	if (!access_ok(ubuf, attr->btf_size))
		return -EFAULT;

	return btf_load(ubuf, attr->btf_size);
}

int bpf_btf_get_fd_by_id(union bpf_attr *attr)
{
	struct btf *btf;
	int fd;

	btf = btf_get(attr->btf.id);
	if (!btf)
		return -ENOENT;

	fd = get_unused_fd_flags(O_CLOEXEC);
	if (fd < 0) {
		btf_put(btf);
		return fd;
	}

	fd_install(fd, btf->data_file);
	btf_put(btf);

	return fd;
}

struct btf *btf_get_by_fd(u32 fd)
{
	struct fd f;
	struct btf *btf;

	f = fdget(fd);
	if (!f.file)
		return ERR_PTR(-EBADF);

	btf = f.file->private_data;
	if (!btf) {
		fdput(f);
		return ERR_PTR(-EINVAL);
	}

	atomic64_inc(&btf->refcnt);
	fdput(f);

	return btf;
}

int btf_get_by_fd_info(struct btf *btf, struct file *btf_file,
		       union bpf_attr *uattr)
{
	return -EOPNOTSUPP;
}

void __init btf_init(void)
{
}
