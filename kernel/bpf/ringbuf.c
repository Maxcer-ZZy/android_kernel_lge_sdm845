// SPDX-License-Identifier: GPL-2.0
/*
 * BPF ringbuf - adapted from upstream Linux 5.10 kernel/bpf/ringbuf.c
 * Simplified implementation for 4.9 kernel backport
 */
#include <linux/bpf.h>
#include <linux/spinlock.h>
#include <linux/ring_buffer.h>
#include <linux/wait.h>
#include <linux/slab.h>

#define RINGBUF_MAX_RECORD_SIZE	(1U << 28)

struct bpf_ringbuf_ring {
	wait_queue_head_t poll;
	struct list_head list;
	void *data;
	void *head;
	void *tail;
	u32 pages;
	u32 size;
};

struct bpf_ringbuf_record {
	u32 len;
	u32 pad;
};

static struct bpf_map *ringbuf_map_alloc(union bpf_attr *attr)
{
	struct bpf_ringbuf_ring *rb;
	struct bpf_map *map;

	if (attr->max_entries == 0 ||
	    attr->max_entries > RINGBUF_MAX_RECORD_SIZE)
		return ERR_PTR(-EINVAL);

	map = kzalloc(sizeof(*map), GFP_KERNEL);
	if (!map)
		return ERR_PTR(-ENOMEM);

	rb = kzalloc(sizeof(*rb), GFP_KERNEL);
	if (!rb) {
		kfree(map);
		return ERR_PTR(-ENOMEM);
	}

	rb->size = attr->max_entries;
	rb->pages = order_base_2((rb->size + PAGE_SIZE - 1) / PAGE_SIZE);

	/* For simplicity, allocate a single page for now */
	rb->data = (void *)__get_free_page(GFP_KERNEL | __GFP_ZERO);
	if (!rb->data) {
		kfree(rb);
		kfree(map);
		return ERR_PTR(-ENOMEM);
	}

	rb->head = rb->data;
	rb->tail = rb->data;
	init_waitqueue_head(&rb->poll);
	INIT_LIST_HEAD(&rb->list);

	map->ops = NULL; /* Will be set by ringbuf_ops */
	map->max_entries = rb->size;
	map->key_size = 0;
	map->value_size = sizeof(void *);

	return map;
}

static void ringbuf_map_release(struct bpf_map *map, struct file *map_file)
{
	struct bpf_ringbuf_ring *rb = map->map_priv;

	if (rb) {
		if (rb->data)
			free_pages((unsigned long)rb->data, 0);
		kfree(rb);
	}
}

static int ringbuf_map_update_elem(struct bpf_map *map, void *key,
				  void *value, u64 flags)
{
	/* Ring buffer is append-only */
	return -EOPNOTSUPP;
}

static int ringbuf_map_delete_elem(struct bpf_map *map, void *key)
{
	return -EOPNOTSUPP;
}

static void *ringbuf_map_lookup_elem(struct bpf_map *map, void *key)
{
	return NULL;
}

static int ringbuf_map_get_next_key(struct bpf_map *map, void *key,
				   void *next_key)
{
	return -ENOSPC;
}

static void *ringbuf_reserve(struct bpf_map *map, u32 size)
{
	struct bpf_ringbuf_ring *rb = map->map_priv;
	void *record;

	if (size == 0 || size > rb->size)
		return NULL;

	record = rb->head;
	if (record + size > rb->data + rb->size)
		record = rb->data; /* wrap around */

	rb->head = record + size;

	return record;
}

static void ringbuf_submit(void *record)
{
	/* Wake up any waiters */
	struct bpf_ringbuf_ring *rb = container_of(record, struct bpf_ringbuf_ring, data);
	wake_up_all(&rb->poll);
}

static void ringbuf_discard(void *record)
{
	/* Discard the record */
	struct bpf_ringbuf_ring *rb = container_of(record, struct bpf_ringbuf_ring, data);
	rb->head = record; /* reset head */
}

static u64 ringbuf_query(struct bpf_map *map, u64 flags)
{
	struct bpf_ringbuf_ring *rb = map->map_priv;
	void *head, *tail;

	switch (flags) {
	case BPF_RB_AVAIL_DATA:
		head = READ_ONCE(rb->head);
		tail = READ_ONCE(rb->tail);
		return (head - tail) % rb->size;
	case BPF_RB_RING_SIZE:
		return rb->size;
	case BPF_RB_CONS_POS:
		return (u64)READ_ONCE(rb->tail);
	case BPF_RB_PROD_POS:
		return (u64)READ_ONCE(rb->head);
	default:
		return 0;
	}
}

/* Helper functions for eBPF programs */
static void *bpf_ringbuf_reserve_helper(struct bpf_map *map, u64 flags,
					u64 size)
{
	if (flags != 0)
		return NULL;
	return ringbuf_map_lookup_elem(map, &size);
}

static void bpf_ringbuf_submit_helper(void *record, u64 flags)
{
	if (record)
		ringbuf_submit(record);
}

static void bpf_ringbuf_discard_helper(void *record, u64 flags)
{
	if (record)
		ringbuf_discard(record);
}

static u64 bpf_ringbuf_query_helper(struct bpf_map *map, u64 flags)
{
	return ringbuf_query(map, flags);
}

static void bpf_ringbuf_output_helper(struct bpf_map *map, void *data,
				      u64 size, u64 flags)
{
	void *record = ringbuf_map_lookup_elem(map, &size);
	if (record) {
		memcpy(record, data, size);
		ringbuf_submit(record);
	}
}

const struct bpf_map_ops ringbuf_map_ops = {
	.map_alloc = ringbuf_map_alloc,
	.map_release = ringbuf_map_release,
	.map_update_elem = ringbuf_map_update_elem,
	.map_delete_elem = ringbuf_map_delete_elem,
	.map_lookup_elem = ringbuf_map_lookup_elem,
	.map_get_next_key = ringbuf_map_get_next_key,
};
