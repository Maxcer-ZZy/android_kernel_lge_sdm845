// SPDX-License-Identifier: GPL-2.0
/*
 * BPF LRU map - adapted from upstream Linux 5.10 kernel/bpf/lru_map.c
 * Simplified implementation for 4.9 kernel backport
 */
#include <linux/bpf.h>
#include <linux/slab.h>
#include <linux/list.h>
#include <linux/spinlock.h>

#define LRU_HASH_SIZE		65536
#define LRU_MAX_ENTRIES		(1 << 20)
#define LRU_NODE_SIZE		ALIGN(sizeof(struct bpf_lru_node), 8)
#define LRU_ELEMENT_SIZE	ALIGN(sizeof(struct lru_hash_elem), 8)

struct bpf_lru_node {
	struct list_head list;
	u32 hash;
};

struct lru_hash_elem {
	struct hlist_node hnode;
	struct bpf_lru_node lru_node;
	void *key;
	void *value;
	u32 hash;
};

struct bpf_lru_map {
	struct hlist_head *hash_table;
	struct list_head lru_list;
	spinlock_t lock;
	u32 key_size;
	u32 value_size;
	u32 max_entries;
	u32 hash_size;
};

static u32 lru_hash_func(struct bpf_lru_map *lru_map, void *key)
{
	u32 hash = 0;
	u8 *data = key;
	u32 i;

	for (i = 0; i < lru_map->key_size; i++)
		hash = hash * 31 + data[i];

	return hash % lru_map->hash_size;
}

static void lru_hash_free(struct bpf_lru_map *lru_map)
{
	struct lru_hash_elem *elem, *tmp;
	int i;

	for (i = 0; i < lru_map->hash_size; i++) {
		hlist_for_each_entry_safe(elem, tmp, &lru_map->hash_table[i], hnode) {
			hlist_del(&elem->hnode);
			kfree(elem);
		}
	}
	kfree(lru_map->hash_table);
}

static struct bpf_map *lru_hash_map_alloc(union bpf_attr *attr)
{
	struct bpf_lru_map *lru_map;
	u32 hash_size;

	if (attr->max_entries == 0 || attr->max_entries > LRU_MAX_ENTRIES)
		return ERR_PTR(-EINVAL);

	if (attr->key_size == 0 || attr->value_size == 0)
		return ERR_PTR(-EINVAL);

	hash_size = min_t(u32, attr->max_entries, LRU_HASH_SIZE);

	lru_map = kzalloc(sizeof(*lru_map), GFP_KERNEL);
	if (!lru_map)
		return ERR_PTR(-ENOMEM);

	lru_map->hash_table = kzalloc(sizeof(struct hlist_head) * hash_size,
				     GFP_KERNEL);
	if (!lru_map->hash_table) {
		kfree(lru_map);
		return ERR_PTR(-ENOMEM);
	}

	spin_lock_init(&lru_map->lock);
	INIT_LIST_HEAD(&lru_map->lru_list);
	lru_map->key_size = attr->key_size;
	lru_map->value_size = attr->value_size;
	lru_map->max_entries = attr->max_entries;
	lru_map->hash_size = hash_size;

	return (struct bpf_map *)lru_map;
}

static void lru_hash_map_release(struct bpf_map *map, struct file *map_file)
{
	struct bpf_lru_map *lru_map = (struct bpf_lru_map *)map;

	lru_hash_free(lru_map);
	kfree(lru_map);
}

static void *lru_hash_map_lookup_elem(struct bpf_map *map, void *key)
{
	struct bpf_lru_map *lru_map = (struct bpf_lru_map *)map;
	struct lru_hash_elem *elem;
	u32 hash;

	if (!key)
		return NULL;

	hash = lru_hash_func(lru_map, key);

	spin_lock_bh(&lru_map->lock);
	hlist_for_each_entry(elem, &lru_map->hash_table[hash], hnode) {
		if (memcmp(elem->key, key, lru_map->key_size) == 0) {
			/* Move to front (MRU) */
			list_del_init(&elem->lru_node.list);
			list_add(&elem->lru_node.list, &lru_map->lru_list);
			spin_unlock_bh(&lru_map->lock);
			return elem->value;
		}
	}
	spin_unlock_bh(&lru_map->lock);

	return NULL;
}

static int lru_hash_map_update_elem(struct bpf_map *map, void *key,
				   void *value, u64 flags)
{
	struct bpf_lru_map *lru_map = (struct bpf_lru_map *)map;
	struct lru_hash_elem *elem;
	u32 hash;

	if (!key || !value)
		return -EINVAL;

	hash = lru_hash_func(lru_map, key);

	/* Check if element already exists */
	spin_lock_bh(&lru_map->lock);
	hlist_for_each_entry(elem, &lru_map->hash_table[hash], hnode) {
		if (memcmp(elem->key, key, lru_map->key_size) == 0) {
			memcpy(elem->value, value, lru_map->value_size);
			/* Move to front (MRU) */
			list_del_init(&elem->lru_node.list);
			list_add(&elem->lru_node.list, &lru_map->lru_list);
			spin_unlock_bh(&lru_map->lock);
			return 0;
		}
	}
	spin_unlock_bh(&lru_map->lock);

	/* If map is full, evict LRU entry */
	if (hlist_empty(&lru_map->hash_table[hash]) == 0) {
		struct lru_hash_elem *lru_elem;

		spin_lock_bh(&lru_map->lock);
		lru_elem = list_first_entry(&lru_map->lru_list,
					   struct lru_hash_elem, lru_node.list);
		hlist_del(&lru_elem->hnode);
		list_del_init(&lru_elem->lru_node.list);
		spin_unlock_bh(&lru_map->lock);
		kfree(lru_elem);
	}

	/* Create new element */
	elem = kzalloc(sizeof(*elem), GFP_KERNEL);
	if (!elem)
		return -ENOMEM;

	elem->key = kmemdup(key, lru_map->key_size, GFP_KERNEL);
	elem->value = kmemdup(value, lru_map->value_size, GFP_KERNEL);
	if (!elem->key || !elem->value) {
		kfree(elem->key);
		kfree(elem->value);
		kfree(elem);
		return -ENOMEM;
	}

	elem->hash = hash;
	INIT_HLIST_NODE(&elem->hnode);
	INIT_LIST_HEAD(&elem->lru_node.list);

	spin_lock_bh(&lru_map->lock);
	hlist_add_head(&elem->hnode, &lru_map->hash_table[hash]);
	list_add(&elem->lru_node.list, &lru_map->lru_list);
	spin_unlock_bh(&lru_map->lock);

	return 0;
}

static int lru_hash_map_delete_elem(struct bpf_map *map, void *key)
{
	struct bpf_lru_map *lru_map = (struct bpf_lru_map *)map;
	struct lru_hash_elem *elem;
	u32 hash;

	if (!key)
		return -EINVAL;

	hash = lru_hash_func(lru_map, key);

	spin_lock_bh(&lru_map->lock);
	hlist_for_each_entry(elem, &lru_map->hash_table[hash], hnode) {
		if (memcmp(elem->key, key, lru_map->key_size) == 0) {
			hlist_del(&elem->hnode);
			list_del_init(&elem->lru_node.list);
			spin_unlock_bh(&lru_map->lock);
			kfree(elem->key);
			kfree(elem->value);
			kfree(elem);
			return 0;
		}
	}
	spin_unlock_bh(&lru_map->lock);

	return -ENOENT;
}

static int lru_hash_map_get_next_key(struct bpf_map *map, void *key,
				    void *next_key)
{
	struct bpf_lru_map *lru_map = (struct bpf_lru_map *)map;
	struct lru_hash_elem *elem;
	u32 hash;

	if (!key) {
		/* Return first element */
		int i;

		for (i = 0; i < lru_map->hash_size; i++) {
			hlist_for_each_entry(elem, &lru_map->hash_table[i], hnode) {
				memcpy(next_key, elem->key, lru_map->key_size);
				return 0;
			}
		}
		return -ENOENT;
	}

	hash = lru_hash_func(lru_map, key);
	hlist_for_each_entry(elem, &lru_map->hash_table[hash], hnode) {
		if (memcmp(elem->key, key, lru_map->key_size) == 0) {
			struct hlist_node *next = elem->hnode.next;

			if (next) {
				memcpy(next_key, hlist_entry(next,
					struct lru_hash_elem, hnode)->key,
					lru_map->key_size);
				return 0;
			}
		}
	}

	return -ENOENT;
}

const struct bpf_map_ops lru_hash_map_ops = {
	.map_alloc = lru_hash_map_alloc,
	.map_release = lru_hash_map_release,
	.map_update_elem = lru_hash_map_update_elem,
	.map_delete_elem = lru_hash_map_delete_elem,
	.map_lookup_elem = lru_hash_map_lookup_elem,
	.map_get_next_key = lru_hash_map_get_next_key,
};
