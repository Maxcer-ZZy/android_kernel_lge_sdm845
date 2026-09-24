obj-y := core.o
CFLAGS_core.o += $(call cc-disable-warning, override-init)

obj-$(CONFIG_BPF_SYSCALL) += syscall.o verifier.o inode.o helpers.o btf.o
obj-$(CONFIG_BPF_SYSCALL) += hashtab.o arraymap.o percpu_freelist.o ringbuf.o lru_map.o
ifeq ($(CONFIG_PERF_EVENTS),y)
obj-$(CONFIG_BPF_SYSCALL) += stackmap.o
endif
obj-$(CONFIG_CGROUP_BPF) += cgroup.o
