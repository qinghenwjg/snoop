// This is a compact version of `vmlinux.h` to be used in the examples using C code.

#pragma once

typedef unsigned char __u8;
typedef short int __s16;
typedef short unsigned int __u16;
typedef int __s32;
typedef unsigned int __u32;
typedef long long int __s64;
typedef long long unsigned int __u64;
typedef __u8 u8;
typedef __s16 s16;
typedef __u16 u16;
typedef __s32 s32;
typedef __u32 u32;
typedef __s64 s64;
typedef __u64 u64;
typedef __u16 __le16;
typedef __u16 __be16;
typedef __u32 __be32;
typedef __u64 __be64;
typedef __u32 __wsum;

#include "bpf_helpers.h"
#include "bpf_core_read.h"

// enum bpf_map_type {
// 	BPF_MAP_TYPE_UNSPEC                = 0,
// 	BPF_MAP_TYPE_HASH                  = 1,
// 	BPF_MAP_TYPE_ARRAY                 = 2,
// 	BPF_MAP_TYPE_PROG_ARRAY            = 3,
// 	BPF_MAP_TYPE_PERF_EVENT_ARRAY      = 4,
// 	BPF_MAP_TYPE_PERCPU_HASH           = 5,
// 	BPF_MAP_TYPE_PERCPU_ARRAY          = 6,
// 	BPF_MAP_TYPE_STACK_TRACE           = 7,
// 	BPF_MAP_TYPE_CGROUP_ARRAY          = 8,
// 	BPF_MAP_TYPE_LRU_HASH              = 9,
// 	BPF_MAP_TYPE_LRU_PERCPU_HASH       = 10,
// 	BPF_MAP_TYPE_LPM_TRIE              = 11,
// 	BPF_MAP_TYPE_ARRAY_OF_MAPS         = 12,
// 	BPF_MAP_TYPE_HASH_OF_MAPS          = 13,
// 	BPF_MAP_TYPE_DEVMAP                = 14,
// 	BPF_MAP_TYPE_SOCKMAP               = 15,
// 	BPF_MAP_TYPE_CPUMAP                = 16,
// 	BPF_MAP_TYPE_XSKMAP                = 17,
// 	BPF_MAP_TYPE_SOCKHASH              = 18,
// 	BPF_MAP_TYPE_CGROUP_STORAGE        = 19,
// 	BPF_MAP_TYPE_REUSEPORT_SOCKARRAY   = 20,
// 	BPF_MAP_TYPE_PERCPU_CGROUP_STORAGE = 21,
// 	BPF_MAP_TYPE_QUEUE                 = 22,
// 	BPF_MAP_TYPE_STACK                 = 23,
// 	BPF_MAP_TYPE_SK_STORAGE            = 24,
// 	BPF_MAP_TYPE_DEVMAP_HASH           = 25,
// 	BPF_MAP_TYPE_STRUCT_OPS            = 26,
// 	BPF_MAP_TYPE_RINGBUF               = 27,
// 	BPF_MAP_TYPE_INODE_STORAGE         = 28,
// };

// enum xdp_action {
// 	XDP_ABORTED = 0,
// 	XDP_DROP = 1,
// 	XDP_PASS = 2,
// 	XDP_TX = 3,
// 	XDP_REDIRECT = 4,
// };

// struct xdp_md {
// 	__u32 data;
// 	__u32 data_end;
// 	__u32 data_meta;
// 	__u32 ingress_ifindex;
// 	__u32 rx_queue_index;
// 	__u32 egress_ifindex;
// };

typedef __u16 __sum16;

// #define ETH_P_IP 0x0800

// struct ethhdr {
// 	unsigned char h_dest[6];
// 	unsigned char h_source[6];
// 	__be16 h_proto;
// };

// struct iphdr {
// 	__u8 ihl: 4;
// 	__u8 version: 4;
// 	__u8 tos;
// 	__be16 tot_len;
// 	__be16 id;
// 	__be16 frag_off;
// 	__u8 ttl;
// 	__u8 protocol;
// 	__sum16 check;
// 	__be32 saddr;
// 	__be32 daddr;
// };

// enum {
// 	BPF_ANY     = 0,
// 	BPF_NOEXIST = 1,
// 	BPF_EXIST   = 2,
// 	BPF_F_LOCK  = 4,
// };

/* BPF_FUNC_perf_event_output, BPF_FUNC_perf_event_read and
 * BPF_FUNC_perf_event_read_value flags.
 */
// #define BPF_F_INDEX_MASK 0xffffffffULL
// #define BPF_F_CURRENT_CPU BPF_F_INDEX_MASK

// #if defined(__TARGET_ARCH_x86)


// struct pt_regs {
// 	/*
// 	 * C ABI says these regs are callee-preserved. They aren't saved on kernel entry
// 	 * unless syscall needs a complete, fully filled "struct pt_regs".
// 	 */
// 	unsigned long r15;
// 	unsigned long r14;
// 	unsigned long r13;
// 	unsigned long r12;
// 	unsigned long rbp;
// 	unsigned long rbx;
// 	/* These regs are callee-clobbered. Always saved on kernel entry. */
// 	unsigned long r11;
// 	unsigned long r10;
// 	unsigned long r9;
// 	unsigned long r8;
// 	unsigned long rax;
// 	unsigned long rcx;
// 	unsigned long rdx;
// 	unsigned long rsi;
// 	unsigned long rdi;
// 	/*
// 	 * On syscall entry, this is syscall#. On CPU exception, this is error code.
// 	 * On hw interrupt, it's IRQ number:
// 	 */
// 	unsigned long orig_rax;
// 	/* Return frame for iretq */
// 	unsigned long rip;
// 	unsigned long cs;
// 	unsigned long eflags;
// 	unsigned long rsp;
// 	unsigned long ss;
// 	/* top of stack page */
// };
// #endif /* __TARGET_ARCH_x86 */

// struct pt_regs {
//         long unsigned int r15;
//         long unsigned int r14;
//         long unsigned int r13;
//         long unsigned int r12;
//         long unsigned int bp;
//         long unsigned int bx;
//         long unsigned int r11;
//         long unsigned int r10;
//         long unsigned int r9;
//         long unsigned int r8;
//         long unsigned int ax;
//         long unsigned int cx;
//         long unsigned int dx;
//         long unsigned int si;
//         long unsigned int di;
//         long unsigned int orig_ax;
//         long unsigned int ip;
//         long unsigned int cs;
//         long unsigned int flags;
//         long unsigned int sp;
//         long unsigned int ss;
// };

#include "vmlinux.h"

static __always_inline void *
bpf_map_lookup_or_try_init(void *map, const void *key, const void *init)
{
	void *val;
	int err;

	val = bpf_map_lookup_elem(map, key);
	if (val)
		return val;

	err = bpf_map_update_elem(map, key, init, 0);
	if (err && err != -17)
		return 0;

	return bpf_map_lookup_elem(map, key);
}



#define PT_REGS_PARM1(ctx)      ((ctx)->di)
#define PT_REGS_PARM2(ctx)      ((ctx)->si)
#define PT_REGS_PARM3(ctx)      ((ctx)->dx)
#define PT_REGS_PARM4(ctx)      ((ctx)->cx)
#define PT_REGS_PARM5(ctx)      ((ctx)->r8)
#define PT_REGS_PARM6(ctx)      ((ctx)->r9)
#define PT_REGS_RET(ctx)        ((ctx)->sp)
#define PT_REGS_FP(ctx)         ((ctx)->bp) /* Works only with CONFIG_FRAME_POINTER */
#define PT_REGS_RC(ctx)         ((ctx)->ax)
#define PT_REGS_IP(ctx)         ((ctx)->ip)
#define PT_REGS_SP(ctx)         ((ctx)->sp)

#define PT_REGS_PARM1_CORE(x) BPF_CORE_READ((x), di)
#define PT_REGS_PARM2_CORE(x) BPF_CORE_READ((x), si)
#define PT_REGS_PARM3_CORE(x) BPF_CORE_READ((x), dx)
#define PT_REGS_PARM4_CORE(x) BPF_CORE_READ((x), cx)
#define PT_REGS_PARM5_CORE(x) BPF_CORE_READ((x), r8)
#define PT_REGS_RET_CORE(x) BPF_CORE_READ((x), sp)
#define PT_REGS_FP_CORE(x) BPF_CORE_READ((x), bp)
#define PT_REGS_RC_CORE(x) BPF_CORE_READ((x), ax)
#define PT_REGS_SP_CORE(x) BPF_CORE_READ((x), sp)
#define PT_REGS_IP_CORE(x) BPF_CORE_READ((x), ip)


// if define BPF_F_INDEX_MASK or BPF_F_CURRENT_CPU
// #define BPF_F_INDEX_MASK 0xffffffffULL
// #define BPF_F_CURRENT_CPU BPF_F_INDEX_MASK


#ifndef BPF_F_INDEX_MASK

#define BPF_F_INDEX_MASK  0xffffffffULL
#define BPF_F_CURRENT_CPU BPF_F_INDEX_MASK

#endif

/* BPF_MAP_TYPE_RINGBUF original defined in /usr/include/linux/bpf.h, which from kernel-headers
   if BPF_MAP_TYPE_RINGBUF wasn't defined, this kernel does not support using ringbuf */
#ifndef BPF_MAP_TYPE_RINGBUF
#define BPF_MAP_TYPE_RINGBUF    27  // defined here to avoid compile error in lower kernel version
#define IS_RINGBUF_DEFINED      0
#else
#define IS_RINGBUF_DEFINED      1
#endif

#if defined(BPF_PROG_KERN) || defined(BPF_PROG_USER)
static inline char probe_ringbuf(void)
{
#if CLANG_VER_MAJOR >= 12
    return (char)bpf_core_type_exists(struct bpf_ringbuf);
#else
    return IS_RINGBUF_DEFINED;
#endif
}
#endif

// #if !defined(BPF_PROG_KERN) && !defined(BPF_PROG_USER) && defined(BPF_MAP_TYPE_RINGBUF)
// static inline bool probe_ringbuf(void) {
//     int map_fd;

//     if ((map_fd = bpf_map_create(BPF_MAP_TYPE_RINGBUF, NULL, 0, 0, getpagesize(), NULL)) < 0) {
//         return false;
//     }

//     close(map_fd);
//     return true;
// }
// #endif

static inline long bpfbuf_output(void *ctx, void *map, void *buf, __u64 size)
{
    return bpf_perf_event_output(ctx, map, BPF_F_CURRENT_CPU, buf, size);
}


#ifndef BPF_ANY
#define BPF_ANY     0
#define BPF_NOEXIST 1
#define BPF_EXIST   2
#define BPF_F_LOCK  4
#endif

#ifndef NSEC_PER_SEC
#define NSEC_PER_SEC    1000000000L
#define NSEC_PER_MSEC   1000000L

#endif

#define bpf_section(NAME) __attribute__((section(NAME), used))

#define KPROBE(func, type) \
    bpf_section("kprobe/" #func) \
    int bpf_##func(struct type *ctx)

#define KRETPROBE(func, type) \
    bpf_section("kretprobe/" #func) \
    int bpf_ret_##func(struct type *ctx)

#define KRAWTRACE(func, type) \
    bpf_section("raw_tracepoint/" #func) \
    int bpf_raw_trace_##func(struct type *ctx)

#define KPROBE_WITH_CONSTPROP(func, type) \
    bpf_section("kprobe/" #func ".constprop.0") \
    int bpf_constprop_##func(struct type *ctx)

#define __maybe_unused      __attribute__((unused))

struct proc_s {
    unsigned int proc_id;           // process id
};

struct obj_ref_s {
    unsigned int count;             // References of object
};



#ifdef VSCODE
const void *__builtin_preserve_access_index(void *);
#endif
#define _(P) (__builtin_preserve_access_index(P))

#ifndef likely
# define likely(X)		__builtin_expect(!!(X), 1)
#endif

#ifndef unlikely
# define unlikely(X)		__builtin_expect(!!(X), 0)
#endif

/**
 * __get_cgroup_kn() Returns the kernfs_node of the cgroup
 * @cgrp: target cgroup
 *
 * Returns the kernfs_node of the cgroup on success, NULL on failures.
 */
static __always_inline struct kernfs_node *__get_cgroup_kn(const struct cgroup *cgrp)
{
    struct kernfs_node *kn = NULL;

    if (cgrp)
        bpf_probe_read(&kn, sizeof(cgrp->kn), _(&cgrp->kn));

    return kn;
}


/* Represent old kernfs node with the kernfs_node_id
 * union to read the id in 5.4 kernels and older
 */
struct kernfs_node___old
{
    union kernfs_node_id id;
};

/**
 * get_cgroup_kn_id() Returns the kernfs node id
 * @cgrp: target kernfs node
 *
 * Returns the kernfs node id on success, zero on failures.
 */
static __always_inline __u64 __get_cgroup_kn_id(const struct kernfs_node *kn)
{
    __u64 id = 0;

    if (!kn)
        return id;

    /* Kernels prior to 5.5 have the kernfs_node_id, but distros (RHEL)
     * seem to have kernfs_node_id defined for UAPI reasons even though
     * its not used here directly. To resolve this walk struct for id.id
     */
    if (bpf_core_field_exists(((struct kernfs_node___old *)0)->id.id))
    {
        struct kernfs_node___old *old_kn;

        old_kn = (void *)kn;
        if (BPF_CORE_READ_INTO(&id, old_kn, id.id) != 0)
            return 0;
    }
    else
    {
        bpf_probe_read(&id, sizeof(id), _(&kn->id));
    }

    return id;
}

/**
 * get_cgroup_id() Returns cgroup id
 * @cgrp: target cgroup
 *
 * Returns the cgroup id of the target cgroup on success, zero on failures.
 */
static __always_inline __u64 get_cgroup_id(const struct cgroup *cgrp)
{
    struct kernfs_node *kn;

    kn = __get_cgroup_kn(cgrp);
    return __get_cgroup_kn_id(kn);
}

static __always_inline char *get_cgroup_name(struct cgroup *cgrp)
{
    struct kernfs_node *kn;
    char *name = NULL;

    kn = __get_cgroup_kn(cgrp);
    if (kn)
        bpf_probe_read(&name, sizeof(name), _(&kn->name));

    return name;
}

#define EVENT_ERROR_CGROUPS 0x100000
#define EVENT_ERROR_CGROUP_SUBSYS 0x080000
#define EVENT_ERROR_CGROUP_SUBSYSCGRP 0x040000

static __always_inline struct cgroup *get_task_cgroup(struct task_struct *task, __u32 subsys_idx, __u32 *error_flags)
{
    struct cgroup_subsys_state *subsys;
    struct css_set *cgroups;
    struct cgroup *cgrp = NULL;

    bpf_probe_read(&cgroups, sizeof(cgroups), _(&task->cgroups));
    if (unlikely(!cgroups))
    {
        *error_flags |= EVENT_ERROR_CGROUPS;
        return cgrp;
    }

    /* We are interested only in the cpuset, memory or pids controllers
     * which are indexed at 0, 4 and 11 respectively assuming all controllers
     * are compiled in.
     * When we use the controllers indexes we will first discover these indexes
     * dynamically in user space which will work on all setups from reading
     * file: /proc/cgroups. If we fail to discover the indexes then passing
     * a default index zero should be fine assuming we also want that.
     *
     * Reference: https://elixir.bootlin.com/linux/v5.19/source/include/linux/cgroup_subsys.h
     *
     * Notes:
     * Newer controllers should be appended at the end. controllers
     * that are not upstreamed may mess the calculation here
     * especially if they happen to be before the desired subsys_idx,
     * we fail.
     */
    if (unlikely(subsys_idx > pids_cgrp_id))
    {
        *error_flags |= EVENT_ERROR_CGROUP_SUBSYS;
        return cgrp;
    }

    /* Read css from the passed subsys index to ensure that we operate
     * on the desired controller. This allows user space to be flexible
     * and chose the right per cgroup subsystem to use in order to
     * support as much as workload as possible. It also reduces errors
     * in a significant way.
     */
    bpf_probe_read(&subsys, sizeof(subsys), _(&cgroups->subsys[subsys_idx]));
    if (unlikely(!subsys))
    {
        *error_flags |= EVENT_ERROR_CGROUP_SUBSYS;
        return cgrp;
    }

    bpf_probe_read(&cgrp, sizeof(cgrp), _(&subsys->cgroup));
    if (!cgrp)
        *error_flags |= EVENT_ERROR_CGROUP_SUBSYSCGRP;

    return cgrp;
}
