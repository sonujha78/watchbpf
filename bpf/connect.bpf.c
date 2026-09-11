// SPDX-License-Identifier: GPL-2.0
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

char LICENSE3[] SEC("license") = "GPL";

#define TASK_COMM_LEN 16

struct connect_event {
    __u32 pid;
    __u32 uid;
    char comm[TASK_COMM_LEN];
    __u8  is_ipv6;       // 0 = IPv4, 1 = IPv6
    __u8  ipv6_addr[16]; // IPv6 hone par use hoga
    __u32 dst_addr;      // IPv4 hone par use hoga (network byte order)
    __u16 dst_port;      // dono ke liye common, host byte order
};

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 256 * 1024);
} rb_connect SEC(".maps");

SEC("tp/syscalls/sys_enter_connect")
int handle_connect(struct trace_event_raw_sys_enter *ctx)
{
    struct connect_event *e;
    __u16 family = 0;

    const void *uservaddr = (const void *)ctx->args[1];
    bpf_probe_read_user(&family, sizeof(family), uservaddr);

    // Sirf IPv4 (2) aur IPv6 (10) events lo, baaki (Unix sockets etc.) skip karo
    if (family != 2 && family != 10) {
        return 0;
    }

    e = bpf_ringbuf_reserve(&rb_connect, sizeof(*e), 0);
    if (!e) {
        return 0;
    }
    __builtin_memset(e, 0, sizeof(*e));

    e->pid = bpf_get_current_pid_tgid() >> 32;
    e->uid = bpf_get_current_uid_gid() & 0xFFFFFFFF;
    bpf_get_current_comm(&e->comm, sizeof(e->comm));

    if (family == 2) {
        // IPv4
        struct sockaddr_in addr = {};
        bpf_probe_read_user(&addr, sizeof(addr), uservaddr);
        e->is_ipv6 = 0;
        e->dst_addr = addr.sin_addr.s_addr;
        e->dst_port = __builtin_bswap16(addr.sin_port);
    } else {
        // IPv6
        struct sockaddr_in6 addr6 = {};
        bpf_probe_read_user(&addr6, sizeof(addr6), uservaddr);
        e->is_ipv6 = 1;
        __builtin_memcpy(e->ipv6_addr, &addr6.sin6_addr, 16);
        e->dst_port = __builtin_bswap16(addr6.sin6_port);
    }

    bpf_ringbuf_submit(e, 0);
    return 0;
}
