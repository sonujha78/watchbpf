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
    __u32 dst_addr;   // IPv4 destination, network byte order
    __u16 dst_port;   // destination port, host byte order
};

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 256 * 1024);
} rb_connect SEC(".maps");

SEC("tp/syscalls/sys_enter_connect")
int handle_connect(struct trace_event_raw_sys_enter *ctx)
{
    struct connect_event *e;
    struct sockaddr_in addr = {};

    // arg[1] is `struct sockaddr *uservaddr`
    const void *uservaddr = (const void *)ctx->args[1];
    bpf_probe_read_user(&addr, sizeof(addr), uservaddr);

    // Sirf IPv4 (AF_INET = 2) events lo abhi ke liye — IPv6 baad mein add karenge
    if (addr.sin_family != 2) {
        return 0;
    }

    e = bpf_ringbuf_reserve(&rb_connect, sizeof(*e), 0);
    if (!e) {
        return 0;
    }

    e->pid = bpf_get_current_pid_tgid() >> 32;
    e->uid = bpf_get_current_uid_gid() & 0xFFFFFFFF;
    bpf_get_current_comm(&e->comm, sizeof(e->comm));
    e->dst_addr = addr.sin_addr.s_addr;
    e->dst_port = __builtin_bswap16(addr.sin_port); // network->host byte order

    bpf_ringbuf_submit(e, 0);
    return 0;
}
