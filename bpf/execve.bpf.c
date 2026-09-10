// SPDX-License-Identifier: GPL-2.0
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

char LICENSE[] SEC("license") = "GPL";

#define TASK_COMM_LEN 16
#define MAX_FILENAME_LEN 256

struct event {
    __u32 pid;
    __u32 uid;
    char comm[TASK_COMM_LEN];
    char filename[MAX_FILENAME_LEN];
};

// Ring buffer: kernel se user-space tak events bhejne ka fast, low-overhead tareeka
struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 256 * 1024); // 256KB buffer
} rb SEC(".maps");

SEC("tp/syscalls/sys_enter_execve")
int handle_execve(struct trace_event_raw_sys_enter *ctx)
{
    struct event *e;
    __u64 uid_gid = bpf_get_current_uid_gid();

    // Ring buffer mein jagah reserve karo
    e = bpf_ringbuf_reserve(&rb, sizeof(*e), 0);
    if (!e) {
        return 0; // buffer full — event drop, crash nahi
    }

    e->pid = bpf_get_current_pid_tgid() >> 32;
    e->uid = uid_gid & 0xFFFFFFFF;
    bpf_get_current_comm(&e->comm, sizeof(e->comm));

    // execve ka pehla argument (filename) padho, jo user-space pointer hai
    const char *filename_ptr = (const char *)ctx->args[0];
    bpf_probe_read_user_str(&e->filename, sizeof(e->filename), filename_ptr);

    bpf_ringbuf_submit(e, 0);
    return 0;
}
