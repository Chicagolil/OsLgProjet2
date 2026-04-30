// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

char LICENSE[] SEC("license") = "Dual BSD/GPL";

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, int);
    __type(value, int);
} shift SEC(".maps");

// Place your code here. Your program must be called "handle_hook".

SEC("tracepoint/syscalls/sys_enter_write")
int handle_hook(struct trace_event_raw_sys_enter *ctx) {
    int fd = ctx->args[0];
    bpf_printk("sys_enter_write fd=%d\n", fd);
    return 0;
}
