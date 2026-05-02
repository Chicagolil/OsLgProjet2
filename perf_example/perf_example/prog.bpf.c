// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>

#include "prog.h"

char LICENSE[] SEC("license") = "Dual BSD/GPL";

struct {
    __uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
    __uint(key_size, sizeof(u32));
    __uint(value_size, sizeof(u32));
} events SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, __u64);
} counter SEC(".maps");

SEC("tracepoint/syscalls/sys_enter_execve")
int handle_execve(struct trace_event_raw_sys_enter *ctx)
{
    __u32 key = 0;
    __u64 *count = bpf_map_lookup_elem(&counter, &key);
    if (!count)
        return 0;

    (*count)++;

    struct struct_to_give_to_perf struct_perf = {.count_value = *count};
    bpf_perf_event_output(ctx, &events, BPF_F_CURRENT_CPU, &struct_perf, sizeof(struct_perf));

    return 0;
}
