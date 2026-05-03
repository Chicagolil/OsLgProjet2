// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

char LICENSE[] SEC("license") = "Dual BSD/GPL";

#define MAX_EVENTS 10000

struct event {
    u32 pid;
    u32 type; // 1 = HIGH
    u64 ts;
};

struct config {
    u64 window_ns;
    u32 upper;
};

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, MAX_EVENTS);
    __type(key, u32);
    __type(value, u64);
} timestamps SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, u32);
    __type(value, u32);
} index_map SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, u32);
    __type(value, struct config);
} config_map SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
} events SEC(".maps");

SEC("kprobe/handle_mm_fault")
int handle_fault(struct pt_regs *ctx)
{
    u32 key = 0;

    // filtre process
    struct task_struct *task = (struct task_struct *)bpf_get_current_task();
    char comm[16];
    BPF_CORE_READ_STR_INTO(&comm, task, comm);

    if (__builtin_memcmp(comm, "page_fault_gen", 15) != 0)
        return 0;

    struct config *cfg = bpf_map_lookup_elem(&config_map, &key);
    if (!cfg)
        return 0;

    u64 now = bpf_ktime_get_ns();

    u32 *idx = bpf_map_lookup_elem(&index_map, &key);
    if (!idx)
        return 0;

    u32 i = *idx;
    u32 slot = i % MAX_EVENTS;

    bpf_map_update_elem(&timestamps, &slot, &now, BPF_ANY);
    *idx = i + 1;

    // compter dans la fenêtre
    u32 count = 0;

#pragma unroll
    for (int j = 0; j < 128; j++) { // limité pour verifier
        if (j >= MAX_EVENTS)
            break;

        u32 k = (i - j) % MAX_EVENTS;
        u64 *ts = bpf_map_lookup_elem(&timestamps, &k);
        if (!ts)
            break;

        if (now - *ts > cfg->window_ns)
            break;

        count++;
    }

    if (count > cfg->upper) {
        struct event e = {};
        e.pid = bpf_get_current_pid_tgid() >> 32;
        e.type = 1;
        e.ts = now;

        bpf_perf_event_output(ctx, &events, BPF_F_CURRENT_CPU, &e, sizeof(e));
    }

    return 0;
}