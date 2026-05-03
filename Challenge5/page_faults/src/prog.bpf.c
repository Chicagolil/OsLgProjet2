// SPDX-License-Identifier: GPL-2.0
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include "buffer_struct.h"

char LICENSE[] SEC("license") = "GPL";

/*
 * options[0] = lower_bound_freq_ms
 * options[1] = upper_bound_freq_ms
 * options[2] = time_window_ms
 * (filled by user space before attachment)
 */
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 3);
    __type(key, __u32);
    __type(value, __u32);
} options SEC(".maps");

/*
 * Circular buffer: timestamps[i] = nanosecond timestamp of the fault
 * stored in slot i.  Indexed by head in [0, MAX_FAULTS).
 */
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, MAX_FAULTS);
    __type(key, __u32);
    __type(value, __u64);
} timestamps SEC(".maps");

/*
 * state[0] = head        — next write slot, wraps in [0, MAX_FAULTS)
 * state[1] = total_count — total faults seen, capped at MAX_FAULTS
 * state[2] = target_pid  — PID of page_fault_gen (0 until first fault)
 */
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 3);
    __type(key, __u32);
    __type(value, __u32);
} state SEC(".maps");

/*
 * first_ts[0] = nanosecond timestamp of the very first observed fault.
 * Used by user space to skip the startup phase for lower-bound checks.
 */
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, __u64);
} first_ts SEC(".maps");

/* Perf output — carries EVENT_TOO_HIGH events to user space */
struct {
    __uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
    __uint(key_size, sizeof(__u32));
    __uint(value_size, sizeof(__u32));
} events SEC(".maps");

SEC("kprobe/handle_mm_fault")
int handle_hook(struct pt_regs *ctx)
{
    /* ---- 1. Filter by process name "page_fault_gen" (14 chars) ---- */
    char comm[16];
    bpf_get_current_comm(comm, sizeof(comm));

    if (comm[0]  != 'p' || comm[1]  != 'a' || comm[2]  != 'g' || comm[3]  != 'e' ||
        comm[4]  != '_' || comm[5]  != 'f' || comm[6]  != 'a' || comm[7]  != 'u' ||
        comm[8]  != 'l' || comm[9]  != 't' || comm[10] != '_' || comm[11] != 'g' ||
        comm[12] != 'e' || comm[13] != 'n')
        return 0;

    __u64 now = bpf_ktime_get_ns();
    __u32 pid = (__u32)(bpf_get_current_pid_tgid() >> 32);

    /* ---- 2. Read current state ---- */
    __u32 k0 = 0, k1 = 1, k2 = 2;

    __u32 *head_p  = bpf_map_lookup_elem(&state, &k0);
    __u32 *total_p = bpf_map_lookup_elem(&state, &k1);
    __u32 *pid_p   = bpf_map_lookup_elem(&state, &k2);
    __u64 *fts_p   = bpf_map_lookup_elem(&first_ts, &k0);
    if (!head_p || !total_p || !pid_p || !fts_p)
        return 0;

    __u32 head  = *head_p;
    __u32 total = *total_p;

    /* Record PID and first-fault timestamp on the very first fault */
    if (*pid_p == 0)
        bpf_map_update_elem(&state, &k2, &pid, BPF_ANY);
    if (*fts_p == 0)
        bpf_map_update_elem(&first_ts, &k0, &now, BPF_ANY);

    /* ---- 3. Write current timestamp into circular buffer ---- */
    bpf_map_update_elem(&timestamps, &head, &now, BPF_ANY);

    /* ---- 4. Advance head and total ---- */
    __u32 new_head  = (head + 1 >= MAX_FAULTS) ? 0 : head + 1;
    __u32 new_total = (total >= MAX_FAULTS) ? MAX_FAULTS : total + 1;
    bpf_map_update_elem(&state, &k0, &new_head,  BPF_ANY);
    bpf_map_update_elem(&state, &k1, &new_total, BPF_ANY);

    /* ---- 5. Upper-bound check ---- *
     *
     * Key idea: we have >= upper_count faults in window_ns if and only if
     * the upper_count-th most recent fault (the "oldest" of the last
     * upper_count faults, including the current one) is still within
     * window_ns.  That slot is at index:
     *   (new_head - upper_count + MAX_FAULTS) % MAX_FAULTS
     * No loop needed — pure O(1).
     */
    __u32 *upper_p  = bpf_map_lookup_elem(&options, &k1); /* upper_bound_freq_ms */
    __u32 *window_p = bpf_map_lookup_elem(&options, &k2); /* time_window_ms      */
    if (!upper_p || !window_p)
        return 0;

    __u32 upper_count = (*upper_p) * (*window_p);
    if (upper_count == 0 || upper_count > MAX_FAULTS)
        return 0;

    __u64 window_ns = (__u64)(*window_p) * 1000000ULL; /* ms → ns */

    if (new_total >= upper_count) {
        __u32 old_slot = (new_head + MAX_FAULTS - upper_count) % MAX_FAULTS;
        /* Explicit bound check so the verifier is happy */
        if (old_slot >= MAX_FAULTS)
            return 0;
        __u64 *old_ts_p = bpf_map_lookup_elem(&timestamps, &old_slot);
        if (old_ts_p && (now - *old_ts_p) < window_ns) {
            struct event e = { .pid = pid, .type = EVENT_TOO_HIGH };
            bpf_perf_event_output(ctx, &events, BPF_F_CURRENT_CPU,
                                  &e, sizeof(e));
        }
    }

    return 0;
}