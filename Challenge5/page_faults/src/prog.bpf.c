// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>
#include "buffer_struct.h"

char LICENSE[] SEC("license") = "Dual BSD/GPL";

/* ── options map: [0]=lower_freq_ms, [1]=upper_freq_ms, [2]=window_ms ── */
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 3);
    __type(key,   __u32);
    __type(value, __u32);
} options SEC(".maps");

/* ── perf event output ── */
struct {
    __uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
    __uint(key_size,   sizeof(__u32));
    __uint(value_size, sizeof(__u32));
} events SEC(".maps");

/* ─────────────────────────────────────────────────────────────────────────
 * Circular buffer of u64 timestamps used for the "too high" detection.
 *
 * Layout (once full):
 *   slot ring_idx  = oldest entry  (about to be overwritten)
 *   slot ring_idx-1 = newest entry
 *
 * If the newest fault and the oldest fault are separated by less than
 * window_ns AND the buffer contains exactly upper_bound_count entries,
 * then more than upper_bound_count faults occurred inside window_ns → too high.
 * ───────────────────────────────────────────────────────────────────────── */
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 10000);   /* max upper_bound_count per spec */
    __type(key,   __u32);
    __type(value, __u64);
} timestamps SEC(".maps");

/* Current write position in the circular buffer (cycles 0 .. up_count-1) */
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key,   __u32);
    __type(value, __u32);
} ring_idx SEC(".maps");

/* Entries written so far, capped at up_count (fill-phase sentinel) */
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key,   __u32);
    __type(value, __u32);
} fill_count SEC(".maps");

/* 1 while the "too high" message has been emitted and PFF is still high */
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key,   __u32);
    __type(value, __u32);
} too_high_flag SEC(".maps");

/* ══════════════════════════════════════════════════════════════════════════
   kprobe – hooked on handle_mm_fault, the architecture-independent entry
   point for all page-fault handling in Linux.
   ══════════════════════════════════════════════════════════════════════════ */
SEC("kprobe/handle_mm_fault")
int BPF_KPROBE(handle_hook)
{
    /* ── 1. Filter: only monitor page_fault_gen ── */
    struct task_struct *task = (struct task_struct *)bpf_get_current_task();
    char comm[16];
    BPF_CORE_READ_STR_INTO(&comm, task, comm);
    if (__builtin_memcmp(comm, "page_fault_gen", 14) != 0)
        return 0;

    /* ── 2. Read options ── */
    __u32 key = 1;
    __u32 *upper_freq = bpf_map_lookup_elem(&options, &key);
    if (!upper_freq) return 0;

    key = 2;
    __u32 *win_ms = bpf_map_lookup_elem(&options, &key);
    if (!win_ms) return 0;

    __u64 now      = bpf_ktime_get_ns();
    __u64 win_ns   = (__u64)(*win_ms) * 1000000ULL;
    __u32 pid      = bpf_get_current_pid_tgid() >> 32;
    __u32 up_count = (*upper_freq) * (*win_ms);

    /* Sanity – guaranteed by spec but guard for the verifier */
    if (up_count == 0 || up_count > 10000)
        return 0;

    /* ── 3. Send timestamp to user space for "too low" detection ──
     *
     * User space will schedule a check at (now + window_ns).  If fewer
     * than lower_bound_count faults are found in [now, now+window_ns],
     * it will print the "too low" message.
     */
    struct event ts_ev = { .pid = pid, .type = EVENT_PF_TS, .timestamp = now };
    bpf_perf_event_output(ctx, &events, BPF_F_CURRENT_CPU, &ts_ev, sizeof(ts_ev));

    /* ── 4. "Too high" detection via circular buffer ── */
    key = 0;
    __u32 *idx = bpf_map_lookup_elem(&ring_idx, &key);
    if (!idx) return 0;

    key = 0;
    __u32 *filled = bpf_map_lookup_elem(&fill_count, &key);
    if (!filled) return 0;

    key = 0;
    __u32 *flag = bpf_map_lookup_elem(&too_high_flag, &key);
    if (!flag) return 0;

    __u32 cur = *idx;
    if (cur >= 10000) return 0;   /* explicit bound for BPF verifier */

    if (*filled >= up_count) {
        /*
         * The buffer is full: timestamps[cur] is the OLDEST recorded fault.
         * If (now - oldest) < win_ns then up_count faults happened in less
         * than win_ns  →  PFF > upper_bound.
         */
        __u32 k = cur;
        __u64 *old_ts = bpf_map_lookup_elem(&timestamps, &k);
        if (!old_ts) return 0;

        if (now - *old_ts < win_ns) {
            if (*flag == 0) {
                struct event e = { .pid = pid, .type = EVENT_TOO_HIGH,
                                   .timestamp = now };
                bpf_perf_event_output(ctx, &events, BPF_F_CURRENT_CPU,
                                      &e, sizeof(e));
                *flag = 1;
            }
        } else {
            /* PFF back in range – allow the next violation to emit again */
            *flag = 0;
        }
    }

    /* ── 5. Write current timestamp and advance the ring index ── */
    bpf_map_update_elem(&timestamps, &cur, &now, BPF_ANY);

    __u32 next = cur + 1;
    if (next >= up_count) next = 0;
    if (next >= 10000)    next = 0;   /* extra verifier bound */
    *idx = next;

    if (*filled < up_count)
        (*filled)++;

    return 0;
}