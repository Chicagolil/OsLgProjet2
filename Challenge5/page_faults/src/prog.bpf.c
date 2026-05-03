// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>
#include "buffer_struct.h"

char LICENSE[] SEC("license") = "Dual BSD/GPL";

/* ── options: [0]=lower_freq_ms  [1]=upper_freq_ms  [2]=window_ms ── */
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 3);
    __type(key,   __u32);
    __type(value, __u32);
} options SEC(".maps");

/* ── perf output ── */
struct {
    __uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
    __uint(key_size,   sizeof(__u32));
    __uint(value_size, sizeof(__u32));
} events SEC(".maps");

/* ════════════════════════════════════════════════════════════════════
 * "Too high" detection
 *
 * Circular buffer of size upper_count = upper_freq_ms × window_ms.
 * ring position = index of the OLDEST entry (once full).
 * Condition: now − oldest < win_ns  →  too high.
 * ════════════════════════════════════════════════════════════════════ */
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 10000);
    __type(key, __u32); __type(value, __u64);
} ts_high SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32); __type(value, __u32);
} high_ring_idx SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32); __type(value, __u32);
} high_fill SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32); __type(value, __u32);
} too_high_flag SEC(".maps");

/* ════════════════════════════════════════════════════════════════════
 * "Too low" detection  (same ring logic, inverted condition)
 *
 * Circular buffer of size lower_count = lower_freq_ms × window_ms.
 * Condition: now − oldest > win_ns  →  too low (at fault time).
 * Handles PFF slightly below the lower bound (regular but too-slow faults).
 * The case where faults stop entirely is handled in user space.
 * ════════════════════════════════════════════════════════════════════ */
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 10000);
    __type(key, __u32); __type(value, __u64);
} ts_low SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32); __type(value, __u32);
} low_ring_idx SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32); __type(value, __u32);
} low_fill SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32); __type(value, __u32);
} too_low_flag SEC(".maps");

/* ── Startup guard: timestamp of the very first observed fault ── */
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32); __type(value, __u64);
} first_fault_ts SEC(".maps");

/* ── Throttle: last time an EVENT_PF_TS was emitted ── */
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32); __type(value, __u64);
} last_pf_ts_sent SEC(".maps");


SEC("kprobe/handle_mm_fault")
int BPF_KPROBE(handle_hook)
{
    /* ── 1. Filter: only page_fault_gen ── */
    struct task_struct *task = (struct task_struct *)bpf_get_current_task();
    char comm[16];
    BPF_CORE_READ_STR_INTO(&comm, task, comm);
    if (__builtin_memcmp(comm, "page_fault_gen", 14) != 0)
        return 0;

    /* ── 2. Read options ── */
    __u32 key = 0;
    __u32 *lower_freq = bpf_map_lookup_elem(&options, &key);
    if (!lower_freq) return 0;

    key = 1;
    __u32 *upper_freq = bpf_map_lookup_elem(&options, &key);
    if (!upper_freq) return 0;

    key = 2;
    __u32 *win_ms = bpf_map_lookup_elem(&options, &key);
    if (!win_ms) return 0;

    __u64 now     = bpf_ktime_get_ns();
    __u64 win_ns  = (__u64)(*win_ms) * 1000000ULL;
    __u32 pid     = bpf_get_current_pid_tgid() >> 32;

    __u32 up_cnt  = (*upper_freq) * (*win_ms);
    __u32 low_cnt = (*lower_freq) * (*win_ms);

    /* Guaranteed by spec (upper_freq × window_ms ≤ 10000), but guard anyway */
    if (up_cnt  == 0 || up_cnt  > 10000) return 0;
    if (low_cnt == 0 || low_cnt > 10000) return 0;

    /* ── 3. Record first fault ── */
    key = 0;
    __u64 *first_ts = bpf_map_lookup_elem(&first_fault_ts, &key);
    if (!first_ts) return 0;
    if (*first_ts == 0)
        *first_ts = now;

    /* ── 4. "Too high" check ─────────────────────────────────────────
     *
     * KEY DEFENSIVE PATTERN: use  raw_idx % 10000  when deriving the
     * map key from a runtime value.  The BPF verifier can then PROVE
     * the key is in-bounds without relying on a branch check alone —
     * some verifier versions reject the branch-only pattern silently.
     * ────────────────────────────────────────────────────────────────── */
    key = 0;
    __u32 *hi_raw = bpf_map_lookup_elem(&high_ring_idx, &key);
    if (!hi_raw) return 0;

    key = 0;
    __u32 *hi_fill_ptr = bpf_map_lookup_elem(&high_fill, &key);
    if (!hi_fill_ptr) return 0;

    key = 0;
    __u32 *hi_flag = bpf_map_lookup_elem(&too_high_flag, &key);
    if (!hi_flag) return 0;

    /* % 10000: proves to the verifier that hi_cur < max_entries */
    __u32 hi_cur = *hi_raw % 10000;

    if (*hi_fill_ptr >= up_cnt) {
        __u64 *old_hi = bpf_map_lookup_elem(&ts_high, &hi_cur);
        if (!old_hi) return 0;

        if (now - *old_hi < win_ns) {
            /* up_cnt faults happened in less than win_ns → too high */
            if (*hi_flag == 0) {
                struct event e = { .pid = pid, .type = EVENT_TOO_HIGH,
                                   .timestamp = now };
                bpf_perf_event_output(ctx, &events, BPF_F_CURRENT_CPU,
                                      &e, sizeof(e));
                *hi_flag = 1;
            }
        } else {
            /* back in range — allow the next violation to emit */
            *hi_flag = 0;
        }
    }

    bpf_map_update_elem(&ts_high, &hi_cur, &now, BPF_ANY);

    __u32 hi_next = hi_cur + 1;
    if (hi_next >= up_cnt)  hi_next = 0;
    if (hi_next >= 10000)   hi_next = 0;   /* explicit verifier hint */
    *hi_raw = hi_next;
    if (*hi_fill_ptr < up_cnt) (*hi_fill_ptr)++;

    /* ── 5. "Too low" check (only after the startup window) ── */
    key = 0;
    __u32 *lo_raw = bpf_map_lookup_elem(&low_ring_idx, &key);
    if (!lo_raw) return 0;

    key = 0;
    __u32 *lo_fill_ptr = bpf_map_lookup_elem(&low_fill, &key);
    if (!lo_fill_ptr) return 0;

    key = 0;
    __u32 *lo_flag = bpf_map_lookup_elem(&too_low_flag, &key);
    if (!lo_flag) return 0;

    __u32 lo_cur = *lo_raw % 10000;

    if (*lo_fill_ptr >= low_cnt && now - *first_ts >= win_ns) {
        __u64 *old_lo = bpf_map_lookup_elem(&ts_low, &lo_cur);
        if (!old_lo) return 0;

        if (now - *old_lo > win_ns) {
            /* fewer than low_cnt faults in last win_ns → too low */
            if (*lo_flag == 0) {
                struct event e = { .pid = pid, .type = EVENT_TOO_LOW,
                                   .timestamp = now };
                bpf_perf_event_output(ctx, &events, BPF_F_CURRENT_CPU,
                                      &e, sizeof(e));
                *lo_flag = 1;
            }
        } else {
            *lo_flag = 0;
        }
    }

    bpf_map_update_elem(&ts_low, &lo_cur, &now, BPF_ANY);

    __u32 lo_next = lo_cur + 1;
    if (lo_next >= low_cnt) lo_next = 0;
    if (lo_next >= 10000)   lo_next = 0;
    *lo_raw = lo_next;
    if (*lo_fill_ptr < low_cnt) (*lo_fill_ptr)++;

    /* ── 6. Throttled EVENT_PF_TS ─────────────────────────────────────
     * User space only needs the most-recent fault timestamp to maintain
     * its single "no-fault" deadline.  Sending once every win_ns/2 is
     * more than enough and keeps the perf buffer nowhere near full.
     * ─────────────────────────────────────────────────────────────────── */
    key = 0;
    __u64 *last_sent = bpf_map_lookup_elem(&last_pf_ts_sent, &key);
    if (!last_sent) return 0;

    if (now - *last_sent > win_ns / 2) {
        struct event ts_ev = { .pid = pid, .type = EVENT_PF_TS,
                               .timestamp = now };
        bpf_perf_event_output(ctx, &events, BPF_F_CURRENT_CPU,
                              &ts_ev, sizeof(ts_ev));
        *last_sent = now;
    }

    return 0;
}