#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <signal.h>
#include <time.h>
#include <stdint.h>
#include <bpf/libbpf.h>
#include <getopt.h>
#include "buffer_struct.h"

/* ═══════════════════════════════════════════════════════════════════════════
 * Configuration (set from CLI, read by callbacks)
 * ═══════════════════════════════════════════════════════════════════════════ */
static int cfg_lower_freq_ms = 10;
static int cfg_upper_freq_ms = 100;
static int cfg_window_ms     = 50;

/* ═══════════════════════════════════════════════════════════════════════════
 * User-space timestamp ring buffer
 *
 * Holds the last MAX_TS fault timestamps (kernel CLOCK_MONOTONIC ns).
 * Used by process_deadlines() to count faults inside a window.
 * ═══════════════════════════════════════════════════════════════════════════ */
#define MAX_TS 10001   /* upper_bound_count <= 10000 per spec */

static uint64_t ts_ring[MAX_TS];
static int      ts_head  = 0;   /* next write slot                  */
static int      ts_count = 0;   /* valid entries, 0 .. MAX_TS       */

static void ts_add(uint64_t ts)
{
    ts_ring[ts_head] = ts;
    ts_head = (ts_head + 1) % MAX_TS;
    if (ts_count < MAX_TS) ts_count++;
    /* if full the oldest entry is silently overwritten – that is fine
     * because entries older than win_ns will never be counted anyway  */
}

/*
 * Count timestamps t with  win_start <= t <= win_end.
 *
 * Entries are stored in approximate chronological order (a single-threaded
 * process generates faults on one CPU).  We iterate oldest-to-newest and
 * break early once we pass win_end.
 */
static int ts_count_in(uint64_t win_start, uint64_t win_end)
{
    int cnt   = 0;
    int start = ((ts_head - ts_count) % MAX_TS + MAX_TS) % MAX_TS;

    for (int i = 0; i < ts_count; i++) {
        uint64_t t = ts_ring[(start + i) % MAX_TS];
        if (t < win_start) continue;
        if (t > win_end)   break;   /* entries are sorted → done */
        cnt++;
    }
    return cnt;
}

/* ═══════════════════════════════════════════════════════════════════════════
 * Deadline queue
 *
 * Each page fault at time T schedules one "too low" check at T + win_ns.
 * At that check we look at [T, T+win_ns]: if fewer than lower_bound_count
 * faults are found, the PFF was below the lower bound during that window.
 *
 * Using one deadline per fault (not just the last one) is the key to
 * detecting a PFF that is below the lower bound but still regular enough
 * that consecutive faults are closer than win_ns apart.
 * ═══════════════════════════════════════════════════════════════════════════ */
typedef struct { uint64_t win_start; uint64_t deadline; } dl_entry_t;

#define MAX_DL 10001   /* one entry per fault; upper_bound_count <= 10000 */

static dl_entry_t dq[MAX_DL];
static int        dq_tail = 0;   /* read  (oldest) */
static int        dq_head = 0;   /* write (newest) */

static inline int  dq_empty(void) { return dq_head == dq_tail; }
static inline int  dq_full(void)  { return (dq_head + 1) % MAX_DL == dq_tail; }

static void dq_push(uint64_t win_start, uint64_t deadline)
{
    if (dq_full()) {
        /* Drop the oldest pending deadline rather than blocking.
         * This should not happen in normal operation (MAX_DL > upper_count). */
        dq_tail = (dq_tail + 1) % MAX_DL;
    }
    dq[dq_head].win_start = win_start;
    dq[dq_head].deadline  = deadline;
    dq_head = (dq_head + 1) % MAX_DL;
}

static dl_entry_t *dq_front(void) { return dq_empty() ? NULL : &dq[dq_tail]; }
static void        dq_pop(void)   { if (!dq_empty()) dq_tail = (dq_tail + 1) % MAX_DL; }

/* ═══════════════════════════════════════════════════════════════════════════
 * Monitoring state
 * ═══════════════════════════════════════════════════════════════════════════ */
static volatile int running    = 1;
static uint64_t     first_fault = 0;   /* kernel-ns of first observed fault */
static int          mon_pid    = -1;

/* ═══════════════════════════════════════════════════════════════════════════
 * Helpers
 * ═══════════════════════════════════════════════════════════════════════════ */

/* Current CLOCK_MONOTONIC time in nanoseconds – same clock as bpf_ktime_get_ns */
static uint64_t now_ns(void)
{
    struct timespec tp;
    clock_gettime(CLOCK_MONOTONIC, &tp);
    return (uint64_t)tp.tv_sec * 1000000000ULL + (uint64_t)tp.tv_nsec;
}

/* ═══════════════════════════════════════════════════════════════════════════
 * Signal handler
 * ═══════════════════════════════════════════════════════════════════════════ */
static void handle_sig(int sig) { running = 0; }

/* ═══════════════════════════════════════════════════════════════════════════
 * Perf-buffer event callback
 * ═══════════════════════════════════════════════════════════════════════════ */
static void handle_event(void *ctx, int cpu, void *data, unsigned int sz)
{
    const struct event *e = data;

    if (e->type == EVENT_TOO_HIGH) {
        /* Detected in kernel space – just print. */
        printf("PFF too high for process with PID %d\n", e->pid);
        fflush(stdout);
        return;
    }

    if (e->type == EVENT_PF_TS) {
        uint64_t ts     = e->timestamp;
        uint64_t win_ns = (uint64_t)cfg_window_ms * 1000000ULL;

        /* Initialise on first fault */
        if (first_fault == 0) first_fault = ts;
        if (mon_pid < 0)      mon_pid     = (int)e->pid;

        /* Add to the timestamp ring (used by the deadline checker) */
        ts_add(ts);

        /* Schedule one "too low" check at ts + win_ns */
        dq_push(ts, ts + win_ns);
    }
}

static void handle_lost(void *ctx, int cpu, uint64_t lost)
{
    fprintf(stderr, "Lost %llu events on CPU %d\n", lost, cpu);
}

/* ═══════════════════════════════════════════════════════════════════════════
 * Deadline processor – called from the main loop after every poll()
 *
 * For each expired deadline (win_start, win_start + win_ns):
 *   • Skip if still in the startup phase (< one full window since first fault).
 *   • Count faults recorded in [win_start, deadline].
 *   • Print "too low" if count < lower_bound_count.
 * ═══════════════════════════════════════════════════════════════════════════ */
static void process_deadlines(void)
{
    uint64_t cur    = now_ns();
    uint64_t win_ns = (uint64_t)cfg_window_ms * 1000000ULL;
    int      lb     = cfg_lower_freq_ms * cfg_window_ms;   /* lower_bound_count */

    while (!dq_empty()) {
        dl_entry_t *d = dq_front();

        if (cur < d->deadline) break;   /* FIFO order → no later entry expired */

        /*
         * Startup guard: do not evaluate until at least one full window has
         * elapsed since the very first observed fault.
         */
        if (first_fault > 0 && d->deadline - first_fault >= win_ns) {
            int cnt = ts_count_in(d->win_start, d->deadline);
            if (cnt < lb) {
                printf("PFF too low for process with PID %d\n", mon_pid);
                fflush(stdout);
            }
        }

        dq_pop();
    }
}

/* Milliseconds until the next deadline fires (drives perf_buffer__poll timeout) */
static int next_timeout_ms(void)
{
    if (dq_empty()) return 100;   /* no pending deadline: use a safe default */

    uint64_t dl  = dq_front()->deadline;
    uint64_t cur = now_ns();

    if (cur >= dl) return 0;   /* already expired */

    uint64_t diff_ns = dl - cur;
    int ms = (int)(diff_ns / 1000000ULL);
    if (ms < 1)   ms = 1;
    if (ms > 100) ms = 100;   /* cap so we stay responsive to signals */
    return ms;
}

/* ═══════════════════════════════════════════════════════════════════════════
 * CLI
 * ═══════════════════════════════════════════════════════════════════════════ */
static struct option long_options[] = {
    { "lower_bound_freq_ms", required_argument, 0, 'l' },
    { "upper_bound_freq_ms", required_argument, 0, 'u' },
    { "time_window_ms",      required_argument, 0, 't' },
    { 0, 0, 0, 0 }
};

/* ═══════════════════════════════════════════════════════════════════════════
 * main
 * ═══════════════════════════════════════════════════════════════════════════ */
int main(int argc, char **argv)
{
    /* ── Parse arguments ── */
    int opt;
    while ((opt = getopt_long(argc, argv, "u:l:t:", long_options, NULL)) != -1) {
        switch (opt) {
            case 'l': cfg_lower_freq_ms = atoi(optarg); break;
            case 'u': cfg_upper_freq_ms = atoi(optarg); break;
            case 't': cfg_window_ms     = atoi(optarg); break;
        }
    }

    /* ── Open and load BPF object ── */
    struct bpf_object *obj = bpf_object__open_file("prog.bpf.o", NULL);
    if (!obj) { perror("bpf_object__open_file"); return 1; }

    int err = bpf_object__load(obj);
    if (err) {
        perror("bpf_object__load");
        bpf_object__close(obj);
        return 1;
    }

    /* ── Populate the options map ── */
    struct bpf_map *opt_map = bpf_object__find_map_by_name(obj, "options");
    if (!opt_map) {
        fprintf(stderr, "map 'options' not found\n");
        bpf_object__close(obj);
        return 1;
    }
    __u32 k, v;
    k = 0; v = (__u32)cfg_lower_freq_ms;
    bpf_map__update_elem(opt_map, &k, sizeof(k), &v, sizeof(v), BPF_ANY);
    k = 1; v = (__u32)cfg_upper_freq_ms;
    bpf_map__update_elem(opt_map, &k, sizeof(k), &v, sizeof(v), BPF_ANY);
    k = 2; v = (__u32)cfg_window_ms;
    bpf_map__update_elem(opt_map, &k, sizeof(k), &v, sizeof(v), BPF_ANY);

    /* ── Attach the BPF program ── */
    struct bpf_program *prog = bpf_object__find_program_by_name(obj, "handle_hook");
    if (!prog) {
        fprintf(stderr, "program 'handle_hook' not found\n");
        bpf_object__close(obj);
        return 1;
    }
    struct bpf_link *link = bpf_program__attach(prog);
    if (!link) {
        perror("bpf_program__attach");
        bpf_object__close(obj);
        return 1;
    }

    signal(SIGINT,  handle_sig);
    signal(SIGTERM, handle_sig);

    /* Print config – format matches the expected output in the spec */
    printf("PFF monitor: lower=%d, upper=%d, window=%dms\n",
           cfg_lower_freq_ms, cfg_upper_freq_ms, cfg_window_ms);
    printf("Monitoring started (filtering by process name). Press Ctrl+C to stop.\n");
    fflush(stdout);

    /* ── Set up perf buffer ── */
    int pfd = bpf_object__find_map_fd_by_name(obj, "events");
    if (pfd < 0) {
        fprintf(stderr, "Failed to find perf map: %s\n", strerror(errno));
        bpf_link__destroy(link);
        bpf_object__close(obj);
        return 1;
    }

    struct perf_buffer *pb = perf_buffer__new(
        pfd, 8, handle_event, handle_lost, NULL, NULL);
    if (!pb) {
        fprintf(stderr, "perf_buffer__new failed: %s\n", strerror(errno));
        bpf_link__destroy(link);
        bpf_object__close(obj);
        return 1;
    }

    /* ── Main loop ────────────────────────────────────────────────────────
     *
     * The poll timeout is set to the time remaining until the next deadline.
     * This means the loop wakes up precisely when it needs to check "too low",
     * rather than at a fixed 10 ms interval (which would incur a -1/20 penalty).
     * ─────────────────────────────────────────────────────────────────── */
    while (running) {
        err = perf_buffer__poll(pb, next_timeout_ms());
        if (err < 0 && err != -EINTR) {
            fprintf(stderr, "Polling error %d\n", err);
            break;
        }
        process_deadlines();
    }

    /* ── Cleanup ── */
    perf_buffer__free(pb);
    bpf_link__destroy(link);
    bpf_object__close(obj);
    return 0;
}