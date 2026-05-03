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
 * Configuration
 * ═══════════════════════════════════════════════════════════════════════════ */
static int cfg_lower_freq_ms = 10;
static int cfg_upper_freq_ms = 100;
static int cfg_window_ms     = 50;

/* ═══════════════════════════════════════════════════════════════════════════
 * Monitoring state
 * ═══════════════════════════════════════════════════════════════════════════ */
static volatile int running         = 1;
static uint64_t     first_fault_ns  = 0;   /* kernel-time of first fault     */
static uint64_t     last_fault_ns   = 0;   /* kernel-time of most recent fault */
static uint64_t     deadline_ns     = UINT64_MAX; /* when to run "no-fault" check */
static int          mon_pid         = -1;

/* ═══════════════════════════════════════════════════════════════════════════
 * Helpers
 * ═══════════════════════════════════════════════════════════════════════════ */

/* CLOCK_MONOTONIC nanoseconds — same clock as bpf_ktime_get_ns() */
static uint64_t now_ns(void)
{
    struct timespec tp;
    clock_gettime(CLOCK_MONOTONIC, &tp);
    return (uint64_t)tp.tv_sec * 1000000000ULL + (uint64_t)tp.tv_nsec;
}

/* ═══════════════════════════════════════════════════════════════════════════
 * Signal
 * ═══════════════════════════════════════════════════════════════════════════ */
static void handle_sig(int sig) { running = 0; }

/* ═══════════════════════════════════════════════════════════════════════════
 * Perf-buffer callbacks
 * ═══════════════════════════════════════════════════════════════════════════ */
static void handle_event(void *ctx, int cpu, void *data, unsigned int sz)
{
    const struct event *e = data;

    if (e->type == EVENT_TOO_HIGH) {
        /* Detected in kernel — just print */
        printf("PFF too high for process with PID %d\n", e->pid);
        fflush(stdout);
        return;
    }

    if (e->type == EVENT_TOO_LOW) {
        /*
         * Detected in kernel at fault time.
         * Handles: PFF slightly below lower bound (regular-but-too-slow faults).
         * The startup guard is enforced in the BPF program.
         */
        printf("PFF too low for process with PID %d\n", e->pid);
        fflush(stdout);
        if (mon_pid < 0) mon_pid = (int)e->pid;
        return;
    }

    if (e->type == EVENT_PF_TS) {
        /*
         * Throttled heartbeat: one event every win_ns/2 at most.
         * Used only to keep `last_fault_ns` fresh so we can schedule
         * the "no-fault" deadline correctly.
         */
        uint64_t ts     = e->timestamp;
        uint64_t win_ns = (uint64_t)cfg_window_ms * 1000000ULL;

        if (first_fault_ns == 0) first_fault_ns = ts;
        if (mon_pid < 0)         mon_pid         = (int)e->pid;

        last_fault_ns = ts;
        deadline_ns   = ts + win_ns;   /* single deadline: re-armed on every heartbeat */
    }
}

static void handle_lost(void *ctx, int cpu, uint64_t lost)
{
    fprintf(stderr, "Lost %llu events on CPU %d\n", lost, cpu);
}

/* ═══════════════════════════════════════════════════════════════════════════
 * "No-fault" deadline check
 *
 * Handles the case where the generator has stopped (or paused for > win_ns).
 * The BPF program already handles "PFF slightly below lower bound" at fault
 * time, so here we only need to fire once when no fault has occurred for an
 * entire window.
 * ═══════════════════════════════════════════════════════════════════════════ */
static void check_deadline(void)
{
    if (deadline_ns == UINT64_MAX || mon_pid < 0)
        return;

    uint64_t cur    = now_ns();
    uint64_t win_ns = (uint64_t)cfg_window_ms * 1000000ULL;

    if (cur < deadline_ns)
        return;

    /* Startup guard: skip until one full window has passed since first fault */
    if (first_fault_ns == 0 || deadline_ns - first_fault_ns < win_ns) {
        deadline_ns = UINT64_MAX;
        return;
    }

    /*
     * A full window elapsed since the last heartbeat without a new heartbeat
     * arriving → the generator produced 0 (or very few) faults → too low.
     */
    printf("PFF too low for process with PID %d\n", mon_pid);
    fflush(stdout);

    deadline_ns = UINT64_MAX;   /* disarm; re-armed by next EVENT_PF_TS */
}

/* ═══════════════════════════════════════════════════════════════════════════
 * Poll timeout
 * ═══════════════════════════════════════════════════════════════════════════ */
static int next_timeout_ms(void)
{
    int timeout_ms = 100;   /* default when no deadline is pending */

    if (deadline_ns != UINT64_MAX) {
        uint64_t cur = now_ns();
        if (cur >= deadline_ns) {
            timeout_ms = 0;
        } else {
            uint64_t diff = deadline_ns - cur;
            timeout_ms = (int)(diff / 1000000ULL);
            if (timeout_ms < 1) timeout_ms = 1;
        }
    }

    /*
     * Hard cap: even without a pending deadline we must drain the perf
     * buffer frequently enough.  EVENT_PF_TS is throttled in BPF, but
     * EVENT_TOO_HIGH / EVENT_TOO_LOW bursts are possible.
     * Cap at window_ms / 5 (at least 1 ms) to stay comfortably below
     * the buffer capacity.
     */
    int cap_ms = cfg_window_ms / 5;
    if (cap_ms < 1)  cap_ms = 1;
    if (timeout_ms > cap_ms) timeout_ms = cap_ms;

    return timeout_ms;
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

    /* ── Populate options map ── */
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

    /* ── Attach BPF program ── */
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

    printf("PFF monitor: lower=%d, upper=%d, window=%dms\n",
           cfg_lower_freq_ms, cfg_upper_freq_ms, cfg_window_ms);
    printf("Monitoring started (filtering by process name). Press Ctrl+C to stop.\n");
    fflush(stdout);

    /* ── Perf buffer ── */
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

    /* ── Main loop ── */
    while (running) {
        err = perf_buffer__poll(pb, next_timeout_ms());
        if (err < 0 && err != -EINTR) {
            fprintf(stderr, "Polling error %d\n", err);
            break;
        }
        check_deadline();
    }

    perf_buffer__free(pb);
    bpf_link__destroy(link);
    bpf_object__close(obj);
    return 0;
}