#include <stdio.h>
#include <unistd.h>
#include <errno.h>
#include <signal.h>
#include <time.h>
#include <stdlib.h>
#include <getopt.h>
#include <bpf/libbpf.h>
#include <bpf/bpf.h>
#include "buffer_struct.h"

static volatile int running = 1;

static void handle_sig(int sig) { running = 0; }

static struct option long_options[] = {
    { "lower_bound_freq_ms", required_argument, 0, 'l' },
    { "upper_bound_freq_ms", required_argument, 0, 'u' },
    { "time_window_ms",      required_argument, 0, 't' },
    { 0, 0, 0, 0 }
};

/* Current CLOCK_MONOTONIC time in nanoseconds (same clock as bpf_ktime_get_ns). */
static unsigned long long now_ns(void)
{
    struct timespec tp;
    clock_gettime(CLOCK_MONOTONIC, &tp);
    return (unsigned long long)tp.tv_sec  * 1000000000ULL
         + (unsigned long long)tp.tv_nsec;
}

/* Called by the perf buffer for every event sent from kernel space. */
void handle_event(void *ctx, int cpu, void *data, unsigned int data_sz)
{
    const struct event *e = data;
    if (e->type == EVENT_TOO_HIGH)
        printf("PFF too high for process with PID %d\n", e->pid);
    /* EVENT_TOO_LOW is detected and printed directly in check_lower_bound(). */
}

void handle_lost(void *ctx, int cpu, __u64 lost_cnt)
{
    fprintf(stderr, "Lost %llu events on CPU %d\n", lost_cnt, cpu);
}

/*
 * Periodic lower-bound check (runs every ~10 ms from the poll loop).
 *
 * Strategy (O(1), no loops):
 *   - Read head and total_count from the `state` map.
 *   - The lower_count-th most recent fault's timestamp is at slot
 *       (head - lower_count + MAX_FAULTS) % MAX_FAULTS
 *   - If that timestamp is older than window_ns (or we haven't seen
 *     lower_count faults yet), the PFF is too low.
 *   - Skip during the startup phase: wait until at least one full
 *     window has elapsed since the first observed fault.
 */
static void check_lower_bound(int state_fd, int first_ts_fd, int timestamps_fd,
                               int lower_bound_freq_ms, int time_window_ms)
{
    unsigned long long now     = now_ns();
    unsigned long long win_ns  = (unsigned long long)time_window_ms * 1000000ULL;
    unsigned int lower_count   = (unsigned int)lower_bound_freq_ms
                                * (unsigned int)time_window_ms;

    if (lower_count == 0)
        return;

    /* Read state */
    __u32 key, head, total, pid;
    __u64 first_fault_ts;

    key = 0;
    if (bpf_map_lookup_elem(state_fd, &key, &head)          != 0) return;
    key = 1;
    if (bpf_map_lookup_elem(state_fd, &key, &total)         != 0) return;
    key = 2;
    if (bpf_map_lookup_elem(state_fd, &key, &pid)           != 0) return;
    key = 0;
    if (bpf_map_lookup_elem(first_ts_fd, &key, &first_fault_ts) != 0) return;

    /* No fault observed yet — skip */
    if (first_fault_ts == 0 || pid == 0)
        return;

    /* Startup phase: wait for one full window since the first fault */
    if (now < first_fault_ts || now - first_fault_ts < win_ns)
        return;

    int too_low = 0;

    if (total < lower_count) {
        /*
         * Fewer than lower_count faults have ever been seen.
         * Combined with the startup check above, this means the average
         * rate over the first full window was already below the lower bound.
         */
        too_low = 1;
    } else {
        /*
         * Look at the lower_count-th most recent fault.
         * If it happened more than window_ns ago, fewer than lower_count
         * faults occurred in the last window → too low.
         */
        __u32 old_slot = (__u32)(head + MAX_FAULTS - lower_count) % MAX_FAULTS;
        __u64 old_ts;
        key = old_slot;
        if (bpf_map_lookup_elem(timestamps_fd, &key, &old_ts) != 0)
            return;
        if (now - old_ts > win_ns)
            too_low = 1;
    }

    if (too_low)
        printf("PFF too low for process with PID %u\n", pid);
}

int main(int argc, char **argv)
{
    struct bpf_object  *obj;
    struct bpf_program *prog;
    struct bpf_link    *link;
    int err;

    /* ---- Open and load the BPF object ---- */
    obj = bpf_object__open_file("prog.bpf.o", NULL);
    if (!obj) { perror("bpf_object__open_file"); return 1; }

    err = bpf_object__load(obj);
    if (err) {
        perror("bpf_object__load");
        bpf_object__close(obj);
        return 1;
    }

    /* ---- Parse command-line arguments ---- */
    int opt;
    int lower_bound_freq_ms = 10;   /* default */
    int upper_bound_freq_ms = 100;  /* default */
    int time_window_ms      = 50;   /* default */

    while ((opt = getopt_long(argc, argv, "u:l:t:", long_options, NULL)) != -1) {
        switch (opt) {
        case 'l': lower_bound_freq_ms = atoi(optarg); break;
        case 'u': upper_bound_freq_ms = atoi(optarg); break;
        case 't': time_window_ms      = atoi(optarg); break;
        }
    }

    /* ---- Push options into the BPF map ---- */
    struct bpf_map *options_map = bpf_object__find_map_by_name(obj, "options");
    if (!options_map) {
        fprintf(stderr, "options map not found\n");
        bpf_object__close(obj);
        return 1;
    }

    __u32 key, val;
    key = 0; val = (__u32)lower_bound_freq_ms;
    bpf_map__update_elem(options_map, &key, sizeof(key), &val, sizeof(val), BPF_ANY);
    key = 1; val = (__u32)upper_bound_freq_ms;
    bpf_map__update_elem(options_map, &key, sizeof(key), &val, sizeof(val), BPF_ANY);
    key = 2; val = (__u32)time_window_ms;
    bpf_map__update_elem(options_map, &key, sizeof(key), &val, sizeof(val), BPF_ANY);

    /* ---- Attach the BPF program ---- */
    prog = bpf_object__find_program_by_name(obj, "handle_hook");
    if (!prog) {
        fprintf(stderr, "program 'handle_hook' not found\n");
        bpf_object__close(obj);
        return 1;
    }

    link = bpf_program__attach(prog);
    if (!link) {
        perror("bpf_program__attach");
        bpf_object__close(obj);
        return 1;
    }

    signal(SIGINT,  handle_sig);
    signal(SIGTERM, handle_sig);

    printf("PFF monitor: lower=%d, upper=%d, window=%dms\n"
           "Monitoring started (filtering by process name). Press Ctrl+C to stop.\n",
           lower_bound_freq_ms, upper_bound_freq_ms, time_window_ms);

    /* ---- Retrieve map FDs needed for perf buffer and lower-bound checks ---- */
    int perf_fd = bpf_object__find_map_fd_by_name(obj, "events");
    if (perf_fd < 0) {
        fprintf(stderr, "Failed to find 'events' map: %s\n", strerror(errno));
        bpf_link__destroy(link);
        bpf_object__close(obj);
        return 1;
    }

    int state_fd      = bpf_object__find_map_fd_by_name(obj, "state");
    int first_ts_fd   = bpf_object__find_map_fd_by_name(obj, "first_ts");
    int timestamps_fd = bpf_object__find_map_fd_by_name(obj, "timestamps");

    if (state_fd < 0 || first_ts_fd < 0 || timestamps_fd < 0) {
        fprintf(stderr, "Failed to find state/first_ts/timestamps maps\n");
        bpf_link__destroy(link);
        bpf_object__close(obj);
        return 1;
    }

    /* ---- Set up perf buffer ---- */
    struct perf_buffer *pb = perf_buffer__new(
        perf_fd, 8, handle_event, handle_lost, NULL, NULL);
    if (!pb) {
        fprintf(stderr, "Failed to create perf buffer: %s\n", strerror(errno));
        bpf_link__destroy(link);
        bpf_object__close(obj);
        return 1;
    }

    /*
     * Main loop:
     *   - Poll perf buffer with a 10 ms timeout.
     *   - After each poll, run the lower-bound check in user space.
     *
     * The 10 ms poll timeout gives us the periodic lower-bound sampling
     * (−1/20 pts approach — straightforward and correct).
     */
    while (running) {
        err = perf_buffer__poll(pb, 10 /* ms */);
        if (err < 0 && err != -EINTR) {
            fprintf(stderr, "Polling error %d\n", err);
            break;
        }
        printf("caca partout");
        check_lower_bound(state_fd, first_ts_fd, timestamps_fd,
                          lower_bound_freq_ms, time_window_ms);
    }

    perf_buffer__free(pb);
    bpf_link__destroy(link);
    bpf_object__close(obj);
    return 0;
}