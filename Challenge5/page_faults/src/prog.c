#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <getopt.h>
#include <time.h>
#include <bpf/libbpf.h>
#include <bpf/bpf.h>

static unsigned long long now_ns(void)
{
    struct timespec tp;
    clock_gettime(CLOCK_MONOTONIC, &tp);
    return (unsigned long long)tp.tv_sec * 1000000000ULL
         + (unsigned long long)tp.tv_nsec;
}

struct event {
    __u32 pid;
    __u32 type;
    __u64 ts;
};

struct state {
    __u64 last_ts;
    __u64 window_ns;
    __u32 lower;
    int started;
};

static struct state st = {};

void handle_event(void *ctx, int cpu, void *data, __u32 size)
{
    struct event *e = data;

    if (!st.started) {
        st.started = 1;
        st.last_ts = e->ts;
    } else {
        st.last_ts = e->ts;
    }

    if (e->type == 1) {
        printf("PFF too high for process with PID %d\n", e->pid);
    }
}

int main(int argc, char **argv)
{
    int upper = 100;
    int lower = 10;
    int window = 50;

    static struct option long_options[] = {
        {"upper_bound_freq_ms", required_argument, 0, 'u'},
        {"lower_bound_freq_ms", required_argument, 0, 'l'},
        {"time_window_ms", required_argument, 0, 't'},
        {0, 0, 0, 0}
    };

    int opt;
    while ((opt = getopt_long(argc, argv, "u:l:t:", long_options, NULL)) != -1) {
        switch (opt) {
            case 'u': upper = atoi(optarg); break;
            case 'l': lower = atoi(optarg); break;
            case 't': window = atoi(optarg); break;
        }
    }

    printf("PFF monitor: lower=%d, upper=%d, window=%dms\n", lower, upper, window);

    struct bpf_object *obj = bpf_object__open_file("prog.bpf.o", NULL);
    bpf_object__load(obj);

    // config
    struct {
        __u64 window_ns;
        __u32 upper;
    } cfg;

    cfg.window_ns = (u64)window * 1000000ULL;
    cfg.upper = upper * window;

    st.window_ns = cfg.window_ns;
    st.lower = lower * window;

    int map_fd = bpf_object__find_map_fd_by_name(obj, "config_map");
    int key = 0;
    bpf_map_update_elem(map_fd, &key, &cfg, 0);

    int perf_fd = bpf_object__find_map_fd_by_name(obj, "events");

    struct perf_buffer *pb =
        perf_buffer__new(perf_fd, 8, handle_event, NULL, NULL, NULL);

    printf("Monitoring started\n");

    while (1) {
        perf_buffer__poll(pb, 50);

        if (!st.started)
            continue;

        __u64 now = now_ns();

        // check LOW
        if (now - st.last_ts > st.window_ns) {
            printf("PFF too low for process with PID (unknown)\n");
            st.last_ts = now; // éviter spam
        }
    }

    return 0;
}