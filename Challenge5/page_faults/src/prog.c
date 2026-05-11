#include <stdio.h>
#include <unistd.h>
#include <errno.h>
#include <signal.h>
#include <time.h>
#include <stdlib.h>
#include <string.h>
#include <getopt.h>
#include <bpf/libbpf.h>
#include <bpf/bpf.h>
#include "buffer_struct.h"

static volatile int running = 1;

static void handle_sig(int sig) { running = 0; }

// Horloge alignée avec bpf_ktime_get_ns (CLOCK_MONOTONIC)
static unsigned long long now_ns(void)
{
    struct timespec tp;
    clock_gettime(CLOCK_MONOTONIC, &tp);
    return (unsigned long long)tp.tv_sec * 1000000000ULL
         + (unsigned long long)tp.tv_nsec;
}

static struct option long_options[] = {
    {"lower_bound_freq_ms", required_argument, 0, 'l'},
    {"upper_bound_freq_ms", required_argument, 0, 'u'},
    {"time_window_ms",      required_argument, 0, 't'},
    {0, 0, 0, 0}
};

void handle_event(void *ctx, int cpu, void *data, unsigned int data_sz)
{
    const struct event *e = data;
    if (e->type == 1)
        printf("PFF too high for process with PID %d\n", e->pid);
    else if (e->type == 0)
        printf("PFF too low for process with PID %d\n", e->pid);
}

void handle_lost(void *ctx, int cpu, __u64 lost_cnt)
{
    fprintf(stderr, "Lost %llu events on CPU %d\n", lost_cnt, cpu);
}

int main(int argc, char **argv)
{
    struct bpf_object  *obj;
    struct bpf_program *prog;
    struct bpf_link    *link;
    int err;

    obj = bpf_object__open_file("prog.bpf.o", NULL);
    if (!obj) { perror("bpf_object__open_file"); return 1; }

    err = bpf_object__load(obj);
    if (err) { perror("bpf_object__load"); bpf_object__close(obj); return 1; }

    // Parse arguments
    int lower_bound_freq_ms = 10;
    int upper_bound_freq_ms = 100;
    int time_window_ms      = 50;
    int opt;
    while ((opt = getopt_long(argc, argv, "u:l:t:", long_options, NULL)) != -1) {
        switch (opt) {
            case 'l': lower_bound_freq_ms = atoi(optarg); break;
            case 'u': upper_bound_freq_ms = atoi(optarg); break;
            case 't': time_window_ms      = atoi(optarg); break;
        }
    }

    // Push des options dans la map
    struct bpf_map *options = bpf_object__find_map_by_name(obj, "options");
    if (!options) {
        fprintf(stderr, "map options not found\n");
        bpf_object__close(obj); return 1;
    }
    __u32 key, val;
    key = 0; val = (__u32)lower_bound_freq_ms;
    bpf_map__update_elem(options, &key, sizeof(key), &val, sizeof(val), BPF_ANY);
    key = 1; val = (__u32)upper_bound_freq_ms;
    bpf_map__update_elem(options, &key, sizeof(key), &val, sizeof(val), BPF_ANY);
    key = 2; val = (__u32)time_window_ms;
    bpf_map__update_elem(options, &key, sizeof(key), &val, sizeof(val), BPF_ANY);

    // FDs des maps qu'on lit en user space
    int timestamps_fd    = bpf_object__find_map_fd_by_name(obj, "timestamps");
    int monitored_pid_fd = bpf_object__find_map_fd_by_name(obj, "monitored_pid");
    int window_index_fd  = bpf_object__find_map_fd_by_name(obj, "window_index");
    if (timestamps_fd < 0 || monitored_pid_fd < 0 || window_index_fd < 0) {
        fprintf(stderr, "Required maps not found\n");
        bpf_object__close(obj); return 1;
    }

    // Attach
    prog = bpf_object__find_program_by_name(obj, "handle_hook");
    if (!prog) {
        fprintf(stderr, "program not found\n");
        bpf_object__close(obj); return 1;
    }
    link = bpf_program__attach(prog);
    if (!link) {
        perror("bpf_program__attach");
        bpf_object__close(obj); return 1;
    }

    signal(SIGINT,  handle_sig);
    signal(SIGTERM, handle_sig);

    printf("PFF monitor: lower=%d, upper=%d, window=%dms\n",
           lower_bound_freq_ms, upper_bound_freq_ms, time_window_ms);
    printf("Monitoring started (filtering by process name). Press Ctrl+C to stop.\n");

    // Perf buffer
    int perf_map_fd = bpf_object__find_map_fd_by_name(obj, "events");
    if (perf_map_fd < 0) {
        fprintf(stderr, "Failed to find perf BPF map: %s\n", strerror(errno));
        bpf_link__destroy(link); bpf_object__close(obj); return 1;
    }
    struct perf_buffer *pb = perf_buffer__new(perf_map_fd, 8,
                                              handle_event, handle_lost,
                                              NULL, NULL);
    if (!pb) {
        fprintf(stderr, "Failed to create perf buffer\n");
        bpf_link__destroy(link); bpf_object__close(obj); return 1;
    }

    // Pré-calculs
    __u32 upper_bound_count = (__u32)upper_bound_freq_ms * (__u32)time_window_ms;
    __u32 lower_bound_count = (__u32)lower_bound_freq_ms * (__u32)time_window_ms;
    __u32 buffer_size       = upper_bound_count + 1;
    if (buffer_size > 10001) buffer_size = 10001;
    unsigned long long window_ns = (unsigned long long)time_window_ms * 1000000ULL;

    __u64 *ts_buf = calloc(buffer_size, sizeof(__u64));
    if (!ts_buf) {
        perror("calloc");
        perf_buffer__free(pb); bpf_link__destroy(link); bpf_object__close(obj);
        return 1;
    }

    // Etat
    unsigned long long first_fault_ts = 0;
    __u32 last_seen_idx = 0;      // dernière valeur de window_index vue
    unsigned long long next_check_deadline = 0; // 0 = pas planifié

    // Helper inline : recalcule la deadline du prochain check lower bound
    // Renvoie 0 si rien à scheduler (count = 0)
    #define RECOMPUTE_DEADLINE() do {                                          \
        unsigned long long _now = now_ns();                                    \
        unsigned long long _ws  = (_now > window_ns) ? _now - window_ns : 0;   \
        for (__u32 _i = 0; _i < buffer_size; _i++) {                           \
            __u64 _v = 0;                                                      \
            if (bpf_map_lookup_elem(timestamps_fd, &_i, &_v) == 0)             \
                ts_buf[_i] = _v;                                               \
            else                                                               \
                ts_buf[_i] = 0;                                                \
        }                                                                      \
        unsigned long long _oldest = 0;                                        \
        for (__u32 _i = 0; _i < buffer_size; _i++) {                           \
            if (ts_buf[_i] >= _ws && ts_buf[_i] <= _now) {                     \
                if (_oldest == 0 || ts_buf[_i] < _oldest)                      \
                    _oldest = ts_buf[_i];                                      \
            }                                                                  \
        }                                                                      \
        if (_oldest == 0) {                                                    \
            next_check_deadline = 0;                                           \
        } else {                                                               \
            /* +1us pour être sûr que le fault soit sorti de la fenêtre */     \
            next_check_deadline = _oldest + window_ns + 1000ULL;               \
        }                                                                      \
    } while (0)

    while (running) {
        // Calcule le timeout du poll en fonction de la deadline
        int poll_timeout_ms;
        unsigned long long now = now_ns();
        if (next_check_deadline == 0) {
            // Pas de deadline planifiée. On poll quand même de temps en temps
            // pour détecter le premier fault et le démarrage de la fenêtre.
            poll_timeout_ms = 100;
        } else if (next_check_deadline <= now) {
            poll_timeout_ms = 0;
        } else {
            unsigned long long delta_ns = next_check_deadline - now;
            unsigned long long delta_ms = delta_ns / 1000000ULL + 1;
            if (delta_ms > 100) delta_ms = 100;
            poll_timeout_ms = (int)delta_ms;
        }

        err = perf_buffer__poll(pb, poll_timeout_ms);
        if (err < 0 && err != -EINTR) {
            fprintf(stderr, "Polling error %d\n", err);
            break;
        }

        now = now_ns();

        // Vérifie si de nouveaux faults sont arrivés (window_index a bougé)
        __u32 zero = 0, cur_idx = 0;
        if (bpf_map_lookup_elem(window_index_fd, &zero, &cur_idx) != 0)
            cur_idx = last_seen_idx;

        int new_faults = (cur_idx != last_seen_idx);
        if (new_faults) {
            last_seen_idx = cur_idx;
            // Met à jour le 1er fault observé si pas encore défini
            if (first_fault_ts == 0) {
                for (__u32 i = 0; i < buffer_size; i++) {
                    __u64 v = 0;
                    if (bpf_map_lookup_elem(timestamps_fd, &i, &v) == 0
                        && v != 0
                        && (first_fault_ts == 0 || v < first_fault_ts))
                        first_fault_ts = v;
                }
            }
            // Re-planifie la deadline (le nouveau fault peut changer t_oldest
            // utile, et surtout signifie qu'on est dans une phase active)
            RECOMPUTE_DEADLINE();
        }

        // Startup phase : pas d'évaluation lower bound tant qu'une fenêtre
        // entière ne s'est pas écoulée depuis le premier fault
        if (first_fault_ts == 0 || now < first_fault_ts + window_ns)
            continue;

        // Si la deadline n'est pas planifiée, on calcule maintenant
        if (next_check_deadline == 0)
            RECOMPUTE_DEADLINE();

        // Si la deadline est atteinte, on évalue
        if (next_check_deadline != 0 && now >= next_check_deadline) {
            // Lit la map et compte dans la fenêtre courante
            unsigned long long window_start = (now > window_ns) ? now - window_ns : 0;
            __u32 count = 0;
            for (__u32 i = 0; i < buffer_size; i++) {
                __u64 v = 0;
                if (bpf_map_lookup_elem(timestamps_fd, &i, &v) == 0)
                    ts_buf[i] = v;
                else
                    ts_buf[i] = 0;
                if (ts_buf[i] >= window_start && ts_buf[i] <= now)
                    count++;
            }

            if (count < lower_bound_count) {
                __u32 pid = 0;
                if (bpf_map_lookup_elem(monitored_pid_fd, &zero, &pid) == 0
                    && pid != 0) {
                    printf("PFF too low for process with PID %d\n", pid);
                }
            }

            // Reprogramme la prochaine deadline depuis l'état actuel
            unsigned long long oldest = 0;
            for (__u32 i = 0; i < buffer_size; i++) {
                if (ts_buf[i] >= window_start && ts_buf[i] <= now) {
                    if (oldest == 0 || ts_buf[i] < oldest)
                        oldest = ts_buf[i];
                }
            }
            if (oldest == 0) {
                // Plus aucun fault dans la fenêtre : le count est à 0,
                // déjà sous le seuil. Pour éviter de spam, on attend qu'un
                // nouveau fault arrive avant de re-check.
                next_check_deadline = 0;
            } else {
                next_check_deadline = oldest + window_ns + 1000ULL;
            }
        }
    }

    free(ts_buf);
    perf_buffer__free(pb);
    bpf_link__destroy(link);
    bpf_object__close(obj);
    return 0;
}