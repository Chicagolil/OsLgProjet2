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

static void handle_sig(int sig) {
    running = 0;
}

// même horloge que bpf_ktime_get_ns()
static unsigned long long now_ns(void) {
    struct timespec tp;
    clock_gettime(CLOCK_MONOTONIC, &tp);
    return (unsigned long long)tp.tv_sec * 1000000000ULL
         + (unsigned long long)tp.tv_nsec;
}

static struct option long_options[] = {
    {"lower_bound_freq_ms",required_argument, 0,'l'},
    {"upper_bound_freq_ms", required_argument, 0, 'u'},
    {"time_window_ms", required_argument, 0, 't'},
    {0,0,0,0}
};



void handle_event(void *ctx, int cpu, void *data, unsigned int data_sz){
    const struct event *e = data;
    if(e->type == 1){ 
        printf("PFF too high for process with PID %d\n", e->pid);

    }
    else if(e->type == 0) {
        printf("PFF too low for process with PID %d\n", e->pid);
    }

}

void handle_lost(void *ctx, int cpu, __u64 lost_cnt){
    fprintf(stderr, "Lost %llu events on CPU %d\n", lost_cnt, cpu);
}

int main(int argc, char **argv) {
    struct bpf_object *obj;
    struct bpf_program *prog;
    struct bpf_link *link;
    int err;

    // Open the BPF object file (kernel compiled BPF program)
    obj = bpf_object__open_file("prog.bpf.o", NULL);
    if (!obj) {
        perror("bpf_object__open_file");
        return 1;
    }
    // Load the BPF object file into the kernel
    err = bpf_object__load(obj);
    if (err) {
        perror("bpf_object__load");
        bpf_object__close(obj);   // clean up on error
        return 1;
    }

    // parser les arguments 
    int opt; 
    int lower_bound_freq_ms = 10; //défaut
    int upper_bound_freq_ms = 100; //défaut 
    int time_window_ms = 50; //défaut 

    while((opt = getopt_long(argc, argv,"u:l:t:",long_options, NULL)) != -1){
        switch(opt){
            case 'l' : 
                lower_bound_freq_ms = atoi(optarg); 
                break;
            case 'u' : 
                upper_bound_freq_ms = atoi(optarg); 
                break; 
            case 't' : 
                time_window_ms = atoi(optarg); 
                break; 
        }
    }


    // map des options 
    struct bpf_map *options = bpf_object__find_map_by_name(obj, "options");
    if(!options){
        fprintf(stderr, "map not found\n");
        bpf_object__close(obj); 
        return -1; 
    }

    __u32 key = 0; 
    __u32 val = (__u32)lower_bound_freq_ms; 
    bpf_map__update_elem(options, &key, sizeof(key), &val, sizeof(val), BPF_ANY);

    key = 1;
    val = (__u32)upper_bound_freq_ms;
    bpf_map__update_elem(options, &key, sizeof(key), &val, sizeof(val), BPF_ANY); 

    key = 2;
    val = (__u32)time_window_ms;
    bpf_map__update_elem(options, &key, sizeof(key), &val, sizeof(val), BPF_ANY); 


    // maps 
    struct bpf_map *timestamps    = bpf_object__find_map_by_name(obj, "timestamps");
    struct bpf_map *monitored_pid = bpf_object__find_map_by_name(obj, "monitored_pid");
    struct bpf_map *window_index  = bpf_object__find_map_by_name(obj, "window_index");
    if (!timestamps || !monitored_pid || !window_index ) {
        fprintf(stderr, "Required maps not found\n");
        bpf_object__close(obj);
        return 1;
    }


    // Find the BPF program by name
    prog = bpf_object__find_program_by_name(obj, "handle_hook");
    if (!prog) {
        fprintf(stderr, "program not found\n");
        bpf_object__close(obj);   // clean up on error
        return 1;
    }

    // Attach the BPF program to the appropriate hook (e.g., tracepoint, kprobe)
    link = bpf_program__attach(prog);
    if (!link) {
        perror("bpf_program__attach");
        bpf_object__close(obj);   // clean up on error
        return 1;
    }

    signal(SIGINT, handle_sig);
    signal(SIGTERM, handle_sig);

    printf("PFF monitor: lower=%dhz, upper=%dhz, window=%dms\n", lower_bound_freq_ms, upper_bound_freq_ms, time_window_ms);
    printf("Monitoring started (filtering by process name). Press Ctrl+C to stop.\n");

    // perf buffer
    int perf_map_fd = bpf_object__find_map_fd_by_name(obj, "events");
    if (perf_map_fd < 0) {
        fprintf(stderr, "Failed to find perf BPF map: %s\n", strerror(errno));
        bpf_link__destroy(link);
        bpf_object__close(obj);
        return 1;
    }
    
    struct perf_buffer *pb = perf_buffer__new(
        perf_map_fd,
        8,            
        handle_event, 
        handle_lost,  
        NULL,
        NULL);
    
    if (!pb) {
        fprintf(stderr, "Failed to create perf buffer: %s\n", strerror(errno));
        bpf_link__destroy(link);
        bpf_object__close(obj);
        return 1;
    }
    

    //  pré-calculs pour le check too low 
    __u32 upper_bound_count = (__u32)upper_bound_freq_ms * (__u32)time_window_ms;
    __u32 lower_bound_count = (__u32)lower_bound_freq_ms * (__u32)time_window_ms;
    __u32 buffer_size       = upper_bound_count + 1;
    if (buffer_size > 10001){
        buffer_size = 10001;
    }
    unsigned long long window_ns = (unsigned long long)time_window_ms * 1000000ULL;


    // Buffer pour lire les timestamps depuis le kernel
    __u64 *ts_buf = calloc(buffer_size, sizeof(__u64));
    if (!ts_buf) {
        perror("calloc");
        perf_buffer__free(pb); 
        bpf_link__destroy(link); 
        bpf_object__close(obj);
        return 1;
    }


    // gestion du startup phase 
    unsigned long long first_fault_ts = 0;

    // Check périodique toutes les 10ms
    const unsigned long long check_interval_ns = 10ULL * 1000000ULL;
    unsigned long long last_check = 0;

    while (running) {
        err = perf_buffer__poll(pb, 10);
        if (err < 0 && err != -EINTR) {
            printf("Polling error %d\n", err);
            break;
        }


        unsigned long long now = now_ns();
        if (now - last_check < check_interval_ns)
            continue;
        last_check = now;

        for (__u32 i = 0; i < buffer_size; i++) {
            __u64 v = 0;
            if (bpf_map__lookup_elem(timestamps, &i, sizeof(i),&v, sizeof(v), 0) == 0)
                ts_buf[i] = v;
            else
                ts_buf[i] = 0;
        }


        // Détecte le 1er fault observé (plus petit timestamp non nul)
        if (first_fault_ts == 0) {
            for (__u32 i = 0; i < buffer_size; i++) {
                if (ts_buf[i] != 0 &&
                    (first_fault_ts == 0 || ts_buf[i] < first_fault_ts))
                    first_fault_ts = ts_buf[i];
            }
        }

        if (first_fault_ts == 0 || now < first_fault_ts + window_ns){
            continue;
        }

        unsigned long long window_start = now - window_ns;
        __u32 count = 0;
        for (__u32 i = 0; i < buffer_size; i++) {
            if (ts_buf[i] >= window_start && ts_buf[i] <= now)
                count++;
        }

        if (count < lower_bound_count) {
            __u32 key = 0, pid = 0;
            if (bpf_map__lookup_elem(monitored_pid, &key, sizeof(key), &pid, sizeof(pid), 0) == 0 && pid != 0) {
                printf("PFF too low for process with PID %d\n", pid);
            }
        }

    }
    
    free(ts_buf); 
    perf_buffer__free(pb);
    // Cleanup
    bpf_link__destroy(link);   // detaches the program from the hook
    bpf_object__close(obj);    // unloads and frees the BPF object

    return 0;
}
