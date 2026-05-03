#include <stdio.h>
#include <unistd.h>
#include <errno.h>
#include <signal.h>
#include <bpf/libbpf.h>
#include <getopt.h>
#include <stdlib.h>
#include "buffer_struct.h"

static volatile int running = 1;

static void handle_sig(int sig) {
    running = 0;
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
    if(e->type == 0){ 
        printf("PFF too low for process with PID %d\n", e->pid);
    }

}

void handle_lost(void *ctx, int cpu, __u64 lost_cnt){
    printf("Lost %llu events on CPU %d\n", lost_cnt, cpu);
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

    printf("PFF monitor: lower=%d hz, upper=%d hz, window=%d ms\nMonitoring started (filtering by process name). Press Ctrl+C to stop.\n",lower_bound_freq_ms,upper_bound_freq_ms,time_window_ms );

    int perf_map_fd = bpf_object__find_map_fd_by_name(obj, "events");
    if (perf_map_fd < 0) {
        fprintf(stderr, "Failed to find perf BPF map: %s\n", strerror(errno));
        bpf_link__destroy(link);
        bpf_object__close(obj);
        return 1;
    }
    
    struct perf_buffer *pb = perf_buffer__new(
        perf_map_fd,
        8,            // number of pages for the buffer (you can keep it at 8 for the project)
        handle_event, // This function will be called for each event received
        handle_lost,  // This function will be called if events are lost
        NULL,
        NULL);
    
    if (!pb) {
        fprintf(stderr, "Failed to create perf buffer: %s\n", strerror(errno));
        bpf_link__destroy(link);
        bpf_object__close(obj);
        return 1;
    }
    
    while (running) {
        err = perf_buffer__poll(pb, 100 /* timeout in ms */);
        if (err < 0 && err != -EINTR) {
            printf("Polling error %d\n", err);
            break;
        }
    }
    
    perf_buffer__free(pb);
    // Cleanup
    bpf_link__destroy(link);   // detaches the program from the hook
    bpf_object__close(obj);    // unloads and frees the BPF object

    return 0;
}
