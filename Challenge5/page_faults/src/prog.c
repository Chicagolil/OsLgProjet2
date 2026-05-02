#include <stdio.h>
#include <unistd.h>
#include <errno.h>
#include <signal.h>
#include <bpf/libbpf.h>
#include <getopt.h>
#include <stdlib.h>

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

    printf("Program loaded. Press Ctrl+C to exit.\n");
    // Keep the program running until interrupted
    while (running)
        sleep(1);

    // Cleanup
    bpf_link__destroy(link);   // detaches the program from the hook
    bpf_object__close(obj);    // unloads and frees the BPF object

    return 0;
}
