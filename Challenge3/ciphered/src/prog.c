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
    {"shift", required_argument, 0, 's'},
    {0,0,0,0}
};

// You need to modify this program to add the --shift argument.
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


    // parser args du programme 
    int opt;
    int shift_value = 3; // valeur par défaut

    while((opt = getopt_long(argc,argv,"s:",long_options, NULL))!= -1){
        switch(opt){
            case 's' : 
                shift_value = atoi(optarg);
                break; 
        }
    }

    // map
    struct bpf_map *map = bpf_object__find_map_by_name(obj, "shift");
    if(!map){
        fprintf(stderr,"map not found\n" );
        bpf_object__close(obj);   // clean up on error
        return -1;
    }
    int key = 0; 
    shift_value = shift_value % 26;
 
    bpf_map__update_elem(map, &key, sizeof(key), &shift_value, sizeof(shift_value),BPF_ANY);

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
