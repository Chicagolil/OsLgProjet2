#include <stdio.h>
#include <unistd.h>
#include <errno.h>  
#include <signal.h>
#include <bpf/libbpf.h>

#include "prog.h"

static volatile int running = 1;

static void handle_sig(int sig) {
    running = 0;
}

void handle_event(void *ctx, int cpu, void *data, unsigned int data_sz) {
    const struct struct_to_give_to_perf *e = data;
    printf("Count value: %lu\n", e->count_value);
}

void handle_lost(void *ctx, int cpu, __u64 lost_cnt) {
    printf("Lost %llu events on CPU %d\n", lost_cnt, cpu);
}


int main(void) {
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

    // Find the BPF program by name
    prog = bpf_object__find_program_by_name(obj, "handle_execve");
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

    // After attaching the eBPF program, look up the map and set up polling
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
