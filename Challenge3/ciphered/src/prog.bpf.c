// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

char LICENSE[] SEC("license") = "Dual BSD/GPL";

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, int);
    __type(value, int);
} shift SEC(".maps");

// Place your code here. Your program must be called "handle_hook".

SEC("tracepoint/syscalls/sys_enter_write")
int handle_hook(struct trace_event_raw_sys_enter *ctx) {
    int fd = ctx->args[0];
    // bpf_printk("hello");
    struct task_struct *task = (struct task_struct *)bpf_get_current_task();
 
    // récupérer le nom du processus
    char task_name[16];
    BPF_CORE_READ_STR_INTO(&task_name, task, comm);

//    bpf_printk("nom du processus : %s", task_name);
    if(__builtin_memcmp(task_name, "echo_test", 9) == 0) {
        // récupérer le fd de l'appel write
        int fd = ctx -> args[0];
        if(fd == 1 || fd == 2) {
            return -1;
        }
        bpf_printk("fd du proccess %s:%d",task_name, fd);
        // récupérer la valeur de la map shift
        int key = 0; 
        int *shift_value = bpf_map_lookup_elem(&shift, &key);
        if(!shift_value) {
            return -1;
        }

    }
    return 0;
}
