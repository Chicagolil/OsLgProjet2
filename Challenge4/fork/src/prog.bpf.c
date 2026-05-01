// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

char LICENSE[] SEC("license") = "Dual BSD/GPL";

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY); 
    __uint(max_entries,2); 
    __type(key, __u32); 
    __type(value, __u32); 
} options SEC(".maps"); 



// hook après le fork pour récup le PID de l'enfant 
SEC("tracepoint/syscalls/sys_exit_clone")
int handle_hook(struct trace_event_raw_sys_exit *ctx){
    
    // récupérer le nom du processus
    struct task_struct *task = (struct task_struct *)bpf_get_current_task();
    
    char task_name[16];
    BPF_CORE_READ_STR_INTO(&task_name, task, comm);
    
    // processus == forking ?
    if(__builtin_memcmp(task_name, "forking", 7) == 0){
        
        // lire les valeurs de la map options
        __u32 key = 0;
        __u32 *n_process = bpf_map_lookup_elem(&options, &key);
        if(!n_process){
            return 0; 
        }

        key = 1;
        __u32 *time_separation = bpf_map_lookup_elem(&options, &key);
        if(!time_separation){
            return 0;
        }
        bpf_printk("n_process: %d, time_separation: %d\n", *n_process, *time_separation);
    }   
    return 0;
}