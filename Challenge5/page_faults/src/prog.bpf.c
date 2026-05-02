// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

char LICENSE[] SEC("license") = "Dual BSD/GPL";

// Place your code here. Your program must be called "handle_hook".

struct{
    __uint(type, BPF_MAP_TYPE_ARRAY); 
    __uint(max_entries,3); 
    __type(key, __u32); 
    __type(value, __u64);   
} options SEC(".maps")

SEC("kprobe/handle_mm_fault")
int BPF_KPROBE(handle_hook){

    struct task_struct *task= (struct task_struct *)bpf_get_current_task();
    char task_name[16]; 
    BPF_CORE_READ_STR_INTO(&task_name, task, comm); 
    
    if(__builtin_memcmp(task_name, "page_fault_gen", 14) == 0){

        // récuperer les options 
        // lower_bound_freq_ms
        __u32 key = 0;
        __u32 *lower_bound_freq_ms = bpf_map_lookup_elem(&options, &key);
        if(!lower_bound_freq_ms){
            return 0; 
        }

        // upper_bound_freq_ms 
        key = 1;
        __u32 *upper_bound_freq_ms  = bpf_map_lookup_elem(&options, &key);
        if(!upper_bound_freq_ms){
            return 0;
        }

        // time_window_ms
        key = 2;
        __u32 *time_window_ms  = bpf_map_lookup_elem(&options, &key);
        if(!time_window_ms){
            return 0;
        }

    }
    return 0;
}