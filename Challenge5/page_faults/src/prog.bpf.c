// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

char LICENSE[] SEC("license") = "Dual BSD/GPL";

// Place your code here. Your program must be called "handle_hook".

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY); 
    __uint(max_entries, 1); 
    __type(key, __u32); 
    __type(value, __u32); 
} counter SEC(".maps"); 


SEC("kprobe/handle_mm_fault")
int BPF_KPROBE(handle_hook){

    struct task_struct *task= (struct task_struct *)bpf_get_current_task();
    
    char task_name[16]; 
    BPF_CORE_READ_STR_INTO(&task_name, task, comm); 

    if((__builtin_memcmp(task_name, "page_fault_gen", 15)) == 0){
        __u32 key = 0;
        __u32 *count = bpf_map_lookup_elem(&counter, &key ); 
        if(!count){
            return 0; 
        }

        bpf_printk("Nbr de fois que le hook est éxécuté : %d", *count); 

        return 0;
    }
}