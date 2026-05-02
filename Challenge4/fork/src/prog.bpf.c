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

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY); 
    __uint(max_entries, 32); 
    __type(key, __u32); 
    __type(value, __u64); 
} timestamps SEC(".maps"); 

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY); 
    __uint(max_entries, 1); 
    __type(key, __u32); 
    __type(value, __u32); 
} child_count SEC(".maps"); 


// hook après le fork pour récup le PID de l'enfant 
SEC("tracepoint/syscalls/sys_exit_clone")
int handle_hook(struct trace_event_raw_sys_exit *ctx){
    
    // récupérer le nom du processus
    struct task_struct *task = (struct task_struct *)bpf_get_current_task();
    
    char task_name[16];
    BPF_CORE_READ_STR_INTO(&task_name, task, comm);
    
    // processus == forking ?
    if(__builtin_memcmp(task_name, "forking", 7) == 0){
        
        // ne garder que les hooks des enfants 
        if(ctx->ret != 0){
            return 0;
        }

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

        // récuperer le timestamp actuel
        __u64 timestamp = bpf_ktime_get_ns();

        // récupérer le count des enfants
        key = 0; 
        __u32 *count = bpf_map_lookup_elem(&child_count, &key);
        if(!count){
            return 0;
        }


        // vérifier si la fenêtre est remplie 
        if(*count < *n_process){
            // ajouter le timestamp à la fenêtre
            key = *count;
            bpf_map_update_elem(&timestamps, &key, &timestamp, BPF_ANY);
            (*count)++;
            return 0; 
        }

        // la fenêtre est remplie, vérifier si le temps de séparation est respecté
        key = 0;
        __u64 *old_timestamp = bpf_map_lookup_elem(&timestamps, &key);
        if(!old_timestamp){
            return 0;
        }
        // si le delta est trop petit, tuer l'enfant
        if(timestamp - *old_timestamp < (__u64)(*time_separation) * 1000000000ULL){
            bpf_send_signal(9);
            return 0; 
        }
        // sinon, mettre à jour la fenêtre
        for (int i = 0; i < 32; i++){
            if(i >= n_process) {
                break;
            }

            __u32 curr_key = i; 
            __u32 next_key = i +1; 
            
            __u64 *next_val = bpf_map_lookup_elem(&timestamps, &next_key); 
            if(!next_val){
                break; 
            }
            bpf_map_update_elem(&timestamps, &curr_key, next_val, BPF_ANY);
        }
        __u32 last_key = *n_process -1; 
        bpf_map_update_elem(&timestamps,&last_key, &timestamp, BPF_ANY); 
        return 0;
    
    }   
    return 0;
}