// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>
#include "buffer_struct.h"

char LICENSE[] SEC("license") = "Dual BSD/GPL";

// Place your code here. Your program must be called "handle_hook".

// options
struct{
    __uint(type, BPF_MAP_TYPE_ARRAY); 
    __uint(max_entries,3); 
    __type(key, __u32); 
    __type(value, __u32);   
} options SEC(".maps");

// perf buffer
struct {
    __uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
    __uint(key_size, sizeof(__u32));
    __uint(value_size, sizeof(__u32));
} events SEC(".maps");

// fenêtre glissante des timestamps 
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 10000);  // max upper_bound_count
    __type(key, __u32);
    __type(value, __u64);
} timestamps SEC(".maps");

// index courant dans la fenêtre
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, __u32);
} window_index SEC(".maps");

// compteur de page faults
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, __u32);
} pf_count SEC(".maps");

// bonus, limiter l'utilisation du buffer 
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, __u32);
} too_high_flag SEC(".maps");

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

        // récuperer le timestamp actuel
        __u64 timestamp = bpf_ktime_get_ns();

        // récupérer l'index courant 
        key = 0;
        __u32 *index = bpf_map_lookup_elem(&window_index, &key); 
        if(!index){
            return 0;
        }

        // récupérer le compteur 
        key = 0;
        __u32 *count = bpf_map_lookup_elem(&pf_count, &key);
        if(!count){
            return 0;
        };

        // vérifier si la fenêtre est remplie 
        __u64 upper_bound_count = (__u64)*upper_bound_freq_ms * (__u64)*time_window_ms;
        if(*count < upper_bound_count ) { 
            // écrire le timestamps à l'index courant 
            key = *count; 
            bpf_map_update_elem(&timestamps, &key, &timestamp, BPF_ANY);
            (*count)++;
            (*index)++; 
            return 0; 
        }

        // la map est remplie 
        __u32 old_index = (*index) % upper_bound_count;
        key = old_index;

        // timestamp le plus vieux 
        __u64 *old_timestamp = bpf_map_lookup_elem(&timestamps,&key); 
        if(!old_timestamp){
            return 0; 
        }
        
        // récupérer le flag 
        key = 0;
        __u32 *flag = bpf_map_lookup_elem(&too_high_flag, &key);
        if(!flag){
            return 0;
        }
        __u64 delta =  timestamp - *old_timestamp;
        __u64 window_ns = (__u64)(*time_window_ms) * 1000000ULL;

        __u64 upper_threshold = window_ns;
        __u64 lower_threshold = window_ns * 5 / 10;  // 90% du seuil

        if(delta < upper_threshold ){
            if(*flag == 0){
                // too high → envoyer message
                __u32 pid = bpf_get_current_pid_tgid() >> 32;
                struct event e = {.pid = pid, .type = 1};
                bpf_perf_event_output(ctx, &events, BPF_F_CURRENT_CPU, &e, sizeof(e));
                *flag = 1;
            }

        } else if(delta > lower_threshold) {
            *flag = 0;
        }
       
        // mettre à jour la fenêtre 
        key = old_index; 
        bpf_map_update_elem(&timestamps, &key, &timestamp, BPF_ANY);
        *index = (*index + 1) % upper_bound_count;
    }
    return 0;
}