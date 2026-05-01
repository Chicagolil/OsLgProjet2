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



// Place your code here. Your program must be called "handle_hook".
