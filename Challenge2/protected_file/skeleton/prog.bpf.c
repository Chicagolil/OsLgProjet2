// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>


# define O_WRONLY 1
# define O_RDWR 2

char LICENSE[] SEC("license") = "Dual BSD/GPL";

// Place your code here. Your program must be called "handle_hook".
SEC("lsm/file_open")
int BPF_PROG(handle_hook, struct file *file) {
    // est ce que le processus courant est le scanner ?
    struct task_struct *task = (struct task_struct *)bpf_get_current_task();
    char task_name[16];
    BPF_CORE_READ_STR_INTO(&task_name, task,comm);
    if(__builtin_memcmp(task_name, "scanner", 7) == 0) {
        
        // récupérer les flags d'ouverture 
        unsigned int flags = BPF_CORE_READ(file, f_flags);
        if(flags & O_WRONLY || flags & O_RDWR) {
            return -1;
        }
    }
    
    return 0;
}