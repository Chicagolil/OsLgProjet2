// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

char LICENSE[] SEC("license") = "Dual BSD/GPL";

// Place your code here. Your program must be called "handle_hook".

SEC("uprobe//home/student/OsLgProjet2/Challenge1/antidebug/hangman/hangman")
int BPF_UPROBE(handle_hook, struct diction_t *dictionary) {
    // task_struct du processus qui fait tourner get_word
    struct task_struct *task = (struct task_struct *)bpf_get_current_task();
    
    // task_struct du processus parent
    struct task_struct *parent_task = BPF_CORE_READ(task, parent);

    // récupérer le nom du processus parent
    char parent_name[16];
    BPF_CORE_READ_STR_INTO(&parent_name, parent_task, comm);

    // compare le nom du processus parent avec "gdb"
    if (__builtin_memcmp(parent_name, "gdb", 3) == 0) {
        bpf_send_signal(9); // signal d'arrêt SIGKILL
    }

    return 0;
}