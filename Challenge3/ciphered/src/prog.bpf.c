// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

#define MAX_BUF_SIZE 256


char LICENSE[] SEC("license") = "Dual BSD/GPL";

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, int);
    __type(value, int);
} shift SEC(".maps");

// Place your code here. Your program must be called "handle_hook".

SEC("kprobe/ksys_write")
int BPF_KPROBE(handle_hook, unsigned int fd, const char *buf, size_t count) {

    // récupérer le nom du processus
    struct task_struct *task = (struct task_struct *)bpf_get_current_task();
    char task_name[16];
    BPF_CORE_READ_STR_INTO(&task_name, task, comm);

    if(__builtin_memcmp(task_name, "echo_test", 9) == 0) {
        // récupérer le fd de l'appel write
        if(fd == 1 || fd == 2) {
            return 0;
        }
        // récupérer la valeur de la map shift
        int key = 0; 
        int *shift_value = bpf_map_lookup_elem(&shift, &key);
        if(!shift_value) {
            return 0;
        }
        
        
        
        char local_buf[MAX_BUF_SIZE] = {0};
        __u64 read_size = count < MAX_BUF_SIZE ? count : MAX_BUF_SIZE;
        int err = bpf_probe_read_user(local_buf, read_size, buf);
        if(err < 0){
            return 0; 
        }
        
        
        for(int i = 0; i < MAX_BUF_SIZE; i++){
            if(i>= count){
                break;
            }
            
            char c = local_buf[i]; 
            
            // majuscule 
            if(c >= 'A' && c <= 'Z'){
                local_buf[i] = 'A' + (unsigned int)(c - 'A' + (*shift_value)) % 26;
            }
            
            // minuscule 
            else if(c >= 'a' && c <= 'z'){
                local_buf[i] = 'a' + (unsigned int)(c - 'a' + (*shift_value)) % 26;
            }
            
            // on ne fait rien pour le reste
        }

        //bpf_probe_write_user(buf, local_buf, count);



    }
    return 0;
}
