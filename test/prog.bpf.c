// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>
#include "buffer_struct.h"

char LICENSE[] SEC("license") = "Dual BSD/GPL";

// Options: clé 0 = lower_bound_freq, 1 = upper_bound_freq, 2 = time_window_ms
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 3);
    __type(key, __u32);
    __type(value, __u32);
} options SEC(".maps");

// Perf buffer pour envoyer les events "too high" à l'user space
struct {
    __uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
    __uint(key_size, sizeof(__u32));
    __uint(value_size, sizeof(__u32));
} events SEC(".maps");

// Buffer circulaire des timestamps : taille max = upper_bound_count + 1 = 10001
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 10001);
    __type(key, __u32);
    __type(value, __u64);
} timestamps SEC(".maps");

// Index courant (= nombre total de page faults observés)
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, __u32);
} window_index SEC(".maps");

// PID du process surveillé (pour que l'user space puisse l'imprimer)
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, __u32);
} monitored_pid SEC(".maps");

SEC("kprobe/handle_mm_fault")
int BPF_KPROBE(handle_hook)
{
    // 1. Filtre par nom de process
    struct task_struct *task = (struct task_struct *)bpf_get_current_task();
    char task_name[16] = {};
    BPF_CORE_READ_STR_INTO(&task_name, task, comm);

    const char target[] = "page_fault_gen";
    if (__builtin_memcmp(task_name, target, sizeof(target)) != 0)
        return 0;

    // 2. Lecture des options
    __u32 zero = 0, k_upper = 1, k_window = 2;
    __u32 *upper_ptr  = bpf_map_lookup_elem(&options, &k_upper);
    __u32 *window_ptr = bpf_map_lookup_elem(&options, &k_window);
    if (!upper_ptr || !window_ptr)
        return 0;

    __u32 upper_bound_freq = *upper_ptr;
    __u32 window_ms        = *window_ptr;
    if (window_ms == 0 || upper_bound_freq == 0)
        return 0;

    __u32 upper_bound_count = upper_bound_freq * window_ms;
    if (upper_bound_count == 0 || upper_bound_count > 10000)
        return 0;

    // On dimensionne le buffer à upper_bound_count + 1 pour pouvoir détecter
    // l'instant où on dépasse strictement upper_bound_count
    __u32 buffer_size = upper_bound_count + 1;
    if (buffer_size > 10001)
        return 0;

    __u64 timestamp       = bpf_ktime_get_ns();
    __u64 window_ns = (__u64)window_ms * 1000000ULL;
    __u32 pid       = bpf_get_current_pid_tgid() >> 32;

    // 3. Enregistre le PID pour l'user space
    bpf_map_update_elem(&monitored_pid, &zero, &pid, BPF_ANY);

    // 4. Récupère l'index courant
    __u32 *idx_ptr = bpf_map_lookup_elem(&window_index, &zero);
    if (!idx_ptr)
        return 0;
    __u32 idx = *idx_ptr;

    // 5. Insertion du timestamp dans le buffer circulaire
    __u32 pos = idx % buffer_size;
    if (pos >= 10001) return 0;  // hint pour le vérifieur
    bpf_map_update_elem(&timestamps, &pos, &timestamp, BPF_ANY);

    __u32 new_idx = idx + 1;
    bpf_map_update_elem(&window_index, &zero, &new_idx, BPF_ANY);

    // 6. Détection "too high" en O(1)
    // L'astuce : avec un buffer de taille upper_bound_count + 1,
    // le (upper_bound_count + 1)-ième fault le plus récent se trouve
    // à la position (new_idx) % buffer_size (= la prochaine case à écraser).
    // Si ce timestamp est encore dans la fenêtre, on a strictement plus de
    // upper_bound_count faults dans la fenêtre → too high.
    if (new_idx >= buffer_size) {
        __u32 oldest_pos = new_idx % buffer_size;
        if (oldest_pos >= 10001) return 0;
        __u64 *oldest_ts_ptr = bpf_map_lookup_elem(&timestamps, &oldest_pos);
        if (oldest_ts_ptr) {
            __u64 oldest_ts    = *oldest_ts_ptr;
            __u64 window_start = (timestamp > window_ns) ? timestamp - window_ns : 0;
            if (oldest_ts >= window_start) {
                struct event e = {};
                e.type = 1;
                e.pid  = pid;
                bpf_perf_event_output(ctx, &events, BPF_F_CURRENT_CPU,
                                      &e, sizeof(e));
            }
        }
    }

    return 0;
}