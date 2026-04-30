// SPDX-License-Identifier: GPL-2.0
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

char LICENSE[] SEC("license") = "GPL";

SEC("tracepoint/syscalls/sys_enter_write")
int handle_hook(struct trace_event_raw_sys_enter *ctx)
{
    int fd = ctx->args[0];
    char *buf = (char *)ctx->args[1];
    size_t count = ctx->args[2];

    // On ne touche que stdout
    if (fd != 1)
        return 0;

    char local[16] = {};
    int size = count < sizeof(local) ? count : sizeof(local);

    if (size == 0) {
        return 0;
    }

    // Lire depuis user space
    if (bpf_probe_read_user(local, size, buf) < 0)
        return 0;

    // Modifier (ex: remplacer premier caractère)
    if (size > 0) {
        local[0] = 'X';
    }


    // Réécrire dans user space ⚠️
    bpf_probe_write_user(buf, local, size);

    return 0;
}