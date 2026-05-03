#ifndef BUFFER_STRUCT_H
#define BUFFER_STRUCT_H

/* Event types sent from kernel to user space via perf buffer */
#define EVENT_PF_TS    0   /* page-fault timestamp  → user space handles "too low" */
#define EVENT_TOO_HIGH 1   /* PFF exceeded upper bound (detected in kernel)         */

struct event {
    __u32 pid;        /* PID of page_fault_gen                  */
    __u32 type;       /* EVENT_PF_TS or EVENT_TOO_HIGH           */
    __u64 timestamp;  /* bpf_ktime_get_ns() at fault time        */
};

#endif /* BUFFER_STRUCT_H */