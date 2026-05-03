#ifndef BUFFER_STRUCT_H
#define BUFFER_STRUCT_H

/* Event types sent from kernel to user space via perf buffer */
#define EVENT_PF_TS    0   /* throttled timestamp (for user-space "no-fault" deadline)  */
#define EVENT_TOO_HIGH 1   /* PFF exceeded upper bound — detected in kernel              */
#define EVENT_TOO_LOW  2   /* PFF below lower bound at fault time — detected in kernel   */

struct event {
    __u32 pid;        /* PID of page_fault_gen       */
    __u32 type;       /* one of the EVENT_* values   */
    __u64 timestamp;  /* bpf_ktime_get_ns()          */
};

#endif /* BUFFER_STRUCT_H */