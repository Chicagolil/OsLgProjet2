#ifndef BUFFER_STRUCT_H
#define BUFFER_STRUCT_H

#define EVENT_TOO_HIGH 1
#define EVENT_PF_TS    0

struct event {
    __u32 pid;      // PID du processus
    __u32 type;     // 0 = too low, 1 = too high
    __u64 timestamp; 
};

#endif