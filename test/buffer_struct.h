#ifndef BUFFER_STRUCT_H
#define BUFFER_STRUCT_H


struct event {
    __u32 pid;      // PID du processus
    __u32 type;     // 0 = too low, 1 = too high
};

#endif