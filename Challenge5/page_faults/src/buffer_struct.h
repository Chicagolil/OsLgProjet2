#ifndef BUFFER_STRUCT_H
#define BUFFER_STRUCT_H

/* Maximum page faults tracked in circular buffer.
 * Constraint: upper_bound_freq_ms * time_window_ms <= 10000. */
#define MAX_FAULTS     10000

#define EVENT_TOO_LOW  0
#define EVENT_TOO_HIGH 1

struct event {
    __u32 pid;   /* PID of the monitored process           */
    __u32 type;  /* EVENT_TOO_LOW or EVENT_TOO_HIGH         */
};

#endif /* BUFFER_STRUCT_H */