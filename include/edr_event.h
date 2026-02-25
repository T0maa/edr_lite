

#ifndef EDR_EVENT_H
    #define EDR_EVENT_H

    #include <stdint.h>
    #define EDR_MAX_COMM 16
    #define EDR_MAX_PATH 256
    

typedef struct event_s {
    uint64_t ts_ns;
    uint32_t pid;
    uint32_t ppid;
    uint32_t uid;
    char comm[EDR_MAX_COMM];
    char filename[EDR_MAX_PATH];
} event_t;

#endif /*EDR_EVENT_H*/
