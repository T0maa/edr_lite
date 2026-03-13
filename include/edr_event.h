#ifndef EDR_EVENT_H
    #define EDR_EVENT_H

#ifdef __BPF__
    typedef unsigned long long u64;
    typedef unsigned int u32;
    typedef unsigned short u16;
#else
    #include <stdint.h>
    typedef uint64_t u64;
    typedef uint32_t u32;
    typedef uint16_t u16;
#endif

#ifndef AF_INET
#define AF_INET 2
#endif

    #define EDR_MAX_COMM 16
    #define EDR_MAX_PATH 256
    
enum edr_event_type {
    EDR_EVENT_EXEC = 1,
    EDR_EVENT_CONNECT = 2,
    EDR_EVENT_OPENAT_ENTER = 3,
    EDR_EVENT_OPENAT_EXIT = 4,
    EDR_EVENT_WRITE = 5,
    EDR_EVENT_UNLINKAT = 6,
    EDR_EVENT_RENAMEAT2 = 7,
    EDR_EVENT_BIND = 8,
    EDR_EVENT_LISTEN = 9,
    EDR_EVENT_ACCEPT = 10,
    EDR_EVENT_READ = 11,
};

typedef struct event_s {

    u64 ts_ns;
    u32 pid;
    u32 ppid;
    u32 uid;
    u32 tid;
    u32 gid;
    u32 type;
    char comm[EDR_MAX_COMM];
    char parent_comm[EDR_MAX_COMM];

    union {
        struct {
            char filename[EDR_MAX_PATH];
        } exec;

        struct {
            u32 dst_ip;
            u16 dst_port;
            u16 pad;
        } connect;

        struct {
            char filename[EDR_MAX_PATH];
            u32 flags;
            int ret;
            int fd;
        } openat;

        struct {
            u32 fd;
            u64 count;
        } write;

        struct {
            char filename[EDR_MAX_PATH];
            u32 flags;
        } unlinkat;

        struct {
            char old_filename[EDR_MAX_PATH];
            char new_filename[EDR_MAX_PATH];
            u32 flags;
        } renameat2;
        
        struct {
            u32 fd;
            u32 addr;
            u16 port;
            u16 family;
        } bind;
        
        struct {
            u32 fd;
            u32 backlog;
        } listen;

        struct {
            u32 fd;
        } accept;

        struct {
            u32 fd;
            u64 count;
        } read;

    } data;
} event_t;

#endif /*EDR_EVENT_H*/
