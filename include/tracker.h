#ifndef TRACKER_H
    #define TRACKER_H

    #include <stdbool.h>
    #include <stddef.h>
    #include <stdint.h>
    #include <string.h>

#define TRACKER_PATH_MAX 256
#define TRACKER_PENDING_CAPACITY 1024
#define TRACKER_FD_CAPACITY 2048
#define TRACKER_LISTENER_CAPACITY 512
#define TRACKER_READ_CAPACITY 2048

typedef struct pid_slot_s {
    uint32_t tid;
    bool used;
    char path[TRACKER_PATH_MAX];
} pid_slot_t;

typedef struct fd_path_slot_s {
    uint32_t pid;
    uint32_t fd;
    bool used;
    char path[TRACKER_PATH_MAX];
} fd_path_slot_t;

typedef struct listener_slot_s {
    uint32_t pid;
    bool used;
} listener_slot_t;

typedef struct read_slot_s {
    uint32_t pid;
    uint32_t fd;
    bool used;
} read_slot_t;

typedef struct tracker_s {
    pid_slot_t *pending_slots;
    size_t pending_capacity;

    fd_path_slot_t *fd_slots;
    size_t fd_capacity;

    listener_slot_t *listener_slots;
    size_t listener_capacity;

    read_slot_t *read_slots;
    size_t read_capacity;
} tracker_t;

int tracker_init(tracker_t *tracker,
    pid_slot_t *pending_buf, size_t pending_cap,
    fd_path_slot_t *fd_buf, size_t fd_cap,
    listener_slot_t *listener_buf, size_t listener_cap,
    read_slot_t *read_buf, size_t read_cap);
void tracker_clear(tracker_t *tracker);

int tracker_set_pending_openat(tracker_t *tracker, uint32_t tid, const char *path);
const char *tracker_get_pending_openat(tracker_t *tracker, uint32_t tid);
void tracker_clear_pending_openat(tracker_t *tracker, uint32_t tid);

int tracker_set_fd_path(tracker_t *tracker, uint32_t pid, uint32_t fd, const char *path);
const char *tracker_get_fd_path(tracker_t *tracker, uint32_t pid, uint32_t fd);
void tracker_clear_fd_path(tracker_t *tracker, uint32_t pid, uint32_t fd);
void tracker_clear_pid_fd_path(tracker_t *tracker, uint32_t pid);

int tracker_set_listener(tracker_t *tracker, uint32_t pid);
bool tracker_is_listener(tracker_t *tracker, uint32_t pid);
void tracker_clear_listener(tracker_t *tracker, uint32_t pid);

bool tracker_mark_read(tracker_t *tracker, uint32_t pid, uint32_t fd);

#endif