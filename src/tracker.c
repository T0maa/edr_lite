#include "../include/tracker.h"

static void clear_pending_slots(tracker_t *tracker)
{
    size_t i = 0;

    for (; i < tracker->pending_capacity; i++) {
        tracker->pending_slots[i].tid = 0;
        tracker->pending_slots[i].used = false;
        tracker->pending_slots[i].path[0] = '\0';
    }
}

static void clear_fd_slots(tracker_t *tracker)
{
    size_t i = 0;

    for (; i < tracker->fd_capacity; i++) {
        tracker->fd_slots[i].pid = 0;
        tracker->fd_slots[i].fd = 0;
        tracker->fd_slots[i].used = false;
        tracker->fd_slots[i].path[0] = '\0';
    }
}

static void clear_listener_slots(tracker_t *tracker)
{
    size_t i = 0;

    for (; i < tracker->listener_capacity; i++) {
        tracker->listener_slots[i].pid = 0;
        tracker->listener_slots[i].used = false;
    }
}

static void clear_read_slots(tracker_t *tracker)
{
    size_t i = 0;

    for (; i < tracker->read_capacity; i++) {
        tracker->read_slots[i].pid = 0;
        tracker->read_slots[i].fd = 0;
        tracker->read_slots[i].used = false;
    }
}

int tracker_init(tracker_t *tracker,
    pid_slot_t *pending_buf, size_t pending_cap,
    fd_path_slot_t *fd_buf, size_t fd_cap,
    listener_slot_t *listener_buf, size_t listener_cap,
    read_slot_t *read_buf, size_t read_cap)
{
    if (!tracker || !pending_buf || !fd_buf || !listener_buf)
        return 84;
    if (pending_cap == 0 || fd_cap == 0 || listener_cap == 0)
        return 84;

    tracker->pending_slots = pending_buf;
    tracker->pending_capacity = pending_cap;
    tracker->fd_slots = fd_buf;
    tracker->fd_capacity = fd_cap;
    tracker->listener_slots = listener_buf;
    tracker->listener_capacity = listener_cap;
    tracker->read_slots = read_buf;
    tracker->read_capacity = read_cap;

    clear_pending_slots(tracker);
    clear_fd_slots(tracker);
    clear_listener_slots(tracker);
    clear_read_slots(tracker);
    return 0;
}

void tracker_clear(tracker_t *tracker)
{
    if (!tracker)
        return;
    clear_pending_slots(tracker);
    clear_fd_slots(tracker);
    clear_listener_slots(tracker);
}

int tracker_set_pending_openat(tracker_t *tracker, uint32_t tid, const char *path)
{
    size_t i = 0;
    size_t free_index = 0;

    if (!tracker || !tracker->pending_slots || tid == 0 || !path)
        return 84;
    
    free_index = tracker->pending_capacity;
    for (; i < tracker->pending_capacity; i++) {
        if (tracker->pending_slots[i].used && tracker->pending_slots[i].tid == tid) {
            strncpy(tracker->pending_slots[i].path, path, TRACKER_PATH_MAX - 1);
            tracker->pending_slots[i].path[TRACKER_PATH_MAX - 1] = '\0';
            return 0;
        }
        if (!tracker->pending_slots[i].used && free_index == tracker->pending_capacity)
            free_index = i;
    }
    if (free_index == tracker->pending_capacity)
        return 84;
    tracker->pending_slots[free_index].tid = tid;
    tracker->pending_slots[free_index].used = true;
    strncpy(tracker->pending_slots[free_index].path, path, TRACKER_PATH_MAX - 1);
    tracker->pending_slots[free_index].path[TRACKER_PATH_MAX - 1] = '\0';
    return 0;
}

const char *tracker_get_pending_openat(tracker_t *tracker, uint32_t tid)
{
    size_t i = 0;

    if (!tracker || !tracker->pending_slots || tid == 0)
        return NULL;
    for (; i < tracker->pending_capacity; i++) {
        if (tracker->pending_slots[i].used && tracker->pending_slots[i].tid == tid) {
            return tracker->pending_slots[i].path;
        }
    }
    return NULL;
}

void tracker_clear_pending_openat(tracker_t *tracker, uint32_t tid)
{
    size_t i = 0;

    if (!tracker || !tracker->pending_slots || tid == 0)
        return;
    for (; i < tracker->pending_capacity; i++) {
        if (tracker->pending_slots[i].used && tracker->pending_slots[i].tid == tid) {
            tracker->pending_slots[i].tid = 0;
            tracker->pending_slots[i].used = false;
            tracker->pending_slots[i].path[0] = '\0';
            return;
        }
    }
}

int tracker_set_fd_path(tracker_t *tracker, uint32_t pid, uint32_t fd, const char *path)
{
    size_t i = 0;
    size_t free_index = 0;

    if (!tracker || !tracker->fd_slots || pid == 0 || !path)
        return 84;
    
    free_index = tracker->fd_capacity;
    for (; i < tracker->fd_capacity; i++) {
        if (tracker->fd_slots[i].used && tracker->fd_slots[i].pid == pid && tracker->fd_slots[i].fd == fd) {
            strncpy(tracker->fd_slots[i].path, path, TRACKER_PATH_MAX - 1);
            tracker->fd_slots[i].path[TRACKER_PATH_MAX - 1] = '\0';
            return 0;
        }
        if (!tracker->fd_slots[i].used && free_index == tracker->fd_capacity)
            free_index = i;
    }
    if (free_index == tracker->fd_capacity)
        return 84;
    tracker->fd_slots[free_index].pid = pid;
    tracker->fd_slots[free_index].used = true;
    tracker->fd_slots[free_index].fd = fd;
    strncpy(tracker->fd_slots[free_index].path, path, TRACKER_PATH_MAX - 1);
    tracker->fd_slots[free_index].path[TRACKER_PATH_MAX - 1] = '\0';
    return 0;
}

const char *tracker_get_fd_path(tracker_t *tracker, uint32_t pid, uint32_t fd)
{
    size_t i = 0;

    if (!tracker || !tracker->fd_slots || pid == 0)
        return NULL;
    for (; i < tracker->fd_capacity; i++) {
        if (tracker->fd_slots[i].used && tracker->fd_slots[i].pid == pid && tracker->fd_slots[i].fd == fd) {
            return tracker->fd_slots[i].path;
        }
    }
    return NULL;
}

void tracker_clear_fd_path(tracker_t *tracker, uint32_t pid, uint32_t fd)
{
    size_t i = 0;

    if (!tracker || !tracker->fd_slots || pid == 0)
        return;
    for (; i < tracker->fd_capacity; i++) {
        if (tracker->fd_slots[i].used && tracker->fd_slots[i].pid == pid && tracker->fd_slots[i].fd == fd) {
            tracker->fd_slots[i].pid = 0;
            tracker->fd_slots[i].fd = 0;
            tracker->fd_slots[i].used = false;
            tracker->fd_slots[i].path[0] = '\0';
            return;
        }
    }
}

void tracker_clear_pid_fd_path(tracker_t *tracker, uint32_t pid)
{
    size_t i = 0;

    if (!tracker || !tracker->fd_slots || pid == 0)
        return;
    for (; i < tracker->fd_capacity; i++) {
        if (tracker->fd_slots[i].used && tracker->fd_slots[i].pid == pid) {
            tracker->fd_slots[i].pid = 0;
            tracker->fd_slots[i].fd = 0;
            tracker->fd_slots[i].used = false;
            tracker->fd_slots[i].path[0] = '\0';
            return;
        }
    }
}

int tracker_set_listener(tracker_t *tracker, uint32_t pid)
{
    size_t i = 0;
    size_t free_index = 0;

    if (!tracker || !tracker->listener_slots || pid == 0)
        return 84;
    
    free_index = tracker->listener_capacity;
    for (; i < tracker->listener_capacity; i++) {
        if (tracker->listener_slots[i].used && tracker->listener_slots[i].pid == pid)
            return 0;
        if (!tracker->listener_slots[i].used && free_index == tracker->listener_capacity)
            free_index = i;
    }
    if (free_index == tracker->listener_capacity)
        return 84;
    tracker->listener_slots[free_index].pid = pid;
    tracker->listener_slots[free_index].used = true;
    return 0;
}

bool tracker_is_listener(tracker_t *tracker, uint32_t pid)
{
    size_t i = 0;

    if (!tracker || !tracker->listener_slots || pid == 0)
        return false;
    for (; i < tracker->listener_capacity; i++) {
        if (tracker->listener_slots[i].used && tracker->listener_slots[i].pid == pid)
            return true;
    }
    return false;
}

void tracker_clear_listener(tracker_t *tracker, uint32_t pid)
{
    size_t i = 0;

    if (!tracker || !tracker->listener_slots || pid == 0)
        return;
    for (; i < tracker->listener_capacity; i++) {
        if (tracker->listener_slots[i].used && tracker->listener_slots[i].pid == pid) {
            tracker->listener_slots[i].pid = 0;
            tracker->listener_slots[i].used = false;
            return;
        }
    }
}

bool tracker_mark_read(tracker_t *tracker, uint32_t pid, uint32_t fd)
{
    size_t i = 0;
    size_t free_index = tracker->read_capacity;

    if (!tracker || !tracker->read_slots)
        return true;
    
    for (; i < tracker->read_capacity; i++) {
        if (tracker->read_slots[i].used && tracker->read_slots[i].pid == pid && tracker->read_slots[i].fd == fd)
            return true;
        if (!tracker->read_slots[i].used && free_index == tracker->read_capacity)
            free_index = i;
    }
    if (free_index == tracker->read_capacity)
        return true;
    tracker->read_slots[free_index].pid = pid;
    tracker->read_slots[free_index].fd = fd;
    tracker->read_slots[free_index].used = true;
    return false;
}