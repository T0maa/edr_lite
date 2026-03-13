#include "../include/storage.h"
#include "../include/tracker.h"

static pid_slot_t pending_slots[TRACKER_PENDING_CAPACITY];
static fd_path_slot_t fd_slots[TRACKER_FD_CAPACITY];
static listener_slot_t listener_slots[TRACKER_LISTENER_CAPACITY];
static read_slot_t read_slots[TRACKER_READ_CAPACITY];
tracker_t tracker;

int init_filters(void)
{
    return tracker_init(&tracker, pending_slots, TRACKER_PENDING_CAPACITY, fd_slots, TRACKER_FD_CAPACITY, listener_slots, TRACKER_LISTENER_CAPACITY, read_slots, TRACKER_READ_CAPACITY);
}

bool is_sensitive_path(const char *path)
{
    if (!path)
        return false;
    if (strstr(path, "/tmp/") ||
        strstr(path, "/var/tmp/") ||
        strstr(path, "/dev/shm") ||
        strstr(path, ".bashrc") ||
        strstr(path, ".zshrc") ||
        strstr(path, ".profile") ||
        strstr(path, ".ssh/") ||
        strstr(path, "/etc/cron") ||
        strstr(path, ".bash") ||
        strstr(path, "/etc/passwd") ||
        strstr(path, "/etc/shadow"))
        return true;
    return false;
}

bool is_noisy_comm(const char *comm)
{
    if (!comm)
        return true;
    if (strcmp(comm, "edr") == 0 ||
        strcmp(comm, "systemd") == 0 ||
        strcmp(comm, "systemd-resolve") == 0 ||
        strcmp(comm, "systemd-udevd") == 0 ||
        strcmp(comm, "systemd-journald") == 0 ||
        strcmp(comm, "systemd-logind") == 0 ||
        strcmp(comm, "systemd-timesyncd") == 0 ||
        strcmp(comm, "dbus-daemon") == 0 ||
        strcmp(comm, "NetworkManager") == 0 ||
        strcmp(comm, "cupsd") == 0 ||
        strcmp(comm, "avahi-daemon") == 0 ||
        strcmp(comm, "polkitd") == 0 ||
        strcmp(comm, "udisksd") == 0 ||
        strcmp(comm, "rtkit-daemon") == 0 ||
        strcmp(comm, "code") == 0 ||
        strcmp(comm, "gnome-shell") == 0 ||
        strcmp(comm, "gnome-terminal-") == 0 ||
        strcmp(comm, "gnome-session-b") == 0 ||
        strcmp(comm, "gnome-settings-") == 0 ||
        strcmp(comm, "gnome-keyring-d") == 0 ||
        strcmp(comm, "Chrome_IOThread") == 0 ||
        strcmp(comm, "Chrome_ChildIOT") == 0 ||
        strcmp(comm, "firefox") == 0 ||
        strcmp(comm, "CompositorTileW") == 0 ||
        strcmp(comm, "chrome") == 0)
        return true;

    if (strstr(comm, "gnome"))
        return true;

    return false;
}

int sort_store_event(const event_t *evt)
{
    if (!evt)
        return 84;

    if (evt->uid < 1000)
        return 84;

    if (is_noisy_comm(evt->comm) == true)
        return 84;

    if (evt->type == EDR_EVENT_EXEC)
        return 0;

    if (evt->type == EDR_EVENT_CONNECT) {
        if (evt->data.connect.dst_ip == 0x7F000035 &&
            evt->data.connect.dst_port == 53)
            return 84;
        if (strcmp(evt->comm, "systemd-resolve") == 0)
            return 84;
        return 0;
    }

    if (evt->type == EDR_EVENT_OPENAT_ENTER) {
        if (!is_sensitive_path(evt->data.openat.filename))
            return 84;
        if (tracker_set_pending_openat(&tracker, evt->tid, evt->data.openat.filename) == 84)
            return 84;
        return 0;
    }

    if (evt->type == EDR_EVENT_OPENAT_EXIT) {
        const char *path = NULL;

        if (evt->data.openat.ret < 0) {
            tracker_clear_pending_openat(&tracker, evt->tid);
            return 84;
        }
        path = tracker_get_pending_openat(&tracker, evt->tid);
        if (!path)
            return 84;
        if (tracker_set_fd_path(&tracker, evt->pid, evt->data.openat.fd, path) == 84) {
            tracker_clear_pending_openat(&tracker, evt->tid);
            return 84;
        }
        tracker_clear_pending_openat(&tracker, evt->tid);
        return 0;
    }

    if (evt->type == EDR_EVENT_WRITE) {
        const char *path = tracker_get_fd_path(&tracker, evt->pid, evt->data.write.fd);

        if (!path)
            return 84;
        if (!is_sensitive_path(path))
            return 84;
        return 0;
    }

    if (evt->type == EDR_EVENT_UNLINKAT) {
        if (!is_sensitive_path(evt->data.unlinkat.filename))
            return 84;
        return 0;
    }

    if (evt->type == EDR_EVENT_RENAMEAT2) {
        if (!is_sensitive_path(evt->data.renameat2.old_filename) &&
            !is_sensitive_path(evt->data.renameat2.new_filename))
            return 84;
        return 0;
    }

    if (evt->type == EDR_EVENT_BIND || evt->type == EDR_EVENT_LISTEN) {
        tracker_set_listener(&tracker, evt->pid);
        return 0;
    }

    if (evt->type == EDR_EVENT_ACCEPT) {
        if (!tracker_is_listener(&tracker, evt->pid))
            return 84;
        return 0;
    }

    if (evt->type == EDR_EVENT_READ) {
        const char *path = tracker_get_fd_path(&tracker, evt->pid, evt->data.read.fd);

        if (!path)
            return 84;
        if (!strstr(path, "/etc/passwd") &&
            !strstr(path, "/etc/shadow") &&
            !strstr(path, ".ssh/"))
            return 84;
        if (tracker_mark_read(&tracker, evt->pid, evt->data.read.fd))
            return 84;
        return 0;
    }
    return 84;
}