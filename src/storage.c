#include <stdio.h>
#include <unistd.h>
#include <signal.h>
#include <errno.h>
#include <bpf/libbpf.h>
#include <bpf/bpf.h>
#include "../include/storage.h"

int init_storage(storage_t *storage)
{
    const char *sql[] = {
        "PRAGMA foreign_keys = ON;",

        "CREATE TABLE IF NOT EXISTS events ("
        "id INTEGER PRIMARY KEY AUTOINCREMENT,"
        "ts_ns INTEGER NOT NULL,"
        "type INTEGER NOT NULL,"
        "type_name TEXT NOT NULL,"
        "pid INTEGER NOT NULL,"
        "ppid INTEGER NOT NULL,"
        "uid INTEGER NOT NULL,"
        "comm TEXT NOT NULL"
        ");",

        "CREATE TABLE IF NOT EXISTS exec_events ("
        "event_id INTEGER PRIMARY KEY,"
        "path TEXT NOT NULL,"
        "FOREIGN KEY (event_id) REFERENCES events(id) ON DELETE CASCADE"
        ");",

        "CREATE TABLE IF NOT EXISTS connect_events ("
        "event_id INTEGER PRIMARY KEY,"
        "dst_ip TEXT NOT NULL,"
        "dst_port INTEGER NOT NULL,"
        "FOREIGN KEY (event_id) REFERENCES events(id) ON DELETE CASCADE"
        ");",

        "CREATE TABLE IF NOT EXISTS openat_enter_events ("
        "event_id INTEGER PRIMARY KEY,"
        "path TEXT NOT NULL,"
        "flags INTEGER NOT NULL,"
        "FOREIGN KEY (event_id) REFERENCES events(id) ON DELETE CASCADE"
        ");",

        "CREATE TABLE IF NOT EXISTS openat_exit_events ("
        "event_id INTEGER PRIMARY KEY,"
        "fd INTEGER NOT NULL,"
        "ret INTEGER NOT NULL,"
        "FOREIGN KEY (event_id) REFERENCES events(id) ON DELETE CASCADE"
        ");",

        "CREATE TABLE IF NOT EXISTS write_events ("
        "event_id INTEGER PRIMARY KEY,"
        "fd INTEGER NOT NULL,"
        "count INTEGER NOT NULL,"
        "path TEXT NOT NULL,"
        "FOREIGN KEY (event_id) REFERENCES events(id) ON DELETE CASCADE"
        ");",

        "CREATE TABLE IF NOT EXISTS unlinkat_events ("
        "event_id INTEGER PRIMARY KEY,"
        "path TEXT NOT NULL,"
        "flags INTEGER NOT NULL,"
        "FOREIGN KEY (event_id) REFERENCES events(id) ON DELETE CASCADE"
        ");",

        "CREATE TABLE IF NOT EXISTS renameat2_events ("
        "event_id INTEGER PRIMARY KEY,"
        "old_path TEXT NOT NULL,"
        "new_path TEXT NOT NULL,"
        "flags INTEGER NOT NULL,"
        "FOREIGN KEY (event_id) REFERENCES events(id) ON DELETE CASCADE"
        ");",

        "CREATE TABLE IF NOT EXISTS bind_events ("
        "event_id INTEGER PRIMARY KEY,"
        "fd INTEGER NOT NULL,"
        "bind_ip TEXT NOT NULL,"
        "bind_port INTEGER NOT NULL,"
        "bind_family INTEGER NOT NULL,"
        "FOREIGN KEY (event_id) REFERENCES events(id) ON DELETE CASCADE"
        ");",

        "CREATE TABLE IF NOT EXISTS listen_events ("
        "event_id INTEGER PRIMARY KEY,"
        "fd INTEGER NOT NULL,"
        "backlog INTEGER NOT NULL,"
        "FOREIGN KEY (event_id) REFERENCES events(id) ON DELETE CASCADE"
        ");",

        "CREATE TABLE IF NOT EXISTS accept_events ("
        "event_id INTEGER PRIMARY KEY,"
        "fd INTEGER NOT NULL,"
        "FOREIGN KEY (event_id) REFERENCES events(id) ON DELETE CASCADE"
        ");",
    
        "CREATE TABLE IF NOT EXISTS read_events ("
        "event_id INTEGER PRIMARY KEY,"
        "fd INTEGER NOT NULL,"
        "count INTEGER NOT NULL,"
        "path TEXT NOT NULL,"
        "FOREIGN KEY (event_id) REFERENCES events(id) ON DELETE CASCADE"
        ");",

        "CREATE INDEX IF NOT EXISTS idx_events_pid ON events(pid);",
        "CREATE INDEX IF NOT EXISTS idx_events_type ON events(type);",
        "CREATE INDEX IF NOT EXISTS idx_events_ts ON events(ts_ns);",
        "CREATE INDEX IF NOT EXISTS idx_events_comm ON events(comm);",
        "CREATE INDEX IF NOT EXISTS idx_events_type_name ON events(type_name);",

        "CREATE INDEX IF NOT EXISTS idx_exec_event_id ON exec_events(event_id);",
        "CREATE INDEX IF NOT EXISTS idx_exec_path ON exec_events(path);",

        "CREATE INDEX IF NOT EXISTS idx_connect_event_id ON connect_events(event_id);",
        "CREATE INDEX IF NOT EXISTS idx_connect_ip ON connect_events(dst_ip);",
        "CREATE INDEX IF NOT EXISTS idx_connect_port ON connect_events(dst_port);",

        "CREATE INDEX IF NOT EXISTS idx_openat_enter_event_id ON openat_enter_events(event_id);",
        "CREATE INDEX IF NOT EXISTS idx_openat_enter_path ON openat_enter_events(path);",

        "CREATE INDEX IF NOT EXISTS idx_openat_exit_event_id ON openat_exit_events(event_id);",
        "CREATE INDEX IF NOT EXISTS idx_openat_exit_fd ON openat_exit_events(fd);",

        "CREATE INDEX IF NOT EXISTS idx_write_event_id ON write_events(event_id);",
        "CREATE INDEX IF NOT EXISTS write_fd ON write_events(fd);",

        "CREATE INDEX IF NOT EXISTS idx_unlinkat_event_id ON unlinkat_events(event_id);",
        "CREATE INDEX IF NOT EXISTS idx_unlinkat_path ON unlinkat_events(path);",

        "CREATE INDEX IF NOT EXISTS idx_renameat2_event_id ON renameat2_events(event_id);",
        "CREATE INDEX IF NOT EXISTS idx_renameat2_old_path ON renameat2_events(old_path);",
        "CREATE INDEX IF NOT EXISTS idx_renameat2_new_path ON renameat2_events(new_path);",

        "CREATE INDEX IF NOT EXISTS idx_bind_event_id ON bind_events(event_id);",
        "CREATE INDEX IF NOT EXISTS idx_bind_port ON bind_events(bind_port);",
        "CREATE INDEX IF NOT EXISTS idx_bind_ip ON bind_events(bind_ip);",

        "CREATE INDEX IF NOT EXISTS idx_listen_event_id ON listen_events(event_id);",
        "CREATE INDEX IF NOT EXISTS idx_listen_fd ON listen_events(fd);",

        "CREATE INDEX IF NOT EXISTS idx_accept_event_id ON accept_events(event_id);",
        "CREATE INDEX IF NOT EXISTS idx_accept_fd ON accept_events(fd);",

        "CREATE INDEX IF NOT EXISTS idx_read_event_id ON read_events(event_id);",
        "CREATE INDEX IF NOT EXISTS idx_read_fd ON read_events(fd);",

        NULL
    };
    char *error_msg = NULL;
    int i = 0;

    if (!storage)
        return 84;
    if (sqlite3_open("edr.db", &storage->db) != SQLITE_OK)
        return 84;

    while (sql[i]) {
        if (sqlite3_exec(storage->db, sql[i], NULL, NULL, &error_msg) != SQLITE_OK) {
            sqlite3_free(error_msg);
            sqlite3_close(storage->db);
            storage->db = NULL;
            return 84;
        }
        i++;
    }
    return 0;
}

int storage_insert_event(const event_t *evt, storage_t *storage)
{
    sqlite3_int64 event_id;

    if (!storage || !evt)
        return 84;
    if (insert_base_event(storage, evt, &event_id) == 84)
        return 84;
    
    if (evt->type == EDR_EVENT_EXEC)
        return insert_exec_event(storage, event_id, evt);
    if (evt->type == EDR_EVENT_CONNECT)
        return insert_connect_event(storage, event_id, evt);
    if (evt->type == EDR_EVENT_OPENAT_ENTER)
        return insert_openat_enter_event(storage, event_id, evt);
    if (evt->type == EDR_EVENT_OPENAT_EXIT)
        return insert_openat_exit_event(storage, event_id, evt);
    if (evt->type == EDR_EVENT_WRITE)
        return insert_write_event(storage, event_id, evt);
    if (evt->type == EDR_EVENT_UNLINKAT)
        return insert_unlinkat_event(storage, event_id, evt);
    if (evt->type == EDR_EVENT_RENAMEAT2)
        return insert_renameat2_event(storage, event_id, evt);
    if (evt->type == EDR_EVENT_BIND)
        return insert_bind_event(storage, event_id, evt);
    if (evt->type == EDR_EVENT_LISTEN)
        return insert_listen_event(storage, event_id, evt);
    if (evt->type == EDR_EVENT_ACCEPT)
        return insert_accept_event(storage, event_id, evt);
    if (evt->type == EDR_EVENT_READ)
        return insert_read_event(storage, event_id, evt);
    return 0;
}

void close_storage(storage_t *storage)
{
    if (!storage || !storage->db)
        return;
    sqlite3_close(storage->db);
    storage->db = NULL;
}

int handle_event(void *ctx, void *data, size_t data_size)
{
    storage_t *storage = (storage_t *)ctx;
    
    if (data_size < sizeof(event_t))
        return 0;
    const event_t *evt = (const event_t *)data;

    if (sort_store_event(evt) == 84)
        return 0;
    if (storage_insert_event(evt, storage) == 84)
        return 0;
    return 0;
}