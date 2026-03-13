#include "../include/storage.h"

static const char *event_type_to_str(u32 type)
{
    if (type == EDR_EVENT_EXEC)
        return "exec";
    if (type == EDR_EVENT_CONNECT)
        return "connect";
    if (type == EDR_EVENT_OPENAT_ENTER)
        return "openat_enter";
    if (type == EDR_EVENT_OPENAT_EXIT)
        return "openat_exit";
    if (type == EDR_EVENT_WRITE)
        return "write";
    if (type == EDR_EVENT_UNLINKAT)
        return "unlink_at";
    if (type == EDR_EVENT_RENAMEAT2)
        return "renameat2";
    if (type == EDR_EVENT_BIND)
        return "bind";
    if (type == EDR_EVENT_LISTEN)
        return "listen";
    if (type == EDR_EVENT_ACCEPT)
        return "accept";
    if (type == EDR_EVENT_READ)
        return "read";
    return "type";
}

int insert_base_event(storage_t *storage, const event_t *evt, sqlite3_int64 *event_id)
{
    sqlite3_stmt *stmt = NULL;
    const char *sql =
        "INSERT INTO events (ts_ns, type, type_name, pid, ppid, uid, comm) "
        "VALUES (?, ?, ?, ?, ?, ?, ?);";
    
    if (!storage || !storage->db || !evt || !event_id)
        return 84;
    if (sqlite3_prepare_v2(storage->db, sql, -1, &stmt, NULL) != SQLITE_OK)
        return 84;
    
    sqlite3_bind_int64(stmt, 1, (sqlite3_int64)evt->ts_ns);
    sqlite3_bind_int(stmt, 2, evt->type);
    sqlite3_bind_text(stmt, 3, event_type_to_str(evt->type), -1, SQLITE_TRANSIENT);
    sqlite3_bind_int(stmt, 4, evt->pid);
    sqlite3_bind_int(stmt, 5, evt->ppid);
    sqlite3_bind_int(stmt, 6, evt->uid);
    sqlite3_bind_text(stmt, 7, evt->comm, -1, SQLITE_TRANSIENT);

    if (sqlite3_step(stmt) != SQLITE_DONE) {
        sqlite3_finalize(stmt);
        return 84;
    }
    sqlite3_finalize(stmt);
    *event_id = sqlite3_last_insert_rowid(storage->db);
    return 0;
}

int insert_exec_event(storage_t *storage, sqlite3_int64 event_id, const event_t *evt)
{
    sqlite3_stmt *stmt = NULL;
    const char *sql =
        "INSERT INTO exec_events (event_id, path) VALUES (?, ?);";

    if (sqlite3_prepare_v2(storage->db, sql, -1, &stmt, NULL) != SQLITE_OK)
        return 84;
    
    sqlite3_bind_int64(stmt, 1, event_id);
    sqlite3_bind_text(stmt, 2, evt->data.exec.filename, -1, SQLITE_TRANSIENT);
    if (sqlite3_step(stmt) != SQLITE_DONE) {
        sqlite3_finalize(stmt);
        return 84;
    }
    sqlite3_finalize(stmt);
    return 0;
}

int insert_connect_event(storage_t *storage, sqlite3_int64 event_id, const event_t *evt)
{
    sqlite3_stmt *stmt = NULL;
    const char *sql =
        "INSERT INTO connect_events (event_id, dst_ip, dst_port) VALUES (?, ?, ?);";
    char ip_str[32];
    u32 ip = evt->data.connect.dst_ip;

    snprintf(ip_str, sizeof(ip_str), "%u.%u.%u.%u",
        ip & 0xFF,
        (ip >> 8) & 0xFF,
        (ip >> 16) & 0xFF,
        (ip >> 24) & 0xFF);

    if (sqlite3_prepare_v2(storage->db, sql, -1, &stmt, NULL) != SQLITE_OK)
        return 84;
    
    sqlite3_bind_int64(stmt, 1, event_id);
    sqlite3_bind_text(stmt, 2, ip_str, -1, SQLITE_TRANSIENT);
    sqlite3_bind_int(stmt, 3, evt->data.connect.dst_port);

    if (sqlite3_step(stmt) != SQLITE_DONE) {
        sqlite3_finalize(stmt);
        return 84;
    }
    sqlite3_finalize(stmt);
    return 0;
}

int insert_openat_enter_event(storage_t *storage, sqlite3_int64 event_id, const event_t *evt)
{
    sqlite3_stmt *stmt = NULL;
    const char *sql =
        "INSERT INTO openat_enter_events (event_id, path, flags) VALUES (?, ?, ?);";

    if (sqlite3_prepare_v2(storage->db, sql, -1, &stmt, NULL) != SQLITE_OK)
        return 84;
    
    sqlite3_bind_int64(stmt, 1, event_id);
    sqlite3_bind_text(stmt, 2, evt->data.openat.filename, -1, SQLITE_TRANSIENT);
    sqlite3_bind_int(stmt, 3, evt->data.openat.flags);

    if (sqlite3_step(stmt) != SQLITE_DONE) {
        sqlite3_finalize(stmt);
        return 84;
    }
    sqlite3_finalize(stmt);
    return 0;
}

int insert_openat_exit_event(storage_t *storage, sqlite3_int64 event_id, const event_t *evt)
{
    sqlite3_stmt *stmt = NULL;
    const char *sql =
        "INSERT INTO openat_exit_events (event_id, fd, ret) VALUES (?, ?, ?);";

    if (sqlite3_prepare_v2(storage->db, sql, -1, &stmt, NULL) != SQLITE_OK)
        return 84;
    
    sqlite3_bind_int64(stmt, 1, event_id);
    sqlite3_bind_int(stmt, 2, evt->data.openat.fd);
    sqlite3_bind_int(stmt, 3, evt->data.openat.ret);

    if (sqlite3_step(stmt) != SQLITE_DONE) {
        sqlite3_finalize(stmt);
        return 84;
    }
    sqlite3_finalize(stmt);
    return 0;
}

int insert_write_event(storage_t *storage, sqlite3_int64 event_id, const event_t *evt)
{
    sqlite3_stmt *stmt = NULL;
    const char *sql =
        "INSERT INTO write_events (event_id, fd, count, path) VALUES (?, ?, ?, ?);";
    const char *path = tracker_get_fd_path(storage->tracker, evt->pid, evt->data.write.fd);

    if (sqlite3_prepare_v2(storage->db, sql, -1, &stmt, NULL) != SQLITE_OK)
        return 84;
    
    sqlite3_bind_int64(stmt, 1, event_id);
    sqlite3_bind_int(stmt, 2, evt->data.write.fd);
    sqlite3_bind_int64(stmt, 3, evt->data.write.count);
    sqlite3_bind_text(stmt, 4, path, -1, SQLITE_TRANSIENT);

    if (sqlite3_step(stmt) != SQLITE_DONE) {
        sqlite3_finalize(stmt);
        return 84;
    }
    sqlite3_finalize(stmt);
    return 0;
}

int insert_unlinkat_event(storage_t *storage, sqlite3_int64 event_id, const event_t *evt)
{
    sqlite3_stmt *stmt = NULL;
    const char *sql =
        "INSERT INTO unlinkat_events (event_id, path, flags) VALUES (?, ?, ?);";

    if (sqlite3_prepare_v2(storage->db, sql, -1, &stmt, NULL) != SQLITE_OK)
        return 84;
    
    sqlite3_bind_int64(stmt, 1, event_id);
    sqlite3_bind_text(stmt, 2, evt->data.unlinkat.filename, -1, SQLITE_TRANSIENT);
    sqlite3_bind_int(stmt, 3, evt->data.unlinkat.flags);

    if (sqlite3_step(stmt) != SQLITE_DONE) {
        sqlite3_finalize(stmt);
        return 84;
    }
    sqlite3_finalize(stmt);
    return 0;
}


int insert_renameat2_event(storage_t *storage, sqlite3_int64 event_id, const event_t *evt)
{
    sqlite3_stmt *stmt = NULL;
    const char *sql =
        "INSERT INTO renameat2_events (event_id, old_path, new_path, flags) VALUES (?, ?, ?, ?);";

    if (sqlite3_prepare_v2(storage->db, sql, -1, &stmt, NULL) != SQLITE_OK)
        return 84;
    
    sqlite3_bind_int64(stmt, 1, event_id);
    sqlite3_bind_text(stmt, 2, evt->data.renameat2.old_filename, -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt, 3, evt->data.renameat2.new_filename, -1, SQLITE_TRANSIENT);
    sqlite3_bind_int(stmt, 4, evt->data.renameat2.flags);

    if (sqlite3_step(stmt) != SQLITE_DONE) {
        sqlite3_finalize(stmt);
        return 84;
    }
    sqlite3_finalize(stmt);
    return 0;
}

int insert_bind_event(storage_t *storage, sqlite3_int64 event_id, const event_t *evt)
{
    sqlite3_stmt *stmt = NULL;
    const char *sql =
        "INSERT INTO bind_events (event_id, fd, bind_ip, bind_port, bind_family) VALUES (?, ?, ?, ?, ?);";
    char ip_str[32];
    u32 ip = evt->data.bind.addr;

    snprintf(ip_str, sizeof(ip_str), "%u.%u.%u.%u",
        ip & 0xFF,
        (ip >> 8) & 0xFF,
        (ip >> 16) & 0xFF,
        (ip >> 24) & 0xFF);

    if (sqlite3_prepare_v2(storage->db, sql, -1, &stmt, NULL) != SQLITE_OK)
        return 84;
    
    sqlite3_bind_int64(stmt, 1, event_id);
    sqlite3_bind_int(stmt, 2, evt->data.bind.fd);
    sqlite3_bind_text(stmt, 3, ip_str, -1, SQLITE_TRANSIENT);
    sqlite3_bind_int(stmt, 4, evt->data.bind.port);
    sqlite3_bind_int(stmt, 5, evt->data.bind.family);

    if (sqlite3_step(stmt) != SQLITE_DONE) {
        sqlite3_finalize(stmt);
        return 84;
    }
    sqlite3_finalize(stmt);
    return 0;
}

int insert_listen_event(storage_t *storage, sqlite3_int64 event_id, const event_t *evt)
{
    sqlite3_stmt *stmt = NULL;
    const char *sql =
        "INSERT INTO listen_events (event_id, fd, backlog) VALUES (?, ?, ?);";

    if (sqlite3_prepare_v2(storage->db, sql, -1, &stmt, NULL) != SQLITE_OK)
        return 84;
    
    sqlite3_bind_int64(stmt, 1, event_id);
    sqlite3_bind_int(stmt, 2, evt->data.listen.fd);
    sqlite3_bind_int(stmt, 3, evt->data.listen.backlog);

    if (sqlite3_step(stmt) != SQLITE_DONE) {
        sqlite3_finalize(stmt);
        return 84;
    }
    sqlite3_finalize(stmt);
    return 0;
}

int insert_accept_event(storage_t *storage, sqlite3_int64 event_id, const event_t *evt)
{
    sqlite3_stmt *stmt = NULL;
    const char *sql =
        "INSERT INTO accept_events (event_id, fd) VALUES (?, ?);";

    if (sqlite3_prepare_v2(storage->db, sql, -1, &stmt, NULL) != SQLITE_OK)
        return 84;
    
    sqlite3_bind_int64(stmt, 1, event_id);
    sqlite3_bind_int(stmt, 2, evt->data.accept.fd);

    if (sqlite3_step(stmt) != SQLITE_DONE) {
        sqlite3_finalize(stmt);
        return 84;
    }
    sqlite3_finalize(stmt);
    return 0;
}

int insert_read_event(storage_t *storage, sqlite3_int64 event_id, const event_t *evt)
{
    sqlite3_stmt *stmt = NULL;
    const char *sql =
        "INSERT INTO read_events (event_id, fd, count, path) VALUES (?, ?, ?, ?);";
    const char *path = tracker_get_fd_path(storage->tracker, evt->pid, evt->data.read.fd);

    if (sqlite3_prepare_v2(storage->db, sql, -1, &stmt, NULL) != SQLITE_OK)
        return 84;
    
    sqlite3_bind_int64(stmt, 1, event_id);
    sqlite3_bind_int(stmt, 2, evt->data.read.fd);
    sqlite3_bind_int64(stmt, 3, evt->data.read.count);
    sqlite3_bind_text(stmt, 4, path, -1, SQLITE_TRANSIENT);

    if (sqlite3_step(stmt) != SQLITE_DONE) {
        sqlite3_finalize(stmt);
        return 84;
    }
    sqlite3_finalize(stmt);
    return 0;
}
