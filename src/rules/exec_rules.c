#include "../include/rules.h"

static sqlite3_int64 last_event_id = 0;


//////////////////EXECUTION ANOMALIES///////////////////////////////

static int rule_exec_from_tmp(sqlite3 *db, sqlite3_int64 *seen_id)
{
    sqlite3_stmt *stmt = NULL;
    const char *sql =
        "SELECT e.id, e.ts_ns, e.pid, e.ppid, e.uid, e.comm, x.path "
        "FROM events e "
        "JOIN exec_events x ON x.event_id = e.id "
        "WHERE e.id > ? "
        "AND (x.path LIKE '/tmp/%' "
        "OR x.path LIKE '/var/tmp/%' "
        "OR x.path LIKE '/dev/shm/%') "
        "ORDER BY e.id ASC;";
    int rc = 0;

    if (!db || !seen_id)
        return 84;
    if (sqlite3_prepare_v2(db, sql, -1, &stmt, NULL) != SQLITE_OK) {
        fprintf(stderr, "prepare failed: %s\n", sqlite3_errmsg(db));
        return 84;
    }
    
    if (sqlite3_bind_int64(stmt, 1, last_event_id) != SQLITE_OK) {
        fprintf(stderr, "bind failed: %s\n", sqlite3_errmsg(db));
        sqlite3_finalize(stmt);
        return 84;
    }

    while ((rc = sqlite3_step(stmt)) == SQLITE_ROW) {
        sqlite3_int64 id = sqlite3_column_int64(stmt, 0);
        sqlite3_int64 ts_ns = sqlite3_column_int64(stmt, 1);
        int pid = sqlite3_column_int(stmt, 2);
        int ppid = sqlite3_column_int(stmt, 3);
        int uid = sqlite3_column_int(stmt, 4);
        const unsigned char *comm = sqlite3_column_text(stmt, 5);
        const unsigned char *path = sqlite3_column_text(stmt, 6);

        raise_alert("EXEC_FROM_TMP", ts_ns, pid, ppid, uid, (const char *)comm, (const char *)path, NULL, -1);

        if (id > *seen_id)
            *seen_id = id;
    }
    if (rc != SQLITE_DONE) {
        sqlite3_finalize(stmt);
        return 84;
    }
    sqlite3_finalize(stmt);
    return 0;
}

static int rule_exec_from_home(sqlite3 *db, sqlite3_int64 *seen_id)
{
    sqlite3_stmt *stmt = NULL;
    const char *sql =
        "SELECT e.id, e.ts_ns, e.pid, e.ppid, e.uid, e.comm, x.path "
        "FROM events e "
        "JOIN exec_events x ON x.event_id = e.id "
        "WHERE e.id > ? "
        "AND (x.path LIKE '/home/%') "
        "ORDER BY e.id ASC;";
    int rc = 0;

    if (!db || !seen_id)
        return 84;
    if (sqlite3_prepare_v2(db, sql, -1, &stmt, NULL) != SQLITE_OK) {
        fprintf(stderr, "prepare failed: %s\n", sqlite3_errmsg(db));
        return 84;
    }
    
    if (sqlite3_bind_int64(stmt, 1, last_event_id) != SQLITE_OK) {
        fprintf(stderr, "bind failed: %s\n", sqlite3_errmsg(db));
        sqlite3_finalize(stmt);
        return 84;
    }

    while ((rc = sqlite3_step(stmt)) == SQLITE_ROW) {
        sqlite3_int64 id = sqlite3_column_int64(stmt, 0);
        sqlite3_int64 ts_ns = sqlite3_column_int64(stmt, 1);
        int pid = sqlite3_column_int(stmt, 2);
        int ppid = sqlite3_column_int(stmt, 3);
        int uid = sqlite3_column_int(stmt, 4);
        const unsigned char *comm = sqlite3_column_text(stmt, 5);
        const unsigned char *path = sqlite3_column_text(stmt, 6);

        raise_alert("EXEC_FROM_HOME", ts_ns, pid, ppid, uid, (const char *)comm, (const char *)path, NULL, -1);

        if (id > *seen_id)
            *seen_id = id;
    }
    if (rc != SQLITE_DONE) {
        sqlite3_finalize(stmt);
        return 84;
    }
    sqlite3_finalize(stmt);
    return 0;
}

static int rule_exec_from_hidden_dir(sqlite3 *db, sqlite3_int64 *seen_id)
{
    sqlite3_stmt *stmt = NULL;
    const char *sql =
        "SELECT e.id, e.ts_ns, e.pid, e.ppid, e.uid, e.comm, x.path "
        "FROM events e "
        "JOIN exec_events x ON x.event_id = e.id "
        "WHERE e.id > ? "
        "AND (x.path LIKE '/.cache/%' "
        "OR x.path LIKE '/.local/%' "
        "OR x.path LIKE '/.config/%') "
        "ORDER BY e.id ASC;";
    int rc = 0;

    if (!db || !seen_id)
        return 84;
    if (sqlite3_prepare_v2(db, sql, -1, &stmt, NULL) != SQLITE_OK) {
        fprintf(stderr, "prepare failed: %s\n", sqlite3_errmsg(db));
        return 84;
    }
    
    if (sqlite3_bind_int64(stmt, 1, last_event_id) != SQLITE_OK) {
        fprintf(stderr, "bind failed: %s\n", sqlite3_errmsg(db));
        sqlite3_finalize(stmt);
        return 84;
    }

    while ((rc = sqlite3_step(stmt)) == SQLITE_ROW) {
        sqlite3_int64 id = sqlite3_column_int64(stmt, 0);
        sqlite3_int64 ts_ns = sqlite3_column_int64(stmt, 1);
        int pid = sqlite3_column_int(stmt, 2);
        int ppid = sqlite3_column_int(stmt, 3);
        int uid = sqlite3_column_int(stmt, 4);
        const unsigned char *comm = sqlite3_column_text(stmt, 5);
        const unsigned char *path = sqlite3_column_text(stmt, 6);

        raise_alert("EXEC_FROM_HIDDEN_DIR", ts_ns, pid, ppid, uid, (const char *)comm, (const char *)path, NULL, -1);

        if (id > *seen_id)
            *seen_id = id;
    }
    if (rc != SQLITE_DONE) {
        sqlite3_finalize(stmt);
        return 84;
    }
    sqlite3_finalize(stmt);
    return 0;
}

static int rule_exec_shell(sqlite3 *db, sqlite3_int64 *seen_id)
{
    sqlite3_stmt *stmt = NULL;
    const char *sql =
        "SELECT e.id, e.ts_ns, e.pid, e.ppid, e.uid, e.comm, x.path "
        "FROM events e "
        "JOIN exec_events x ON x.event_id = e.id "
        "WHERE e.id > ? "
        "AND (x.path = '/bin/sh' "
        "OR x.path = '/bin/bash' "
        "OR x.path = '/usr/bin/bash' "
        "OR x.path = '/usr/bin/sh' "
        "OR x.path = '/bin/zsh' "
        "OR x.path = '/usr/bin/zsh') "
        "ORDER BY e.id ASC;";
    int rc = 0;

    if (!db || !seen_id)
        return 84;
    if (sqlite3_prepare_v2(db, sql, -1, &stmt, NULL) != SQLITE_OK) {
        fprintf(stderr, "prepare failed: %s\n", sqlite3_errmsg(db));
        return 84;
    }
    
    if (sqlite3_bind_int64(stmt, 1, last_event_id) != SQLITE_OK) {
        fprintf(stderr, "bind failed: %s\n", sqlite3_errmsg(db));
        sqlite3_finalize(stmt);
        return 84;
    }

    while ((rc = sqlite3_step(stmt)) == SQLITE_ROW) {
        sqlite3_int64 id = sqlite3_column_int64(stmt, 0);
        sqlite3_int64 ts_ns = sqlite3_column_int64(stmt, 1);
        int pid = sqlite3_column_int(stmt, 2);
        int ppid = sqlite3_column_int(stmt, 3);
        int uid = sqlite3_column_int(stmt, 4);
        const unsigned char *comm = sqlite3_column_text(stmt, 5);
        const unsigned char *path = sqlite3_column_text(stmt, 6);

        raise_alert("EXEC_SHELL", ts_ns, pid, ppid, uid, (const char *)comm, (const char *)path, NULL, -1);

        if (id > *seen_id)
            *seen_id = id;
    }
    if (rc != SQLITE_DONE) {
        sqlite3_finalize(stmt);
        return 84;
    }
    sqlite3_finalize(stmt);
    return 0;
}

static int rule_exec_after_tmp_open_write(sqlite3 *db, sqlite3_int64 *seen_id)
{
    sqlite3_stmt *stmt = NULL;
    const char *sql =
        "SELECT e_exec.id, e_exec.ts_ns, e_exec.pid, e_exec.ppid, e_exec.uid, e_exec.comm, ex.path, oe.flags "
        "FROM exec_events ex "
        "JOIN events e_exec ON e_exec.id = ex.event_id "
        "JOIN openat_enter_events oe ON oe.path = ex.path "
        "JOIN events e_open ON e_open.id = oe.event_id "
        "WHERE e_exec.id > ? "
        "AND (ex.path LIKE '/tmp/%' "
        "OR ex.path LIKE '/var/tmp/%' "
        "OR ex.path LIKE '/dev/shm/%') "
        "AND e_open.ts_ns < e_exec.ts_ns "
        "AND e_open.pid = e_exec.ppid "
        "ORDER BY e_exec.id ASC;";
    int rc = 0;

    if (!db || !seen_id)
        return 84;
    if (sqlite3_prepare_v2(db, sql, -1, &stmt, NULL) != SQLITE_OK) {
        fprintf(stderr, "prepare failed: %s\n", sqlite3_errmsg(db));
        return 84;
    }
    
    if (sqlite3_bind_int64(stmt, 1, last_event_id) != SQLITE_OK) {
        fprintf(stderr, "bind failed: %s\n", sqlite3_errmsg(db));
        sqlite3_finalize(stmt);
        return 84;
    }

    while ((rc = sqlite3_step(stmt)) == SQLITE_ROW) {
        sqlite3_int64 id = sqlite3_column_int64(stmt, 0);
        sqlite3_int64 ts_ns = sqlite3_column_int64(stmt, 1);
        int pid = sqlite3_column_int(stmt, 2);
        int ppid = sqlite3_column_int(stmt, 3);
        int uid = sqlite3_column_int(stmt, 4);
        const unsigned char *comm = sqlite3_column_text(stmt, 5);
        const unsigned char *path = sqlite3_column_text(stmt, 6);
        int flags = sqlite3_column_int(stmt, 7);

        if (!is_write_open_flags(flags))
            continue;

        raise_alert("EXEC_AFTER_TMP_OPEN_FOR_WRITE", ts_ns, pid, ppid, uid, (const char *)comm, (const char *)path, NULL, -1);

        if (id > *seen_id)
            *seen_id = id;
    }
    if (rc != SQLITE_DONE) {
        sqlite3_finalize(stmt);
        return 84;
    }
    sqlite3_finalize(stmt);
    return 0;
}

int run_exec_rules(storage_t *storage)
{
    sqlite3_int64 seen_id = last_event_id;

    if (!storage || !storage->db)
        return 84;
    
    if (rule_exec_from_tmp(storage->db, &seen_id) == 84)
        return 84;
    if (rule_exec_from_home(storage->db, &seen_id) == 84)
        return 84;
    if (rule_exec_from_hidden_dir(storage->db, &seen_id) == 84)
        return 84;
    if (rule_exec_shell(storage->db, &seen_id) == 84)
        return 84;
    if (rule_exec_after_tmp_open_write(storage->db, &seen_id) == 84)
        return 84;

    last_event_id = seen_id;
    return 0;
}