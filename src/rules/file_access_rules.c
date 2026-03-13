#include "../include/rules.h"

static sqlite3_int64 last_event_id = 0;


//////////////////SENSITIVE FILE ACCESS///////////////////////////////

static int rule_read_passwd(sqlite3 *db, sqlite3_int64 *seen_id)
{
    sqlite3_stmt *stmt = NULL;
    const char *sql =
        "SELECT e.id, e.ts_ns, e.pid, e.ppid, e.uid, e.comm, r.path "
        "FROM read_events r "
        "JOIN events e ON e.id = r.event_id "
        "WHERE e.id > ? "
        "AND r.path = '/etc/passwd' "
        "AND NOT EXISTS ( "
        "SELECT 1 "
        "FROM read_events r2 "
        "JOIN events e2 ON e2.id = r2.event_id "
        "WHERE r2.path = r.path "
        "AND e2.pid = e.pid "
        "AND e2.pid = e.pid "
        "AND e2.ts_ns < e.ts_ns "
        "AND e.ts_ns - e2.ts_ns < 5000000000) "
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

        raise_alert("READ_PASSWD", ts_ns, pid, ppid, uid, (const char *)comm, (const char *)path, NULL, -1);

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

static int rule_read_shadow(sqlite3 *db, sqlite3_int64 *seen_id)
{
    sqlite3_stmt *stmt = NULL;
    const char *sql =
        "SELECT e.id, e.ts_ns, e.pid, e.ppid, e.uid, e.comm, r.path "
        "FROM read_events r "
        "JOIN events e ON e.id = r.event_id "
        "WHERE e.id > ? "
        "AND r.path = '/etc/shadow' "
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

        raise_alert("READ_SHADOW", ts_ns, pid, ppid, uid, (const char *)comm, (const char *)path, NULL, -1);

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

static int rule_read_ssh_keys(sqlite3 *db, sqlite3_int64 *seen_id)
{
    sqlite3_stmt *stmt = NULL;
    const char *sql =
        "SELECT e.id, e.ts_ns, e.pid, e.ppid, e.uid, e.comm, r.path "
        "FROM read_events r "
        "JOIN events e ON e.id = r.event_id "
        "WHERE e.id > ? "
        "AND (r.path LIKE '%/.ssh/id_rsa' "
        "OR r.path LIKE '%/.ssh/id_ed25519' "
        "OR r.path LIKE '%/.ssh/id_dsa') "
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

        raise_alert("READ_SSH_KEYS", ts_ns, pid, ppid, uid, (const char *)comm, (const char *)path, NULL, -1);

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

static int rule_write_authorized_keys(sqlite3 *db, sqlite3_int64 *seen_id)
{
    sqlite3_stmt *stmt = NULL;
    const char *sql =
        "SELECT e.id, e.ts_ns, e.pid, e.ppid, e.uid, e.comm, w.path "
        "FROM write_events w "
        "JOIN events e ON e.id = w.event_id "
        "WHERE e.id > ? "
        "AND w.path LIKE '%/.ssh/authorized_keys' "
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

        raise_alert("WRITE_AUTHORIZED_KEYS", ts_ns, pid, ppid, uid, (const char *)comm, (const char *)path, NULL, -1);

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

static int rule_open_for_write_bashrc(sqlite3 *db, sqlite3_int64 *seen_id)
{
    sqlite3_stmt *stmt = NULL;
    const char *sql =
        "SELECT e.id, e.ts_ns, e.pid, e.ppid, e.uid, e.comm, oe.path, oe.flags "
        "FROM openat_enter_events oe "
        "JOIN events e ON e.id = oe.event_id "
        "WHERE e.id > ? "
        "AND (oe.path LIKE '%/.bashrc' "
        "OR oe.path LIKE '%/.zshrc' "
        "OR oe.path LIKE '%/.profile' "
        "OR oe.path LIKE '%/.bash_profile') "
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
        int flags = sqlite3_column_int(stmt, 7);

        if (!is_write_open_flags(flags))
            continue;

        raise_alert("OPEN_FOR_WRITE_BASHRC", ts_ns, pid, ppid, uid, (const char *)comm, (const char *)path, NULL, -1);

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

int run_file_access_rules(storage_t *storage)
{
    sqlite3_int64 seen_id = last_event_id;

    if (!storage || !storage->db)
        return 84;

    if (rule_read_passwd(storage->db, &seen_id) == 84)
        return 84;
    if (rule_read_shadow(storage->db, &seen_id) == 84)
        return 84;
    if (rule_read_ssh_keys(storage->db, &seen_id) == 84)
        return 84;
    if (rule_write_authorized_keys(storage->db, &seen_id) == 84)
        return 84;
    if (rule_open_for_write_bashrc(storage->db, &seen_id) == 84)
        return 84;

    last_event_id = seen_id;
    return 0;
}
