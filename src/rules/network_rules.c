#include "../include/rules.h"

static sqlite3_int64 last_event_id = 0;


//////////////////NETWORK///////////////////////////////

static int rule_exec_then_connect(sqlite3 *db, sqlite3_int64 *seen_id)
{
    sqlite3_stmt *stmt = NULL;
    const char *sql =
        "SELECT DISTINCT e_conn.id, e_conn.ts_ns, e_conn.pid, e_conn.ppid, e_conn.uid, e_conn.comm, ex.path, c.dst_ip, c.dst_port "
        "FROM connect_events c "
        "JOIN events e_conn ON e_conn.id = c.event_id "
        "JOIN exec_events ex "
        "JOIN events e_exec ON e_exec.id = ex.event_id "
        "WHERE e_conn.id > ? "
        "AND e_conn.pid = e_exec.pid "
        "AND e_exec.ts_ns < e_conn.ts_ns "
        "AND e_conn.ts_ns - e_exec.ts_ns < 5000000000 "
        "AND NOT EXISTS ( "
        "SELECT 1 "
        "FROM exec_events ex2 "
        "JOIN events e_exec2 ON e_exec2.id = ex2.event_id "
        "WHERE e_exec2.pid = e_conn.pid "
        "AND e_exec2.ts_ns < e_conn.ts_ns "
        "AND e_exec2.ts_ns > e_exec.ts_ns) "
        "ORDER BY e_conn.id ASC;";
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
        const unsigned char *dst_ip = sqlite3_column_text(stmt, 7);
        int dst_port = sqlite3_column_int(stmt, 8);

        raise_alert("EXEC_THEN_CONNECT", ts_ns, pid, ppid, uid, (const char *)comm, (const char *)path, (const char *)dst_ip, dst_port);

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

static int rule_exec_from_tmp_then_connect(sqlite3 *db, sqlite3_int64 *seen_id)
{
    sqlite3_stmt *stmt = NULL;
    const char *sql =
        "SELECT e_conn.id, e_conn.ts_ns, e_conn.pid, e_conn.ppid, e_conn.uid, e_conn.comm, ex.path, c.dst_ip, c.dst_port "
        "FROM exec_events ex "
        "JOIN events e_exec ON e_exec.id = ex.event_id "
        "JOIN connect_events c "
        "JOIN events e_conn ON e_conn.id = c.event_id "
        "WHERE e_conn.ppid = e_exec.pid "
        "AND e_exec.ts_ns < e_conn.ts_ns "
        "AND (ex.path LIKE '/tmp/%' "
        "OR ex.path LIKE '/var/tmp/%' "
        "OR ex.path LIKE '/dev/shm/%') "
        "AND e_conn.id > ? "
        "ORDER BY e_conn.id ASC;";
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
        const unsigned char *dst_ip = sqlite3_column_text(stmt, 7);
        int dst_port = sqlite3_column_int(stmt, 8);

        raise_alert("EXEC_FROM_TMP_THEN_CONNECT", ts_ns, pid, ppid, uid, (const char *)comm, (const char *)path, (const char *)dst_ip, dst_port);

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

static int rule_shell_then_connect(sqlite3 *db, sqlite3_int64 *seen_id)
{
    sqlite3_stmt *stmt = NULL;
    const char *sql =
        "SELECT e_conn.id, e_conn.ts_ns, e_conn.pid, e_conn.ppid, e_conn.uid, e_conn.comm, ex.path, c.dst_ip, c.dst_port "
        "FROM exec_events ex "
        "JOIN events e_exec ON e_exec.id = ex.event_id "
        "JOIN connect_events c "
        "JOIN events e_conn ON e_conn.id = c.event_id "
        "WHERE e_conn.ppid = e_exec.pid "
        "AND e_exec.ts_ns < e_conn.ts_ns "
        "AND (ex.path LIKE '%/bash' "
        "OR ex.path LIKE '%/sh' "
        "OR ex.path LIKE '%/zsh') "
        "AND e_conn.id > ? "
        "ORDER BY e_conn.id ASC;";
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
        const unsigned char *dst_ip = sqlite3_column_text(stmt, 7);
        int dst_port = sqlite3_column_int(stmt, 8);

        raise_alert("SHELL_THEN_CONNECT", ts_ns, pid, ppid, uid, (const char *)comm, (const char *)path, (const char *)dst_ip, dst_port);

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

static int rule_connect_external_ip(sqlite3 *db, sqlite3_int64 *seen_id)
{
    sqlite3_stmt *stmt = NULL;
    const char *sql =
        "SELECT e.id, e.ts_ns, e.pid, e.ppid, e.uid, e.comm, c.dst_ip, c.dst_port "
        "FROM connect_events c "
        "JOIN events e ON e.id = c.event_id "
        "WHERE e.id > ? "
        "AND (c.dst_ip NOT LIKE '127.%' "
        "OR c.dst_ip NOT LIKE '10.%' "
        "OR c.dst_ip NOT LIKE '192.168.%' "
        "OR c.dst_ip NOT LIKE '172.16.%' "
        "OR c.dst_ip NOT LIKE '172.17.%' "
        "OR c.dst_ip NOT LIKE '172.18.%' "
        "OR c.dst_ip NOT LIKE '172.19.%' "
        "OR c.dst_ip NOT LIKE '172.2%.%' "
        "OR c.dst_ip NOT LIKE '172.30.%' "
        "OR c.dst_ip NOT LIKE '172.31.%') "
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
        const unsigned char *dst_ip = sqlite3_column_text(stmt, 6);
        int dst_port = sqlite3_column_int(stmt, 7);

        raise_alert("CONNECT_TO_EXTERNAL_IP", ts_ns, pid, ppid, uid, (const char *)comm, NULL, (const char *)dst_ip, dst_port);

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

static int rule_bind_listen_accept(sqlite3 *db, sqlite3_int64 *seen_id)
{
    sqlite3_stmt *stmt = NULL;
    const char *sql =
        "SELECT DISTINCT e_accept.id, e_accept.ts_ns, e_accept.pid, e_accept.ppid, e_accept.uid, e_accept.comm, b.bind_ip, b.bind_port, l.backlog, a.fd "
        "FROM accept_events a "
        "JOIN events e_accept ON e_accept.id = a.event_id "
        "JOIN listen_events l "
        "JOIN events e_listen ON e_listen.id = l.event_id "
        "JOIN bind_events b "
        "JOIN events e_bind ON e_bind.id = b.event_id "
        "WHERE e_accept.id > ? "
        "AND e_accept.pid = e_listen.pid "
        "AND e_listen.pid = e_bind.pid "
        "AND e_bind.ts_ns < e_listen.ts_ns "
        "AND e_listen.ts_ns < e_accept.ts_ns "
        "ORDER BY e_accept.id ASC;";
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
        const unsigned char *dst_ip = sqlite3_column_text(stmt, 6);
        int dst_port = sqlite3_column_int(stmt, 7);

        raise_alert("BIND_LISTEN_ACCEPT", ts_ns, pid, ppid, uid, (const char *)comm, NULL, (const char *)dst_ip, dst_port);

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

int run_network_rules(storage_t *storage)
{
    sqlite3_int64 seen_id = last_event_id;

    if (!storage || !storage->db)
        return 84;

    if (rule_exec_then_connect(storage->db, &seen_id) == 84)
        return 84;
    if (rule_exec_from_tmp_then_connect(storage->db, &seen_id) == 84)
        return 84;
    if (rule_shell_then_connect(storage->db, &seen_id) == 84)
        return 84;
    if (rule_connect_external_ip(storage->db, &seen_id) == 84)
        return 84;
    if (rule_bind_listen_accept(storage->db, &seen_id) == 84)
        return 84;

    last_event_id = seen_id;
    return 0;
}