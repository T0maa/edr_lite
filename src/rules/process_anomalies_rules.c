#include "../include/rules.h"

static sqlite3_int64 last_event_id = 0;


//////////////////PROCESS ANOMALIES///////////////////////////////

static int rule_exec_from_dev_shm(sqlite3 *db, sqlite3_int64 *seen_id)
{
    sqlite3_stmt *stmt = NULL;
    const char *sql =
        "SELECT e.id, e.ts_ns, e.pid, e.ppid, e.uid, e.comm, ex.path "
        "FROM exec_events ex "
        "JOIN events e ON e.id = ex.event_id "
        "WHERE e.id > ? "
        "AND ex.path LIKE '/dev/shm/%' "
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

        raise_alert("EXEC_FROM_DEV_SHM", ts_ns, pid, ppid, uid, (const char *)comm, (const char *)path, NULL, -1);

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


static int rule_exec_from_var_tmp(sqlite3 *db, sqlite3_int64 *seen_id)
{
    sqlite3_stmt *stmt = NULL;
    const char *sql =
        "SELECT e.id, e.ts_ns, e.pid, e.ppid, e.uid, e.comm, ex.path "
        "FROM exec_events ex "
        "JOIN events e ON e.id = ex.event_id "
        "WHERE e.id > ? "
        "AND ex.path LIKE '/var/tmp/%' "
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

        raise_alert("EXEC_FROM_VAR_TMP", ts_ns, pid, ppid, uid, (const char *)comm, (const char *)path, NULL, -1);

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

static int rule_exec_network_tool(sqlite3 *db, sqlite3_int64 *seen_id)
{
    sqlite3_stmt *stmt = NULL;
    const char *sql =
        "SELECT e.id, e.ts_ns, e.pid, e.ppid, e.uid, e.comm, ex.path "
        "FROM exec_events ex "
        "JOIN events e ON e.id = ex.event_id "
        "WHERE e.id > ? "
        "AND (ex.path LIKE '%/nc' "
        "OR ex.path LIKE '%/ncat' "
        "OR ex.path LIKE '%/curl' "
        "OR ex.path LIKE '%/wget' "
        "OR ex.path LIKE '%/python' "
        "OR ex.path LIKE '%/python3') "
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

        raise_alert("EXEC_NETWORK_TOOL", ts_ns, pid, ppid, uid, (const char *)comm, (const char *)path, NULL, -1);

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

static int rule_exec_by_network_tool(sqlite3 *db, sqlite3_int64 *seen_id)
{
    sqlite3_stmt *stmt = NULL;
    const char *sql =
        "SELECT e_child.id, e_child.ts_ns, e_child.pid, e_child.ppid, e_child.uid, e_child.comm, ex_child.path "
        "FROM exec_events ex_child "
        "JOIN events e_child ON e_child.id = ex_child.event_id "
        "JOIN events e_parent ON e_parent.pid = e_child.ppid "
        "WHERE e_child.id > ? "
        "AND e_parent.ts_ns < e_child.ts_ns "
        "AND (e_parent.comm = 'curl' "
        "OR e_parent.comm = 'wget' "
        "OR e_parent.comm = 'python' "
        "OR e_parent.comm = 'python3' "
        "OR e_parent.comm = 'nc') "
        "ORDER BY e_child.id ASC;";
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

        raise_alert("EXEC_BY_NETWORK_TOOL", ts_ns, pid, ppid, uid, (const char *)comm, (const char *)path, NULL, -1);

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

int run_anomalies_rules(storage_t *storage)
{
    sqlite3_int64 seen_id = last_event_id;

    if (!storage || !storage->db)
        return 84;

    if (rule_exec_from_dev_shm(storage->db, &seen_id) == 84)
        return 84;
    if (rule_exec_from_var_tmp(storage->db, &seen_id) == 84)
        return 84;
    if (rule_exec_network_tool(storage->db, &seen_id) == 84)
        return 84;
    if (rule_exec_by_network_tool(storage->db, &seen_id) == 84)
        return 84; 

    last_event_id = seen_id;
    return 0;
}