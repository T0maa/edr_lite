#ifndef STORAGE_H
    #define STORAGE_H

    #include "edr_event.h"
    #include <stdio.h>
    #include <unistd.h>
    #include <signal.h>
    #include <errno.h>
    #include <bpf/libbpf.h>
    #include <bpf/bpf.h>
    #include <sqlite3.h>
    #include "../include/edr_event.h"
    #include "../include/tracker.h"

typedef struct storage_s {
    sqlite3 *db;
    tracker_t *tracker;
} storage_t;

int init_storage(storage_t *storage);
void close_storage(storage_t *storage);

int init_filters(void);

int handle_event(void *ctx, void *data, size_t data_size);

int insert_base_event(storage_t *storage, const event_t *evt, sqlite3_int64 *event_id);
int insert_exec_event(storage_t *storage, sqlite3_int64 event_id, const event_t *evt);
int insert_connect_event(storage_t *storage, sqlite3_int64 event_id, const event_t *evt);
int insert_openat_enter_event(storage_t *storage, sqlite3_int64 event_id, const event_t *evt);
int insert_openat_exit_event(storage_t *storage, sqlite3_int64 event_id, const event_t *evt);
int insert_write_event(storage_t *storage, sqlite3_int64 event_id, const event_t *evt);
int insert_unlinkat_event(storage_t *storage, sqlite3_int64 event_id, const event_t *evt);
int insert_renameat2_event(storage_t *storage, sqlite3_int64 event_id, const event_t *evt);
int insert_bind_event(storage_t *storage, sqlite3_int64 event_id, const event_t *evt);
int insert_listen_event(storage_t *storage, sqlite3_int64 event_id, const event_t *evt);
int insert_accept_event(storage_t *storage, sqlite3_int64 event_id, const event_t *evt);
int insert_read_event(storage_t *storage, sqlite3_int64 event_id, const event_t *evt);

int sort_store_event(const event_t *evt);

#endif /*STORAGE_H*/
