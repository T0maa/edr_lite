#ifndef RULES_H
    #define RULES_H

    #include "storage.h"

int run_rules(storage_t *storage);

void raise_alert(const char *alert_name, uint64_t ts_ns, int pid, int ppid,
    int uid, const char *comm, const char *path, const char *dst_ip, int dst_port);

bool is_write_open_flags(int flags);

int run_exec_rules(storage_t *storage);
int run_file_access_rules(storage_t *storage);
int run_network_rules(storage_t *storage);
int run_anomalies_rules(storage_t *storage);


#endif