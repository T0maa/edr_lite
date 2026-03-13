#define _POSIX_C_SOURCE 200809L
#include "../include/rules.h"
#include <time.h>
#include <stdint.h>
#include <stdio.h>

static void get_real_timestamp(uint64_t ts_ns, char *buf, size_t buf_size)
{
    struct timespec real;
    struct timespec mono;
    uint64_t offset = 0;
    uint64_t real_ns = 0;
    time_t sec = 0;
    long nsec = 0;
    struct tm tm;
    char tmp[32];

    clock_gettime(CLOCK_REALTIME, &real);
    clock_gettime(CLOCK_MONOTONIC, &mono);

    offset = (uint64_t)real.tv_sec * 1000000000ULL + real.tv_nsec - ((uint64_t)mono.tv_sec * 1000000000ULL + mono.tv_nsec);
    real_ns = ts_ns + offset;

    sec = real_ns / 1000000000ULL;
    nsec = real_ns % 1000000000ULL;

    localtime_r(&sec, &tm);

    strftime(tmp, sizeof(tmp), "%Y-%m-%d %H:%M:%S", &tm);
    snprintf(buf, buf_size, "%s.%09ld", tmp, nsec);
}

void raise_alert(const char *alert_name, uint64_t ts_ns, int pid, int ppid,
    int uid, const char *comm, const char *path, const char *dst_ip, int dst_port)
{
    char buf[64];

    get_real_timestamp(ts_ns, buf, sizeof(buf));

    printf("[ALERT] %s\n", alert_name);
    printf("timestamp %s\n", buf);
    printf("pid %d, ppid %d, uid %d, comm %s\n", pid, ppid, uid, comm ? comm : "(null)");
    printf("path %s\n", path ? path : "(null)");

    if (dst_ip)
        printf("dst_ip %s, dst_port=%d\n\n", dst_ip, dst_port);
    else
        printf("\n");
}


bool is_write_open_flags(int flags)
{
    if (((flags & 1) || (flags & 2)) &&
        ((flags & 64) || (flags & 512)))
        return true;
    return false;
}

int run_rules(storage_t *storage)
{
    if (!storage || !storage->db)
        return 84;
    
    if (run_exec_rules(storage) == 84)
        return 84;
    if (run_file_access_rules(storage) == 84)
        return 84;
    if (run_network_rules(storage) == 84)
        return 84;
    if (run_anomalies_rules(storage) == 84)
        return 84;

    return 0;
}