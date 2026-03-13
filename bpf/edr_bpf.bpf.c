#include "vmlinux.h"
#include "../include/edr_event.h"
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_endian.h>

/*FICHIER QUI VA ETRE INTERPRETE NIVEAU KERNEL */

char LICENSE[] SEC("license") = "GPL"; /*DECLARATION DE LA LICENSE AFIN QUE LES FONCTIONS SOIENT ACCEPTEES NIVEAU KERNEL*/


struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 24);
} rb SEC(".maps");

SEC("tracepoint/syscalls/sys_enter_execve")
int tp_execve(struct trace_event_raw_sys_enter *ctx)
{
    struct task_struct *task;
    struct task_struct *parent;
    event_t *e = bpf_ringbuf_reserve(&rb, sizeof(*e), 0);
    if (!e)
        return 0;

    task = bpf_get_current_task_btf();
    parent = BPF_CORE_READ(task, real_parent);
    if (!parent)
        e->ppid = 0;
    else
        e->ppid = BPF_CORE_READ(parent, tgid);
    e->ts_ns = bpf_ktime_get_ns();
    e->pid = (u32)(bpf_get_current_pid_tgid() >> 32);
    e->tid = (u32)bpf_get_current_pid_tgid();
    e->uid = (u32)bpf_get_current_uid_gid();
    e->type = EDR_EVENT_EXEC;
    bpf_get_current_comm(e->comm, sizeof(e->comm));

    const char *filename = (const char *)ctx->args[0];
    bpf_probe_read_user_str(e->data.exec.filename, sizeof(e->data.exec.filename), filename);

    bpf_ringbuf_submit(e, 0);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_connect")
int tp_connect(struct trace_event_raw_sys_enter *ctx)
{
    struct task_struct *task;
    struct task_struct *parent;
    event_t *e;
    void *useraddr;
    struct sockaddr sa = {0};
    struct sockaddr_in sa4 = {0};

    e = bpf_ringbuf_reserve(&rb, sizeof(*e), 0);
    if (!e)
        return 0;

    task = bpf_get_current_task_btf();
    parent = BPF_CORE_READ(task, real_parent);
    if (!parent)
        e->ppid = 0;
    else
        e->ppid = BPF_CORE_READ(parent, tgid);
    e->ts_ns = bpf_ktime_get_ns();
    e->pid = (u32)(bpf_get_current_pid_tgid() >> 32);
    e->tid = (u32)bpf_get_current_pid_tgid();
    e->uid = (u32)bpf_get_current_uid_gid();
    e->type = EDR_EVENT_CONNECT;

    bpf_get_current_comm(e->comm, sizeof(e->comm));

    useraddr = (void *)ctx->args[1];

    if (bpf_probe_read_user(&sa, sizeof(sa), useraddr) < 0) {
        bpf_ringbuf_discard(e, 0);
        return 0;
    }

    if (sa.sa_family != AF_INET) {
        bpf_ringbuf_discard(e, 0);
        return 0;
    }

    if (bpf_probe_read_user(&sa4, sizeof(sa4), useraddr) < 0) {
        bpf_ringbuf_discard(e, 0);
        return 0;
    }

    e->data.connect.dst_ip = sa4.sin_addr.s_addr;
    e->data.connect.dst_port = bpf_ntohs(sa4.sin_port);

    bpf_ringbuf_submit(e, 0);
    return 0;
}


SEC("tracepoint/syscalls/sys_enter_openat")
int tp_enter_openat(struct trace_event_raw_sys_enter *ctx)
{
     struct task_struct *task;
    struct task_struct *parent;
    event_t *e;
    const char *filename;

    e = bpf_ringbuf_reserve(&rb, sizeof(*e), 0);
    if (!e)
        return 0;

    task = bpf_get_current_task_btf();
    parent = BPF_CORE_READ(task, real_parent);
    if (!parent)
        e->ppid = 0;
    else
        e->ppid = BPF_CORE_READ(parent, tgid);
    e->ts_ns = bpf_ktime_get_ns();
    e->pid = (u32)(bpf_get_current_pid_tgid() >> 32);
    e->tid = (u32)bpf_get_current_pid_tgid();
    e->uid = (u32)bpf_get_current_uid_gid();
    e->type = EDR_EVENT_OPENAT_ENTER;
    bpf_get_current_comm(e->comm, sizeof(e->comm));

    filename = (const char *)ctx->args[1];
    bpf_probe_read_user_str(e->data.openat.filename, sizeof(e->data.openat.filename), filename);

    e->data.openat.flags = (u32)ctx->args[2];

    bpf_ringbuf_submit(e, 0);
    return 0;
}

SEC("tracepoint/syscalls/sys_exit_openat")
int tp_exit_openat(struct trace_event_raw_sys_exit *ctx)
{
     struct task_struct *task;
    struct task_struct *parent;
    event_t *e;
    const char *filename;

    e = bpf_ringbuf_reserve(&rb, sizeof(*e), 0);
    if (!e)
        return 0;

    task = bpf_get_current_task_btf();
    parent = BPF_CORE_READ(task, real_parent);
    if (!parent)
        e->ppid = 0;
    else
        e->ppid = BPF_CORE_READ(parent, tgid);
    e->ts_ns = bpf_ktime_get_ns();
    e->pid = (u32)(bpf_get_current_pid_tgid() >> 32);
    e->tid = (u32)bpf_get_current_pid_tgid();
    e->uid = (u32)bpf_get_current_uid_gid();
    e->type = EDR_EVENT_OPENAT_EXIT;
    bpf_get_current_comm(e->comm, sizeof(e->comm));

    e->data.openat.ret = (int)ctx->ret;

    if (ctx->ret >= 0)
        e->data.openat.fd = ctx->ret;
    else
        e->data.openat.fd = -1;

    bpf_ringbuf_submit(e, 0);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_write")
int tp_write(struct trace_event_raw_sys_enter *ctx)
{
    struct task_struct *task;
    struct task_struct *parent;
    event_t *e;

    e = bpf_ringbuf_reserve(&rb, sizeof(*e), 0);
    if (!e)
        return 0;

    task = bpf_get_current_task_btf();
    parent = BPF_CORE_READ(task, real_parent);
    if (!parent)
        e->ppid = 0;
    else
        e->ppid = BPF_CORE_READ(parent, tgid);
    e->ts_ns = bpf_ktime_get_ns();
    e->pid = (u32)(bpf_get_current_pid_tgid() >> 32);
    e->tid = (u32)bpf_get_current_pid_tgid();
    e->uid = (u32)bpf_get_current_uid_gid();
    e->type = EDR_EVENT_WRITE;
    bpf_get_current_comm(e->comm, sizeof(e->comm));
    
    e->data.write.fd = (u32)ctx->args[0];

    e->data.write.count = (u64)ctx->args[2];

    bpf_ringbuf_submit(e, 0);
    return 0;
}


SEC("tracepoint/syscalls/sys_enter_unlinkat")
int tp_unlink(struct trace_event_raw_sys_enter *ctx)
{
    struct task_struct *task;
    struct task_struct *parent;
    event_t *e;
    const char *filename;

    e = bpf_ringbuf_reserve(&rb, sizeof(*e), 0);
    if (!e)
        return 0;

    task = bpf_get_current_task_btf();
    parent = BPF_CORE_READ(task, real_parent);
    if (!parent)
        e->ppid = 0;
    else
        e->ppid = BPF_CORE_READ(parent, tgid);
    e->ts_ns = bpf_ktime_get_ns();
    e->pid = (u32)(bpf_get_current_pid_tgid() >> 32);
    e->tid = (u32)bpf_get_current_pid_tgid();
    e->uid = (u32)bpf_get_current_uid_gid();
    e->type = EDR_EVENT_UNLINKAT;
    bpf_get_current_comm(e->comm, sizeof(e->comm));
    
    filename = (const char *)ctx->args[1];
    bpf_probe_read_user_str(e->data.unlinkat.filename, sizeof(e->data.unlinkat.filename), filename);

    e->data.unlinkat.flags = (u32)ctx->args[2];

    bpf_ringbuf_submit(e, 0);
    return 0;
}


SEC("tracepoint/syscalls/sys_enter_renameat2")
int tp_renameat2(struct trace_event_raw_sys_enter *ctx)
{
    struct task_struct *task;
    struct task_struct *parent;
    event_t *e;
    const char *old_filename;
    const char *new_filename;

    e = bpf_ringbuf_reserve(&rb, sizeof(*e), 0);
    if (!e)
        return 0;

    task = bpf_get_current_task_btf();
    parent = BPF_CORE_READ(task, real_parent);
    if (!parent)
        e->ppid = 0;
    else
        e->ppid = BPF_CORE_READ(parent, tgid);
    e->ts_ns = bpf_ktime_get_ns();
    e->pid = (u32)(bpf_get_current_pid_tgid() >> 32);
    e->tid = (u32)bpf_get_current_pid_tgid();
    e->uid = (u32)bpf_get_current_uid_gid();
    e->type = EDR_EVENT_RENAMEAT2;
    bpf_get_current_comm(e->comm, sizeof(e->comm));
    
    old_filename = (const char *)ctx->args[1];
    bpf_probe_read_user_str(e->data.renameat2.old_filename, sizeof(e->data.renameat2.old_filename), old_filename);

    new_filename = (const char *)ctx->args[1];
    bpf_probe_read_user_str(e->data.renameat2.new_filename, sizeof(e->data.renameat2.new_filename), new_filename);

    e->data.renameat2.flags = (u32)ctx->args[4];

    bpf_ringbuf_submit(e, 0);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_bind")
int tp_bind(struct trace_event_raw_sys_enter *ctx)
{
    struct task_struct *task;
    struct task_struct *parent;
    event_t *e;
    struct sockaddr sa = {0};
    struct sockaddr_in sa4 = {0};
    void *useraddr;

    e = bpf_ringbuf_reserve(&rb, sizeof(*e), 0);
    if (!e)
        return 0;

    task = bpf_get_current_task_btf();
    parent = BPF_CORE_READ(task, real_parent);
    if (!parent)
        e->ppid = 0;
    else
        e->ppid = BPF_CORE_READ(parent, tgid);
    e->ts_ns = bpf_ktime_get_ns();
    e->pid = (u32)(bpf_get_current_pid_tgid() >> 32);
    e->tid = (u32)bpf_get_current_pid_tgid();
    e->uid = (u32)bpf_get_current_uid_gid();
    e->type = EDR_EVENT_BIND;
    bpf_get_current_comm(e->comm, sizeof(e->comm));
    
    e->data.bind.fd = (u32)ctx->args[0];
    useraddr = (void *)ctx->args[1];

    if (bpf_probe_read_user(&sa, sizeof(sa), useraddr) < 0) {
        bpf_ringbuf_discard(e, 0);
        return 0;
    }
    if (sa.sa_family != AF_INET) {
        bpf_ringbuf_discard(e, 0);
        return 0;
    }
    if (bpf_probe_read_user(&sa4, sizeof(sa4), useraddr) < 0) {
        bpf_ringbuf_discard(e, 0);
        return 0;
    }
    e->data.bind.family = sa4.sin_family;
    e->data.bind.addr = sa4.sin_addr.s_addr;
    e->data.bind.port = bpf_ntohs(sa4.sin_port);

    bpf_ringbuf_submit(e, 0);
    return 0;
}


SEC("tracepoint/syscalls/sys_enter_listen")
int tp_listen(struct trace_event_raw_sys_enter *ctx)
{
    struct task_struct *task;
    struct task_struct *parent;
    event_t *e;

    e = bpf_ringbuf_reserve(&rb, sizeof(*e), 0);
    if (!e)
        return 0;

    task = bpf_get_current_task_btf();
    parent = BPF_CORE_READ(task, real_parent);
    if (!parent)
        e->ppid = 0;
    else
        e->ppid = BPF_CORE_READ(parent, tgid);
    e->ts_ns = bpf_ktime_get_ns();
    e->pid = (u32)(bpf_get_current_pid_tgid() >> 32);
    e->tid = (u32)bpf_get_current_pid_tgid();
    e->uid = (u32)bpf_get_current_uid_gid();
    e->type = EDR_EVENT_LISTEN;
    bpf_get_current_comm(e->comm, sizeof(e->comm));

    e->data.listen.fd = (u32)ctx->args[0];
    e->data.listen.backlog = (u32)ctx->args[1];

    bpf_ringbuf_submit(e, 0);
    return 0;
}


SEC("tracepoint/syscalls/sys_enter_accept")
int tp_accept(struct trace_event_raw_sys_enter *ctx)
{
    struct task_struct *task;
    struct task_struct *parent;
    event_t *e;

    e = bpf_ringbuf_reserve(&rb, sizeof(*e), 0);
    if (!e)
        return 0;

    task = bpf_get_current_task_btf();
    parent = BPF_CORE_READ(task, real_parent);
    if (!parent)
        e->ppid = 0;
    else
        e->ppid = BPF_CORE_READ(parent, tgid);
    e->ts_ns = bpf_ktime_get_ns();
    e->pid = (u32)(bpf_get_current_pid_tgid() >> 32);
    e->tid = (u32)bpf_get_current_pid_tgid();
    e->uid = (u32)bpf_get_current_uid_gid();
    e->type = EDR_EVENT_ACCEPT;
    bpf_get_current_comm(e->comm, sizeof(e->comm));

    e->data.accept.fd = (u32)ctx->args[0];

    bpf_ringbuf_submit(e, 0);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_accept4")
int tp_accept4(struct trace_event_raw_sys_enter *ctx)
{
    struct task_struct *task;
    struct task_struct *parent;
    event_t *e;

    e = bpf_ringbuf_reserve(&rb, sizeof(*e), 0);
    if (!e)
        return 0;

    task = bpf_get_current_task_btf();
    parent = BPF_CORE_READ(task, real_parent);
    if (!parent)
        e->ppid = 0;
    else
        e->ppid = BPF_CORE_READ(parent, tgid);
    e->ts_ns = bpf_ktime_get_ns();
    e->pid = (u32)(bpf_get_current_pid_tgid() >> 32);
    e->tid = (u32)bpf_get_current_pid_tgid();
    e->uid = (u32)bpf_get_current_uid_gid();
    e->type = EDR_EVENT_ACCEPT;
    bpf_get_current_comm(e->comm, sizeof(e->comm));

    e->data.accept.fd = (u32)ctx->args[0];

    bpf_ringbuf_submit(e, 0);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_read")
int tp_read(struct trace_event_raw_sys_enter *ctx)
{
    struct task_struct *task;
    struct task_struct *parent;
    event_t *e;

    e = bpf_ringbuf_reserve(&rb, sizeof(*e), 0);
    if (!e)
        return 0;

    task = bpf_get_current_task_btf();
    parent = BPF_CORE_READ(task, real_parent);
    if (!parent)
        e->ppid = 0;
    else
        e->ppid = BPF_CORE_READ(parent, tgid);
    e->ts_ns = bpf_ktime_get_ns();
    e->pid = (u32)(bpf_get_current_pid_tgid() >> 32);
    e->tid = (u32)bpf_get_current_pid_tgid();
    e->uid = (u32)bpf_get_current_uid_gid();
    e->type = EDR_EVENT_READ;
    bpf_get_current_comm(e->comm, sizeof(e->comm));

    e->data.read.fd = (u32)ctx->args[0];
    e->data.read.count = (u32)ctx->args[2];

    bpf_ringbuf_submit(e, 0);
    return 0;
}