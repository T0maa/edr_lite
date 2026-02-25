#include "../include/edr_event.h"
#include "vmlinux.h"
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>

/*FICHIER QUI VA ETRE INTERPRETE NIVEAU KERNEL */

char LICENSE[] SEC("license") = "GPL"; /*DECLARATION DE LA LICENSE AFIN QUE LES FONCTIONS SOIENT ACCEPTEES NIVEAU KERNEL*/


struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 24);
} rb SEC(".maps");