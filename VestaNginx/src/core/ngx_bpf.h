
/*
 * Copyright (C) Nginx, Inc.
 */


#ifndef _NGX_BPF_H_INCLUDED_
#define _NGX_BPF_H_INCLUDED_


#include <ngx_config.h>
#include <ngx_core.h>

#include <linux/bpf.h>


typedef struct {
    char                *name;
    int                  offset;
} ngx_bpf_reloc_t;

typedef struct {
    char                *license;
    enum bpf_prog_type   type;
    struct bpf_insn     *ins;
    size_t               nins;
    ngx_bpf_reloc_t     *relocs;
    size_t               nrelocs;
} ngx_bpf_program_t;


void ngx_bpf_program_link(ngx_bpf_program_t *program, const char *symbol,
    int fd);
int ngx_bpf_load_program(ngx_log_t *log, ngx_bpf_program_t *program);

int ngx_bpf_map_create(ngx_log_t *log, enum bpf_map_type type, int key_size,
    int value_size, int max_entries, uint32_t map_flags);
int ngx_bpf_map_update(int fd, const void *key, const void *value,
    uint64_t flags);
int ngx_bpf_map_delete(int fd, const void *key);
int ngx_bpf_map_lookup(int fd, const void *key, void *value);

#endif /* _NGX_BPF_H_INCLUDED_ */
