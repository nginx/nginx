
/*
 * Copyright (C) Igor Sysoev
 */


#ifndef _NGX_PROCESS_CYCLE_H_INCLUDED_
#define _NGX_PROCESS_CYCLE_H_INCLUDED_


#include <ngx_config.h>
#include <ngx_core.h>


typedef struct {
     ngx_file_t    pid;
     u_char       *name;
     int           argc;
     char *const  *argv;
} ngx_master_ctx_t;


#define NGX_PROCESS_SINGLE   0
#define NGX_PROCESS_MASTER   1
#define NGX_PROCESS_WORKER   2


void ngx_master_process_cycle(ngx_cycle_t *cycle, ngx_master_ctx_t *ctx);
void ngx_single_process_cycle(ngx_cycle_t *cycle, ngx_master_ctx_t *ctx);


extern ngx_uint_t      ngx_process;
extern ngx_pid_t       ngx_pid;
extern ngx_pid_t       ngx_new_binary;
extern ngx_uint_t      ngx_inherited;
extern ngx_uint_t      ngx_threaded;
extern ngx_uint_t      ngx_exiting;

extern sig_atomic_t    ngx_reap;
extern sig_atomic_t    ngx_timer;
extern sig_atomic_t    ngx_quit;
extern sig_atomic_t    ngx_terminate;
extern sig_atomic_t    ngx_noaccept;
extern sig_atomic_t    ngx_reconfigure;
extern sig_atomic_t    ngx_reopen;
extern sig_atomic_t    ngx_change_binary;


#endif /* _NGX_PROCESS_CYCLE_H_INCLUDED_ */
