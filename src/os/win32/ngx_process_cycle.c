
/*
 * Copyright (C) Igor Sysoev
 */


#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_event.h>


#if 0
ngx_pid_t     ngx_new_binary;

sig_atomic_t  ngx_reap;
sig_atomic_t  ngx_timer;

#endif

ngx_uint_t    ngx_process;
ngx_pid_t     ngx_pid;
ngx_uint_t    ngx_threaded;
ngx_uint_t    ngx_inherited;


sig_atomic_t  ngx_terminate;
sig_atomic_t  ngx_quit;
ngx_uint_t    ngx_exiting;

#if 0

sig_atomic_t  ngx_noaccept;
sig_atomic_t  ngx_reconfigure;
sig_atomic_t  ngx_reopen;
sig_atomic_t  ngx_change_binary;

#endif



void ngx_master_process_cycle(ngx_cycle_t *cycle, ngx_master_ctx_t *ctx)
{
    ngx_log_error(NGX_LOG_EMERG, cycle->log, 0, "master mode is not supported");

    exit(2);
}


void ngx_single_process_cycle(ngx_cycle_t *cycle, ngx_master_ctx_t *ctx)
{
    ngx_int_t  i;

    ngx_init_temp_number();

    for (i = 0; ngx_modules[i]; i++) {
        if (ngx_modules[i]->init_process) {
            if (ngx_modules[i]->init_process(cycle) == NGX_ERROR) {
                /* fatal */
                exit(2);
            }
        }
    }

    for ( ;; ) {
        ngx_log_debug0(NGX_LOG_DEBUG_EVENT, cycle->log, 0, "worker cycle");

        ngx_process_events(cycle);
    }
}
