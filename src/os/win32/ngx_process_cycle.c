
#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_event.h>


#if 0

ngx_int_t     ngx_process;
ngx_pid_t     ngx_pid;
ngx_pid_t     ngx_new_binary;
ngx_int_t     ngx_inherited;

sig_atomic_t  ngx_reap;
sig_atomic_t  ngx_timer;
sig_atomic_t  ngx_terminate;
sig_atomic_t  ngx_quit;
sig_atomic_t  ngx_noaccept;
sig_atomic_t  ngx_reconfigure;
sig_atomic_t  ngx_reopen;
sig_atomic_t  ngx_change_binary;

#endif


void ngx_master_process_cycle(ngx_cycle_t *cycle, ngx_master_ctx_t *ctx)
{
}
