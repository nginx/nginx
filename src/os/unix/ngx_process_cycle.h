#ifndef _NGX_PROCESS_CYCLE_H_INCLUDED_
#define _NGX_PROCESS_CYCLE_H_INCLUDED_


#include <ngx_config.h>
#include <ngx_core.h>


#define NGX_CMD_OPEN_CHANNEL   1
#define NGX_CMD_CLOSE_CHANNEL  2
#define NGX_CMD_QUIT           3
#define NGX_CMD_TERMINATE      4
#define NGX_CMD_REOPEN         5


typedef struct {
     ngx_uint_t  command;
     ngx_pid_t   pid;
     ngx_int_t   slot;
     ngx_fd_t    fd;
} ngx_channel_t;


typedef struct {
     int           argc;
     char *const  *argv;
} ngx_master_ctx_t;


#define NGX_PROCESS_SINGLE   0
#define NGX_PROCESS_MASTER   1
#define NGX_PROCESS_WORKER   2


void ngx_master_process_cycle(ngx_cycle_t *cycle, ngx_master_ctx_t *ctx);
void ngx_single_process_cycle(ngx_cycle_t *cycle, ngx_master_ctx_t *ctx);


ngx_int_t ngx_write_channel(ngx_socket_t s, ngx_channel_t *ch, size_t size,
                            ngx_log_t *log);
ngx_int_t ngx_read_channel(ngx_socket_t s, ngx_channel_t *ch, size_t size,
                           ngx_log_t *log);


extern ngx_uint_t      ngx_process;
extern ngx_pid_t       ngx_pid;
extern ngx_pid_t       ngx_new_binary;
extern ngx_uint_t      ngx_inherited;
extern ngx_uint_t      ngx_threaded;
extern ngx_uint_t      ngx_exiting;

extern sig_atomic_t    ngx_reap;
extern sig_atomic_t    ngx_timer;
extern sig_atomic_t    ngx_sigio;
extern sig_atomic_t    ngx_quit;
extern sig_atomic_t    ngx_terminate;
extern sig_atomic_t    ngx_noaccept;
extern sig_atomic_t    ngx_reconfigure;
extern sig_atomic_t    ngx_reopen;
extern sig_atomic_t    ngx_change_binary;


#endif /* _NGX_PROCESS_CYCLE_H_INCLUDED_ */
