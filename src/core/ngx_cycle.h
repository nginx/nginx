#ifndef _NGX_CYCLE_H_INCLUDED_
#define _NGX_CYCLE_H_INCLUDED_


#include <ngx_config.h>
#include <ngx_core.h>


struct ngx_cycle_s {
    void           ****conf_ctx;
    ngx_pool_t        *pool;
    ngx_log_t         *log;
    ngx_array_t        listening;
    ngx_array_t        open_files;
    ngx_array_t        pathes;

    ngx_uint_t         connection_n;
    ngx_connection_t  *connections;
    ngx_event_t       *read_events;
    ngx_event_t       *write_events;

    ngx_cycle_t       *old_cycle;

    ngx_str_t          conf_file;
};


typedef struct {
     ngx_flag_t  daemon;
     ngx_flag_t  master;

     ngx_int_t   worker_processes;

     ngx_uid_t   user;
     ngx_gid_t   group;

     ngx_str_t   pid;
     ngx_str_t   newpid;
} ngx_core_conf_t;


ngx_cycle_t *ngx_init_cycle(ngx_cycle_t *old_cycle);
ngx_int_t ngx_create_pidfile(ngx_cycle_t *cycle, ngx_cycle_t *old_cycle);
void ngx_delete_pidfile(ngx_cycle_t *cycle);
void ngx_reopen_files(ngx_cycle_t *cycle, ngx_uid_t user);
ngx_pid_t ngx_exec_new_binary(ngx_cycle_t *cycle, char *const *argv);


extern volatile ngx_cycle_t  *ngx_cycle;
extern ngx_array_t            ngx_old_cycles;
extern ngx_module_t           ngx_core_module;


#endif /* _NGX_CYCLE_H_INCLUDED_ */
