#ifndef _NGX_PROCESS_H_INCLUDED_
#define _NGX_PROCESS_H_INCLUDED_


typedef pid_t       ngx_pid_t;

typedef void (*ngx_spawn_proc_pt) (ngx_cycle_t *cycle, void *data);

typedef struct {
    ngx_pid_t           pid;
    int                 status;

    ngx_spawn_proc_pt   proc;
    void               *data;
    char               *name;

    unsigned            respawn:1;
    unsigned            detached:1;
    unsigned            signal:1;
    unsigned            exiting:1;
    unsigned            exited:1;
} ngx_process_t;


typedef struct {
    char         *path;
    char         *name;
    char *const  *argv;
    char *const  *envp;
} ngx_exec_ctx_t;


#define NGX_PROCESS_SINGLE   0
#define NGX_PROCESS_MASTER   1
#define NGX_PROCESS_WORKER   2

#define NGX_MAX_PROCESSES  1024

#define NGX_PROCESS_NORESPAWN  -1
#define NGX_PROCESS_RESPAWN    -2
#define NGX_PROCESS_DETACHED   -3


#define ngx_getpid  getpid

ngx_pid_t ngx_spawn_process(ngx_cycle_t *cycle,
                            ngx_spawn_proc_pt proc, void *data,
                            char *name, ngx_int_t respawn);
ngx_int_t ngx_exec(ngx_cycle_t *cycle, ngx_exec_ctx_t *ctx);
void ngx_signal_processes(ngx_cycle_t *cycle, ngx_int_t signo);
void ngx_respawn_processes(ngx_cycle_t *cycle);
void ngx_process_get_status(void);

extern ngx_uint_t     ngx_last_process;
extern ngx_process_t  ngx_processes[NGX_MAX_PROCESSES];


#endif /* _NGX_PROCESS_H_INCLUDED_ */
