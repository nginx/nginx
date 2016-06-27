
/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) Nginx, Inc.
 */


#ifndef _NGX_PROCESS_H_INCLUDED_
#define _NGX_PROCESS_H_INCLUDED_


typedef DWORD               ngx_pid_t;
#define NGX_INVALID_PID     0


#define ngx_getpid          GetCurrentProcessId
#define ngx_log_pid         ngx_pid


#define NGX_PROCESS_SYNC_NAME                                                 \
    (sizeof("ngx_cache_manager_mutex_") + NGX_INT32_LEN)


typedef uint64_t            ngx_cpuset_t;


typedef struct {
    HANDLE                  handle;
    ngx_pid_t               pid;
    char                   *name;

    HANDLE                  term;
    HANDLE                  quit;
    HANDLE                  reopen;

    u_char                  term_event[NGX_PROCESS_SYNC_NAME];
    u_char                  quit_event[NGX_PROCESS_SYNC_NAME];
    u_char                  reopen_event[NGX_PROCESS_SYNC_NAME];

    unsigned                just_spawn:1;
    unsigned                exiting:1;
} ngx_process_t;


typedef struct {
    char                   *path;
    char                   *name;
    char                   *args;
    char *const            *argv;
    char *const            *envp;
    HANDLE                  child;
} ngx_exec_ctx_t;


ngx_pid_t ngx_spawn_process(ngx_cycle_t *cycle, char *name, ngx_int_t respawn);
ngx_pid_t ngx_execute(ngx_cycle_t *cycle, ngx_exec_ctx_t *ctx);

#define ngx_debug_point()
#define ngx_sched_yield()   SwitchToThread()


#define NGX_MAX_PROCESSES         (MAXIMUM_WAIT_OBJECTS - 4)

#define NGX_PROCESS_RESPAWN       -2
#define NGX_PROCESS_JUST_RESPAWN  -3


extern int                  ngx_argc;
extern char               **ngx_argv;
extern char               **ngx_os_argv;

extern ngx_int_t            ngx_last_process;
extern ngx_process_t        ngx_processes[NGX_MAX_PROCESSES];

extern ngx_pid_t            ngx_pid;


#endif /* _NGX_PROCESS_H_INCLUDED_ */
