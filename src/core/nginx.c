
#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_event.h>
#include <nginx.h>


typedef struct {
     ngx_flag_t  daemon;
     ngx_flag_t  master;
     ngx_flag_t  worker_reopen;
     uid_t       user;
     gid_t       group;
     ngx_str_t   pid;
     ngx_str_t   newpid;
} ngx_core_conf_t;


typedef struct {
     ngx_file_t    pid;
     char         *name;
     char *const  *argv;
} ngx_master_ctx_t;


static void ngx_master_process_cycle(ngx_cycle_t *cycle, ngx_master_ctx_t *ctx);
static void ngx_master_exit(ngx_cycle_t *cycle, ngx_master_ctx_t *ctx);
static void ngx_worker_process_cycle(ngx_cycle_t *cycle, void *data);
static ngx_int_t ngx_add_inherited_sockets(ngx_cycle_t *cycle, char **envp);
static ngx_pid_t ngx_exec_new_binary(ngx_cycle_t *cycle, char *const *argv);
static ngx_int_t ngx_core_module_init(ngx_cycle_t *cycle);
static char *ngx_set_user(ngx_conf_t *cf, ngx_command_t *cmd, void *conf);


static ngx_str_t  core_name = ngx_string("core");

static ngx_command_t  ngx_core_commands[] = {

    { ngx_string("user"),
      NGX_MAIN_CONF|NGX_CONF_TAKE12,
      ngx_set_user,
      0,
      0,
      NULL },

    { ngx_string("daemon"),
      NGX_MAIN_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_core_flag_slot,
      0,
      offsetof(ngx_core_conf_t, daemon),
      NULL },

    { ngx_string("master_process"),
      NGX_MAIN_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_core_flag_slot,
      0,
      offsetof(ngx_core_conf_t, master),
      NULL },

    { ngx_string("worker_reopen"),
      NGX_MAIN_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_core_flag_slot,
      0,
      offsetof(ngx_core_conf_t, worker_reopen),
      NULL },

      ngx_null_command
};


ngx_module_t  ngx_core_module = {
    NGX_MODULE,
    &core_name,                            /* module context */
    ngx_core_commands,                     /* module directives */
    NGX_CORE_MODULE,                       /* module type */
    ngx_core_module_init,                  /* init module */
    NULL                                   /* init child */
};


ngx_int_t   ngx_max_module;
ngx_uint_t  ngx_connection_counter;

ngx_int_t   ngx_process;
ngx_pid_t   ngx_new_binary;

ngx_int_t   ngx_inherited;
ngx_int_t   ngx_reap;
ngx_int_t   ngx_timer;
ngx_int_t   ngx_terminate;
ngx_int_t   ngx_quit;
ngx_int_t   ngx_noaccept;
ngx_int_t   ngx_reconfigure;
ngx_int_t   ngx_reopen;
ngx_int_t   ngx_change_binary;


int main(int argc, char *const *argv, char **envp)
{
    ngx_fd_t           fd;
    ngx_int_t          i;
    ngx_log_t         *log;
    ngx_cycle_t       *cycle, init_cycle;
    ngx_open_file_t   *file;
    ngx_core_conf_t   *ccf;
    ngx_master_ctx_t   ctx;
#if !(WIN32)
    size_t             len;
    char               pid[/* STUB */ 10];
#endif

#if __FreeBSD__
    ngx_debug_init();
#endif

    /* TODO */ ngx_max_sockets = -1;

    ngx_time_init();

#if (HAVE_PCRE)
    ngx_regex_init();
#endif

    log = ngx_log_init_errlog();

    /* init_cycle->log is required for signal handlers */

    ngx_memzero(&init_cycle, sizeof(ngx_cycle_t));
    init_cycle.log = log;
    ngx_cycle = &init_cycle;

    if (ngx_os_init(log) == NGX_ERROR) {
        return 1;
    }

    ngx_max_module = 0;
    for (i = 0; ngx_modules[i]; i++) {
        ngx_modules[i]->index = ngx_max_module++;
    }

    if (!(init_cycle.pool = ngx_create_pool(1024, log))) {
        return 1;
    }

    if (ngx_add_inherited_sockets(&init_cycle, envp) == NGX_ERROR) {
        return 1;
    }

    cycle = ngx_init_cycle(&init_cycle);
    if (cycle == NULL) {
        return 1;
    }

    ngx_cycle = cycle;

    ccf = (ngx_core_conf_t *) ngx_get_conf(cycle->conf_ctx, ngx_core_module);

    ngx_process = (ccf->master != 0) ? NGX_PROCESS_MASTER : NGX_PROCESS_SINGLE;

#if (WIN32)

#if 0

    if (run_as_service) {
        if (ngx_servie(cycle->log) == NGX_ERROR) {
            return 1;
        }

        return 0;
    }

#endif

#else

    if (ccf->daemon != 0) {
        if (ngx_daemon(cycle->log) == NGX_ERROR) {
            return 1;
        }
    }

    if (dup2(cycle->log->file->fd, STDERR_FILENO) == -1) {
        ngx_log_error(NGX_LOG_EMERG, cycle->log, ngx_errno,
                      "dup2(STDERR) failed");
        return 1;
    }

    if (ccf->pid.len == 0) {
        ccf->pid.len = sizeof(NGINX_PID) - 1;
        ccf->pid.data = NGINX_PID;
        ccf->newpid.len = sizeof(NGINX_NEW_PID) - 1;
        ccf->newpid.data = NGINX_NEW_PID;
    }

    len = ngx_snprintf(pid, /* STUB */ 10, PID_T_FMT, ngx_getpid());
    ngx_memzero(&ctx.pid, sizeof(ngx_file_t));
    ctx.pid.name = ngx_inherited ? ccf->newpid : ccf->pid;
    ctx.name = ccf->pid.data;

    ctx.pid.fd = ngx_open_file(ctx.pid.name.data, NGX_FILE_RDWR,
                               NGX_FILE_CREATE_OR_OPEN);

    if (ctx.pid.fd == NGX_INVALID_FILE) {
        ngx_log_error(NGX_LOG_EMERG, cycle->log, ngx_errno,
                      ngx_open_file_n " \"%s\" failed", ctx.pid.name.data);
        return 1;
    }

    if (ngx_write_file(&ctx.pid, pid, len, 0) == NGX_ERROR) {
        return 1;
    }

    if (ngx_close_file(ctx.pid.fd) == NGX_FILE_ERROR) {
        ngx_log_error(NGX_LOG_ALERT, cycle->log, ngx_errno,
                      ngx_close_file_n " \"%s\" failed", ctx.pid.name.data);
    }

#endif

    ctx.argv = argv;

    ngx_master_process_cycle(cycle, &ctx);

    return 0;
}


/* TODO: broken single process */

static void ngx_master_process_cycle(ngx_cycle_t *cycle, ngx_master_ctx_t *ctx)
{
    int                signo;
    sigset_t           set;
    struct timeval     tv;
    struct itimerval   itv;
    ngx_uint_t         i, live;
    ngx_msec_t         delay;
    ngx_core_conf_t   *ccf;

    sigemptyset(&set);
    sigaddset(&set, SIGCHLD);
    sigaddset(&set, SIGALRM);
    sigaddset(&set, SIGINT);
    sigaddset(&set, ngx_signal_value(NGX_RECONFIGURE_SIGNAL));
    sigaddset(&set, ngx_signal_value(NGX_REOPEN_SIGNAL));
    sigaddset(&set, ngx_signal_value(NGX_NOACCEPT_SIGNAL));
    sigaddset(&set, ngx_signal_value(NGX_TERMINATE_SIGNAL));
    sigaddset(&set, ngx_signal_value(NGX_SHUTDOWN_SIGNAL));
    sigaddset(&set, ngx_signal_value(NGX_CHANGEBIN_SIGNAL));

    if (sigprocmask(SIG_BLOCK, &set, NULL) == -1) {
        ngx_log_error(NGX_LOG_ALERT, cycle->log, ngx_errno,
                      "sigprocmask() failed");
    }

    sigemptyset(&set);

    ngx_setproctitle("master process");

    ngx_new_binary = 0;
    delay = 0;
    signo = 0;
    live = 0;

    for ( ;; ) {
        ngx_log_debug0(NGX_LOG_DEBUG_EVENT, cycle->log, 0, "new cycle");

        if (ngx_process == NGX_PROCESS_MASTER) {
            ngx_spawn_process(cycle, ngx_worker_process_cycle, NULL,
                              "worker process", NGX_PROCESS_RESPAWN);

            /*
             * we have to limit the maximum life time of the worker processes
             * by 1 month because our millisecond event timer is limited
             * by 49 days on 32-bit platforms
             */

            itv.it_interval.tv_sec = 0;
            itv.it_interval.tv_usec = 0;
            itv.it_value.tv_sec = 30 * 24 * 60 * 60;
            itv.it_value.tv_usec = 0;

            if (setitimer(ITIMER_REAL, &itv, NULL) == -1) {
                ngx_log_error(NGX_LOG_ALERT, cycle->log, ngx_errno,
                              "setitimer() failed");
            }

            live = 1;

        } else {
            ngx_init_temp_number();

            for (i = 0; ngx_modules[i]; i++) {
                if (ngx_modules[i]->init_process) {
                    if (ngx_modules[i]->init_process(cycle) == NGX_ERROR) {
                        /* fatal */
                        exit(1);
                    }
                }
            }
        }

        ccf = (ngx_core_conf_t *) ngx_get_conf(cycle->conf_ctx,
                                               ngx_core_module);

        /* a cycle with the same configuration because a new one is invalid */

        for ( ;; ) {

            /* an event loop */

            for ( ;; ) {

                if (ngx_process == NGX_PROCESS_MASTER) {
                    if (delay) {
                        delay *= 2;

                        ngx_log_debug1(NGX_LOG_DEBUG_EVENT, cycle->log, 0,
                                       "temination cycle: %d", delay);

                        itv.it_interval.tv_sec = 0;
                        itv.it_interval.tv_usec = 0;
                        itv.it_value.tv_sec = delay / 1000;
                        itv.it_value.tv_usec = (delay % 1000 ) * 1000;

                        if (setitimer(ITIMER_REAL, &itv, NULL) == -1) {
                            ngx_log_error(NGX_LOG_ALERT, cycle->log, ngx_errno,
                                          "setitimer() failed");
                        }
                    }

                    ngx_log_debug0(NGX_LOG_DEBUG_EVENT, cycle->log, 0,
                                   "sigsuspend");

                    sigsuspend(&set);

                    ngx_gettimeofday(&tv);
                    ngx_time_update(tv.tv_sec);

                    ngx_log_debug0(NGX_LOG_DEBUG_EVENT, cycle->log, 0,
                                   "wake up");

                } else { /* NGX_PROCESS_SINGLE */
                    ngx_log_debug0(NGX_LOG_DEBUG_EVENT, cycle->log, 0,
                                   "worker cycle");

                    ngx_process_events(cycle->log);
                    live = 0;
                }

                if (ngx_reap) {
                    ngx_reap = 0;
                    ngx_log_debug0(NGX_LOG_DEBUG_EVENT, cycle->log, 0,
                                   "reap childs");

                    live = 0;
                    for (i = 0; i < ngx_last_process; i++) {

                        ngx_log_debug6(NGX_LOG_DEBUG_EVENT, cycle->log, 0,
                                       "child: " PID_T_FMT
                                       " s:%d e:%d t:%d d:%d r:%d",
                                       ngx_processes[i].pid,
                                       ngx_processes[i].signal,
                                       ngx_processes[i].exiting,
                                       ngx_processes[i].exited,
                                       ngx_processes[i].detached,
                                       ngx_processes[i].respawn);

                        if (ngx_processes[i].exited) {

                            if (ngx_processes[i].respawn
                                && !ngx_processes[i].exiting
                                && !ngx_terminate
                                && !ngx_quit)
                            {
                                 if (ngx_spawn_process(cycle,
                                                       ngx_processes[i].proc,
                                                       ngx_processes[i].data,
                                                       ngx_processes[i].name, i)
                                                                  == NGX_ERROR)
                                 {
                                     ngx_log_error(NGX_LOG_ALERT, cycle->log, 0,
                                                   "can not respawn %s",
                                                   ngx_processes[i].name);
                                 }

                                 continue;
                            }

                            if (ngx_processes[i].pid == ngx_new_binary) {
                                ngx_new_binary = 0;
                            }

                            if (i != --ngx_last_process) {
                                ngx_processes[i--] =
                                               ngx_processes[ngx_last_process];
                            }

                        } else if (!ngx_processes[i].detached
                                   && (ngx_terminate || ngx_quit))
                        {
                            live = 1;

                        } else if (ngx_processes[i].exiting) {
                            live = 1;
                        }
                    }
                }

                if (!live && (ngx_terminate || ngx_quit)) {
                    ngx_master_exit(cycle, ctx);
                }

                if (ngx_terminate) {
                    if (delay == 0) {
                        delay = 50;
                    }

                    if (delay > 1000) {
                        signo = SIGKILL;
                    } else {
                        signo = ngx_signal_value(NGX_TERMINATE_SIGNAL);
                    }

                } else if (ngx_quit) {
                    signo = ngx_signal_value(NGX_SHUTDOWN_SIGNAL);

                } else if (ngx_timer) {
                    signo = ngx_signal_value(NGX_SHUTDOWN_SIGNAL);

                } else {

                    if (ngx_noaccept) {
                        signo = ngx_signal_value(NGX_SHUTDOWN_SIGNAL);
                    }

                    if (ngx_change_binary) {
                        ngx_change_binary = 0;
                        ngx_log_error(NGX_LOG_INFO, cycle->log, 0,
                                      "changing binary");
                        ngx_new_binary = ngx_exec_new_binary(cycle, ctx->argv);
                    }

                    if (ngx_reconfigure) {
                        signo = ngx_signal_value(NGX_SHUTDOWN_SIGNAL);
                        ngx_log_error(NGX_LOG_INFO, cycle->log, 0,
                                      "reconfiguring");
                    }

                    if (ngx_reopen) {
                        if (ngx_process == NGX_PROCESS_MASTER) {
                            if (ccf->worker_reopen > 0) {
                                signo = ngx_signal_value(NGX_REOPEN_SIGNAL);
                                ngx_reopen = 0;
                            } else {
                                signo = ngx_signal_value(NGX_SHUTDOWN_SIGNAL);
                            }

                        } else { /* NGX_PROCESS_SINGLE */
                            ngx_reopen = 0;
                        }

                        ngx_log_error(NGX_LOG_INFO, cycle->log, 0,
                                      "reopening logs");
                        ngx_reopen_files(cycle,
                                       ccf->worker_reopen > 0 ? ccf->user : -1);
                    }
                }

                if (signo) {
                    for (i = 0; i < ngx_last_process; i++) {

                        if (!ngx_processes[i].detached) {
                            ngx_processes[i].signal = signo;

                            ngx_log_debug2(NGX_LOG_DEBUG_EVENT,
                                           cycle->log, 0,
                                           "signal " PID_T_FMT " %d",
                                           ngx_processes[i].pid, signo);
                        }
                    }
                    signo = 0;
                }

                for (i = 0; i < ngx_last_process; i++) {

                    if (ngx_processes[i].signal == 0) {
                        continue;
                    }

                    ngx_log_debug2(NGX_LOG_DEBUG_CORE, cycle->log, 0,
                                   "kill (" PID_T_FMT ", %d)" ,
                                   ngx_processes[i].pid,
                                   ngx_processes[i].signal);

                    if (kill(ngx_processes[i].pid, ngx_processes[i].signal)
                                                                         == -1)
                    {
                        ngx_log_error(NGX_LOG_ALERT, cycle->log, ngx_errno,
                                      "kill(%d, %d) failed",
                                      ngx_processes[i].pid,
                                      ngx_processes[i].signal);
                        continue;
                    }

                    if (ngx_processes[i].signal
                                        != ngx_signal_value(NGX_REOPEN_SIGNAL))
                    {
                        ngx_processes[i].exiting = 1;
                    }
                }

                if (ngx_reopen || ngx_reconfigure || ngx_timer) {
                    break;
                }
            }

            if (ngx_reopen) {
                ngx_reopen = 0;

            } else if (ngx_timer) {
                ngx_timer = 0;

            } else if (ngx_noaccept) {
                ngx_noaccept = 0;
                ngx_reconfigure = 0;

            } else {
                cycle = ngx_init_cycle(cycle);
                if (cycle == NULL) {
                    cycle = (ngx_cycle_t *) ngx_cycle;
                    continue;
                }

                ngx_cycle = cycle;
                ngx_reconfigure = 0;
            }

            break;
        }
    }
}


static void ngx_master_exit(ngx_cycle_t *cycle, ngx_master_ctx_t *ctx)
{
    char  *name;

    if (ngx_inherited && getppid() > 1) {
        name = ctx->pid.name.data;

    } else {
        name = ctx->name;
    }

    if (ngx_delete_file(name) == NGX_FILE_ERROR) {
        ngx_log_error(NGX_LOG_ALERT, cycle->log, ngx_errno,
                      ngx_delete_file_n " \"%s\" failed", name);
    }

    ngx_log_error(NGX_LOG_INFO, cycle->log, 0, "exit");
    exit(0);
}


static void ngx_worker_process_cycle(ngx_cycle_t *cycle, void *data)
{
    sigset_t          set;
    ngx_int_t         i;
    ngx_listening_t  *ls;
    ngx_core_conf_t  *ccf;

    ngx_process = NGX_PROCESS_WORKER;
    ngx_last_process = 0;

    ccf = (ngx_core_conf_t *) ngx_get_conf(cycle->conf_ctx, ngx_core_module);

    if (ccf->group != (gid_t) NGX_CONF_UNSET) {
        if (setuid(ccf->group) == -1) {
            ngx_log_error(NGX_LOG_EMERG, cycle->log, ngx_errno,
                          "setgid(%d) failed", ccf->group);
            /* fatal */
            exit(2);
        }
    }

    if (ccf->user != (uid_t) NGX_CONF_UNSET && geteuid() == 0) {
        if (setuid(ccf->user) == -1) {
            ngx_log_error(NGX_LOG_EMERG, cycle->log, ngx_errno,
                          "setuid(%d) failed", ccf->user);
            /* fatal */
            exit(2);
        }
    }

    sigemptyset(&set);

    if (sigprocmask(SIG_SETMASK, &set, NULL) == -1) {
        ngx_log_error(NGX_LOG_ALERT, cycle->log, ngx_errno,
                      "sigprocmask() failed");
    }

    ngx_init_temp_number();

    /*
     * disable deleting previous events for the listening sockets because
     * in the worker processes there are no events at all at this point
     */ 
    ls = cycle->listening.elts;
    for (i = 0; i < cycle->listening.nelts; i++) {
        ls[i].remain = 0;
    }

    for (i = 0; ngx_modules[i]; i++) {
        if (ngx_modules[i]->init_process) {
            if (ngx_modules[i]->init_process(cycle) == NGX_ERROR) {
                /* fatal */
                exit(1);
            }
        }
    }

    ngx_setproctitle("worker process");

    /* TODO: threads: start ngx_worker_thread_cycle() */

    for ( ;; ) {
        ngx_log_debug0(NGX_LOG_DEBUG_EVENT, cycle->log, 0, "worker cycle");

        ngx_process_events(cycle->log);

        if (ngx_terminate) {
            ngx_log_error(NGX_LOG_INFO, cycle->log, 0, "exiting");
            exit(0);
        }

        if (ngx_quit) {
            ngx_log_error(NGX_LOG_INFO, cycle->log, 0,
                          "gracefully shutting down");
            ngx_setproctitle("worker process is shutting down");
            break;
        }

        if (ngx_reopen) {
            ngx_log_error(NGX_LOG_INFO, cycle->log, 0, "reopen logs");
            ngx_reopen_files(cycle, -1);
            ngx_reopen = 0;
        }
    }

    ngx_close_listening_sockets(cycle);

    for ( ;; ) {
        if (ngx_event_timer_rbtree == &ngx_event_timer_sentinel) {
            ngx_log_error(NGX_LOG_INFO, cycle->log, 0, "exiting");
            exit(0);
        }

        ngx_log_debug0(NGX_LOG_DEBUG_EVENT, cycle->log, 0, "worker cycle");

        ngx_process_events(cycle->log);
    }
}


static ngx_int_t ngx_add_inherited_sockets(ngx_cycle_t *cycle, char **envp)
{
    char                *p, *v;
    ngx_socket_t         s;
    ngx_listening_t     *ls;

    for ( /* void */ ; *envp; envp++) {
        if (ngx_strncmp(*envp, NGINX_VAR, NGINX_VAR_LEN) != 0) {
            continue;
        }

        ngx_log_error(NGX_LOG_INFO, cycle->log, 0,
                      "using inherited sockets from \"%s\"", *envp);

        ngx_init_array(cycle->listening, cycle->pool,
                       10, sizeof(ngx_listening_t), NGX_ERROR);

        for (p = *envp + NGINX_VAR_LEN, v = p; *p; p++) {
            if (*p == ':' || *p == ';') {
                s = ngx_atoi(v, p - v);
                if (s == NGX_ERROR) {
                    ngx_log_error(NGX_LOG_EMERG, cycle->log, 0,
                                  "invalid socket number \"%s\" "
                                  "in NGINX enviroment variable, "
                                  "ignoring the rest of the variable", v);
                    break;
                }
                v = p + 1;

                if (!(ls = ngx_push_array(&cycle->listening))) {
                    return NGX_ERROR;
                }

                ls->fd = s;
            }
        }

        ngx_inherited = 1;

        return ngx_set_inherited_sockets(cycle);
    }

    return NGX_OK;
}


static ngx_pid_t ngx_exec_new_binary(ngx_cycle_t *cycle, char *const *argv)
{
    char             *env[2], *var, *p;
    ngx_int_t         i;
    ngx_pid_t         pid;
    ngx_exec_ctx_t    ctx;
    ngx_listening_t  *ls;

    ctx.path = argv[0];
    ctx.name = "new binary process";
    ctx.argv = argv;

    var = ngx_alloc(NGINX_VAR_LEN
                            + cycle->listening.nelts * (NGX_INT32_LEN + 1) + 1,
                    cycle->log);

    p = ngx_cpymem(var, NGINX_VAR, NGINX_VAR_LEN);

    ls = cycle->listening.elts;
    for (i = 0; i < cycle->listening.nelts; i++) {
        p += ngx_snprintf(p, NGX_INT32_LEN + 2, "%u;", ls[i].fd);
    }

    env[0] = var;
    env[1] = NULL;
    ctx.envp = (char *const *) &env;

    pid = ngx_exec(cycle, &ctx);

    ngx_free(var);

    return pid;
}


static ngx_int_t ngx_core_module_init(ngx_cycle_t *cycle)
{
    ngx_core_conf_t  *ccf;

    /*
     * ngx_core_module has a special init procedure: it is called by
     * ngx_init_cycle() before the configuration file parsing to create
     * ngx_core_module configuration and to set its default parameters
     */

    if (((void **)(cycle->conf_ctx))[ngx_core_module.index] != NULL) {
        return NGX_OK;
    }

    if (!(ccf = ngx_pcalloc(cycle->pool, sizeof(ngx_core_conf_t)))) {
        return NGX_ERROR;
    }
    /* set by pcalloc()
     *
     * ccf->pid = NULL;
     */
    ccf->daemon = NGX_CONF_UNSET;
    ccf->master = NGX_CONF_UNSET;
    ccf->worker_reopen = NGX_CONF_UNSET;
    ccf->user = (uid_t) NGX_CONF_UNSET;
    ccf->group = (gid_t) NGX_CONF_UNSET;

    ((void **)(cycle->conf_ctx))[ngx_core_module.index] = ccf;

    return NGX_OK;
}


static char *ngx_set_user(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    struct passwd    *pwd;
    struct group     *grp;
    ngx_str_t        *value;
    ngx_core_conf_t  *ccf;

    ccf = *(void **)conf;

    if (ccf->user != (uid_t) NGX_CONF_UNSET) {
        return "is duplicate";
    }

    value = (ngx_str_t *) cf->args->elts;

    pwd = getpwnam(value[1].data);
    if (pwd == NULL) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, ngx_errno,
                           "getpwnam(%s) failed", value[1].data);
        return NGX_CONF_ERROR;
    }

    ccf->user = pwd->pw_uid;

    if (cf->args->nelts == 2) {
        return NGX_CONF_OK;
    }

    grp = getgrnam(value[2].data);
    if (grp == NULL) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, ngx_errno,
                           "getgrnam(%s) failed", value[1].data);
        return NGX_CONF_ERROR;
    }

    ccf->group = grp->gr_gid;

    return NGX_CONF_OK;
}
