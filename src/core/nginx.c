
#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_event.h>
#include <nginx.h>


#if 0

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
     int           argc;
     char *const  *argv;
} ngx_master_ctx_t;


static void ngx_master_process_cycle(ngx_cycle_t *cycle, ngx_master_ctx_t *ctx);
static void ngx_master_exit(ngx_cycle_t *cycle, ngx_master_ctx_t *ctx);
static void ngx_worker_process_cycle(ngx_cycle_t *cycle, void *data);
#if (NGX_THREADS)
static int ngx_worker_thread_cycle(void *data);
#endif

#endif

static ngx_int_t ngx_add_inherited_sockets(ngx_cycle_t *cycle, char **envp);
static ngx_int_t ngx_getopt(ngx_master_ctx_t *ctx, ngx_cycle_t *cycle);
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

    { ngx_string("pid"),
      NGX_MAIN_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_core_str_slot,
      0,
      offsetof(ngx_core_conf_t, pid),
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


ngx_int_t     ngx_max_module;
ngx_atomic_t  ngx_connection_counter;

ngx_int_t     ngx_process;
ngx_pid_t     ngx_pid;
ngx_pid_t     ngx_new_binary;

ngx_int_t     ngx_inherited;
ngx_int_t     ngx_reap;
ngx_int_t     ngx_timer;
ngx_int_t     ngx_terminate;
ngx_int_t     ngx_quit;
ngx_int_t     ngx_noaccept;
ngx_int_t     ngx_reconfigure;
ngx_int_t     ngx_reopen;
ngx_int_t     ngx_change_binary;


int main(int argc, char *const *argv, char **envp)
{
    ngx_int_t          i;
    ngx_log_t         *log;
    ngx_cycle_t       *cycle, init_cycle;
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
    ngx_pid = ngx_getpid();

    /* init_cycle->log is required for signal handlers and ngx_getopt() */

    ngx_memzero(&init_cycle, sizeof(ngx_cycle_t));
    init_cycle.log = log;
    ngx_cycle = &init_cycle;

    ngx_memzero(&ctx, sizeof(ngx_master_ctx_t));
    ctx.argc = argc;
    ctx.argv = argv;

#if (NGX_THREADS)
    if (ngx_time_mutex_init(log) == NGX_ERROR) {
        return 1;
    }
#endif

    if (ngx_getopt(&ctx, &init_cycle) == NGX_ERROR) {
        return 1;
    }

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

    if (!ngx_inherited && ccf->daemon != 0) {
        if (ngx_daemon(cycle->log) == NGX_ERROR) {
            return 1;
        }
    }

    if (ccf->pid.len == 0) {
        ccf->pid.len = sizeof(NGINX_PID) - 1;
        ccf->pid.data = NGINX_PID;
        ccf->newpid.len = sizeof(NGINX_NEW_PID) - 1;
        ccf->newpid.data = NGINX_NEW_PID;

    } else {
        ccf->newpid.len = ccf->pid.len + sizeof(NGINX_NEW_PID_EXT);
        if (!(ccf->newpid.data = ngx_alloc(ccf->newpid.len, cycle->log))) {
            return 1;
        }

        ngx_memcpy(ngx_cpymem(ccf->newpid.data, ccf->pid.data, ccf->pid.len),
                   NGINX_NEW_PID_EXT, sizeof(NGINX_NEW_PID_EXT));
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

    ngx_master_process_cycle(cycle, &ctx);

    return 0;
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


ngx_pid_t ngx_exec_new_binary(ngx_cycle_t *cycle, char *const *argv)
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

    pid = ngx_execute(cycle, &ctx);

    ngx_free(var);

    return pid;
}


static ngx_int_t ngx_getopt(ngx_master_ctx_t *ctx, ngx_cycle_t *cycle)
{
    ngx_int_t  i;

    for (i = 1; i < ctx->argc; i++) {
        if (ctx->argv[i][0] != '-') {
            ngx_log_error(NGX_LOG_EMERG, cycle->log, 0,
                          "invalid option: \"%s\"", ctx->argv[i]);
            return NGX_ERROR;
        }

        switch (ctx->argv[i][1]) {

        case 'c':
            cycle->conf_file.data = ctx->argv[++i];
            cycle->conf_file.len = ngx_strlen(cycle->conf_file.data);
            break;

        default:
            ngx_log_error(NGX_LOG_EMERG, cycle->log, 0,
                          "invalid option: \"%s\"", ctx->argv[i]);
            return NGX_ERROR;
        }
    }

    if (cycle->conf_file.data == NULL) {
        cycle->conf_file.len = sizeof(NGINX_CONF) - 1;
        cycle->conf_file.data = NGINX_CONF;
    }

    return NGX_OK;
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
     * ccf->newpid = NULL;
     */
    ccf->daemon = NGX_CONF_UNSET;
    ccf->master = NGX_CONF_UNSET;
    ccf->worker_reopen = NGX_CONF_UNSET;
    ccf->user = (ngx_uid_t) NGX_CONF_UNSET;
    ccf->group = (ngx_gid_t) NGX_CONF_UNSET;

    ((void **)(cycle->conf_ctx))[ngx_core_module.index] = ccf;

    return NGX_OK;
}


static char *ngx_set_user(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
#if (WIN32)

    ngx_conf_log_error(NGX_LOG_WARN, cf, 0,
                       "\"user\" is not supported, ignored");

    return NGX_CONF_OK;

#else

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

#endif
}
