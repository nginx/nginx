
#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_event.h>
#include <nginx.h>


static ngx_cycle_t *ngx_init_cycle(ngx_cycle_t *old_cycle, ngx_log_t *log);
static int ngx_open_listening_sockets(ngx_cycle_t *cycle, ngx_log_t *log);
static void ngx_clean_old_cycles(ngx_event_t *ev);


#if (NGX_DEBUG) && (__FreeBSD__)
extern char *malloc_options;
#endif


typedef struct {
     int   daemon;
} ngx_core_conf_t;


static ngx_str_t  core_name = ngx_string("core");

static ngx_command_t  ngx_core_commands[] = {

    {ngx_string("daemon"),
     NGX_MAIN_CONF|NGX_CONF_TAKE1,
     ngx_conf_set_core_flag_slot,
     0,
     offsetof(ngx_core_conf_t, daemon),
     NULL},

    ngx_null_command
};


ngx_module_t  ngx_core_module = {
    NGX_MODULE,
    &core_name,                            /* module context */
    ngx_core_commands,                     /* module directives */
    NGX_CORE_MODULE,                       /* module type */
    NULL,                                  /* init module */
    NULL                                   /* init child */
};


int           ngx_max_module;
ngx_os_io_t   ngx_io;

ngx_cycle_t  *ngx_cycle;
ngx_pool_t   *ngx_temp_pool;
ngx_array_t   ngx_old_cycles;
ngx_event_t   ngx_cleaner_event;

/* STUB NAME */
ngx_connection_t  dumb;

int ngx_connection_counter;


int restart;
int rotate;


int main(int argc, char *const *argv)
{
    int               i;
    ngx_log_t        *log;
    ngx_cycle_t      *cycle;
    ngx_core_conf_t  *ccf;

#if (NGX_DEBUG) && (__FreeBSD__)
#if __FreeBSD_version >= 500014
    _malloc_options
#else
    malloc_options
#endif
                    = "J";
#endif

    /* TODO */ ngx_max_sockets = -1;

    log = ngx_log_init_errlog();

    if (ngx_os_init(log) == NGX_ERROR) {
        return 1;
    }

    ngx_max_module = 0;
    for (i = 0; ngx_modules[i]; i++) {
        ngx_modules[i]->index = ngx_max_module++;
    }

    cycle = ngx_init_cycle(NULL, log);
    if (cycle == NULL) {
        return 1;
    }

    ngx_cycle = cycle;

#if !(WIN32)

    ccf = (ngx_core_conf_t *) ngx_get_conf(ngx_cycle->conf_ctx,
                                           ngx_core_module);

    if (ccf->daemon != 0) {
        if (ngx_daemon(ngx_cycle->log) == NGX_ERROR) {
            return 1;
        }
    }

    if (dup2(ngx_cycle->log->file->fd, STDERR_FILENO) == -1) {
        ngx_log_error(NGX_LOG_EMERG, ngx_cycle->log, ngx_errno,
                      "dup2(STDERR) failed");
        return 1;
    }

#endif

    /* life cycle */

    for ( ;; ) {
        /* STUB */ ngx_cycle->log->log_level = NGX_LOG_DEBUG;

        /* forks */

        ngx_init_temp_number();

        for (i = 0; ngx_modules[i]; i++) {
            if (ngx_modules[i]->init_child) {
                if (ngx_modules[i]->init_child(ngx_cycle) == NGX_ERROR) {
                    /* fatal */
                    exit(1);
                }
            }
        }

        /* threads */

        restart = 0;
        rotate = 0;

        for ( ;; ) {

            for ( ;; ) {
                ngx_log_debug(ngx_cycle->log, "worker cycle");

                ngx_process_events(ngx_cycle->log);

                if (rotate) {
                    ngx_log_debug(ngx_cycle->log, "rotate");
                }

                if (restart) {
                    ngx_log_debug(ngx_cycle->log, "restart");
                    break;
                }

            }

            cycle = ngx_init_cycle(ngx_cycle, ngx_cycle->log);
            if (cycle == NULL) {
                continue;
            }

            ngx_cycle = cycle;
            break;
        }
    }

    return 0;
}


static ngx_cycle_t *ngx_init_cycle(ngx_cycle_t *old_cycle, ngx_log_t *log)
{
    int               i, n, failed;
    ngx_str_t         conf_file;
    ngx_conf_t        conf;
    ngx_pool_t       *pool;
    ngx_cycle_t      *cycle, **old;
    ngx_core_conf_t  *ccf;
    ngx_open_file_t  *file;
    ngx_listening_t  *ls, *nls;


    pool = ngx_create_pool(16 * 1024, log);
    if (pool == NULL) {
        return NULL;
    }

    cycle = ngx_pcalloc(pool, sizeof(ngx_cycle_t));
    if (cycle == NULL) {
        ngx_destroy_pool(pool);
        return NULL;
    }
    cycle->pool = pool;

    cycle->old_cycle = old_cycle;


    n = old_cycle ? old_cycle->open_files.nelts : 20;
    cycle->open_files.elts = ngx_pcalloc(pool, n * sizeof(ngx_open_file_t));
    if (cycle->open_files.elts == NULL) {
        ngx_destroy_pool(pool);
        return NULL;
    }
    cycle->open_files.nelts = 0;
    cycle->open_files.size = sizeof(ngx_open_file_t);
    cycle->open_files.nalloc = n;
    cycle->open_files.pool = pool;


    cycle->log = ngx_log_create_errlog(cycle, NULL);
    if (cycle->log == NULL) {
        ngx_destroy_pool(pool);
        return NULL;
    }


    n = old_cycle ? old_cycle->listening.nelts : 10;
    cycle->listening.elts = ngx_pcalloc(pool, n * sizeof(ngx_listening_t));
    if (cycle->listening.elts == NULL) {
        ngx_destroy_pool(pool);
        return NULL;
    }
    cycle->listening.nelts = 0;
    cycle->listening.size = sizeof(ngx_listening_t);
    cycle->listening.nalloc = n;
    cycle->listening.pool = pool;


    cycle->conf_ctx = ngx_pcalloc(pool, ngx_max_module * sizeof(void *));
    if (cycle->conf_ctx == NULL) {
        ngx_destroy_pool(pool);
        return NULL;
    }


    ccf = ngx_pcalloc(pool, sizeof(ngx_core_conf_t));
    if (ccf == NULL) {
        ngx_destroy_pool(pool);
        return NULL;
    }
    ccf->daemon = -1;
    ((void **)(cycle->conf_ctx))[ngx_core_module.index] = ccf;


    ngx_memzero(&conf, sizeof(ngx_conf_t));
    /* STUB: init array ? */
    conf.args = ngx_create_array(pool, 10, sizeof(ngx_str_t));
    if (conf.args == NULL) {
        ngx_destroy_pool(pool);
        return NULL;
    }

    conf.ctx = cycle->conf_ctx;
    conf.cycle = cycle;
    /* STUB */ conf.pool = cycle->pool;
    conf.log = log;
    conf.module_type = NGX_CORE_MODULE;
    conf.cmd_type = NGX_MAIN_CONF;

    conf_file.len = sizeof(NGINX_CONF) - 1;
    conf_file.data = NGINX_CONF;

    if (ngx_conf_parse(&conf, &conf_file) != NGX_CONF_OK) {
        ngx_destroy_pool(pool);
        return NULL;
    }


    failed = 0;

    file = cycle->open_files.elts;
    for (i = 0; i < cycle->open_files.nelts; i++) {
        if (file->name.data == NULL) {
            continue;
        }

        file->fd = ngx_open_file(file->name.data,
                                 NGX_FILE_RDWR,
                                 NGX_FILE_CREATE_OR_OPEN|NGX_FILE_APPEND);

ngx_log_debug(log, "OPEN: %d:%s" _ file->fd _ file->name.data);

        if (file->fd == NGX_INVALID_FILE) {
            ngx_log_error(NGX_LOG_EMERG, log, ngx_errno,
                          ngx_open_file_n " \"%s\" failed",
                          file->name.data);
            failed = 1;
            break;
        }

        /* TODO: Win32 append */
    }

    /* STUB */ cycle->log->log_level = NGX_LOG_DEBUG;

    if (!failed) {
        if (old_cycle) {
            ls = old_cycle->listening.elts;
            for (i = 0; i < old_cycle->listening.nelts; i++) {
                ls[i].remain = 0;
            }

            nls = cycle->listening.elts;
            for (n = 0; n < cycle->listening.nelts; n++) {
                for (i = 0; i < old_cycle->listening.nelts; i++) {
                    if (ngx_memcmp(nls[n].sockaddr,
                                   ls[i].sockaddr, ls[i].socklen) == 0)
                    {
                        nls[n].fd = ls[i].fd;
                        nls[i].remain = 1;
                        ls[i].remain = 1;
                        break;
                    }
                }

                if (nls[n].fd == -1) {
                    nls[n].new = 1;
                }
            }

        } else {
            ls = cycle->listening.elts;
            for (i = 0; i < cycle->listening.nelts; i++) {
                ls[i].new = 1;
            }
        }

        if (ngx_open_listening_sockets(cycle, log) == NGX_ERROR) {
            failed = 1;
        }
    }

    if (failed) {

        /* rollback the new cycle configuration */

        file = cycle->open_files.elts;
        for (i = 0; i < cycle->open_files.nelts; i++) {
            if (file->fd == NGX_INVALID_FILE) {
                continue;
            }

            if (ngx_close_file(file->fd) == NGX_FILE_ERROR) {
                ngx_log_error(NGX_LOG_EMERG, log, ngx_errno,
                              ngx_close_file_n " \"%s\" failed",
                              file->name.data);
            }
        }

        ls = cycle->listening.elts;
        for (i = 0; i < cycle->listening.nelts; i++) {
            if (ls[i].new && ls[i].fd == -1) {
                continue;
            }

            if (ngx_close_socket(ls[i].fd) == -1) {
                ngx_log_error(NGX_LOG_EMERG, log, ngx_socket_errno,
                              ngx_close_socket_n " %s failed",
                              ls[i].addr_text.data);
            }
        }

        ngx_destroy_pool(pool);
        return NULL;
    }

    /* commit the new cycle configuration */

    pool->log = cycle->log;

#if 1
    /* STUB */ cycle->one_process = 1;
#endif

    for (i = 0; ngx_modules[i]; i++) {
        if (ngx_modules[i]->init_module) {
            if (ngx_modules[i]->init_module(cycle) == NGX_ERROR) {
                /* fatal */
                exit(1);
            }
        }
    }

    if (old_cycle == NULL) {
        return cycle;
    }

    ls = old_cycle->listening.elts;
    for (i = 0; i < old_cycle->listening.nelts; i++) {
        if (ls[i].remain) {
            continue;
        }

        if (ngx_close_socket(ls[i].fd) == -1) {
            ngx_log_error(NGX_LOG_EMERG, log, ngx_socket_errno,
                          ngx_close_socket_n " %s failed",
                          ls[i].addr_text.data);
        }
    }

    file = old_cycle->open_files.elts;
    for (i = 0; i < old_cycle->open_files.nelts; i++) {
        if (file->fd == NGX_INVALID_FILE) {
            continue;
        }

        if (ngx_close_file(file->fd) == NGX_FILE_ERROR) {
            ngx_log_error(NGX_LOG_EMERG, log, ngx_errno,
                          ngx_close_file_n " \"%s\" failed",
                          file->name.data);
        }
    }


    if (!old_cycle->one_process) {
        ngx_destroy_pool(old_cycle->pool);
        return cycle;
    }

    if (ngx_temp_pool == NULL) {
        ngx_temp_pool = ngx_create_pool(128, cycle->log);
        if (ngx_temp_pool == NULL) {
            ngx_log_error(NGX_LOG_EMERG, cycle->log, 0,
                          "can not create ngx_temp_pool");
            exit(1);
        }

        n = 10;
        ngx_old_cycles.elts = ngx_pcalloc(ngx_temp_pool,
                                          n * sizeof(ngx_cycle_t *));
        if (ngx_old_cycles.elts == NULL) {
            exit(1);
        }
        ngx_old_cycles.nelts = 0;
        ngx_old_cycles.size = sizeof(ngx_cycle_t *);
        ngx_old_cycles.nalloc = n;
        ngx_old_cycles.pool = ngx_temp_pool;

        ngx_cleaner_event.event_handler = ngx_clean_old_cycles;
        ngx_cleaner_event.log = cycle->log;
        ngx_cleaner_event.data = &dumb;
        dumb.fd = -1;
    }

    ngx_temp_pool->log = cycle->log;

    old = ngx_push_array(&ngx_old_cycles);
    if (old == NULL) {
        exit(1);
    }
    *old = old_cycle;

    if (!ngx_cleaner_event.timer_set) {
        ngx_add_timer(&ngx_cleaner_event, 30000);
        ngx_cleaner_event.timer_set = 1;
    }

    return cycle;
}


static int ngx_open_listening_sockets(ngx_cycle_t *cycle, ngx_log_t *log)
{
    int              times, failed, reuseaddr, i;
    ngx_err_t        err;
    ngx_socket_t     s;
    ngx_listening_t *ls;

    reuseaddr = 1;

    /* TODO: times configurable */

    for (times = 10; times; times--) {
         failed = 0;

        /* for each listening socket */

        ls = cycle->listening.elts;
        for (i = 0; i < cycle->listening.nelts; i++) {

            if (ls[i].fd != -1) {
                continue;
            }

            if (ls[i].inherited) {

                /* TODO: close on exit */
                /* TODO: nonblocking */
                /* TODO: deferred accept */

                continue;
            }

            s = ngx_socket(ls[i].family, ls[i].type, ls[i].protocol,
                           ls[i].flags);

            if (s == -1) {
                ngx_log_error(NGX_LOG_EMERG, log, ngx_socket_errno,
                              ngx_socket_n " %s falied", ls[i].addr_text.data);
                return NGX_ERROR;
            }

#if (WIN32)
            /*
             * Winsock assignes a socket number divisible by 4
             * so to find a connection we divide a socket number by 4.
             */

            if (s % 4) {
                ngx_log_error(NGX_LOG_EMERG, ls->log, 0,
                              ngx_socket_n " created socket %d", s);
                return NGX_ERROR;
            }
#endif

            if (setsockopt(s, SOL_SOCKET, SO_REUSEADDR,
                           (const void *) &reuseaddr, sizeof(int)) == -1) {
                ngx_log_error(NGX_LOG_EMERG, log, ngx_socket_errno,
                              "setsockopt(SO_REUSEADDR) %s failed",
                              ls[i].addr_text.data);
                return NGX_ERROR;
            }

            /* TODO: close on exit */

            if (ls[i].nonblocking) {
                if (ngx_nonblocking(s) == -1) {
                    ngx_log_error(NGX_LOG_EMERG, log, ngx_socket_errno,
                                  ngx_nonblocking_n " %s failed",
                                  ls[i].addr_text.data);
                    return NGX_ERROR;
                }
            }

            if (bind(s, ls[i].sockaddr, ls[i].socklen) == -1) {
                err = ngx_socket_errno;
                ngx_log_error(NGX_LOG_EMERG, log, err,
                              "bind() to %s failed", ls[i].addr_text.data);

                if (err != NGX_EADDRINUSE)
                    return NGX_ERROR;

                if (ngx_close_socket(s) == -1)
                    ngx_log_error(NGX_LOG_EMERG, log, ngx_socket_errno,
                                  ngx_close_socket_n " %s failed",
                                  ls[i].addr_text.data);

                failed = 1;
                continue;
            }

            if (listen(s, ls[i].backlog) == -1) {
                ngx_log_error(NGX_LOG_EMERG, log, ngx_socket_errno,
                              "listen() to %s failed", ls[i].addr_text.data);
                return NGX_ERROR;
            }

            /* TODO: deferred accept */

            ls[i].fd = s;
        }

        if (!failed)
            break;

        /* TODO: delay configurable */

        ngx_log_error(NGX_LOG_NOTICE, log, 0,
                      "try again to bind() after 500ms");
        ngx_msleep(500);
    }

    if (failed) {
        ngx_log_error(NGX_LOG_EMERG, log, 0, "still can not bind()");
        return NGX_ERROR;
    }

    return NGX_OK;
}


static void ngx_clean_old_cycles(ngx_event_t *ev)
{
    int            i, n, found, live;
    ngx_cycle_t  **cycle;

    ngx_temp_pool->log = ngx_cycle->log;

    ngx_log_debug(ngx_cycle->log, "clean old cycles");

    live = 0;

    cycle = ngx_old_cycles.elts;
    for (i = 0; i < ngx_old_cycles.nelts; i++) {

        if (cycle[i] == NULL) {
            continue;
        }

        found = 0;

        for (n = 0; n < cycle[i]->connection_n; n++) {
            if (cycle[i]->connections[n].fd != -1) {
                found = 1;
                ngx_log_debug(ngx_cycle->log, "live fd: %d" _ n);
                break;
            }
        }

        if (found) {
            live = 1;
            continue;
        }

        ngx_log_debug(ngx_cycle->log, "clean old cycle: %d" _ i);
        ngx_destroy_pool(cycle[i]->pool);
        cycle[i] = NULL;
    }

    ngx_log_debug(ngx_cycle->log, "old cycles status: %d" _ live);

    if (live) {
        ngx_log_debug(ngx_cycle->log, "TIMER");
        ngx_add_timer(ev, 30000);

    } else {
        ngx_cleaner_event.timer_set = 0;
        ngx_destroy_pool(ngx_temp_pool);
        ngx_temp_pool = NULL;
        ngx_old_cycles.nelts = 0;
    }
}
