
#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_event.h>
/* STUB */
#include <nginx.h>


static void ngx_clean_old_cycles(ngx_event_t *ev);


volatile ngx_cycle_t  *ngx_cycle;
ngx_array_t            ngx_old_cycles;

static ngx_pool_t     *ngx_temp_pool;
static ngx_event_t     ngx_cleaner_event;


/* STUB NAME */
static ngx_connection_t  dumb;
/* STUB */


ngx_cycle_t *ngx_init_cycle(ngx_cycle_t *old_cycle)
{
    ngx_int_t         i, n, failed;
    ngx_str_t         conf_file;
    ngx_log_t        *log;
    ngx_conf_t        conf;
    ngx_pool_t       *pool;
    ngx_cycle_t      *cycle, **old;
    ngx_socket_t      fd;
    ngx_open_file_t  *file;
    ngx_listening_t  *ls, *nls;

    log = old_cycle->log;

    if (!(pool = ngx_create_pool(16 * 1024, log))) {
        return NULL;
    }

    if (!(cycle = ngx_pcalloc(pool, sizeof(ngx_cycle_t)))) {
        ngx_destroy_pool(pool);
        return NULL;
    }
    cycle->pool = pool;

    cycle->old_cycle = old_cycle;


    n = old_cycle->pathes.nelts ? old_cycle->pathes.nelts : 10;
    if (!(cycle->pathes.elts = ngx_pcalloc(pool, n * sizeof(ngx_path_t *)))) {
        ngx_destroy_pool(pool);
        return NULL;
    }
    cycle->pathes.nelts = 0;
    cycle->pathes.size = sizeof(ngx_path_t *);
    cycle->pathes.nalloc = n;
    cycle->pathes.pool = pool;


    n = old_cycle->open_files.nelts ? old_cycle->open_files.nelts : 20;
    cycle->open_files.elts = ngx_pcalloc(pool, n * sizeof(ngx_open_file_t));
    if (cycle->open_files.elts == NULL) {
        ngx_destroy_pool(pool);
        return NULL;
    }
    cycle->open_files.nelts = 0;
    cycle->open_files.size = sizeof(ngx_open_file_t);
    cycle->open_files.nalloc = n;
    cycle->open_files.pool = pool;


    if (!(cycle->log = ngx_log_create_errlog(cycle, NULL))) {
        ngx_destroy_pool(pool);
        return NULL;
    }


    n = old_cycle->listening.nelts ? old_cycle->listening.nelts : 10;
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


    if (ngx_core_module.init_module(cycle) == NGX_ERROR) {
        ngx_destroy_pool(pool);
        return NULL;
    }


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
        if (file[i].name.data == NULL) {
            continue;
        }

        file[i].fd = ngx_open_file(file[i].name.data,
                                   NGX_FILE_RDWR,
                                   NGX_FILE_CREATE_OR_OPEN|NGX_FILE_APPEND);

ngx_log_debug(log, "OPEN: %d:%s" _ file[i].fd _ file[i].name.data);

        if (file[i].fd == NGX_INVALID_FILE) {
            ngx_log_error(NGX_LOG_EMERG, log, ngx_errno,
                          ngx_open_file_n " \"%s\" failed",
                          file[i].name.data);
            failed = 1;
            break;
        }

#if (WIN32)
        if (ngx_file_append_mode(file[i].fd) == NGX_ERROR) {
            ngx_log_error(NGX_LOG_EMERG, log, ngx_errno,
                          ngx_file_append_mode_n " \"%s\" failed",
                          file[i].name.data);
            failed = 1;
            break;
        }
#endif
    }

    if (!failed) {
        if (old_cycle->listening.nelts) {
            ls = old_cycle->listening.elts;
            for (i = 0; i < old_cycle->listening.nelts; i++) {
                ls[i].remain = 0;
            }

            nls = cycle->listening.elts;
            for (n = 0; n < cycle->listening.nelts; n++) {
                for (i = 0; i < old_cycle->listening.nelts; i++) {
                    if (ls[i].ignore) {
                        continue;
                    }

                    if (ngx_memcmp(nls[n].sockaddr,
                                   ls[i].sockaddr, ls[i].socklen) == 0)
                    {
                        fd = ls[i].fd;
#if (WIN32)
                        /*
                         * Winsock assignes a socket number divisible by 4 so
                         * to find a connection we divide a socket number by 4.
                         */

                        fd /= 4;
#endif
                        if (fd >= (ngx_socket_t) cycle->connection_n) {
                            ngx_log_error(NGX_LOG_EMERG, log, 0,
                                        "%d connections is not enough to hold "
                                        "an open listening socket on %s, "
                                        "required at least %d connections",
                                        cycle->connection_n,
                                        ls[i].addr_text.data, fd);
                            failed = 1;
                            break;
                        }

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

        if (!failed) {
            if (ngx_open_listening_sockets(cycle) == NGX_ERROR) {
                failed = 1;
            }
        }
    }

    if (failed) {

        /* rollback the new cycle configuration */

        file = cycle->open_files.elts;
        for (i = 0; i < cycle->open_files.nelts; i++) {
            if (file[i].fd == NGX_INVALID_FILE) {
                continue;
            }

            if (ngx_close_file(file[i].fd) == NGX_FILE_ERROR) {
                ngx_log_error(NGX_LOG_EMERG, log, ngx_errno,
                              ngx_close_file_n " \"%s\" failed",
                              file[i].name.data);
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


    for (i = 0; ngx_modules[i]; i++) {
        if (ngx_modules[i]->init_module) {
            if (ngx_modules[i]->init_module(cycle) == NGX_ERROR) {
                /* fatal */
                exit(1);
            }
        }
    }

    /* close and delete stuff that lefts from an old cycle */

    /* close the unneeded listening sockets */

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


    /* close the unneeded open files */

    file = old_cycle->open_files.elts;
    for (i = 0; i < old_cycle->open_files.nelts; i++) {
        if (file[i].fd == NGX_INVALID_FILE) {
            continue;
        }

        if (ngx_close_file(file[i].fd) == NGX_FILE_ERROR) {
            ngx_log_error(NGX_LOG_EMERG, log, ngx_errno,
                          ngx_close_file_n " \"%s\" failed",
                          file[i].name.data);
        }
    }

    if (old_cycle->connections == NULL) {
        /* an old cycle is an init cycle */
        ngx_destroy_pool(old_cycle->pool);
        return cycle;
    }

    if (ngx_master) {
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
        dumb.fd = (ngx_socket_t) -1;
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


#if 0


static ngx_int_t ngx_set_inherited_sockets(ngx_cycle_t *cycle, char **envp)
{
    char                *p, *v;
    ngx_socket_t         s;
    ngx_listening_t     *ls;
    struct sockaddr_in  *addr_in;

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

                /* AF_INET only */

                ls->sockaddr = ngx_palloc(cycle->pool,
                                          sizeof(struct sockaddr_in));
                if (ls->sockaddr == NULL) {
                    return NGX_ERROR;
                }

                ls->socklen = sizeof(struct sockaddr_in);
                if (getsockname(s, ls->sockaddr, &ls->socklen) == -1) {
                    ngx_log_error(NGX_LOG_CRIT, cycle->log, ngx_socket_errno,
                                  "getsockname() of the inherited "
                                  "socket #%d failed", s);
                    ls->ignore = 1;
                    continue;
                }

                addr_in = (struct sockaddr_in *) ls->sockaddr;

                if (addr_in->sin_family != AF_INET) {
                    ngx_log_error(NGX_LOG_CRIT, cycle->log, ngx_socket_errno,
                                  "the inherited socket #%d has "
                                  "unsupported family", s);
                    ls->ignore = 1;
                    continue;
                }
                ls->addr_text_max_len = INET_ADDRSTRLEN;

                ls->addr_text.data = ngx_palloc(cycle->pool,
                                                ls->addr_text_max_len);
                if (ls->addr_text.data == NULL) {
                    return NGX_ERROR;
                }

                addr_in->sin_len = 0;

                ls->family = addr_in->sin_family;
                ls->addr_text.len = ngx_sock_ntop(ls->family, ls->sockaddr,
                                                  ls->addr_text.data,
                                                  ls->addr_text_max_len);
                if (ls->addr_text.len == 0) {
                    return NGX_ERROR;
                }
            }
        }

        break;
    }

    return NGX_OK;
}


static ngx_int_t ngx_open_listening_sockets(ngx_cycle_t *cycle)
{
    int              tries, failed, reuseaddr, i;
    ngx_err_t        err;
    ngx_log_t       *log;
    ngx_socket_t     s;
    ngx_listening_t *ls;

    reuseaddr = 1;
#if (NGX_SUPPRESS_WARN)
    failed = 0;
#endif

    log = cycle->log;

    /* TODO: tries configurable */

    for (tries = 10; tries; tries--) {
        failed = 0;

        /* for each listening socket */

        ls = cycle->listening.elts;
        for (i = 0; i < cycle->listening.nelts; i++) {

            if (ls[i].ignore) {
                continue;
            }

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
                              ngx_socket_n " %s failed", ls[i].addr_text.data);
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

            if (!(ngx_event_flags & NGX_USE_AIO_EVENT)) {
                if (ngx_nonblocking(s) == -1) {
                    ngx_log_error(NGX_LOG_EMERG, log, ngx_socket_errno,
                                  ngx_nonblocking_n " %s failed",
                                  ls[i].addr_text.data);
                    return NGX_ERROR;
                }
            }

#if 0
            if (ls[i].nonblocking) {
                if (ngx_nonblocking(s) == -1) {
                    ngx_log_error(NGX_LOG_EMERG, log, ngx_socket_errno,
                                  ngx_nonblocking_n " %s failed",
                                  ls[i].addr_text.data);
                    return NGX_ERROR;
                }
            }
#endif

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


#endif


void ngx_reopen_files(ngx_cycle_t *cycle)
{
    ngx_fd_t          fd;
    ngx_int_t         i;
    ngx_open_file_t  *file;

    file = cycle->open_files.elts;
    for (i = 0; i < cycle->open_files.nelts; i++) {
        if (file[i].name.data == NULL) {
            continue;
        }

        fd = ngx_open_file(file[i].name.data, NGX_FILE_RDWR,
                           NGX_FILE_CREATE_OR_OPEN|NGX_FILE_APPEND);

        ngx_log_debug3(NGX_LOG_DEBUG_EVENT, cycle->log, 0,
                       "reopen file \"%s\", old:%d new:%d",
                       file[i].name.data, file[i].fd, fd);

        if (fd == NGX_INVALID_FILE) {
            ngx_log_error(NGX_LOG_EMERG, cycle->log, ngx_errno,
                          ngx_open_file_n " \"%s\" failed", file[i].name.data);
            continue;
        }

#if (WIN32)
        if (ngx_file_append_mode(fd) == NGX_ERROR) {
            ngx_log_error(NGX_LOG_EMERG, cycle->log, ngx_errno,
                          ngx_file_append_mode_n " \"%s\" failed",
                          file[i].name.data);

            if (ngx_close_file(fd) == NGX_FILE_ERROR) {
                ngx_log_error(NGX_LOG_EMERG, cycle->log, ngx_errno,
                              ngx_close_file_n " \"%s\" failed",
                              file[i].name.data);
            }

            continue;
        }
#endif

        if (ngx_close_file(file[i].fd) == NGX_FILE_ERROR) {
            ngx_log_error(NGX_LOG_EMERG, cycle->log, ngx_errno,
                          ngx_close_file_n " \"%s\" failed",
                          file[i].name.data);
        }

        file[i].fd = fd;
    }
}


#if 0

static void ngx_close_listening_sockets(ngx_cycle_t *cycle)
{
    ngx_int_t         i;
    ngx_socket_t      fd;
    ngx_listening_t  *ls;

    if (ngx_event_flags & NGX_USE_IOCP_EVENT) {
        return;
    }

    ls = cycle->listening.elts;
    for (i = 0; i < cycle->listening.nelts; i++) {
        fd = ls[i].fd;

#if (WIN32)
        /*
         * Winsock assignes a socket number divisible by 4
         * so to find a connection we divide a socket number by 4.
         */

        fd /= 4;
#endif

        ngx_del_event(&cycle->read_events[fd], NGX_READ_EVENT, NGX_CLOSE_EVENT);

        if (ngx_close_socket(ls[i].fd) == -1) {
            ngx_log_error(NGX_LOG_EMERG, cycle->log, ngx_socket_errno,
                          ngx_close_socket_n " %s failed",
                          ls[i].addr_text.data);
        }

        cycle->connections[fd].fd = -1;
    }
}

#endif


static void ngx_clean_old_cycles(ngx_event_t *ev)
{
    int            i, n, found, live;
    ngx_log_t     *log;
    ngx_cycle_t  **cycle;

    log = ngx_cycle->log;
    ngx_temp_pool->log = log;

    ngx_log_debug(log, "clean old cycles");

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
                ngx_log_debug(log, "live fd: %d" _ n);
                break;
            }
        }

        if (found) {
            live = 1;
            continue;
        }

        ngx_log_debug(log, "clean old cycle: %d" _ i);
        ngx_destroy_pool(cycle[i]->pool);
        cycle[i] = NULL;
    }

    ngx_log_debug(log, "old cycles status: %d" _ live);

    if (live) {
        ngx_log_debug(log, "TIMER");
        ngx_add_timer(ev, 30000);

    } else {
        ngx_destroy_pool(ngx_temp_pool);
        ngx_temp_pool = NULL;
        ngx_old_cycles.nelts = 0;
    }
}
