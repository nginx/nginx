
#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_event.h>
/* STUB */
#include <nginx.h>


ngx_os_io_t            ngx_io;


ngx_int_t ngx_set_inherited_sockets(ngx_cycle_t *cycle, char **envp)
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


ngx_int_t ngx_open_listening_sockets(ngx_cycle_t *cycle)
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


void ngx_close_listening_sockets(ngx_cycle_t *cycle)
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
