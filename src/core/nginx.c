
#include <nginx.h>

#include <ngx_config.h>

#include <ngx_core.h>
#include <ngx_string.h>
#include <ngx_errno.h>
#include <ngx_time.h>
#include <ngx_log.h>
#include <ngx_alloc.h>
#include <ngx_array.h>
#include <ngx_socket.h>
#include <ngx_server.h>
#include <ngx_connection.h>
#include <ngx_listen.h>
#include <ngx_conf_file.h>

/* STUB */
#include <ngx_http.h>
/* */


static void ngx_set_signals(ngx_log_t *log);
static void ngx_open_listening_sockets(ngx_log_t *log);


/* STUB */
int ngx_max_conn = 512;

ngx_server_t  ngx_server;
/* */

ngx_log_t     ngx_log;
ngx_pool_t   *ngx_pool;


int ngx_connection_counter;

ngx_array_t  ngx_listening_sockets;


int main(int argc, char *const *argv)
{
    int         i;
    ngx_str_t   conf_file;
    ngx_conf_t  conf;

    /* STUB */
    ngx_log.log_level = NGX_LOG_DEBUG;

    ngx_pool = ngx_create_pool(16 * 1024, &ngx_log);
    /* */

#if (WIN32)
    ngx_init_sockets(&ngx_log);
#else
    ngx_set_signals(&ngx_log);
#endif


    ngx_init_array(ngx_listening_sockets, ngx_pool, 10, sizeof(ngx_listen_t),
                   1);

    ngx_memzero(&conf, sizeof(ngx_conf_t));
    ngx_test_null(conf.args,
                  ngx_create_array(ngx_pool, 10, sizeof(ngx_str_t)), 1);
    conf.pool = ngx_pool;
    conf.log = &ngx_log;
    conf.type = NGX_CORE_MODULE_TYPE;

    conf_file.len = sizeof("nginx.conf") - 1;
    conf_file.data = "nginx.conf";

    if (ngx_conf_parse(&conf, &conf_file) != NGX_CONF_OK) {
        return 1;
    }

    for (i = 0; ngx_modules[i]; i++) {
        if (ngx_modules[i]->init_module) {
            if (ngx_modules[i]->init_module(ngx_pool) == NGX_ERROR) {
                return 1;
            }
        }
    }


#if 0
    /* STUB */
    /* TODO: init chain of global modules (like ngx_http.c),
       they would init its modules and ngx_listening_sockets */
    ngx_http_init(ngx_pool, &ngx_log);
#endif

    ngx_open_listening_sockets(&ngx_log);

    /* TODO: daemon */

    /* TODO: fork */

    ngx_pre_thread(&ngx_listening_sockets, ngx_pool, &ngx_log);

    /* TODO: threads */

    /* STUB */
    ngx_worker(&ngx_log);

    return 0;
}

#if !(WIN32)
static void ngx_set_signals(ngx_log_t *log)
{
    struct sigaction sa;

    ngx_memzero(&sa, sizeof(struct sigaction));
    sa.sa_handler = SIG_IGN;
    sigemptyset(&sa.sa_mask);
    if (sigaction(SIGPIPE, &sa, NULL) == -1) {
        ngx_log_error(NGX_LOG_EMERG, log, ngx_errno,
                      "sigaction(SIGPIPE, SIG_IGN) failed");
        exit(1);
    }
}
#endif

static void ngx_open_listening_sockets(ngx_log_t *log)
{
    int           times, failed, reuseaddr, i;
    ngx_err_t     err;
    ngx_socket_t  s;
    ngx_listen_t *ls;

    reuseaddr = 1;

    for (times = 10; times; times--) {
         failed = 0;

        /* for each listening socket */
        ls = (ngx_listen_t *) ngx_listening_sockets.elts;
        for (i = 0; i < ngx_listening_sockets.nelts; i++) {

            if (ls[i].bound)
                continue;

            if (ls[i].inherited) {

                /* TODO: close on exit */
                /* TODO: nonblocking */
                /* TODO: deferred accept */

                ls[i].bound = 1;
                continue;
            }

            s = ngx_socket(ls[i].family, ls[i].type, ls[i].protocol,
                           ls[i].flags);
            if (s == -1) {
                ngx_log_error(NGX_LOG_EMERG, log, ngx_socket_errno,
                              ngx_socket_n " %s falied", ls[i].addr_text.data);
                exit(1);
            }

            if (setsockopt(s, SOL_SOCKET, SO_REUSEADDR,
                           (const void *) &reuseaddr, sizeof(int)) == -1) {
                ngx_log_error(NGX_LOG_EMERG, log, ngx_socket_errno,
                              "setsockopt(SO_REUSEADDR) %s failed",
                              ls[i].addr_text.data);
                exit(1);
            }

            /* TODO: close on exit */

            if (ls[i].nonblocking) {
                if (ngx_nonblocking(s) == -1) {
                    ngx_log_error(NGX_LOG_EMERG, log, ngx_socket_errno,
                                  ngx_nonblocking_n " %s failed",
                                  ls[i].addr_text.data);
                    exit(1);
                }
            }

            if (bind(s, ls[i].sockaddr, ls[i].socklen) == -1) {
                err = ngx_socket_errno;
                ngx_log_error(NGX_LOG_EMERG, log, err,
                              "bind() to %s failed", ls[i].addr_text.data);

                if (err != NGX_EADDRINUSE)
                    exit(1);

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
                exit(1);
            }

            /* TODO: deferred accept */

            ls[i].fd = s;
            ls[i].bound = 1;
        }

        if (!failed)
            break;

        ngx_log_error(NGX_LOG_NOTICE, log, 0,
                      "try again to bind() after 500ms");
        ngx_msleep(500);
    }

    if (failed) {
        ngx_log_error(NGX_LOG_EMERG, log, 0, "can not bind(), exiting");
        exit(1);
    }
}
