
#include <nginx.h>

#include <ngx_config.h>

#include <ngx_core.h>
#include <ngx_connection.h>
#include <ngx_os_init.h>
#include <ngx_string.h>
#include <ngx_errno.h>
#include <ngx_time.h>
#include <ngx_log.h>
#include <ngx_alloc.h>
#include <ngx_array.h>
#include <ngx_socket.h>
#include <ngx_server.h>
#include <ngx_listen.h>
#include <ngx_conf_file.h>

/* STUB */
#include <ngx_http.h>
/* */


static void ngx_set_signals(ngx_log_t *log);
static void ngx_open_listening_sockets(ngx_log_t *log);


/* STUB */
int ngx_max_conn = 512;
u_int  ngx_sendfile_flags;

ngx_server_t  ngx_server;
/* */

ngx_log_t       ngx_log;
ngx_pool_t     *ngx_pool;
void        ****ngx_conf_ctx;


ngx_os_io_t  ngx_io;


int ngx_max_module;
void *ctx_conf;

int ngx_connection_counter;

ngx_array_t  ngx_listening_sockets;


int main(int argc, char *const *argv)
{
    int         i;
    ngx_str_t   conf_file;
    ngx_conf_t  conf;

    /* STUB */
    ngx_log.log_level = NGX_LOG_DEBUG;

    if (ngx_os_init(&ngx_log) == NGX_ERROR) {
        return 1;
    }

    ngx_pool = ngx_create_pool(16 * 1024, &ngx_log);
    /* */

    ngx_max_module = 0;
    for (i = 0; ngx_modules[i]; i++) {
        ngx_modules[i]->index = ngx_max_module++;
    }

    /* life cycle */

    {
        ngx_init_array(ngx_listening_sockets,
                       ngx_pool, 10, sizeof(ngx_listen_t),
                       1);

        ngx_memzero(&conf, sizeof(ngx_conf_t));

        ngx_test_null(conf.args,
                      ngx_create_array(ngx_pool, 10, sizeof(ngx_str_t)),
                      1);

        ngx_test_null(ngx_conf_ctx,
                      ngx_pcalloc(ngx_pool, ngx_max_module * sizeof(void *)),
                      1);

        conf.ctx = ngx_conf_ctx;
        conf.pool = ngx_pool;
        conf.log = &ngx_log;
        conf.module_type = NGX_CORE_MODULE_TYPE;
        conf.cmd_type = NGX_MAIN_CONF;

        conf_file.len = sizeof("nginx.conf") - 1;
        conf_file.data = "nginx.conf";

        if (ngx_conf_parse(&conf, &conf_file) != NGX_CONF_OK) {
            return 1;
        }

        ngx_init_temp_number();

        ngx_io = ngx_os_io;

        for (i = 0; ngx_modules[i]; i++) {
            if (ngx_modules[i]->init_module) {
                if (ngx_modules[i]->init_module(ngx_pool) == NGX_ERROR) {
                    return 1;
                }
            }
        }

        ngx_open_listening_sockets(&ngx_log);

        /* TODO: daemon, once only */

        /* TODO: fork */

        ngx_pre_thread(&ngx_listening_sockets, ngx_pool, &ngx_log);

        /* TODO: threads */

        /* STUB */
        ngx_worker(&ngx_log);
    }     

    return 0;
}


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
