
#include <nginx.h>

#include <ngx_config.h>
#include <ngx_string.h>
#include <ngx_log.h>
#include <ngx_alloc.h>
#include <ngx_array.h>
#include <ngx_socket.h>
#include <ngx_server.h>
#include <ngx_connection.h>
#include <ngx_listen.h>

/* STUB */
#include <ngx_http.h>
/* */



int ngx_max_conn = 512;

ngx_pool_t   ngx_pool;
ngx_log_t    ngx_log;
ngx_server_t ngx_server;


ngx_array_t ngx_listening_sockets;


int main(int argc, char *const *argv)
{
    int  i;
    ngx_socket_t  s;
    ngx_listen_t *ls;

    int  reuseaddr = 1;

    ngx_log.log_level = NGX_LOG_DEBUG;
    ngx_pool.log = &ngx_log;

    ngx_init_sockets(&ngx_log);

    /* TODO: read config */

    /* STUB */
    /* TODO: init chain of global modules (like ngx_http.c),
       they would init its modules and ngx_listening_sockets */
    ngx_http_init();

    /* for each listening socket */
    ls = (ngx_listen_t *) ngx_listening_sockets.elts;
    for (i = 0; i < ngx_listening_sockets.nelts; i++) {
        s = socket(ls->family, ls->type, ls->protocol);
        if (s == -1)
            ngx_log_error(NGX_LOG_EMERG, &(ngx_log), ngx_socket_errno,
                          "nginx: socket %s falied", ls->addr_text);

        if (setsockopt(s, SOL_SOCKET, SO_REUSEADDR,
                       (const void *) &reuseaddr, sizeof(int)) == -1)
            ngx_log_error(NGX_LOG_EMERG, &(ngx_log), ngx_socket_errno,
                         "nginx: setsockopt (SO_REUSEADDR) %s failed",
                         ls->addr_text);

        /* TODO: close on exit */

        if (ngx_nonblocking(s) == -1)
            ngx_log_error(NGX_LOG_EMERG, &(ngx_log), ngx_socket_errno,
                          ngx_nonblocking_n " %s failed", ls->addr_text);

        if (bind(s, (struct sockaddr *) ls->addr, ls->addr_len) == -1)
            ngx_log_error(NGX_LOG_EMERG, &(ngx_log), ngx_socket_errno,
                         "bind to %s failed", ls->addr_text);

        if (listen(s, ls->backlog) == -1)
            ngx_log_error(NGX_LOG_EMERG, &(ngx_log), ngx_socket_errno,
                         "listen to %s failed", ls->addr_text);

        /* TODO: deferred accept */

        ls->fd = s;
        ls->server = &ngx_http_server;
        ls->log = &ngx_log;
    }

    /* TODO: daemon */

    /* TODO: fork */

    /* TODO: events: init ngx_connections and listen slots */

    /* TODO: threads */

    /* STUB */
    ngx_worker(&ls, 1, &ngx_pool, &ngx_log);
}
