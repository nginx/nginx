
#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_event.h>


void ngx_imap_proxy_init_connection(ngx_connection_t *c)
{
    ngx_log_debug0(NGX_LOG_DEBUG_IMAP, c->log, 0,
                   "imap proxy init connection");

    if (ngx_close_socket(c->fd) == -1) {

        /* we use ngx_cycle->log because c->log was in c->pool */

        ngx_log_error(NGX_LOG_ALERT, ngx_cycle->log, ngx_socket_errno,
                      ngx_close_socket_n " failed");
    }
}
