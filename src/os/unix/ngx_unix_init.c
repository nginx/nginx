
#include <ngx_config.h>
#include <ngx_core.h>


/* STUB */
ssize_t ngx_unix_recv(ngx_connection_t *c, char *buf, size_t size);
ngx_chain_t *ngx_writev_chain(ngx_connection_t *c, ngx_chain_t *in);
int ngx_posix_init(ngx_log_t *log);
int ngx_posix_post_conf_init(ngx_log_t *log);
/* */


ngx_os_io_t ngx_os_io = {
    ngx_unix_recv,
    NULL,
    NULL,
    ngx_writev_chain,
    NGX_HAVE_ZEROCOPY
};


int ngx_os_init(ngx_log_t *log)
{
    return ngx_posix_init(log);
}


int ngx_os_post_conf_init(ngx_log_t *log)
{
    return ngx_posix_post_conf_init(log);
}
