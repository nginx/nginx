
#include <ngx_config.h>
#include <ngx_core.h>


int  ngx_max_sockets;


ngx_os_io_t ngx_os_io = {
#if 0
    ngx_unix_recv,
    NULL,
    NULL,
    ngx_freebsd_write_chain
#else
    NULL,
    NULL,
    NULL,
    NULL
#endif
};


int ngx_os_init(ngx_log_t *log)
{
    if (ngx_init_sockets(log) == NGX_ERROR) {
        return NGX_ERROR;
    }

    return NGX_OK;
}
