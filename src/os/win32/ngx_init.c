
#include <ngx_config.h>
#include <ngx_core.h>


int  ngx_max_sockets;


ngx_os_io_t ngx_os_io = {
    ngx_wsarecv,
    NULL,
    NULL,
    NULL
};


int ngx_os_init(ngx_log_t *log)
{
    if (ngx_init_sockets(log) == NGX_ERROR) {
        return NGX_ERROR;
    }

    return NGX_OK;
}
