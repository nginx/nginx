
#include <ngx_os_init.h>

int ngx_os_init(ngx_log_t *log)
{
    if (ngx_init_sockets(&ngx_log) == NGX_ERROR) {
        return NGX_ERROR;
    }

    return NGX_OK;
}
