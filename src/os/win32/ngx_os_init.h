#ifndef _NGX_OS_INIT_H_INCLUDED_
#define _NGX_OS_INIT_H_INCLUDED_


#include <ngx_config.h>
#include <ngx_core.h>


int ngx_os_init(ngx_log_t *log);

ssize_t ngx_wsarecv(ngx_connection_t *c, char *buf, size_t size);


#endif /* _NGX_OS_INIT_H_INCLUDED_ */
