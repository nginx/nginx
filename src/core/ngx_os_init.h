#ifndef _NGX_OS_INIT_H_INCLUDED_
#define _NGX_OS_INIT_H_INCLUDED_


#include <ngx_config.h>
#include <ngx_core.h>
#if 0
#include <ngx_connection.h>
#endif


typedef struct {
    ssize_t       (*recv)(ngx_connection_t *c, char *buf, size_t size);
    void           *dummy_recv_chain;
    void           *dummy_send;
    ngx_chain_t  *(*send_chain)(ngx_connection_t *c, ngx_chain_t *in);
} ngx_os_io_t;


int ngx_os_init(ngx_log_t *log);

extern ngx_os_io_t  ngx_os_io;
extern int          ngx_max_sockets;


#endif /* _NGX_OS_INIT_H_INCLUDED_ */
