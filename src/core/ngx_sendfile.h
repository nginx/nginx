#ifndef _NGX_SENDFILE_H_INCLUDED_
#define _NGX_SENDFILE_H_INCLUDED_


#include <ngx_config.h>
#include <ngx_types.h>
#include <ngx_files.h>
#include <ngx_socket.h>
#include <ngx_log.h>
#include <ngx_connection.h>
#include <ngx_sendv.h>

int ngx_sendfile(ngx_connection_t *c,
                 ngx_iovec_t *headers, int hdr_cnt,
                 ngx_fd_t fd, off_t offset, size_t nbytes,
                 ngx_iovec_t *trailers, int trl_cnt,
                 off_t *sent, u_int flags);


extern u_int ngx_sendfile_flags;


#endif /* _NGX_SENDFILE_H_INCLUDED_ */
