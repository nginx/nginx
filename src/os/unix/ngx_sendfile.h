#ifndef _NGX_SENDFILE_H_INCLUDED_
#define _NGX_SENDFILE_H_INCLUDED_


#include <ngx_types.h>
#include <ngx_file.h>
#include <ngx_socket.h>
#include <ngx_log.h>
#include <ngx_sendv.h>

int ngx_sendfile(ngx_socket_t s,
                 ngx_iovec_t *headers, int hdr_cnt,
                 ngx_file_t fd, off_t offset, size_t nbytes,
                 ngx_iovec_t *trailers, int trl_cnt,
                 off_t *sent,
                 ngx_log_t *log);


#endif /* _NGX_SENDFILE_H_INCLUDED_ */
