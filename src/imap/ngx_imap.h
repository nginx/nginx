#ifndef _NGX_IMAP_H_INCLUDED_
#define _NGX_IMAP_H_INCLUDED_


#include <ngx_config.h>
#include <ngx_core.h>


typedef struct {
    ngx_connection_t      *connection;

    ngx_buf_t             *downstream_buffer;
    ngx_buf_t             *upstream_buffer;
} ngx_imap_proxy_ctx_t;


typedef struct {
    uint32_t               signature;         /* "IMAP" */

    ngx_connection_t      *connection;
    ngx_imap_proxy_ctx_t  *proxy;
} ngx_imap_session_t;


#define NGX_POP3_USER      1
#define NGX_POP3_PASS      2
#define NGX_POP3_APOP      3
#define NGX_POP3_STAT      4
#define NGX_POP3_LIST      5
#define NGX_POP3_RETR      6
#define NGX_POP3_DELE      7
#define NGX_POP3_NOOP      8
#define NGX_POP3_RSET      9
#define NGX_POP3_TOP       10
#define NGX_POP3_UIDL      11
#define NGX_POP3_QUIT      12


void ngx_imap_init_connection(ngx_connection_t *c);
void ngx_imap_close_connection(ngx_connection_t *c);


#endif /* _NGX_IMAP_H_INCLUDED_ */
