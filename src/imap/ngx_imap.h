
/*
 * Copyright (C) Igor Sysoev
 */


#ifndef _NGX_IMAP_H_INCLUDED_
#define _NGX_IMAP_H_INCLUDED_


#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_event.h>
#include <ngx_event_connect.h>


typedef struct {
    ngx_peer_connection_t   upstream;

    ngx_buf_t              *buffer;
} ngx_imap_proxy_ctx_t;


typedef enum {
    ngx_pop3_start = 0,
    ngx_pop3_user
} ngx_imap_state_e;


typedef struct {
    uint32_t                signature;         /* "IMAP" */

    ngx_connection_t       *connection;
    ngx_buf_t              *buffer;

    ngx_imap_state_e        imap_state;

    ngx_imap_proxy_ctx_t   *proxy;

    ngx_str_t               login;
    ngx_str_t               passwd;

    ngx_uint_t              command;
    ngx_array_t             args;

    /* used to parse IMAP/POP3 command */

    ngx_uint_t              state;
    u_char                 *arg_start;
    u_char                 *arg_end;
} ngx_imap_session_t;


#define NGX_POP3_USER       1
#define NGX_POP3_PASS       2
#define NGX_POP3_APOP       3
#define NGX_POP3_STAT       4
#define NGX_POP3_LIST       5
#define NGX_POP3_RETR       6
#define NGX_POP3_DELE       7
#define NGX_POP3_NOOP       8
#define NGX_POP3_RSET       9
#define NGX_POP3_TOP        10
#define NGX_POP3_UIDL       11
#define NGX_POP3_QUIT       12


#define NGX_IMAP_PARSE_INVALID_COMMAND  10


#define NGX_IMAP_PROXY_INVALID  10
#define NGX_IMAP_PROXY_ERROR    11


#define NGX_IMAP_MODULE      0x50414D49     /* "IMAP" */

#define NGX_IMAP_SRV_CONF    0x02000000
#define NGX_IMAP_IMAP_CONF   0x04000000
#define NGX_IMAP_POP3_CONF   0x08000000


void ngx_imap_init_connection(ngx_connection_t *c);
void ngx_imap_close_connection(ngx_connection_t *c);

void ngx_imap_proxy_init(ngx_imap_session_t *s);

ngx_int_t ngx_pop3_parse_command(ngx_imap_session_t *s);


#endif /* _NGX_IMAP_H_INCLUDED_ */
