
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
    void   **main_conf;
    void   **srv_conf;
} ngx_imap_conf_ctx_t;


typedef struct {
    ngx_array_t           servers;         /* ngx_imap_core_srv_conf_t */
} ngx_imap_core_main_conf_t;


#define NGX_IMAP_POP3_PROTOCOL  0
#define NGX_IMAP_IMAP_PROTOCOL  1

typedef struct {
    ngx_msec_t            timeout;

    size_t                imap_client_buffer_size;
    size_t                proxy_buffer_size;

    ngx_uint_t            protocol;

    /* server ctx */
    ngx_imap_conf_ctx_t  *ctx;
} ngx_imap_core_srv_conf_t;


typedef struct {
    void       *(*create_main_conf)(ngx_conf_t *cf);
    char       *(*init_main_conf)(ngx_conf_t *cf, void *conf);

    void       *(*create_srv_conf)(ngx_conf_t *cf);
    char       *(*merge_srv_conf)(ngx_conf_t *cf, void *prev, void *conf);
} ngx_imap_module_t;


typedef enum {
    ngx_pop3_start = 0,
    ngx_pop3_user
} ngx_imap_state_e;


typedef struct {
    ngx_peer_connection_t   upstream;
    ngx_buf_t              *buffer;
} ngx_imap_proxy_ctx_t;


typedef struct {
    uint32_t                signature;         /* "IMAP" */

    ngx_connection_t       *connection;

    ngx_buf_t              *buffer;

    void                  **ctx;
    void                  **main_conf;
    void                  **srv_conf;

    ngx_imap_proxy_ctx_t   *proxy;

    ngx_imap_state_e        imap_state;

    unsigned                protocol:1;

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

#define NGX_IMAP_MAIN_CONF   0x02000000
#define NGX_IMAP_SRV_CONF    0x04000000


#define NGX_IMAP_MAIN_CONF_OFFSET  offsetof(ngx_imap_conf_ctx_t, main_conf)
#define NGX_IMAP_SRV_CONF_OFFSET   offsetof(ngx_imap_conf_ctx_t, srv_conf)


#define ngx_imap_get_module_ctx(s, module)     (s)->ctx[module.ctx_index]
#define ngx_imap_set_ctx(s, c, module)         s->ctx[module.ctx_index] = c;
#define ngx_imap_delete_ctx(s, module)         s->ctx[module.ctx_index] = NULL;


#define ngx_imap_get_module_main_conf(s, module)                             \
    (s)->main_conf[module.ctx_index]
#define ngx_imap_get_module_srv_conf(s, module)  (s)->srv_conf[module.ctx_index]


void ngx_imap_init_connection(ngx_connection_t *c);
void ngx_imap_close_connection(ngx_connection_t *c);

ngx_int_t ngx_pop3_parse_command(ngx_imap_session_t *s);


/* STUB */
void ngx_imap_proxy_init(ngx_imap_session_t *s, ngx_peers_t *peers);
void ngx_imap_auth_http_init(ngx_imap_session_t *s);
/**/


extern ngx_uint_t    ngx_imap_max_module;
extern ngx_module_t  ngx_imap_core_module;


#endif /* _NGX_IMAP_H_INCLUDED_ */
