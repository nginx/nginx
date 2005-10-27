
/*
 * Copyright (C) Igor Sysoev
 */


#ifndef _NGX_IMAP_H_INCLUDED_
#define _NGX_IMAP_H_INCLUDED_


#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_event.h>
#include <ngx_event_connect.h>

#if (NGX_IMAP_SSL)
#include <ngx_imap_ssl_module.h>
#endif



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

    ngx_uint_t            protocol;

    ngx_buf_t            *pop3_capability;
    ngx_buf_t            *imap_capability;

    ngx_array_t           pop3_capabilities;
    ngx_array_t           imap_capabilities;

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
    ngx_imap_start = 0,
    ngx_imap_login,
    ngx_imap_user,
    ngx_imap_passwd,
} ngx_imap_state_e;


typedef enum {
    ngx_pop3_start = 0,
    ngx_pop3_user,
    ngx_pop3_passwd
} ngx_po3_state_e;


typedef struct {
    ngx_peer_connection_t   upstream;
    ngx_buf_t              *buffer;
} ngx_imap_proxy_ctx_t;


typedef struct {
    uint32_t                signature;         /* "IMAP" */

    ngx_connection_t       *connection;

    ngx_str_t               out;
    ngx_buf_t              *buffer;

    void                  **ctx;
    void                  **main_conf;
    void                  **srv_conf;

    ngx_imap_proxy_ctx_t   *proxy;

    ngx_uint_t              imap_state;

    unsigned                blocked:1;
    unsigned                quit:1;
    unsigned                protocol:1;
    unsigned                quoted:1;
    unsigned                backslash:1;
    unsigned                no_sync_literal:1;

    ngx_str_t               login;
    ngx_str_t               passwd;

    ngx_str_t               tag;
    ngx_str_t               tagged_line;

    ngx_uint_t              command;
    ngx_array_t             args;

    ngx_uint_t              login_attempt;

    /* used to parse IMAP/POP3 command */

    ngx_uint_t              state;
    u_char                 *cmd_start;
    u_char                 *arg_start;
    u_char                 *arg_end;
    ngx_uint_t              literal_len;
} ngx_imap_session_t;


typedef struct {
    ngx_str_t           *client;
    ngx_imap_session_t  *session;
} ngx_imap_log_ctx_t;


#define NGX_POP3_USER       1
#define NGX_POP3_PASS       2
#define NGX_POP3_CAPA       3
#define NGX_POP3_QUIT       4
#define NGX_POP3_NOOP       5
#define NGX_POP3_APOP       6
#define NGX_POP3_STAT       7
#define NGX_POP3_LIST       8
#define NGX_POP3_RETR       9
#define NGX_POP3_DELE       10
#define NGX_POP3_RSET       11
#define NGX_POP3_TOP        12
#define NGX_POP3_UIDL       13


#define NGX_IMAP_LOGIN      1
#define NGX_IMAP_LOGOUT     2
#define NGX_IMAP_CAPABILITY 3
#define NGX_IMAP_NOOP       4

#define NGX_IMAP_NEXT       5


#define NGX_IMAP_PARSE_INVALID_COMMAND  20


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
void ngx_imap_send(ngx_event_t *wev);
void ngx_imap_auth_state(ngx_event_t *rev);
void ngx_pop3_auth_state(ngx_event_t *rev);
void ngx_imap_close_connection(ngx_connection_t *c);
void ngx_imap_session_internal_server_error(ngx_imap_session_t *s);

ngx_int_t ngx_imap_parse_command(ngx_imap_session_t *s);
ngx_int_t ngx_pop3_parse_command(ngx_imap_session_t *s);


/* STUB */
void ngx_imap_proxy_init(ngx_imap_session_t *s, ngx_peers_t *peers);
void ngx_imap_auth_http_init(ngx_imap_session_t *s);
/**/


extern ngx_uint_t    ngx_imap_max_module;
extern ngx_module_t  ngx_imap_core_module;


#endif /* _NGX_IMAP_H_INCLUDED_ */
