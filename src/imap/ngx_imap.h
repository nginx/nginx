
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
    void                  **main_conf;
    void                  **srv_conf;
} ngx_imap_conf_ctx_t;


typedef struct {
    in_addr_t               addr;
    in_port_t               port;
    int                     family;

    /* server ctx */
    ngx_imap_conf_ctx_t    *ctx;

    unsigned                bind:1;
} ngx_imap_listen_t;


typedef struct {
    in_addr_t               addr;
    ngx_imap_conf_ctx_t    *ctx;
    ngx_str_t               addr_text;
} ngx_imap_in_addr_t;


typedef struct {
    ngx_imap_in_addr_t     *addrs;       /* array of ngx_imap_in_addr_t */
    ngx_uint_t              naddrs;
} ngx_imap_in_port_t;


typedef struct {
    in_port_t               port;
    ngx_array_t             addrs;       /* array of ngx_imap_conf_in_addr_t */
} ngx_imap_conf_in_port_t;


typedef struct {
    in_addr_t               addr;
    ngx_imap_conf_ctx_t    *ctx;
    unsigned                bind:1;
} ngx_imap_conf_in_addr_t;


typedef struct {
    ngx_array_t             servers;     /* ngx_imap_core_srv_conf_t */
    ngx_array_t             listen;      /* ngx_imap_listen_t */
} ngx_imap_core_main_conf_t;


#define NGX_IMAP_POP3_PROTOCOL  0
#define NGX_IMAP_IMAP_PROTOCOL  1

typedef struct {
    ngx_msec_t              timeout;

    size_t                  imap_client_buffer_size;

    ngx_uint_t              protocol;

    ngx_flag_t              so_keepalive;

    ngx_str_t               pop3_capability;
    ngx_str_t               pop3_starttls_capability;
    ngx_str_t               pop3_auth_capability;

    ngx_str_t               imap_capability;
    ngx_str_t               imap_starttls_capability;
    ngx_str_t               imap_starttls_only_capability;

    ngx_str_t               server_name;

    ngx_uint_t              auth_methods;

    ngx_array_t             pop3_capabilities;
    ngx_array_t             imap_capabilities;

    /* server ctx */
    ngx_imap_conf_ctx_t    *ctx;
} ngx_imap_core_srv_conf_t;


typedef struct {
    void                 *(*create_main_conf)(ngx_conf_t *cf);
    char                 *(*init_main_conf)(ngx_conf_t *cf, void *conf);

    void                 *(*create_srv_conf)(ngx_conf_t *cf);
    char                 *(*merge_srv_conf)(ngx_conf_t *cf, void *prev,
                                void *conf);
} ngx_imap_module_t;


typedef enum {
    ngx_imap_start = 0,
    ngx_imap_login,
    ngx_imap_user,
    ngx_imap_passwd
} ngx_imap_state_e;


typedef enum {
    ngx_pop3_start = 0,
    ngx_pop3_user,
    ngx_pop3_passwd,
    ngx_pop3_auth_login_username,
    ngx_pop3_auth_login_password,
    ngx_pop3_auth_plain,
    ngx_pop3_auth_cram_md5
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
    unsigned                starttls:1;
    unsigned                auth_method:2;
    unsigned                auth_wait:1;

    ngx_str_t               login;
    ngx_str_t               passwd;

    ngx_str_t               salt;
    ngx_str_t               tag;
    ngx_str_t               tagged_line;

    ngx_str_t              *addr_text;

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
    ngx_str_t              *client;
    ngx_imap_session_t     *session;
} ngx_imap_log_ctx_t;


#define NGX_POP3_USER        1
#define NGX_POP3_PASS        2
#define NGX_POP3_CAPA        3
#define NGX_POP3_QUIT        4
#define NGX_POP3_NOOP        5
#define NGX_POP3_STLS        6
#define NGX_POP3_APOP        7
#define NGX_POP3_AUTH        8
#define NGX_POP3_STAT        9
#define NGX_POP3_LIST        10
#define NGX_POP3_RETR        11
#define NGX_POP3_DELE        12
#define NGX_POP3_RSET        13
#define NGX_POP3_TOP         14
#define NGX_POP3_UIDL        15


#define NGX_IMAP_LOGIN       1
#define NGX_IMAP_LOGOUT      2
#define NGX_IMAP_CAPABILITY  3
#define NGX_IMAP_NOOP        4
#define NGX_IMAP_STARTTLS    5

#define NGX_IMAP_NEXT        6


#define NGX_IMAP_AUTH_PLAIN     0
#define NGX_IMAP_AUTH_APOP      1
#define NGX_IMAP_AUTH_CRAM_MD5  2


#define NGX_IMAP_AUTH_PLAIN_ENABLED     0x0002
#define NGX_IMAP_AUTH_APOP_ENABLED      0x0004
#define NGX_IMAP_AUTH_CRAM_MD5_ENABLED  0x0008


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

#define ngx_imap_conf_get_module_main_conf(cf, module)                       \
    ((ngx_imap_conf_ctx_t *) cf->ctx)->main_conf[module.ctx_index]


void ngx_imap_init_connection(ngx_connection_t *c);
void ngx_imap_send(ngx_event_t *wev);
void ngx_imap_auth_state(ngx_event_t *rev);
void ngx_pop3_auth_state(ngx_event_t *rev);
void ngx_imap_close_connection(ngx_connection_t *c);
void ngx_imap_session_internal_server_error(ngx_imap_session_t *s);

ngx_int_t ngx_imap_parse_command(ngx_imap_session_t *s);
ngx_int_t ngx_pop3_parse_command(ngx_imap_session_t *s);


/* STUB */
void ngx_imap_proxy_init(ngx_imap_session_t *s, ngx_peer_addr_t *peer);
void ngx_imap_auth_http_init(ngx_imap_session_t *s);
/**/


extern ngx_uint_t    ngx_imap_max_module;
extern ngx_module_t  ngx_imap_core_module;


#endif /* _NGX_IMAP_H_INCLUDED_ */
