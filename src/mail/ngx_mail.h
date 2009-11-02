
/*
 * Copyright (C) Igor Sysoev
 */


#ifndef _NGX_MAIL_H_INCLUDED_
#define _NGX_MAIL_H_INCLUDED_


#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_event.h>
#include <ngx_event_connect.h>

#if (NGX_MAIL_SSL)
#include <ngx_mail_ssl_module.h>
#endif



typedef struct {
    void                  **main_conf;
    void                  **srv_conf;
} ngx_mail_conf_ctx_t;


typedef struct {
    u_char                  sockaddr[NGX_SOCKADDRLEN];
    socklen_t               socklen;

    /* server ctx */
    ngx_mail_conf_ctx_t    *ctx;

    unsigned                bind:1;
    unsigned                wildcard:1;
#if (NGX_MAIL_SSL)
    unsigned                ssl:1;
#endif
#if (NGX_HAVE_INET6 && defined IPV6_V6ONLY)
    unsigned                ipv6only:2;
#endif
} ngx_mail_listen_t;


typedef struct {
    ngx_mail_conf_ctx_t    *ctx;
    ngx_str_t               addr_text;
#if (NGX_MAIL_SSL)
    ngx_uint_t              ssl;    /* unsigned   ssl:1; */
#endif
} ngx_mail_addr_conf_t;

typedef struct {
    in_addr_t               addr;
    ngx_mail_addr_conf_t    conf;
} ngx_mail_in_addr_t;


#if (NGX_HAVE_INET6)

typedef struct {
    struct in6_addr         addr6;
    ngx_mail_addr_conf_t    conf;
} ngx_mail_in6_addr_t;

#endif


typedef struct {
    /* ngx_mail_in_addr_t or ngx_mail_in6_addr_t */
    void                   *addrs;
    ngx_uint_t              naddrs;
} ngx_mail_port_t;


typedef struct {
    int                     family;
    in_port_t               port;
    ngx_array_t             addrs;       /* array of ngx_mail_conf_addr_t */
} ngx_mail_conf_port_t;


typedef struct {
    struct sockaddr        *sockaddr;
    socklen_t               socklen;

    ngx_mail_conf_ctx_t    *ctx;

    unsigned                bind:1;
    unsigned                wildcard:1;
#if (NGX_MAIL_SSL)
    unsigned                ssl:1;
#endif
#if (NGX_HAVE_INET6 && defined IPV6_V6ONLY)
    unsigned                ipv6only:2;
#endif
} ngx_mail_conf_addr_t;


typedef struct {
    ngx_array_t             servers;     /* ngx_mail_core_srv_conf_t */
    ngx_array_t             listen;      /* ngx_mail_listen_t */
} ngx_mail_core_main_conf_t;


#define NGX_MAIL_POP3_PROTOCOL  0
#define NGX_MAIL_IMAP_PROTOCOL  1
#define NGX_MAIL_SMTP_PROTOCOL  2


typedef struct ngx_mail_protocol_s  ngx_mail_protocol_t;


typedef struct {
    ngx_mail_protocol_t    *protocol;

    ngx_msec_t              timeout;
    ngx_msec_t              resolver_timeout;

    ngx_flag_t              so_keepalive;

    ngx_str_t               server_name;

    u_char                 *file_name;
    ngx_int_t               line;

    ngx_resolver_t         *resolver;

    /* server ctx */
    ngx_mail_conf_ctx_t    *ctx;
} ngx_mail_core_srv_conf_t;


typedef enum {
    ngx_pop3_start = 0,
    ngx_pop3_user,
    ngx_pop3_passwd,
    ngx_pop3_auth_login_username,
    ngx_pop3_auth_login_password,
    ngx_pop3_auth_plain,
    ngx_pop3_auth_cram_md5
} ngx_pop3_state_e;


typedef enum {
    ngx_imap_start = 0,
    ngx_imap_auth_login_username,
    ngx_imap_auth_login_password,
    ngx_imap_auth_plain,
    ngx_imap_auth_cram_md5,
    ngx_imap_login,
    ngx_imap_user,
    ngx_imap_passwd
} ngx_imap_state_e;


typedef enum {
    ngx_smtp_start = 0,
    ngx_smtp_auth_login_username,
    ngx_smtp_auth_login_password,
    ngx_smtp_auth_plain,
    ngx_smtp_auth_cram_md5,
    ngx_smtp_helo,
    ngx_smtp_helo_xclient,
    ngx_smtp_helo_from,
    ngx_smtp_xclient,
    ngx_smtp_xclient_from,
    ngx_smtp_xclient_helo,
    ngx_smtp_from,
    ngx_smtp_to
} ngx_smtp_state_e;


typedef struct {
    ngx_peer_connection_t   upstream;
    ngx_buf_t              *buffer;
} ngx_mail_proxy_ctx_t;


typedef struct {
    uint32_t                signature;         /* "MAIL" */

    ngx_connection_t       *connection;

    ngx_str_t               out;
    ngx_buf_t              *buffer;

    void                  **ctx;
    void                  **main_conf;
    void                  **srv_conf;

    ngx_resolver_ctx_t     *resolver_ctx;

    ngx_mail_proxy_ctx_t   *proxy;

    ngx_uint_t              mail_state;

    unsigned                protocol:3;
    unsigned                blocked:1;
    unsigned                quit:1;
    unsigned                quoted:1;
    unsigned                backslash:1;
    unsigned                no_sync_literal:1;
    unsigned                starttls:1;
    unsigned                esmtp:1;
    unsigned                auth_method:3;
    unsigned                auth_wait:1;

    ngx_str_t               login;
    ngx_str_t               passwd;

    ngx_str_t               salt;
    ngx_str_t               tag;
    ngx_str_t               tagged_line;
    ngx_str_t               text;

    ngx_str_t              *addr_text;
    ngx_str_t               host;
    ngx_str_t               smtp_helo;
    ngx_str_t               smtp_from;
    ngx_str_t               smtp_to;

    ngx_uint_t              command;
    ngx_array_t             args;

    ngx_uint_t              login_attempt;

    /* used to parse POP3/IMAP/SMTP command */

    ngx_uint_t              state;
    u_char                 *cmd_start;
    u_char                 *arg_start;
    u_char                 *arg_end;
    ngx_uint_t              literal_len;
} ngx_mail_session_t;


typedef struct {
    ngx_str_t              *client;
    ngx_mail_session_t     *session;
} ngx_mail_log_ctx_t;


#define NGX_POP3_USER          1
#define NGX_POP3_PASS          2
#define NGX_POP3_CAPA          3
#define NGX_POP3_QUIT          4
#define NGX_POP3_NOOP          5
#define NGX_POP3_STLS          6
#define NGX_POP3_APOP          7
#define NGX_POP3_AUTH          8
#define NGX_POP3_STAT          9
#define NGX_POP3_LIST          10
#define NGX_POP3_RETR          11
#define NGX_POP3_DELE          12
#define NGX_POP3_RSET          13
#define NGX_POP3_TOP           14
#define NGX_POP3_UIDL          15


#define NGX_IMAP_LOGIN         1
#define NGX_IMAP_LOGOUT        2
#define NGX_IMAP_CAPABILITY    3
#define NGX_IMAP_NOOP          4
#define NGX_IMAP_STARTTLS      5

#define NGX_IMAP_NEXT          6

#define NGX_IMAP_AUTHENTICATE  7


#define NGX_SMTP_HELO          1
#define NGX_SMTP_EHLO          2
#define NGX_SMTP_AUTH          3
#define NGX_SMTP_QUIT          4
#define NGX_SMTP_NOOP          5
#define NGX_SMTP_MAIL          6
#define NGX_SMTP_RSET          7
#define NGX_SMTP_RCPT          8
#define NGX_SMTP_DATA          9
#define NGX_SMTP_VRFY          10
#define NGX_SMTP_EXPN          11
#define NGX_SMTP_HELP          12
#define NGX_SMTP_STARTTLS      13


#define NGX_MAIL_AUTH_PLAIN             0
#define NGX_MAIL_AUTH_LOGIN             1
#define NGX_MAIL_AUTH_LOGIN_USERNAME    2
#define NGX_MAIL_AUTH_APOP              3
#define NGX_MAIL_AUTH_CRAM_MD5          4
#define NGX_MAIL_AUTH_NONE              5


#define NGX_MAIL_AUTH_PLAIN_ENABLED     0x0002
#define NGX_MAIL_AUTH_LOGIN_ENABLED     0x0004
#define NGX_MAIL_AUTH_APOP_ENABLED      0x0008
#define NGX_MAIL_AUTH_CRAM_MD5_ENABLED  0x0010
#define NGX_MAIL_AUTH_NONE_ENABLED      0x0020


#define NGX_MAIL_PARSE_INVALID_COMMAND  20


typedef void (*ngx_mail_init_session_pt)(ngx_mail_session_t *s,
    ngx_connection_t *c);
typedef void (*ngx_mail_init_protocol_pt)(ngx_event_t *rev);
typedef void (*ngx_mail_auth_state_pt)(ngx_event_t *rev);
typedef ngx_int_t (*ngx_mail_parse_command_pt)(ngx_mail_session_t *s);


struct ngx_mail_protocol_s {
    ngx_str_t                   name;
    in_port_t                   port[4];
    ngx_uint_t                  type;

    ngx_mail_init_session_pt    init_session;
    ngx_mail_init_protocol_pt   init_protocol;
    ngx_mail_parse_command_pt   parse_command;
    ngx_mail_auth_state_pt      auth_state;

    ngx_str_t                   internal_server_error;
};


typedef struct {
    ngx_mail_protocol_t        *protocol;

    void                       *(*create_main_conf)(ngx_conf_t *cf);
    char                       *(*init_main_conf)(ngx_conf_t *cf, void *conf);

    void                       *(*create_srv_conf)(ngx_conf_t *cf);
    char                       *(*merge_srv_conf)(ngx_conf_t *cf, void *prev,
                                      void *conf);
} ngx_mail_module_t;


#define NGX_MAIL_MODULE         0x4C49414D     /* "MAIL" */

#define NGX_MAIL_MAIN_CONF      0x02000000
#define NGX_MAIL_SRV_CONF       0x04000000


#define NGX_MAIL_MAIN_CONF_OFFSET  offsetof(ngx_mail_conf_ctx_t, main_conf)
#define NGX_MAIL_SRV_CONF_OFFSET   offsetof(ngx_mail_conf_ctx_t, srv_conf)


#define ngx_mail_get_module_ctx(s, module)     (s)->ctx[module.ctx_index]
#define ngx_mail_set_ctx(s, c, module)         s->ctx[module.ctx_index] = c;
#define ngx_mail_delete_ctx(s, module)         s->ctx[module.ctx_index] = NULL;


#define ngx_mail_get_module_main_conf(s, module)                             \
    (s)->main_conf[module.ctx_index]
#define ngx_mail_get_module_srv_conf(s, module)  (s)->srv_conf[module.ctx_index]

#define ngx_mail_conf_get_module_main_conf(cf, module)                       \
    ((ngx_mail_conf_ctx_t *) cf->ctx)->main_conf[module.ctx_index]
#define ngx_mail_conf_get_module_srv_conf(cf, module)                        \
    ((ngx_mail_conf_ctx_t *) cf->ctx)->srv_conf[module.ctx_index]


#if (NGX_MAIL_SSL)
void ngx_mail_starttls_handler(ngx_event_t *rev);
ngx_int_t ngx_mail_starttls_only(ngx_mail_session_t *s, ngx_connection_t *c);
#endif


void ngx_mail_init_connection(ngx_connection_t *c);

ngx_int_t ngx_mail_salt(ngx_mail_session_t *s, ngx_connection_t *c,
    ngx_mail_core_srv_conf_t *cscf);
ngx_int_t ngx_mail_auth_plain(ngx_mail_session_t *s, ngx_connection_t *c,
    ngx_uint_t n);
ngx_int_t ngx_mail_auth_login_username(ngx_mail_session_t *s,
    ngx_connection_t *c, ngx_uint_t n);
ngx_int_t ngx_mail_auth_login_password(ngx_mail_session_t *s,
    ngx_connection_t *c);
ngx_int_t ngx_mail_auth_cram_md5_salt(ngx_mail_session_t *s,
    ngx_connection_t *c, char *prefix, size_t len);
ngx_int_t ngx_mail_auth_cram_md5(ngx_mail_session_t *s, ngx_connection_t *c);
ngx_int_t ngx_mail_auth_parse(ngx_mail_session_t *s, ngx_connection_t *c);

void ngx_mail_send(ngx_event_t *wev);
ngx_int_t ngx_mail_read_command(ngx_mail_session_t *s, ngx_connection_t *c);
void ngx_mail_auth(ngx_mail_session_t *s, ngx_connection_t *c);
void ngx_mail_close_connection(ngx_connection_t *c);
void ngx_mail_session_internal_server_error(ngx_mail_session_t *s);
u_char *ngx_mail_log_error(ngx_log_t *log, u_char *buf, size_t len);


char *ngx_mail_capabilities(ngx_conf_t *cf, ngx_command_t *cmd, void *conf);


/* STUB */
void ngx_mail_proxy_init(ngx_mail_session_t *s, ngx_addr_t *peer);
void ngx_mail_auth_http_init(ngx_mail_session_t *s);
/**/


extern ngx_uint_t    ngx_mail_max_module;
extern ngx_module_t  ngx_mail_core_module;


#endif /* _NGX_MAIL_H_INCLUDED_ */
