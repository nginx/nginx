/*
 * ***** BEGIN LICENSE BLOCK *****
 * Zimbra Collaboration Suite Server
 * Copyright (C) 2011 Zimbra Software, LLC.
 *
 * The contents of this file are subject to the Zimbra Public License
 * Version 1.4 ("License"); you may not use this file except in
 * compliance with the License.  You may obtain a copy of the License at
 * http://www.zimbra.com/license.
 *
 * Software distributed under the License is distributed on an "AS IS"
 * basis, WITHOUT WARRANTY OF ANY KIND, either express or implied.
 * ***** END LICENSE BLOCK *****
 */

#ifndef _NGX_ZM_LOOKUP_H_INCLUDED_
#define _NGX_ZM_LOOKUP_H_INCLUDED_

#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_event.h>
#include <ngx_event_connect.h>

#define NGX_ZM_LOOKUP_CONF        0x02000000

typedef struct {
    ngx_addr_t  *peer;
    ngx_str_t    host;
    ngx_str_t    uri;
    time_t       failure_time;     /* the time of last connection failure
                                      to this handler peer, 0 means the
                                      peer is now available */
    ngx_uint_t   ssl;              /* whether handler talks SSL or plain http */
} ngx_zm_lookup_handler_t;

typedef struct {
    ngx_pool_t     *pool;           /* main pool where self resides */
    ngx_log_t      *log;
    ngx_array_t     handlers;       /* ngx_zm_lookup_handler_t*[] */
    ngx_uint_t      handler_index;  /* current index of round robin */
    ngx_msec_t      retry_interval; /* time to retry to connect a handler after a failure (in ms) */
    ngx_msec_t      timeout;        /* timeout to fetch the result from nginx lookup handler (in ms) */
    ngx_str_t       master_auth_username;
    ngx_str_t       master_auth_password;
    ngx_str_t       url;
    ngx_flag_t      caching;        /* whether to add and check the alias/route in memcache */
    ngx_flag_t      allow_unqualified; /* whether to append client ip to the "account-->route" caching key,
                                          when the alias part is an unqualified name*/
    size_t          buffer_size;
    ngx_ssl_t      *ssl;
} ngx_zm_lookup_conf_t;

struct ngx_zm_lookup_work_s;

typedef void (*ngx_zm_lookup_callback)(struct ngx_zm_lookup_work_s *);

/* zmauth type */
typedef enum {
    zmauth_web_client,
    zmauth_admin_console,
    zmauth_zx
} ngx_http_zmauth_t;


struct ngx_zm_lookup_work_s {
    ngx_pool_t    *pool;
    ngx_log_t     *log;

    /* input */
    ngx_str_t      username;        /* the original username given by user */
    ngx_str_t      auth_id;         /* GSSAPI auth id (principal) */

    ngx_http_zmauth_t    type;     /* whether is web, admin or /zx/ */

    ngx_uint_t     protocol:3;      /* protocol               */
    ngx_uint_t     auth_method:4;   /* auth method            */
    ngx_uint_t     alias_check_stat:2; /* the alias-->account caching lookup status */
    ngx_uint_t     login_attempts;  /* only used for mail     */
    ngx_str_t      virtual_host;    /* only used for web      */
    ngx_connection_t * connection;  /* client connection      */
    ngx_str_t      salt;            /* only used for mail     */
    ngx_str_t      route_key;       /* the key for "account-->route" cache */

    /* output */
    ngx_addr_t    *route;           /* fetched route */
    ngx_str_t      err;             /* error message */
    time_t         wait_time;       /* wait time if login failed */

    /* input & output */
    ngx_str_t      zm_auth_token;   /* for web route lookup, this will be input;
                                       for client cert auth, this will be output
                                     */
    ngx_str_t      account_name;    /* for mail route lookup, account name is
                                       always returned
                                     */
    ngx_str_t      alias_key;       /* the key for "alias-->account" cache */

    ngx_zm_lookup_callback   on_success;
    ngx_zm_lookup_callback   on_failure;

    ngx_int_t     result;

    void          *data;            /* context such as http request or mail session */
    void          *ctx;             /* zm_lookup_ctx */
};

typedef struct ngx_zm_lookup_work_s ngx_zm_lookup_work_t;

extern ngx_module_t ngx_zm_lookup_module;

struct ngx_zm_lookup_ctx_s;

typedef void (*ngx_zm_lookup_response_handler_t) (struct ngx_zm_lookup_ctx_s * ctx);

struct ngx_zm_lookup_ctx_s {
    ngx_pool_t              *pool;
    ngx_log_t               *log;

    /* for lookup handler elect */
    ngx_uint_t               tries;
    ngx_uint_t               handler_index;

    ngx_zm_lookup_handler_t *handler; /*current handler to be used */
    ngx_peer_connection_t    peer;

    /* for request send & response processing */
    ngx_buf_t               *lookup_req;     /* lookup request buffer  */
    ngx_buf_t               *lookup_resp;    /* lookup response buffer */
    ngx_uint_t               state;          /* response parse state   */
    u_char                  *header_name_start;
    u_char                  *header_name_end;
    u_char                  *header_start;
    u_char                  *header_end;
    ngx_zm_lookup_response_handler_t  lookup_response_handler;

    ngx_zm_lookup_work_t    *work;

    ngx_uint_t               wait_memcache; /* whether memcache request is
                                               posted but response doesn't come */
    ngx_event_t             *wait_ev;
};

typedef struct ngx_zm_lookup_ctx_s ngx_zm_lookup_ctx_t;

/* lookup result */
#define ZM_LOOKUP_SUCCESS                 0
#define ZM_LOOKUP_MEM_ALLOC_ERROR         1
#define ZM_LOOKUP_WRITE_ERROR             2
#define ZM_LOOKUP_READ_ERROR              3
#define ZM_LOOKUP_WRITE_TIMEOUT           4
#define ZM_LOOKUP_READ_TIMEOUT            5
#define ZM_LOOKUP_NO_VALID_HANDLER        6
#define ZM_LOOKUP_INVALID_ROUTE           7
#define ZM_LOOKUP_LOGIN_FAILED            8
#define ZM_LOOKUP_INVALID_RESPONSE        9
#define ZM_LOOKUP_CLIENT_CONNECTION_CLOSE 10
#define ZM_LOOKUP_OTHER_ERROR             50
#define ZM_LOOKUP_SSL_EVENT_SUCCESS       0
#define ZM_LOOKUP_SSL_EVENT_FAILED        1

/* the protocols nginx lookup can serve for */
#define ZM_PROTO_UNKNOWN 0
#define ZM_PROTO_HTTP    1
#define ZM_PROTO_HTTPS   2
#define ZM_PROTO_POP3    3
#define ZM_PROTO_POP3S   4
#define ZM_PROTO_IMAP    5
#define ZM_PROTO_IMAPS   6

#define IS_PROTO_MAIL(proto) (proto == ZM_PROTO_POP3  || \
                              proto == ZM_PROTO_POP3S || \
                              proto == ZM_PROTO_IMAP  || \
                              proto == ZM_RPOTO_IMAPS)

#define IS_PROTO_WEB(proto) (proto == ZM_PROTO_HTTP || \
                             proto == ZM_PROTO_HTTPS)

/* alias-->account caching check state */
#define ZM_ALIAS_NOT_CHECKED 0  /* need to be checked but not done yet     */
#define ZM_ALIAS_FOUND       1  /* has been checked and found              */
#define ZM_ALIAS_NOT_FOUND   2  /* has been checked and not found          */
#define ZM_ALIAS_IGNORED     3  /* has been checked and found, but ignored */

/* the auth method supported */
#define ZM_AUTHMETH_USERNAME 0  /* get route by user name                  */
#define ZM_AUTHMETH_GSSAPI   1  /* get route and account id by kerberos v5 */
#define ZM_AUTHMETH_ZIMBRAID 2  /* get route by zimbra account id          */
#define ZM_AUTHMETH_CERTAUTH 3  /* get account id by client certificate    */

#define IS_LOOKUP_ROUTE(auth_meth) (!(auth_meth == ZM_AUTHMETH_CERTAUTH))

void ngx_zm_lookup(ngx_zm_lookup_work_t * work);
void ngx_zm_lookup_delete_cache(ngx_str_t alias_key, ngx_str_t route_key);
void ngx_zm_lookup_finalize(ngx_zm_lookup_work_t * work);
ngx_flag_t ngx_zm_lookup_check_broken_connection(ngx_event_t *ev,
        ngx_zm_lookup_work_t *work);

/* utility */
ngx_flag_t is_login_qualified (ngx_str_t login);

/* memcache key create */
ngx_str_t ngx_zm_lookup_get_http_alias_key(ngx_pool_t *pool,
        ngx_log_t *log, ngx_str_t alias, ngx_str_t vhost);
ngx_str_t ngx_zm_lookup_get_mail_alias_key(ngx_pool_t *pool,
        ngx_log_t *log, ngx_str_t user, ngx_str_t ip);

#endif
