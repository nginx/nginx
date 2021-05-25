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

#include <ngx_zm_lookup.h>
#include <ngx_memcache.h>

static char * ngx_zm_lookup_handlers(ngx_conf_t *cf, ngx_command_t *cmd,
        void *conf);

/* lookup from memcache */
static void ngx_zm_lookup_account_from_cache(ngx_zm_lookup_ctx_t *ctx);
static void ngx_zm_lookup_account_from_cache_success_handler(mc_work_t *work);
static void ngx_zm_lookup_account_from_cache_failure_handler(mc_work_t *work);
static void ngx_zm_lookup_route_from_cache(ngx_zm_lookup_ctx_t *ctx);
static void ngx_zm_lookup_route_from_cache_success_handler(mc_work_t *work);
static void ngx_zm_lookup_route_from_cache_failure_handler(mc_work_t *work);
static void ngx_zm_lookup_cache_alias(ngx_zm_lookup_ctx_t *ctx,
        ngx_str_t alias, ngx_str_t account_name);
static void ngx_zm_lookup_cache_route(ngx_zm_lookup_ctx_t *ctx,
        ngx_str_t user, ngx_str_t route);
static void ngx_zm_lookup_cache_dummy_handler(mc_work_t *work);
static void ngx_zm_lookup_delete_cache_handler(mc_work_t *work);

/* memcache key creation */
static ngx_str_t
ngx_zm_lookup_get_user_route_key(ngx_pool_t *pool, ngx_log_t *log,
        ngx_str_t proto, ngx_str_t account_name, ngx_str_t client_ip);
static ngx_str_t
ngx_zm_lookup_get_id_route_key(ngx_pool_t *pool, ngx_log_t *log, ngx_str_t proto,
        ngx_str_t id, ngx_http_zmauth_t type);

/* lookup from route lookup servlet */
static void ngx_zm_lookup_dummy_handler(ngx_event_t *ev);
static void ngx_zm_lookup_connect_handler(ngx_event_t *ev);
static void ngx_zm_lookup_connect(ngx_zm_lookup_ctx_t * ctx);
static ngx_int_t ngx_zm_lookup_parse_response_headers(ngx_zm_lookup_ctx_t * ctx);
static ngx_int_t ngx_zm_lookup_create_request(ngx_zm_lookup_ctx_t *ctx);
static ngx_str_t ngx_zm_lookup_get_local_socket_addr_text (ngx_pool_t *pool,
        ngx_socket_t s);
static void ngx_zm_lookup_process_response(ngx_zm_lookup_ctx_t *ctx);
static void ngx_zm_lookup_process_response_headers(ngx_zm_lookup_ctx_t *ctx);
static void ngx_zm_lookup_send_request_handler(ngx_event_t *wev);
static void ngx_zm_lookup_recv_response_handler(ngx_event_t *rev);
static ngx_int_t ngx_zm_lookup_retrieve_route(ngx_pool_t * pool,
        ngx_str_t * addr_text, ngx_str_t * port_text, ngx_addr_t * route);
static void ngx_zm_lookup_close_connection(ngx_zm_lookup_ctx_t * ctx);

/* module configuration */
static void * ngx_zm_lookup_create_conf(ngx_cycle_t *cycle);
static char * ngx_zm_lookup_init_conf(ngx_cycle_t *cycle, void *conf);
static char *ngx_zm_lookup_block(ngx_conf_t *cf, ngx_command_t *cmd, void *conf);

/* utility */
static const u_char * ngx_zm_strchr (ngx_str_t str, int chr);

static ngx_command_t ngx_zm_lookup_commands[] =
{
    { ngx_string("zm_lookup"),
      NGX_MAIN_CONF|NGX_CONF_BLOCK|NGX_CONF_NOARGS,
      ngx_zm_lookup_block,
      0,
      0,
      NULL },

    { ngx_string("zm_lookup_handlers"),
      NGX_ZM_LOOKUP_CONF|NGX_DIRECT_CONF|NGX_CONF_1MORE,
      ngx_zm_lookup_handlers,
      0,
      0,
      NULL },

    { ngx_string("zm_lookup_handler_retry_interval"),
      NGX_ZM_LOOKUP_CONF|NGX_DIRECT_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_msec_slot,
      0,
      offsetof(ngx_zm_lookup_conf_t, retry_interval),
      NULL },

    { ngx_string("zm_lookup_timeout"),
      NGX_ZM_LOOKUP_CONF|NGX_DIRECT_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_msec_slot,
      0,
      offsetof(ngx_zm_lookup_conf_t, timeout),
      NULL },

    { ngx_string("zm_lookup_buffer_size"),
      NGX_ZM_LOOKUP_CONF|NGX_DIRECT_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_size_slot,
      0,
      offsetof(ngx_zm_lookup_conf_t, buffer_size),
      NULL },

    { ngx_string("zm_lookup_master_auth_username"),
      NGX_ZM_LOOKUP_CONF|NGX_DIRECT_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_str_slot,
      0,
      offsetof(ngx_zm_lookup_conf_t, master_auth_username),
      NULL },

    { ngx_string("zm_lookup_master_auth_password"),
      NGX_ZM_LOOKUP_CONF|NGX_DIRECT_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_str_slot,
      0,
      offsetof(ngx_zm_lookup_conf_t, master_auth_password),
      NULL },

    { ngx_string("zm_lookup_caching"),
      NGX_ZM_LOOKUP_CONF|NGX_DIRECT_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_flag_slot,
      0,
      offsetof(ngx_zm_lookup_conf_t, caching),
      NULL },

    { ngx_string("zm_lookup_allow_unqualified"),
      NGX_ZM_LOOKUP_CONF|NGX_DIRECT_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_flag_slot,
      0,
      offsetof(ngx_zm_lookup_conf_t, allow_unqualified),
      NULL },

    { ngx_string("zm_prefix_url"),
      NGX_ZM_LOOKUP_CONF|NGX_DIRECT_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_str_slot,
      0,
      offsetof(ngx_zm_lookup_conf_t, url),
      NULL },

    ngx_null_command
};

static ngx_core_module_t ngx_zm_lookup_module_ctx =
{
    ngx_string("ngx_zm_lookup"),
    ngx_zm_lookup_create_conf,
    ngx_zm_lookup_init_conf
};

/*static const u_char * LOGIN_FAILED = (u_char *)"login failed";*/

static const ngx_str_t ZM_PROTO[] = {
        ngx_string("unknown"),
        ngx_string("http"),
        ngx_string("httpssl"),
        ngx_string("pop3"),
        ngx_string("pop3ssl"),
        ngx_string("imap"),
        ngx_string("imapssl")
};

static const ngx_str_t ZM_AUTHMETH[] = {
        ngx_string("username"),
        ngx_string("gssapi"),
        ngx_string("zimbraId"),
        ngx_string("certauth")
};

static const ngx_str_t ERRMSG[] = {
        ngx_string("success"),
        ngx_string("mem alloc err"),
        ngx_string("error occurs when writing lookup request to handler"),
        ngx_string("error occurs when reading lookup response from handler"),
        ngx_string("timeout occurs when writing lookup request to handler"),
        ngx_string("timeout occurs when reading lookup response from handler"),
        ngx_string("no valid lookup handlers"),
        ngx_string("invalid route is returned"),
        ngx_string("LOGIN failed"),
        ngx_string("invalid response from lookup handler"),
        ngx_string("client connection is closed"),
        ngx_string("dummy")
};

/*There is no need to send real password for now */
static const ngx_str_t
ngx_zm_lookup_password_placeholder = ngx_string("_password_");

static const ngx_str_t
ngx_zm_prefix_url = ngx_string("/");

ngx_module_t ngx_zm_lookup_module =
{
    NGX_MODULE_V1,
    &ngx_zm_lookup_module_ctx,          /* module context */
    ngx_zm_lookup_commands,             /* module directives */
    NGX_CORE_MODULE,                    /* module type */
    NULL,                               /* init master */
    NULL,                               /* init module */
    NULL,                               /* init process */
    NULL,                               /* init thread */
    NULL,                               /* exit thread */
    NULL,                               /* exit process */
    NULL,                               /* exit master */
    NGX_MODULE_V1_PADDING
};

static char *ngx_zm_lookup_block(ngx_conf_t *cf, ngx_command_t *cmd,
        void *conf)
{
    ngx_conf_t  ocf;
    char        *rc;

    ocf = *cf;

    cf->ctx = cf->cycle->conf_ctx;
    cf->module_type = NGX_CORE_MODULE;
    cf->cmd_type = NGX_ZM_LOOKUP_CONF;

    rc = ngx_conf_parse(cf, NULL);

    *cf = ocf;

    return rc;
}

static void *
ngx_zm_lookup_create_conf(ngx_cycle_t *cycle)
{
    ngx_zm_lookup_conf_t *zlcf;
    ngx_pool_t          *pool;
    ngx_log_t           *log;

    log = cycle->log;
    pool = ngx_create_pool (8 * ngx_pagesize, cycle->log);

    zlcf = ngx_pcalloc (pool, sizeof(ngx_zm_lookup_conf_t));
    if (zlcf == NULL) {
        return NGX_CONF_ERROR;
    }

    zlcf->pool = pool;
    zlcf->log = log;

#if (NGX_SSL)

    ngx_pool_cleanup_t    *cln;
    zlcf->ssl = ngx_pcalloc(pool, sizeof(ngx_ssl_t));

    if (zlcf->ssl == NULL) {
        return NGX_CONF_ERROR;
    }

    zlcf->ssl->log = log;

    // don't support SSLv2 anymore
    if (ngx_ssl_create(zlcf->ssl, ~(NGX_SSL_SSLv2|NGX_SSL_SSLv3), NULL)
            != NGX_OK) {
        return NGX_CONF_ERROR;
    }

    cln = ngx_pool_cleanup_add(zlcf->pool, 0);
    if (cln == NULL) {
        return NGX_CONF_ERROR;
    }

    cln->handler = ngx_ssl_cleanup_ctx;
    cln->data = zlcf->ssl;

#endif

    if(ngx_array_init (&zlcf->handlers, zlcf->pool, 4,
            sizeof(ngx_zm_lookup_handler_t)) != NGX_OK) {
        return NGX_CONF_ERROR;
    }

    zlcf->retry_interval = NGX_CONF_UNSET;
    zlcf->buffer_size = NGX_CONF_UNSET_SIZE;
    zlcf->timeout = NGX_CONF_UNSET;
    zlcf->caching = NGX_CONF_UNSET;
    zlcf->allow_unqualified = NGX_CONF_UNSET;
    ngx_str_null(&zlcf->master_auth_username);
    ngx_str_null(&zlcf->master_auth_password);
    ngx_str_null(&zlcf->url);
    ngx_log_error(NGX_LOG_DEBUG_ZIMBRA, cycle->log, 0,
        "zm lookup configuration created");
    return zlcf;
}

static char *
ngx_zm_lookup_init_conf(ngx_cycle_t *cycle, void *conf)
{
    ngx_zm_lookup_conf_t *zlcf = conf;

    // set default value of timeout
    if (zlcf->retry_interval == NGX_CONF_UNSET_UINT) {
        zlcf->retry_interval = 60000;
    }

    if (zlcf->caching == NGX_CONF_UNSET) {
        zlcf->caching = 1;
    }

    if (zlcf->allow_unqualified == NGX_CONF_UNSET) {
        zlcf->allow_unqualified = 0;
    }

    if (zlcf->buffer_size == NGX_CONF_UNSET_SIZE) {
        zlcf->buffer_size = 1024;
    }

    if (zlcf->timeout == NGX_CONF_UNSET_UINT) {
        zlcf->timeout = 15000;
    }

    if (zlcf->master_auth_username.data == NULL) {
        zlcf->master_auth_username = ngx_zm_lookup_password_placeholder;
    }

    if (zlcf->master_auth_password.data == NULL) {
        zlcf->master_auth_password = ngx_zm_lookup_password_placeholder;
    }

    if (zlcf->url.data == NULL) {
        zlcf->url = ngx_zm_prefix_url;
    }

    ngx_log_error(NGX_LOG_DEBUG_ZIMBRA,cycle->log, 0,
        "zm lookup - initialized config defaults");
    return NGX_CONF_OK;
}

static char *
ngx_zm_lookup_handlers(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    ngx_zm_lookup_conf_t       *zlcf = conf;
    ngx_zm_lookup_handler_t    *handler;
    ngx_url_t                   u;
    ngx_uint_t                  i;
    ngx_uint_t                  add;

    /* parse each url specified against directive "zm_lookup_handlers" */
    for(i = 1; i < cf->args->nelts; ++i)
    {
        ngx_memzero(&u, sizeof(ngx_url_t));
        u.url = ((ngx_str_t*)cf->args->elts)[i];
        u.default_port = 7072;
        u.uri_part = 1;
        add = 0;

        if (ngx_strncasecmp(u.url.data, (u_char *) "http://", 7) == 0) {
            add = 7;
        } else if (ngx_strncasecmp(u.url.data, (u_char *) "https://", 8) == 0) {
#if (NGX_SSL)
            add = 8;
#else
            ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                               "https protocol requires SSL support");
            return NGX_CONF_ERROR;
#endif
        } else {
            ngx_conf_log_error(NGX_LOG_EMERG, cf, 0, "invalid URL prefix");
            return NGX_CONF_ERROR;
        }
        u.url.len -= add;
        u.url.data += add;

        if (ngx_parse_url(cf->pool, &u) != NGX_OK) {
            if (u.err) {
                ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                    "%s in zm lookup handlers \"%V\"", u.err, &u.url);
            }
            return NGX_CONF_ERROR;
        }

        handler = ngx_array_push(&zlcf->handlers);
        if (handler == NULL) {
            return NGX_CONF_ERROR;
        }

        handler->peer = u.addrs;
        handler->host = u.host;
        handler->uri = u.uri;
        handler->failure_time = 0;
        if (add == 7) {
            handler->ssl = 0;
        } else if (add == 8) {
            handler->ssl = 1;
        }

        ngx_conf_log_error(NGX_LOG_INFO, cf, 0,
                    "add zimbra route lookup handler %V", &u.url);
    }

    if (zlcf->handlers.nelts == 0) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
            "zero valid zmauth route handlers");
        return NGX_CONF_ERROR;
    }

    return NGX_CONF_OK;
}

static ngx_int_t
ngx_zm_lookup_elect_handler(ngx_zm_lookup_ctx_t *ctx, ngx_zm_lookup_conf_t *zlcf)
{
    ngx_zm_lookup_handler_t * handler;
    time_t now = time(NULL);

    if (zlcf->handlers.nelts == 0) {
        return NGX_ERROR;
    }
    /* so the loop below can start from zlcf->handler_index rather than
       zlcf->handler_index + 1
     */
    ctx->handler_index = zlcf->handler_index - 1;
    zlcf->handler_index = (zlcf->handler_index + 1) % zlcf->handlers.nelts;
    do {
        if (ctx->tries >= zlcf->handlers.nelts) {
           ngx_log_error (NGX_LOG_ERR, ctx->log, 0,
                   "All nginx lookup handlers are unavailable");
           return NGX_ERROR;

        } else {
            ctx->handler_index = (ctx->handler_index + 1) % zlcf->handlers.nelts;
            ctx->tries ++;

            handler = ((ngx_zm_lookup_handler_t*)zlcf->handlers.elts) + ctx->handler_index;
            if (handler->failure_time != 0) {
                if((now < handler->failure_time ||
                (now - handler->failure_time) < (time_t)(zlcf->retry_interval / 1000))) {
                    continue;
                } else {
                    handler->failure_time = 0; // mark it as available and try to connect it
                }
            }
            ctx->handler = handler;
            break;
        }
    } while (1);

    return NGX_OK;
}

/* portal API */
void
ngx_zm_lookup(ngx_zm_lookup_work_t * work)
{
    ngx_zm_lookup_ctx_t          *ctx;
    ngx_zm_lookup_conf_t         *zlcf;

    zlcf = (ngx_zm_lookup_conf_t *)
            ngx_get_conf (ngx_cycle->conf_ctx, ngx_zm_lookup_module);

    ctx = ngx_pcalloc(work->pool, sizeof(ngx_zm_lookup_ctx_t));
    if (ctx == NULL) {
        work->result = ZM_LOOKUP_MEM_ALLOC_ERROR;
        work->err = ERRMSG[ZM_LOOKUP_MEM_ALLOC_ERROR];
        work->on_failure(work);
        return;
    }
    ctx->pool = work->pool;
    ctx->log = work->log;
    ctx->work = work;
    ctx->tries = 0;
    ctx->handler = NULL;
    ctx->state = 0;
    work->ctx = ctx;

    if (ctx->work->auth_method == ZM_AUTHMETH_GSSAPI ||
        ctx->work->auth_method == ZM_AUTHMETH_CERTAUTH) {
        /* These methods should never be cached */
        ngx_zm_lookup_connect(ctx);
        return;
    }

    if (zlcf->caching) {

        if (work->auth_method == ZM_AUTHMETH_ZIMBRAID) {
            ngx_zm_lookup_route_from_cache(ctx);
            return;
        }

        if (work->alias_check_stat == ZM_ALIAS_NOT_CHECKED) {
            ngx_zm_lookup_account_from_cache(ctx);
        } else {
            ngx_zm_lookup_route_from_cache(ctx);
        }

    } else {
        ngx_zm_lookup_connect(ctx);
    }
}

/*
 * Consider current user name is an alias and lookup its
 * corresponding account name, such 'john' --> 'john@test.com'
 */
static void
ngx_zm_lookup_account_from_cache (ngx_zm_lookup_ctx_t * ctx)
{
    ngx_zm_lookup_work_t                    *work;
    ngx_str_t                                key;
    ngx_log_t                               *log;
    mc_work_t                                mc;
    ngx_pool_t                              *pool;

    log = ctx->log;
    pool = ctx->pool;
    work = ctx->work;

    if (work->alias_key.len > 0) {
        key = work->alias_key;
    } else {
        if (IS_PROTO_WEB(work->protocol)) {
            key = ngx_zm_lookup_get_http_alias_key
                    (pool, log, work->username, work->virtual_host);
        } else {
            key = ngx_zm_lookup_get_mail_alias_key
                    (pool, log, work->username, work->connection->addr_text);
        }

        if (key.len == 0) {    /* NOMEM */
            work->result = ZM_LOOKUP_MEM_ALLOC_ERROR;
            work->err = ERRMSG[ZM_LOOKUP_MEM_ALLOC_ERROR];
            work->on_failure(work);
            return;
        }

        work->alias_key = key;
    }

    mc.ctx = ctx;
    mc.request_code = mcreq_get;
    mc.response_code = mcres_unknown;
    mc.on_success = ngx_zm_lookup_account_from_cache_success_handler;
    mc.on_failure = ngx_zm_lookup_account_from_cache_failure_handler;

    ctx->wait_memcache = 1;
    ngx_memcache_post(&mc, key, NGX_EMPTY_STR,/* pool */ NULL, log);
}

static void
ngx_zm_lookup_account_from_cache_success_handler (mc_work_t *mc)
{
    ngx_zm_lookup_ctx_t          *ctx;
    ngx_str_t                     account_name;

    ctx = (ngx_zm_lookup_ctx_t *)mc->ctx;
    ctx->wait_memcache = 0;

    account_name.data = ngx_pstrdup(ctx->pool, &mc->payload);
    if (account_name.data != NULL)
    {
        account_name.len = mc->payload.len;
        ctx->work->account_name = account_name;

        ngx_log_debug2 (NGX_LOG_DEBUG_ZIMBRA, ctx->log, 0,
            "zm lookup: user:%V aliased to account name:%V",
            &ctx->work->username, &account_name
            );

        ctx->work->alias_check_stat = ZM_ALIAS_FOUND;
        ngx_zm_lookup_route_from_cache(ctx);
    }
}

static void
ngx_zm_lookup_account_from_cache_failure_handler(mc_work_t *work)
{
    ngx_zm_lookup_ctx_t          *ctx;

    ctx = (ngx_zm_lookup_ctx_t *)work->ctx;
    ctx->wait_memcache = 0;
    ctx->work->alias_check_stat = ZM_ALIAS_NOT_FOUND;
    /* If account name is not found, take username as the account name */
    ctx->work->account_name = ctx->work->username;

    ngx_zm_lookup_route_from_cache(ctx);
}

/* lookup route by zimbra id/account name in memcache */
static void
ngx_zm_lookup_route_from_cache (ngx_zm_lookup_ctx_t *ctx)
{
    ngx_pool_t                     *pool;
    ngx_log_t                      *log;
    ngx_str_t                       key;
    mc_work_t                       mc;
    ngx_zm_lookup_work_t           *work;
    ngx_zm_lookup_conf_t           *zlcf;
    ngx_str_t                       username;

    zlcf = (ngx_zm_lookup_conf_t *)
            ngx_get_conf(ngx_cycle->conf_ctx, ngx_zm_lookup_module);

    pool = ctx->pool;
    log = ctx->log;
    work = ctx->work;

    if (work->auth_method == ZM_AUTHMETH_ZIMBRAID) {
        key = ngx_zm_lookup_get_id_route_key(
                pool, log, ZM_PROTO[work->protocol], work->username,
                work->type);
    } else {
        if (work->alias_check_stat == ZM_ALIAS_FOUND) {
            username = work->account_name;
        } else {
            username = work->username;
        }

        if (zlcf->allow_unqualified == 0 && !is_login_qualified(username)) {
            key = ngx_zm_lookup_get_user_route_key(pool, log, ZM_PROTO[work->protocol],
                    username, work->connection->addr_text);
        } else {
            key = ngx_zm_lookup_get_user_route_key(pool, log, ZM_PROTO[work->protocol],
                    username, NGX_EMPTY_STR);
        }
    }

    if (key.len == 0) {   /* NOMEM */
        work->result = ZM_LOOKUP_MEM_ALLOC_ERROR;
        work->err = ERRMSG[ZM_LOOKUP_MEM_ALLOC_ERROR];
        work->on_failure(work);
        return;
    }

    ctx->work->route_key = key;

    mc.ctx = ctx;
    mc.request_code = mcreq_get;
    mc.response_code = mcres_unknown;
    mc.on_success = ngx_zm_lookup_route_from_cache_success_handler;
    mc.on_failure = ngx_zm_lookup_route_from_cache_failure_handler;

    ctx->wait_memcache = 1;
    ngx_memcache_post(&mc, key, NGX_EMPTY_STR,/* pool */ NULL, log);
}

static void
ngx_zm_lookup_route_from_cache_success_handler (mc_work_t *mc)
{
    ngx_zm_lookup_ctx_t                     *ctx;
    ngx_str_t                                route_text;
    ngx_url_t                                u;

    ctx = (ngx_zm_lookup_ctx_t *)mc->ctx;
    ctx->wait_memcache = 0;

    route_text.data = ngx_pstrdup(ctx->pool, &mc->payload);

    if (route_text.data == NULL) {
        ctx->work->result = ZM_LOOKUP_MEM_ALLOC_ERROR;
        ctx->work->on_failure(ctx->work);
        return;
    } else {
        route_text.len = mc->payload.len;

        ngx_log_debug2 (NGX_LOG_DEBUG_HTTP, ctx->log,0,
            "zm lookup: fetch cached route:%V for user:%V",
            &route_text, &ctx->work->username
            );

        ngx_memzero(&u, sizeof(u));
        u.url = route_text;
        u.listen = 1;

        if (ngx_parse_url(ctx->pool, &u) != NGX_OK) {
            ctx->work->result = ZM_LOOKUP_INVALID_ROUTE;
            ctx->work->on_failure(ctx->work);
            return;
        }

        ctx->work->route = ngx_palloc(ctx->pool, sizeof(ngx_addr_t));
        if (ctx->work->route == NULL) {
            ctx->work->result = ZM_LOOKUP_MEM_ALLOC_ERROR;
            ctx->work->err = ERRMSG[ZM_LOOKUP_MEM_ALLOC_ERROR];
            ctx->work->on_failure(ctx->work);
            return;
        }
        ctx->work->route->name = route_text;
        ctx->work->route->socklen = u.socklen;
        ctx->work->route->sockaddr = ngx_palloc(ctx->pool, u.socklen);
        if(ctx->work->route->sockaddr == NULL) {
            ctx->work->result = ZM_LOOKUP_MEM_ALLOC_ERROR;
            ctx->work->err = ERRMSG[ZM_LOOKUP_MEM_ALLOC_ERROR];
            ctx->work->on_failure(ctx->work);
            return;
        }
        ngx_memcpy(ctx->work->route->sockaddr, &u.sockaddr, u.socklen);
        ctx->work->result = ZM_LOOKUP_SUCCESS;
        ctx->work->on_success(ctx->work);
        return;
    }
}

static void
ngx_zm_lookup_route_from_cache_failure_handler(mc_work_t *mc)
{
    ngx_zm_lookup_ctx_t          *ctx;
    ctx = (ngx_zm_lookup_ctx_t *) mc->ctx;
    ctx->wait_memcache = 0;

    /* if alias-->account lookup succeeds, but route lookup fails,
     * ignore the found account. Still use what user initial input
     * do the route lookup. (bug 49283)
     */
    if (ctx->work->alias_check_stat == ZM_ALIAS_FOUND) {
        ctx->work->alias_check_stat = ZM_ALIAS_IGNORED;
    }

    ngx_zm_lookup_connect (ctx);
}

#if (NGX_SSL)

static void
ngx_zm_lookup_ssl_handshake(ngx_connection_t *c)
{
    ngx_zm_lookup_ctx_t *ctx = c->data;

    if (c->ssl->handshaked) {
        c->read->handler = ngx_zm_lookup_dummy_handler;
        c->write->handler = ngx_zm_lookup_connect_handler;
        ngx_reusable_connection(c, 1);
        c->write->handler(c->write);
        ngx_log_debug1 (NGX_LOG_DEBUG_ZIMBRA, ctx->log, 0,
                 "zm lookup: ngx_zm_lookup_ssl_handshake set fd:%d", c->fd);
    } else {
        /* when handshake fails, we should close the session */
        ngx_zm_lookup_close_connection(ctx);
        ngx_log_debug1 (NGX_LOG_DEBUG_ZIMBRA, ctx->log, 0,
                         "zm lookup: ngx_zm_lookup_ssl_handshake unset fd:%d", c->fd);
    }
}

static ngx_flag_t
ngx_zm_lookup_ssl_init_connection(ngx_ssl_t* ssl, ngx_connection_t *c)
{
    ngx_int_t   rc;
    ngx_int_t   marker = 20;
    ngx_zm_lookup_ctx_t *ctx = c->data;

    if (ngx_ssl_create_connection(ssl, c,
                                  NGX_SSL_BUFFER|NGX_SSL_CLIENT)
        != NGX_OK)
    {
        ngx_zm_lookup_close_connection(ctx);
        return;
    }

    c->log->action = "SSL handshaking to lookup handler";

    do {
        rc = ngx_ssl_handshake(c);
        if(rc == NGX_AGAIN)
        {
            ngx_log_debug0 (NGX_LOG_DEBUG_ZIMBRA, c->log, 0,
                    "zm lookup: ngx_zm_lookup_ssl_init_connection ngx_ssl_handshake returned NGX_AGAIN");
            ngx_msleep(5);
        }
        else if (rc == NGX_ERROR)
        {
            ngx_log_debug0 (NGX_LOG_DEBUG_ZIMBRA, c->log, 0,
                    "zm lookup: ngx_zm_lookup_ssl_init_connection ssl event failed with NGX_ERROR");
            ngx_zm_lookup_ssl_handshake(c);
            return ZM_LOOKUP_SSL_EVENT_FAILED;
        }
    }while (rc == NGX_AGAIN && --marker > 0);

    if( 0 == marker )
    {
        ngx_log_debug0 (NGX_LOG_DEBUG_ZIMBRA, c->log, 0,
                "zm lookup: ngx_zm_lookup_ssl_init_connection marker reached");
        ngx_zm_lookup_ssl_handshake(c);
        return ZM_LOOKUP_SSL_EVENT_FAILED;
    }

    ngx_log_debug0 (NGX_LOG_DEBUG_ZIMBRA, c->log, 0,
            "zm lookup: ngx_zm_lookup_ssl_init_connection before call to ngx_zm_lookup_ssl_handshake");
    ngx_zm_lookup_ssl_handshake(c);
    return ZM_LOOKUP_SSL_EVENT_SUCCESS;
}

#endif

static void
ngx_zm_lookup_connect (ngx_zm_lookup_ctx_t * ctx)
{
    ngx_zm_lookup_conf_t         *zlcf;
    ngx_zm_lookup_handler_t      *handler;
    ngx_int_t                     rc;

    zlcf = (ngx_zm_lookup_conf_t *)ngx_get_conf(ngx_cycle->conf_ctx, ngx_zm_lookup_module);

    ngx_log_debug1 (NGX_LOG_DEBUG_ZIMBRA, ctx->log, 0,
         "zm lookup: elected route handler #%d", ctx->handler_index);
     if (ngx_zm_lookup_elect_handler(ctx, zlcf) != NGX_OK) {
         ngx_log_error(NGX_LOG_ERR, ctx->log, 0,
              "zm lookup: all lookup handlers exhausted");
         ctx->work->result = ZM_LOOKUP_NO_VALID_HANDLER;
         ctx->work->err = ERRMSG[ZM_LOOKUP_NO_VALID_HANDLER];
         ctx->work->on_failure(ctx->work);
         return;
     }

     handler = ctx->handler;
     ctx->peer.sockaddr = handler->peer->sockaddr;
     ctx->peer.socklen = handler->peer->socklen;
     ctx->peer.name = &handler->peer->name;
     ctx->peer.get = ngx_event_get_peer;
     ctx->peer.log = ctx->log;
     ctx->peer.log_error = NGX_ERROR_ERR;

     rc = ngx_event_connect_peer(&ctx->peer);

     if (rc == NGX_ERROR || rc == NGX_BUSY || rc == NGX_DECLINED) {
         ngx_log_debug2(NGX_LOG_DEBUG_ZIMBRA, ctx->log, 0,
             "zm lookup: connect to lookup handler failed, host:%V, uri:%V",
             ctx->peer.name, &handler->uri);
         ngx_zm_lookup_close_connection(ctx);

         /* try again */
         ngx_log_error(NGX_LOG_WARN, ctx->log, 0, "zm lookup: "
                       "connect lookup handle error, fail over to the next one");
         ngx_zm_lookup_connect(ctx);
         return;

     }

     ctx->peer.connection->data = ctx;
     ctx->peer.connection->pool = ctx->pool;
     ctx->peer.connection->log = ctx->log;
     ngx_add_timer(ctx->peer.connection->read, zlcf->timeout);
     ngx_add_timer(ctx->peer.connection->write, zlcf->timeout);

#if (NGX_SSL)

    if (ctx->handler->ssl && ctx->peer.connection->ssl == NULL) {
        if(ngx_zm_lookup_ssl_init_connection(zlcf->ssl, ctx->peer.connection) == ZM_LOOKUP_SSL_EVENT_FAILED)
        {
            ngx_log_error(NGX_LOG_WARN, ctx->log, 0, "zm lookup: ngx_zm_lookup_connect "
                    "connect lookup handle error for host:%V, uri:%V, fail over to the next one",ctx->peer.name, &handler->uri);
            ngx_zm_lookup_connect(ctx);
        }
        return;
    }

#endif

    ctx->peer.connection->read->handler = ngx_zm_lookup_dummy_handler;
    ctx->peer.connection->write->handler = ngx_zm_lookup_connect_handler;
}

static void
ngx_zm_lookup_dummy_handler(ngx_event_t *ev)
{
    ngx_log_debug0(NGX_LOG_DEBUG_ZIMBRA, ev->log, 0,
        "ngx_zm_lookup_dummy_handler()");
}

static void
ngx_zm_lookup_connect_handler(ngx_event_t *ev)
{
    ngx_connection_t                    *c;
    ngx_zm_lookup_ctx_t                 *ctx;
    int                                  sockerr;
    socklen_t                            sockerr_len;
    struct timeval                       tv;

    c = ev->data;
    ctx = c->data;

    /* Add health checked as auth http? */

    sockerr = 0;
    sockerr_len = sizeof(sockerr);
    getsockopt(c->fd, SOL_SOCKET, SO_ERROR, &sockerr, &sockerr_len);

    if(sockerr == EINPROGRESS) {
        /* expect to be reinvoked */
        ngx_log_debug0(NGX_LOG_DEBUG_HTTP, c->log, 0,
            "zm lookup: connect to route handler in progress");
        return;
    } else if (sockerr != 0) {
        ngx_log_debug1(NGX_LOG_DEBUG_HTTP, c->log, 0,
            "zm lookup: connect to route handler error:%d, will re-elect",
            sockerr);
        ngx_gettimeofday(&tv);
        ctx->handler->failure_time = tv.tv_sec;
        ngx_close_connection(c);
        ctx->peer.connection = NULL;

        /* try again */
        ngx_log_error(NGX_LOG_WARN, c->log, sockerr, "zm lookup: "
                      "connect lookup handle error, fail over to the next one");
        ngx_zm_lookup_connect(ctx);
        return;
    } else {

       if (ngx_zm_lookup_create_request(ctx) != NGX_OK) {
           ctx->work->result = ZM_LOOKUP_MEM_ALLOC_ERROR;
           ctx->work->err = ERRMSG[ZM_LOOKUP_MEM_ALLOC_ERROR];
           ctx->work->on_failure(ctx->work);
           return;
       }

        ngx_log_debug0(NGX_LOG_DEBUG_ZIMBRA, c->log, 0,
            "zm lookup: begin zm lookup");
        ctx->peer.connection->write->handler = ngx_zm_lookup_send_request_handler;
        ctx->peer.connection->read->handler = ngx_zm_lookup_recv_response_handler;
        ctx->lookup_response_handler = ngx_zm_lookup_process_response;
        ctx->peer.connection->write->handler(ctx->peer.connection->write);
        return;
    }
}

static void
ngx_zm_lookup_send_request_handler(ngx_event_t *wev)
{
    ngx_connection_t             *c;
    ngx_zm_lookup_ctx_t          *ctx;
    ngx_zm_lookup_work_t         *work;
    ngx_zm_lookup_conf_t         *zlcf;
    ssize_t                       size, n;

    c = wev->data;
    ctx = c->data;
    work = ctx->work;
    zlcf = (ngx_zm_lookup_conf_t *)ngx_get_conf(ngx_cycle->conf_ctx, ngx_zm_lookup_module);

    if (wev->timedout) {
    	ngx_log_error(NGX_LOG_ERR, wev->log, NGX_ETIMEDOUT,
    	    "zm lookup: route handler timed out, failing over to the next one");
    	ngx_zm_lookup_close_connection(ctx);

    	/* try again */
    	ngx_zm_lookup_connect(ctx);
        return;
    }

    size = ctx->lookup_req->last - ctx->lookup_req->pos;

    n = c->send(c, ctx->lookup_req->pos, size);

    if (n == NGX_ERROR) {
        work->result = ZM_LOOKUP_WRITE_ERROR;
        ngx_zm_lookup_close_connection(ctx);
        work->on_failure(work);
        return;
    }
    if (n > 0) {
        ctx->lookup_req->pos += n;
        if (n == size) {
            wev->handler = ngx_zm_lookup_dummy_handler;
            if (wev->timer_set) {
                ngx_del_timer(wev);
            }
            if (ngx_handle_write_event(wev, 0) == NGX_ERROR) {
                work->result = ZM_LOOKUP_WRITE_ERROR;
                ngx_zm_lookup_close_connection(ctx);
                work->on_failure(work);
                return;
            }
        }
    }
    if (!wev->timer_set) {
        ngx_add_timer(wev, zlcf->timeout);
    }
}

static ngx_int_t
ngx_zm_lookup_create_request(ngx_zm_lookup_ctx_t *ctx)
{
    ngx_buf_t                           *b;
    size_t                               len;
    ngx_pool_t                          *pool;
    ngx_zm_lookup_conf_t                *zlcf;
    ngx_zm_lookup_work_t                *work;
    ngx_str_t                            proxy_ip, username;
    zlcf = (ngx_zm_lookup_conf_t *)ngx_get_conf(ngx_cycle->conf_ctx, ngx_zm_lookup_module);
    pool = ctx->pool;
    work = ctx->work;

    if(work->alias_check_stat == ZM_ALIAS_FOUND) {
        username = work->account_name;
    } else {
        username = work->username;
    }

    proxy_ip = ngx_zm_lookup_get_local_socket_addr_text (pool, work->connection->fd);

    len = sizeof("GET ") - 1 + ctx->handler->uri.len + sizeof(" HTTP/1.0" CRLF) - 1
        + sizeof("Host: ") - 1 + ctx->handler->host.len + sizeof(CRLF) - 1
        + sizeof("Auth-Method: ") - 1 + ZM_AUTHMETH[work->auth_method].len + sizeof(CRLF) - 1
        + sizeof("Auth-User: ") - 1 + username.len + sizeof(CRLF) - 1
        + sizeof("Auth-Pass: ") - 1 + ngx_zm_lookup_password_placeholder.len + sizeof(CRLF) - 1
        + sizeof("Auth-Protocol: ") - 1 + ZM_PROTO[work->protocol].len + sizeof(CRLF) - 1
        + sizeof("Auth-Login-Attempt: ") - 1 + NGX_INT_T_LEN + sizeof(CRLF) - 1
        + sizeof ("X-Proxy-IP: ") - 1 + proxy_ip.len + sizeof(CRLF) - 1
        + sizeof ("Client-IP: ") - 1 + work->connection->addr_text.len + sizeof(CRLF) - 1;

    if (work->type == zmauth_admin_console) {
        len += sizeof ("Auth-Zimbra-Admin: True" CRLF) - 1;
    } else if (work->type == zmauth_zx) {
        len += sizeof ("Auth-Zimbra-Zx: True" CRLF) - 1;
    }

    if (IS_PROTO_WEB(work->protocol)) {
        len += sizeof("X-Proxy-Host: ") - 1 + work->virtual_host.len + sizeof(CRLF) - 1;
    }

    if (work->auth_method == ZM_AUTHMETH_CERTAUTH ||
        work->auth_method == ZM_AUTHMETH_GSSAPI) {
        len += sizeof ("Auth-Admin-User: ") - 1 + zlcf->master_auth_username.len + sizeof(CRLF) - 1;
        len += sizeof ("Auth-Admin-User: ") - 1 + zlcf->master_auth_password.len + sizeof(CRLF) - 1;

        if (work->auth_method == ZM_AUTHMETH_GSSAPI) {
            len += sizeof ("Auth-ID: ") - 1 + work->auth_id.len + sizeof(CRLF) - 1;
        }
    }

    len += sizeof(CRLF) - 1;

    b = ngx_create_temp_buf(pool, len);

    if (b == NULL) {
        return NGX_ERROR;
    }

    b->last = ngx_sprintf(b->last, "GET %V HTTP/1.0" CRLF, &ctx->handler->uri);
    b->last = ngx_sprintf(b->last, "Host: %V" CRLF, &ctx->handler->host);
    b->last = ngx_sprintf(b->last, "Auth-Method: %V" CRLF, &ZM_AUTHMETH[work->auth_method]);
    b->last = ngx_sprintf(b->last, "Auth-User: %V" CRLF, &username);
    b->last = ngx_sprintf(b->last, "Auth-Pass: %V" CRLF, &ngx_zm_lookup_password_placeholder);
    b->last = ngx_sprintf(b->last, "Auth-Protocol: %V" CRLF, &ZM_PROTO[work->protocol]);
    if (IS_PROTO_WEB(work->protocol)) {
        work->login_attempts = 0; /* for web, login attempts is always 0 */
    }
    b->last = ngx_sprintf(b->last, "Auth-Login-Attempt: %d" CRLF, work->login_attempts);
    b->last = ngx_sprintf(b->last, "X-Proxy-IP: %V" CRLF, &proxy_ip);
    b->last = ngx_sprintf(b->last, "Client-IP: %V" CRLF, &work->connection->addr_text);
    if (work->type == zmauth_admin_console) {
       b->last = ngx_cpymem(b->last, "Auth-Zimbra-Admin: True" CRLF, sizeof("Auth-Zimbra-Admin: True" CRLF) - 1);
    } else if (work->type == zmauth_zx) {
        b->last = ngx_cpymem(b->last, "Auth-Zimbra-Zx: True" CRLF, sizeof("Auth-Zimbra-Zx: True" CRLF) - 1);
    }

    if (IS_PROTO_WEB(work->protocol)) {
        b->last = ngx_sprintf(b->last, "X-Proxy-Host: %V" CRLF, &work->virtual_host);
    }

    if (work->auth_method == ZM_AUTHMETH_CERTAUTH||
        work->auth_method == ZM_AUTHMETH_GSSAPI) {
        b->last = ngx_sprintf(b->last, "Auth-Admin-User: %V" CRLF, &zlcf->master_auth_username);
        b->last = ngx_sprintf(b->last, "Auth-Admin-Pass: %V" CRLF, &zlcf->master_auth_password);

        if (work->auth_method == ZM_AUTHMETH_GSSAPI) {
            b->last = ngx_sprintf(b->last, "Auth-ID: %V" CRLF, &work->auth_id);
        }
    }

    b->last = ngx_cpymem(b->last, CRLF, sizeof(CRLF) - 1);

    ctx->lookup_req = b;

#if (NGX_DEBUG)
    ngx_str_t temp;
    temp.data = b->pos;
    temp.len = b->last - b->pos;

    ngx_log_debug1 (NGX_LOG_DEBUG_ZIMBRA, ctx->log, 0,
            "send lookup request:\n%V", &temp);
#endif

    return NGX_OK;
}

static void
ngx_zm_lookup_recv_response_handler(ngx_event_t *rev)
{
    ngx_connection_t         *c;
    ngx_zm_lookup_ctx_t      *ctx;
    ngx_zm_lookup_work_t     *work;
    ngx_zm_lookup_conf_t     *zlcf;
    ssize_t                   n, size;

    c = rev->data;
    ctx = c->data;
    work = ctx->work;
    zlcf = (ngx_zm_lookup_conf_t *)ngx_get_conf(ngx_cycle->conf_ctx, ngx_zm_lookup_module);

    if(rev->timedout) {
        ngx_log_debug2(NGX_LOG_DEBUG_ZIMBRA, rev->log, 0,
            "zm_route_lookup_module: lookup handler timed out, host:%V, uri:%V",
            &ctx->handler->peer->name, &ctx->handler->uri);

        ngx_zm_lookup_close_connection(ctx);
        work->result = ZM_LOOKUP_READ_TIMEOUT;
        work->err = ERRMSG[ZM_LOOKUP_READ_TIMEOUT];
        work->on_failure(work);
        return;
    }

    if(ctx->lookup_resp == NULL) {
        ctx->lookup_resp = ngx_create_temp_buf(ctx->pool, zlcf->buffer_size);

        if (ctx->lookup_resp == NULL) {
            ngx_zm_lookup_close_connection(ctx);
            work->ctx = NULL;
            work->result = ZM_LOOKUP_MEM_ALLOC_ERROR;
            work->err = ERRMSG[ZM_LOOKUP_MEM_ALLOC_ERROR];
            work->on_failure(work);
            return;
        }
    }

    size = ctx->lookup_resp->end - ctx->lookup_resp->last;
    n = c->recv(c, ctx->lookup_resp->pos, size);

    ngx_log_debug1(NGX_LOG_DEBUG_ZIMBRA, rev->log, 0,
            "zm lookup: ngx_recv() returned %d bytes", n);
    if(n > 0) {
        ctx->lookup_resp->last += n;
        ctx->lookup_response_handler (ctx);
        return;
    }

    if(n == NGX_AGAIN) {
        ngx_log_debug0(NGX_LOG_DEBUG_ZIMBRA, rev->log, 0,
                    "zm lookup: ngx_recv() returned NGX_AGAIN");
        return;
    }

    ngx_zm_lookup_close_connection(ctx);
    work->ctx = NULL;
    work->result = ZM_LOOKUP_READ_ERROR;
    work->err = ERRMSG[ZM_LOOKUP_READ_ERROR];
    work->on_failure(work);
}

static void
ngx_zm_lookup_process_response(ngx_zm_lookup_ctx_t *ctx)
{
    u_char                              *p, ch, *code_start;
    ngx_int_t                           code;
    ngx_flag_t                          error;
    ngx_str_t                           errmsg;

    enum  {
        sw_start = 0,
        sw_H,
        sw_HT,
        sw_HTT,
        sw_HTTP,
        sw_HTTPVER,
        sw_code,
        sw_skip,
        sw_almost_done
    } state;

    ngx_log_debug0(NGX_LOG_DEBUG_ZIMBRA, ctx->log, 0,
                   "zm lookup: process route discovery HTTP status");

    state = ctx->state;

    error = 0;

    for (p = ctx->lookup_resp->pos; p < ctx->lookup_resp->last; p++)
    {
        ch = *p;

        switch (state) {

        /* "HTTP/" */
        case sw_start:
            if (ch == 'H') {
                state = sw_H;
                break;
            }
            goto next;

        case sw_H:
            if (ch == 'T') {
                state = sw_HT;
                break;
            }
            goto next;

        case sw_HT:
            if (ch == 'T') {
                state = sw_HTT;
                break;
            }
            goto next;

        case sw_HTT:
            if (ch == 'P') {
                state = sw_HTTP;
                break;
            }
            goto next;

        case sw_HTTP:
            if (ch == '/') {
                state = sw_HTTPVER;
                break;
            }
            goto next;

        case sw_HTTPVER:
            if (ch == ' ') {
                state = sw_code;
                code_start = p + 1;
                break;
            }

            if ((ch >= '0' && ch <= '9') || ch == '.') {
                break;
            }
            goto next;

        case sw_code:
            switch (ch)  {
            case ' ':
               code = ngx_atoi(code_start, p - code_start);
               if (code != 200) {
                   error = 1;
               }
               state = sw_skip;
               break;
            case CR:
                state = sw_almost_done;
                break;
            case LF:
                goto done;
            }
            break;

        /* any text until end of line */
        case sw_skip:
            switch (ch) {
            case CR:
                state = sw_almost_done;
                break;
            case LF:
                goto done;
            }
            break;

        /* end of status line */
        case sw_almost_done:
            if (ch == LF) {
                goto done;
            }

            ngx_log_error(NGX_LOG_ERR, ctx->log, 0,
                          "zm lookup: lookup handler %V sent invalid response",
                          ctx->peer.name);
            ngx_zm_lookup_close_connection(ctx);
            ctx->work->result = ZM_LOOKUP_INVALID_RESPONSE;
            ctx->work->on_failure(ctx->work);
            return;
        }
    }

    ctx->lookup_resp->pos = p;
    ctx->state = state;

    return;

next:

    p = ctx->lookup_resp->start - 1;

done:

    if (error) {
        errmsg.data = code_start;
        errmsg.len = p - code_start + 1;
        /* trim the trailing CR LF */
        while (((*p) == CR || (*p) == LF) && p >= ctx->lookup_resp->start) {
            errmsg.len--;
            p--;
        }

        ngx_log_error(NGX_LOG_ERR, ctx->log, 0,
                      "zm lookup: lookup handler %V sent error response: %V",
                      ctx->peer.name, &errmsg);
        ngx_zm_lookup_close_connection(ctx);
        ctx->work->result = ZM_LOOKUP_INVALID_RESPONSE;
        ctx->work->on_failure(ctx->work);
        return;
    }

    ctx->lookup_resp->pos = p + 1;
    ctx->state = 0;
    ctx->lookup_response_handler = ngx_zm_lookup_process_response_headers;
    ctx->lookup_response_handler (ctx);
}

static ngx_int_t
ngx_zm_lookup_parse_response_headers(ngx_zm_lookup_ctx_t *ctx)
{
    u_char      c, ch, *p;
    enum {
        sw_start = 0,
        sw_name,
        sw_space_before_value,
        sw_value,
        sw_space_after_value,
        sw_almost_done,
        sw_header_almost_done
    } state;

    state = ctx->state;

    for (p = ctx->lookup_resp->pos; p < ctx->lookup_resp->last; p++) {
        ch = *p;

        switch (state) {

        /* first char */
        case sw_start:

            switch (ch) {
            case CR:
                ctx->header_end = p;
                state = sw_header_almost_done;
                break;
            case LF:
                ctx->header_end = p;
                goto header_done;
            default:
                state = sw_name;
                ctx->header_name_start = p;

                c = (u_char) (ch | 0x20);
                if (c >= 'a' && c <= 'z') {
                    break;
                }

                if (ch >= '0' && ch <= '9') {
                    break;
                }

                return NGX_ERROR;
            }
            break;

        /* header name */
        case sw_name:
            c = (u_char) (ch | 0x20);
            if (c >= 'a' && c <= 'z') {
                break;
            }

            if (ch == ':') {
                ctx->header_name_end = p;
                state = sw_space_before_value;
                break;
            }

            if (ch == '-') {
                break;
            }

            if (ch >= '0' && ch <= '9') {
                break;
            }

            if (ch == CR) {
                ctx->header_name_end = p;
                ctx->header_start = p;
                ctx->header_end = p;
                state = sw_almost_done;
                break;
            }

            if (ch == LF) {
                ctx->header_name_end = p;
                ctx->header_start = p;
                ctx->header_end = p;
                goto done;
            }

            return NGX_ERROR;

        /* space* before header value */
        case sw_space_before_value:
            switch (ch) {
            case ' ':
                break;
            case CR:
                ctx->header_start = p;
                ctx->header_end = p;
                state = sw_almost_done;
                break;
            case LF:
                ctx->header_start = p;
                ctx->header_end = p;
                goto done;
            default:
                ctx->header_start = p;
                state = sw_value;
                break;
            }
            break;

        /* header value */
        case sw_value:
            switch (ch) {
            case ' ':
                ctx->header_end = p;
                state = sw_space_after_value;
                break;
            case CR:
                ctx->header_end = p;
                state = sw_almost_done;
                break;
            case LF:
                ctx->header_end = p;
                goto done;
            }
            break;

        /* space* before end of header line */
        case sw_space_after_value:
            switch (ch) {
            case ' ':
                break;
            case CR:
                state = sw_almost_done;
                break;
            case LF:
                goto done;
            default:
                state = sw_value;
                break;
            }
            break;

        /* end of header line */
        case sw_almost_done:
            switch (ch) {
            case LF:
                goto done;
            default:
                return NGX_ERROR;
            }

        /* end of header */
        case sw_header_almost_done:
            switch (ch) {
            case LF:
                goto header_done;
            default:
                return NGX_ERROR;
            }
        }
    }

    ctx->lookup_resp->pos = p;
    ctx->state = state;

    return NGX_AGAIN;

done:

    ctx->lookup_resp->pos = p + 1;
    ctx->state = sw_start;

    return NGX_OK;

header_done:

    ctx->lookup_resp->pos = p + 1;
    ctx->state = sw_start;

    return NGX_DONE;
}

static void
ngx_zm_lookup_process_response_headers(ngx_zm_lookup_ctx_t *ctx)
{
    ngx_zm_lookup_conf_t         *zlcf;

    size_t                        len;
    ngx_int_t                     rc, n;
    ngx_zm_lookup_work_t         *work;
    ngx_str_t                     addr; /* route ipaddr */
    ngx_str_t                     port; /* route port   */
    ngx_flag_t                    isCacheAlias;  /* whether to cache alias for the auth account */

    zlcf = (ngx_zm_lookup_conf_t *)ngx_get_conf(ngx_cycle->conf_ctx, ngx_zm_lookup_module);

    work = ctx->work;

    ngx_log_debug0(NGX_LOG_DEBUG_ZIMBRA, ctx->log, 0,
                   "zm lookup: process route discovery HTTP headers");

    for (;;)
    {
        rc = ngx_zm_lookup_parse_response_headers(ctx);

        if (rc == NGX_OK)
        {

#if (NGX_DEBUG)
            {
            ngx_str_t  key, value;

            key.len = ctx->header_name_end - ctx->header_name_start;
            key.data = ctx->header_name_start;
            value.len = ctx->header_end - ctx->header_start;
            value.data = ctx->header_start;

            ngx_log_debug2(NGX_LOG_DEBUG_HTTP, ctx->log, 0,
                           "zm_ngx_lookup_module: zm lookup http header: \"%V: %V\"",
                           &key, &value);
            }
#endif

            len = ctx->header_name_end - ctx->header_name_start;

            if (len == sizeof("Auth-Status") - 1
                && ngx_strncasecmp(ctx->header_name_start,
                                   (u_char *) "Auth-Status",
                                   sizeof("Auth-Status") - 1)
                   == 0)
            {
                len = ctx->header_end - ctx->header_start;

                if (len == 2
                    && ctx->header_start[0] == 'O'
                    && ctx->header_start[1] == 'K')
                {
                    continue;
                }

                if (len == 4
                    && ctx->header_start[0] == 'W'
                    && ctx->header_start[1] == 'A'
                    && ctx->header_start[2] == 'I'
                    && ctx->header_start[3] == 'T')
                {
                    /* NginxLookup never return "Auth-Status: WAIT" */
                    continue;
                }

                /* Accept error msg like "Auth-Status: login failed" */
                work->err.len = len;
                work->err.data = ctx->header_start;

                continue;
            }

            if (len == sizeof("Auth-Server") - 1
                && ngx_strncasecmp(ctx->header_name_start,
                                   (u_char *) "Auth-Server",
                                   sizeof("Auth-Server") - 1)
                    == 0)
            {
                addr.len = ctx->header_end - ctx->header_start;
                addr.data = ctx->header_start;

                continue;
            }

            if (len == sizeof("Auth-Port") - 1
                && ngx_strncasecmp(ctx->header_name_start,
                                   (u_char *) "Auth-Port",
                                   sizeof("Auth-Port") - 1)
                   == 0)
            {
                port.len = ctx->header_end - ctx->header_start;
                port.data = ctx->header_start;

                continue;
            }

            if (len == sizeof("Auth-Cache-Alias") - 1
                && ngx_strncasecmp(ctx->header_name_start,
                                   (u_char *) "Auth-Cache-Alias",
                                   sizeof("Auth-Cache-Alias") - 1)
                   == 0)
            {
                len = ctx->header_end - ctx->header_start;

                if (len == 4
                    && ctx->header_start[0] == 'T'
                    && ctx->header_start[1] == 'R'
                    && ctx->header_start[2] == 'U'
                    && ctx->header_start[3] == 'E')
                {
                    /* cache the alias if True*/
                    isCacheAlias = 1;
                } else {
                    isCacheAlias = 0;
                }
                continue;
            }
            if (len == sizeof("Auth-User") - 1
                && ngx_strncasecmp(ctx->header_name_start,
                                   (u_char *) "Auth-User",
                                   sizeof("Auth-User") - 1)
                   == 0)
            {
                work->account_name.len = ctx->header_end - ctx->header_start;
                work->account_name.data = ctx->header_start;

                continue;
            }

            if (len == sizeof("Auth-Pass") - 1
                && ngx_strncasecmp(ctx->header_name_start,
                                   (u_char *) "Auth-Pass",
                                   sizeof("Auth-Pass") - 1)
                   == 0)
            {
                /* client cert auth will return zm_auth_token in
                   Auth-Pass
                 */
                if (work->auth_method == ZM_AUTHMETH_GSSAPI ||
                    work->auth_method == ZM_AUTHMETH_CERTAUTH) {
                    work->zm_auth_token.len = ctx->header_end - ctx->header_start;
                    work->zm_auth_token.data = ctx->header_start;
                }

                continue;
            }

            if (len == sizeof("Auth-ID") - 1
                    && ngx_strncasecmp(ctx->header_name_start,
                                 (u_char *) "Auth-ID",
                                 sizeof("Auth-ID") - 1)
                 == 0)
            {
                /* just for GSSAPI */
                if (work->auth_method == ZM_AUTHMETH_GSSAPI) {
                    work->auth_id.len = ctx->header_end - ctx->header_start;
                    work->auth_id.data = ctx->header_start;
                }

                continue;
            }


            if (len == sizeof("Auth-Wait") - 1
                && ngx_strncasecmp(ctx->header_name_start,
                                   (u_char *) "Auth-Wait",
                                   sizeof("Auth-Wait") - 1)
                   == 0)
            {
                n = ngx_atoi(ctx->header_start,
                             ctx->header_end - ctx->header_start);

                if (n != NGX_ERROR) {
                    work->wait_time = n;
                }

                continue;
            }


            if (len == sizeof("Auth-Error-Code") - 1
                && ngx_strncasecmp(ctx->header_name_start,
                                   (u_char *) "Auth-Error-Code",
                                   sizeof("Auth-Error-Code") - 1)
                   == 0)
            {
               /* NginxLookup never return this header */
            }

            continue;
        }

        if (rc == NGX_AGAIN ) {
            return;
        }

        /* close connection to the lookup handler */
        ngx_zm_lookup_close_connection(ctx);
        work->ctx = NULL; /* avoid duplicate clean up */

        if (rc == NGX_DONE){
            ngx_log_debug0(NGX_LOG_DEBUG_ZIMBRA, ctx->log, 0,
                           "zm lookup: done processing lookup headers");
            if (work->err.len) {
                /* Login failed */
                ngx_log_error(NGX_LOG_ERR, ctx->log, 0, "zm lookup: an error is "
                                       "returned by zimbra lookup handler: %V", &work->err);
                work->result = ZM_LOOKUP_LOGIN_FAILED;
                work->on_failure(work);
                return;

            } else {
                if (IS_LOOKUP_ROUTE(work->auth_method)) {

                    ngx_log_debug3(NGX_LOG_DEBUG_ZIMBRA, ctx->log, 0,
                             "zm lookup: lookup handler %V sent route %V:%V",
                             ctx->peer.name, &addr, &port);
                   if (addr.len == 0 || port.len == 0) {
                       work->result = ZM_LOOKUP_INVALID_ROUTE;
                       work->on_failure(work);
                       return;
                   } else {
                       /* retrieve route */
                       work->route = ngx_palloc(ctx->pool, sizeof(ngx_addr_t));
                       if (work->route == NULL) { /* NO MEM */
                           work->result = ZM_LOOKUP_MEM_ALLOC_ERROR;
                           work->err = ERRMSG[ZM_LOOKUP_MEM_ALLOC_ERROR];
                           work->on_failure(work);
                           return;
                       }
                       if (ngx_zm_lookup_retrieve_route (ctx->pool,
                              &addr, &port, work->route) == NGX_ERROR) {

                           /* route retrival error */
                           ngx_log_error(NGX_LOG_ERR, ctx->log, 0,
                                  "Error occurs when retrieve route info from lookup handler, "
                                  "addr=%V, port=%V", &addr, &port);
                           work->result = ZM_LOOKUP_INVALID_ROUTE;
                           work->err = ERRMSG[ZM_LOOKUP_INVALID_ROUTE];
                           work->on_failure(work);
                           return;
                       } else {

                           /* route retrival succeed */
                           if (zlcf->caching &&
                               ctx->work->auth_method != ZM_AUTHMETH_GSSAPI &&
                               ctx->work->auth_method != ZM_AUTHMETH_CERTAUTH) {
                               /* add alias-->account && account-->route caching */
                               if (ctx->work->alias_check_stat != ZM_ALIAS_FOUND &&
                                   ctx->work->alias_check_stat != ZM_ALIAS_IGNORED && isCacheAlias) {
                                   /* only cache alias-->account when the account is unavailable from cache */
                                   /* cache alias-->account with default domain */
                                   ngx_zm_lookup_cache_alias(ctx, work->username, work->account_name);
                               }

                               if (work->account_name.len > 0) {
                                   ngx_zm_lookup_cache_route(ctx, work->account_name, work->route->name);
                               } else {
                                   ngx_zm_lookup_cache_route(ctx, work->username, work->route->name);
                               }
                           }
                           work->result = ZM_LOOKUP_SUCCESS;
                           work->on_success(work);
                           return;
                       }
                   }
                } else {
                    /* non-route lookup, such as certauth */
                    work->result = ZM_LOOKUP_SUCCESS;
                    work->on_success(work);
                    return;
                }
            }
        }

        /* rc == NGX_ERROR */
        ngx_log_error(NGX_LOG_ERR, ctx->log, 0,
              "zm lookup: route handler %V sent invalid header in response",
              ctx->peer.name);

        return;
    }
}


static ngx_int_t
ngx_zm_lookup_retrieve_route (ngx_pool_t * pool, ngx_str_t * addr_text,
            ngx_str_t * port_text, ngx_addr_t * route)
{
    ngx_int_t                rc;
    size_t                   i;
    ngx_flag_t               ipv6, domainName;
    ngx_url_t                u;
    u_char                   c;

    ipv6 = 0, domainName = 0;
    for (i = 0; i < addr_text->len; i++) {
        c = addr_text->data[i];
        if (c == ':') {
            /* an addr containing ":" may be IPv6 */
            domainName = 0;
            ipv6 = 1;
            break;
        } else if (c >= 'A' && c != '.') {
            domainName = 1;
            // try to look for ":". if found it must be ipv6
        }
    }

    ngx_memzero(&u, sizeof(ngx_url_t));
    u.uri_part = 0;

    if(ipv6) {
        u.url.len = addr_text->len + port_text->len + 3;
        u.url.data = ngx_palloc(pool, u.url.len);
        ngx_sprintf(u.url.data, "[%V]:%V", addr_text, port_text);
    } else { /* ipv4 or domain name */
        u.url.len = addr_text->len + port_text->len + 1;
        u.url.data = ngx_palloc(pool, u.url.len);
        ngx_sprintf(u.url.data, "%V:%V", addr_text, port_text);
    }

    if(!domainName) {
        u.listen = 1; // set this will only parse the IP but not resolve addr
    }

    rc = ngx_parse_url(pool, &u);

    if(rc != NGX_OK) {
        return rc;
    }

    route->name = u.url;
    route->socklen = u.socklen;
    route->sockaddr = ngx_palloc(pool, route->socklen);
    ngx_memcpy(route->sockaddr, &u.sockaddr, route->socklen);

    return NGX_OK;
}

static void
ngx_zm_lookup_close_connection(ngx_zm_lookup_ctx_t * ctx) {
    if (ctx->peer.connection) {
        ngx_log_debug2 (NGX_LOG_DEBUG_ZIMBRA, ctx->log, 0,
               "close connection %p to nginx lookup handler %V",
               ctx->peer.connection, ctx->peer.name);
#if (NGX_SSL)

        if (ctx->handler->ssl && ctx->peer.connection->ssl) {
            ctx->peer.connection->ssl->no_wait_shutdown = 1;
            ngx_ssl_shutdown(ctx->peer.connection);
        }

#endif
        ngx_close_connection(ctx->peer.connection);
        ctx->peer.connection = NULL;
    }
}

void
ngx_zm_lookup_finalize(ngx_zm_lookup_work_t * work)
{
    ngx_zm_lookup_ctx_t  *ctx;

    if (work == NULL) {
        return;
    }

    ctx = work->ctx;

    if(ctx != NULL) {
        if(ctx->wait_memcache) {
            ngx_memcache_ignore_work_by_ctx(ctx);
            work->ctx = NULL;
            return;
        }

        ngx_zm_lookup_close_connection(ctx);
        work->ctx = NULL;
        return;
    }
}

/*
 * Giving a socket, return its local addr string representation IP. The
 * string will be allocated on "pool".
 */
ngx_str_t
ngx_zm_lookup_get_local_socket_addr_text (ngx_pool_t *pool, ngx_socket_t s)
{
    int family;
    static ngx_str_t     res;
    struct sockaddr_in  *sin;
#if (NGX_HAVE_INET6)
    struct sockaddr_in6 *sin6;
#endif
    u_char              *p;
    socklen_t            len, strlen;
    u_char               sockaddr[NGX_SOCKADDRLEN];

    len = NGX_SOCKADDRLEN;
    ngx_memzero(sockaddr, len);
    getsockname(s, (struct sockaddr*)sockaddr, &len);

    family = ((struct sockaddr *)sockaddr)->sa_family;
    if (family == AF_INET) {
        sin = (struct sockaddr_in *)sockaddr;
        p = ngx_palloc(pool, NGX_INET_ADDRSTRLEN);
        strlen = ngx_inet_ntop (family, &(sin->sin_addr.s_addr), p,
                NGX_INET_ADDRSTRLEN);

#if (NGX_HAVE_INET6)
    } else {
        sin6 = (struct sockaddr_in6 *)sockaddr;
        p = ngx_palloc(pool, NGX_INET6_ADDRSTRLEN);
        strlen = ngx_inet_ntop (family, &(sin6->sin6_addr.s6_addr),
                p, NGX_INET6_ADDRSTRLEN);
#endif

    }

    res.data = p;
    res.len = strlen;

    return res;
}

/* make the cache "alias-->account" */
static void
ngx_zm_lookup_cache_alias(ngx_zm_lookup_ctx_t *ctx, ngx_str_t alias,
        ngx_str_t account_name) {
    mc_work_t                                mc;
    ngx_str_t                                key;
    ngx_log_t                               *log;
    ngx_zm_lookup_work_t                    *work;
    ngx_pool_t                              *pool;
    const u_char                            *p;

    log = ctx->log;
    work = ctx->work;
    pool = ctx->pool;

    if (alias.len == account_name.len &&
        ngx_memcmp(alias.data, account_name.data, alias.len) == 0
       ) {
        /* bug 66469, try to take the part before '@' as alias */
        p = ngx_zm_strchr(alias, '@');
        if (p == NULL) {
            return;
        }

        alias.len = p - alias.data;

        if (work->alias_key.len > 0) {
            ngx_str_null(&work->alias_key); /* reset it and force regeneration later */
        }
    }

    if (work->alias_key.len > 0) {
            key = work->alias_key;

    } else {
        if (IS_PROTO_WEB(work->protocol)) {
            key = ngx_zm_lookup_get_http_alias_key
                    (pool, log, alias, work->virtual_host);
        } else {
            key = ngx_zm_lookup_get_mail_alias_key
                    (pool, log, alias, work->connection->addr_text);
        }

        if (key.len == 0) {    /* NOMEM */
            work->result = ZM_LOOKUP_MEM_ALLOC_ERROR;
            work->err = ERRMSG[ZM_LOOKUP_MEM_ALLOC_ERROR];
            work->on_failure(work);
            return;
        }

        work->alias_key = key;
    }

    mc.ctx = ctx;
    mc.request_code = mcreq_add;
    mc.response_code = mcres_unknown;
    mc.on_success = ngx_zm_lookup_cache_dummy_handler;
    mc.on_failure = ngx_zm_lookup_cache_dummy_handler;

    //no need to set ctx->wait_memcache_response since w.ctx won't be
    //destroyed before response comes
    ngx_memcache_post(&mc, key, account_name, NULL, log);
}

/*
 * make the cache account-->route/id-->route
 * user: account_name/zimbra id
 */
static void
ngx_zm_lookup_cache_route(ngx_zm_lookup_ctx_t *ctx, ngx_str_t user, ngx_str_t route)
{
    mc_work_t                 mc;
    ngx_log_t                *log;
    ngx_str_t                 key;
    ngx_zm_lookup_work_t    *work;
    ngx_zm_lookup_conf_t    *zlcf;

    zlcf = (ngx_zm_lookup_conf_t *)
              ngx_get_conf(ngx_cycle->conf_ctx, ngx_zm_lookup_module);

    log = ctx->log;
    work = ctx->work;

    if (work->auth_method == ZM_AUTHMETH_ZIMBRAID) {
            key = ngx_zm_lookup_get_id_route_key(
                    ctx->pool, log,
                    ZM_PROTO[work->protocol], user, work->type);
    } else {
        if (zlcf->allow_unqualified == 0 && !is_login_qualified(user)) {
            key = ngx_zm_lookup_get_user_route_key(ctx->pool, log,
                    ZM_PROTO[work->protocol], user, work->connection->addr_text);
        } else {
            key = ngx_zm_lookup_get_user_route_key(ctx->pool, log,
                    ZM_PROTO[work->protocol], user, NGX_EMPTY_STR);
        }
    }

    if (key.len == 0) {   /* NOMEM */
        work->result = ZM_LOOKUP_MEM_ALLOC_ERROR;
        work->err = ERRMSG[ZM_LOOKUP_MEM_ALLOC_ERROR];
        work->on_failure(work);
        return;
    }

    ctx->work->route_key = key;

    mc.ctx = ctx;
    mc.request_code = mcreq_add;
    mc.response_code = mcres_unknown;
    mc.on_success = ngx_zm_lookup_cache_dummy_handler;
    mc.on_failure = ngx_zm_lookup_cache_dummy_handler;

    //no need to set ctx->wait_memcache_response because nothing
    //will be disposed
    ngx_memcache_post(&mc, key, route, NULL, log);
}

static void
ngx_zm_lookup_cache_dummy_handler (mc_work_t *work)
{
    /* do nothing */
}

static ngx_str_t
ngx_zm_lookup_get_user_route_key(ngx_pool_t *pool, ngx_log_t *log,
        ngx_str_t proto, ngx_str_t account_name, ngx_str_t client_ip)
{
    ngx_str_t        key;
    size_t           len;
    u_char          *p;

    len = sizeof("route:") - 1 +
    sizeof("proto=") - 1 +
    proto.len +
    sizeof(";") - 1 +
    sizeof("user=") - 1 +
    account_name.len;

    if (client_ip.len > 0) {
        len += sizeof("@") - 1 + client_ip.len;
    }

    key.data = ngx_palloc(pool, len);
    if (key.data == NULL) {
        key.len = 0;
        return key;
    }

    p = key.data;
    p = ngx_cpymem(p, "route:", sizeof("route:") - 1);
    p = ngx_cpymem(p, "proto=", sizeof("proto=") - 1);
    p = ngx_cpymem(p, proto.data, proto.len);
   *p++ = ';';
    p = ngx_cpymem(p, "user=", sizeof("user=") - 1);
    p = ngx_cpymem(p, account_name.data, account_name.len);

    if (client_ip.len > 0) {
        *p++ = '@';
        p = ngx_cpymem(p, client_ip.data, client_ip.len);
    }

    key.len = p - key.data;

    return key;
}

ngx_str_t
ngx_zm_lookup_get_mail_alias_key (ngx_pool_t  *pool, ngx_log_t *log,
    ngx_str_t alias, ngx_str_t ip)
{
    ngx_str_t       key;
    size_t          len;
    u_char         *p;

    len = sizeof("alias:") - 1 +
        sizeof("user=") - 1 +
        alias.len +
        sizeof(";") - 1 +
        sizeof("ip=") - 1 +
        ip.len;

    key.data = ngx_palloc(pool, len);
    if (key.data == NULL) {
        key.len = 0;
        return key;
    }

    p = key.data;
    p = ngx_cpymem(p, "alias:", sizeof("alias:") - 1);
    p = ngx_cpymem(p, "user=", sizeof("user=") - 1);
    p = ngx_cpymem(p, alias.data, alias.len);
    *p++ = ';';
    p = ngx_cpymem(p,"ip=", sizeof("ip=") - 1);
    p = ngx_cpymem(p, ip.data, ip.len);

    key.len = p - key.data;

    return key;
}

ngx_str_t
ngx_zm_lookup_get_http_alias_key (ngx_pool_t *pool, ngx_log_t *log,
    ngx_str_t alias, ngx_str_t vhost)
{
    ngx_str_t       key;
    size_t          len;
    u_char         *p;

    len = sizeof("alias:") - 1 +
        sizeof("user=") - 1 +
        alias.len +
        sizeof(";") - 1 +
        sizeof("vhost=") - 1 +
        vhost.len;

    key.data = ngx_palloc(pool, len);
    if (key.data == NULL) {
        key.len = 0;
        return key;
    }

    p = key.data;
    p = ngx_cpymem(p, "alias:", sizeof("alias:") - 1);
    p = ngx_cpymem(p, "user=", sizeof("user=") - 1);
    p = ngx_cpymem(p, alias.data, alias.len);
    *p++ = ';';
    p = ngx_cpymem(p, "vhost=", sizeof("vhost=") - 1);
    p = ngx_cpymem(p, vhost.data, vhost.len);

    key.len = p - key.data;

    return key;
}

static ngx_str_t
ngx_zm_lookup_get_id_route_key(ngx_pool_t *pool, ngx_log_t *log,
        ngx_str_t proto, ngx_str_t id, ngx_http_zmauth_t type)
{
    ngx_str_t       key;
    size_t          len;
    u_char         *p;

    len = sizeof("route:") - 1 +
        sizeof("proto=") - 1 +
        proto.len +
        sizeof(";") - 1 +
        sizeof("id=") - 1 +
        id.len;

    if (type == zmauth_admin_console) {
        len += sizeof("admin=1;") - 1;
    } else if (type == zmauth_zx) {
        len += sizeof("zx=1;") - 1;
    }

    key.data = ngx_palloc(pool, len);
    if (key.data == NULL) {
        key.len = 0;
        return key;
    }

    p = key.data;
    p = ngx_cpymem(p, "route:", sizeof("route:") - 1);
    p = ngx_cpymem(p, "proto=", sizeof("proto=") - 1);
    p = ngx_cpymem(p, proto.data, proto.len);
    *p++ = ';';
    if (type == zmauth_admin_console) {
        p = ngx_cpymem(p, "admin=1;", sizeof("admin=1;") - 1);
    } else if (type == zmauth_zx) {
        p = ngx_cpymem(p, "zx=1;", sizeof("zx=1;") - 1);
    }
    p = ngx_cpymem(p, "id=", sizeof("id=") - 1);
    p = ngx_cpymem(p, id.data, id.len);

    key.len = p - key.data;

    return key;
}

/*
 * delete alias-->account & account-->route cache from memcache
 * after auth failure
 */
void
ngx_zm_lookup_delete_cache(ngx_str_t alias_key, ngx_str_t route_key)
{
    mc_work_t              w;
    ngx_log_t             *log;
    ngx_flag_t             delete_alias_cache, delete_route_cache;

    delete_alias_cache = 0;
    delete_route_cache = 0;

    if (alias_key.len > 0) {
        delete_alias_cache = 1;
    }

    if (route_key.len > 0) {
        delete_route_cache = 1;
    }

    if (delete_alias_cache == 0 && delete_route_cache == 0) {
        return;
    }

    log = ngx_cycle->log;

    w.request_code = mcreq_delete;
    w.response_code = mcres_unknown;
    w.on_success = ngx_zm_lookup_delete_cache_handler;
    w.on_failure = ngx_zm_lookup_delete_cache_handler;

    if (delete_alias_cache) {
        ngx_log_debug1 (NGX_LOG_DEBUG_ZIMBRA, log, 0,
              "delete cached alias, key:%V", &alias_key);
        ngx_memcache_post(&w, alias_key, NGX_EMPTY_STR, /* pool */ NULL, log);
    }

    if (delete_route_cache) {
        ngx_log_debug1 (NGX_LOG_DEBUG_ZIMBRA, log, 0,
            "delete cached route, key:%V", &route_key);

        ngx_memcache_post (&w, route_key, NGX_EMPTY_STR, /* pool */ NULL, log);
    }
}

static void
ngx_zm_lookup_delete_cache_handler (mc_work_t *work)
{
    /* do nothing */
}

/* Utility function to check whether a login name is fully qualified
   Return value is boolean (ngx_flag_t for portability)
 */
ngx_flag_t
is_login_qualified (ngx_str_t login)
{
    /* we cannot use the crt strchr because login is not 0 terminated,
     * neither we have no strnchr to use
     */

    size_t      i, len;
    len = login.len - 1; /* if the last symbol is @, it's not qualified */

    for (i = 0; i < len; ++i) {
        if (login.data[i] == '@') {
            return 1;
        }
    }

    return 0;
}

static const u_char *
ngx_zm_strchr (ngx_str_t str, int chr) {
    const u_char *end;
    u_char       *p;
    u_char        c;

    end = str.data + str.len;
    p = str.data;
    c = (u_char)chr;
    do {
        if (*p == c) {
            return p;
        }
    } while (++p <= end);

    return NULL;
}
