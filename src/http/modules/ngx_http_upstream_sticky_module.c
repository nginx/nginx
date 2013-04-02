
/*
 * Copyright (C) Nginx, Inc.
 */


#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>
#include <ngx_md5.h>


#define NGX_HTTP_STICKY_COOKIE_MAX_EXPIRES  2145916555


/* per-upstream sticky configuration */
typedef struct {
    ngx_http_upstream_init_pt                   original_init_upstream;
    ngx_http_upstream_init_peer_pt              original_init_peer;

    ngx_array_t                                *lookup_vars; /* of ngx_int_t */

    ngx_str_t                                   cookie_name;
    ngx_str_t                                   cookie_domain;
    ngx_str_t                                   cookie_path;
    time_t                                      cookie_expires;
} ngx_http_upstream_sticky_srv_conf_t;


typedef struct {
    void                                       *original_data;
    ngx_http_request_t                         *request;

    ngx_http_upstream_sticky_srv_conf_t        *conf;

    ngx_str_t                                   id;
    ngx_table_elt_t                            *cookie;

    ngx_event_get_peer_pt                       original_get_peer;
    ngx_event_free_peer_pt                      original_free_peer;

#if (NGX_HTTP_SSL)
    ngx_event_set_peer_session_pt               original_set_session;
    ngx_event_save_peer_session_pt              original_save_session;
#endif
} ngx_http_upstream_sticky_peer_data_t;


static ngx_int_t ngx_http_upstream_sticky_init_upstream(ngx_conf_t *cf,
    ngx_http_upstream_srv_conf_t *us);
static ngx_int_t ngx_http_upstream_sticky_init_peer(ngx_http_request_t *r,
    ngx_http_upstream_srv_conf_t *us);
static ngx_int_t ngx_http_upstream_sticky_get_id(
    ngx_http_upstream_sticky_srv_conf_t *stcf, ngx_http_request_t *r,
    ngx_str_t *id);
static ngx_int_t ngx_http_upstream_sticky_get_peer(ngx_peer_connection_t *pc,
    void *data);
static void ngx_http_upstream_sticky_free_peer(ngx_peer_connection_t *pc,
    void *data, ngx_uint_t state);


#if (NGX_HTTP_SSL)
static ngx_int_t ngx_http_upstream_sticky_set_session(
    ngx_peer_connection_t *pc, void *data);
static void ngx_http_upstream_sticky_save_session(ngx_peer_connection_t *pc,
    void *data);
#endif


static ngx_int_t ngx_http_upstream_sticky_cookie_insert(
    ngx_peer_connection_t *pc, ngx_http_upstream_sticky_peer_data_t *stp);


static void *ngx_http_upstream_sticky_create_conf(ngx_conf_t *cf);
static char *ngx_http_upstream_sticky(ngx_conf_t *cf, ngx_command_t *cmd,
    void *conf);


static u_char expires[] = "; expires=Thu, 31-Dec-37 23:55:55 GMT";


static ngx_command_t  ngx_http_upstream_sticky_commands[] = {

    { ngx_string("sticky"),
      NGX_HTTP_UPS_CONF|NGX_CONF_2MORE,
      ngx_http_upstream_sticky,
      0,
      0,
      NULL },

      ngx_null_command
};


static ngx_http_module_t
ngx_http_upstream_sticky_module_ctx = {
    NULL,                                 /* preconfiguration */
    NULL,                                 /* postconfiguration */

    NULL,                                 /* create main configuration */
    NULL,                                 /* init main configuration */

    ngx_http_upstream_sticky_create_conf, /* create server configuration */
    NULL,                                 /* merge server configuration */

    NULL,                                 /* create location configuration */
    NULL                                  /* merge location configuration */
};


ngx_module_t
ngx_http_upstream_sticky_module =
{
    NGX_MODULE_V1,

    &ngx_http_upstream_sticky_module_ctx, /* module context */
    ngx_http_upstream_sticky_commands,    /* module directives */

    NGX_HTTP_MODULE,                      /* module type */
    NULL,                                 /* init master */

    NULL,                                 /* init module */
    NULL,                                 /* init process */

    NULL,                                 /* init thread */
    NULL,                                 /* exit thread */

    NULL,                                 /* exit process */
    NULL,                                 /* exit master */

    NGX_MODULE_V1_PADDING
};


static ngx_int_t
ngx_http_upstream_sticky_init_upstream(ngx_conf_t *cf,
    ngx_http_upstream_srv_conf_t *us)
{
    ngx_http_upstream_sticky_srv_conf_t  *stcf;

    stcf = ngx_http_conf_upstream_srv_conf(us, ngx_http_upstream_sticky_module);

    if (stcf->original_init_upstream(cf, us) != NGX_OK) {
        return NGX_ERROR;
    }

    stcf->original_init_peer = us->peer.init;
    us->peer.init = ngx_http_upstream_sticky_init_peer;

    return NGX_OK;
}


static ngx_int_t
ngx_http_upstream_sticky_init_peer(ngx_http_request_t *r,
    ngx_http_upstream_srv_conf_t *us)
{
    ngx_int_t                              rc;
    ngx_http_upstream_t                   *u;
    ngx_http_upstream_sticky_srv_conf_t   *stcf;
    ngx_http_upstream_sticky_peer_data_t  *stp;

    stcf = ngx_http_conf_upstream_srv_conf(us, ngx_http_upstream_sticky_module);

    stp = ngx_pcalloc(r->pool, sizeof(ngx_http_upstream_sticky_peer_data_t));
    if (stp == NULL) {
        return NGX_ERROR;
    }

    rc = stcf->original_init_peer(r, us);

    if (rc != NGX_OK) {
        return rc;
    }

    u = r->upstream;

    stp->original_data = u->peer.data;
    stp->original_get_peer = u->peer.get;
    stp->original_free_peer = u->peer.free;

    stp->request = r;
    stp->conf = stcf;

    u->peer.get = ngx_http_upstream_sticky_get_peer;
    u->peer.free = ngx_http_upstream_sticky_free_peer;
    u->peer.data = stp;

#if (NGX_HTTP_SSL)
    stp->original_set_session = u->peer.set_session;
    stp->original_save_session = u->peer.save_session;
    u->peer.set_session = ngx_http_upstream_sticky_set_session;
    u->peer.save_session = ngx_http_upstream_sticky_save_session;
#endif

    ngx_http_upstream_sticky_get_id(stcf, r, &stp->id);

    return NGX_OK;
}


static ngx_int_t
ngx_http_upstream_sticky_get_id(ngx_http_upstream_sticky_srv_conf_t *stcf,
    ngx_http_request_t *r, ngx_str_t *id)
{
    ngx_int_t                  *index;
    ngx_uint_t                  i;
    ngx_http_variable_value_t  *v;

    index = stcf->lookup_vars->elts;

    for (i = 0; i < stcf->lookup_vars->nelts; i++) {

        v = ngx_http_get_flushed_variable(r, index[i]);

        if (v == NULL || v->not_found || v->len == 0) {
            continue;
        }

        id->data = v->data;
        id->len = v->len;

        ngx_log_debug2(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                       "sticky: using \"%v\" found in variable #%i", v, i + 1);

        return NGX_OK;
    }

    ngx_str_null(id);

    return NGX_DONE;
}


static ngx_int_t
ngx_http_upstream_sticky_get_peer(ngx_peer_connection_t *pc, void *data)
{
    ngx_http_upstream_sticky_peer_data_t  *stp = data;

    ngx_int_t  rc;

    if (pc->hint == NULL && stp->id.len) {
        pc->hint = &stp->id;
    }

    rc = stp->original_get_peer(pc, stp->original_data);

    pc->hint = NULL;

    if (rc != NGX_OK && rc != NGX_DONE) {
        return rc;
    }

    if (stp->conf->cookie_name.len == 0) {
        return rc;
    }

    if (ngx_http_upstream_sticky_cookie_insert(pc, stp) != NGX_OK) {
        return NGX_ERROR;
    }

    return rc;
}


static void
ngx_http_upstream_sticky_free_peer(ngx_peer_connection_t *pc, void *data,
    ngx_uint_t state)
{
    ngx_http_upstream_sticky_peer_data_t  *stp = data;

    stp->original_free_peer(pc, stp->original_data, state);
}


#if (NGX_HTTP_SSL)

static ngx_int_t
ngx_http_upstream_sticky_set_session(ngx_peer_connection_t *pc, void *data)
{
    ngx_http_upstream_sticky_peer_data_t  *stp = data;

    return stp->original_set_session(pc, stp->original_data);
}


static void
ngx_http_upstream_sticky_save_session(ngx_peer_connection_t *pc, void *data)
{
    ngx_http_upstream_sticky_peer_data_t  *stp = data;

    stp->original_save_session(pc, stp->original_data);
}

#endif


static ngx_int_t
ngx_http_upstream_sticky_cookie_insert(ngx_peer_connection_t *pc,
    ngx_http_upstream_sticky_peer_data_t *stp)
{
    size_t                                len;
    u_char                               *data, *p;
    ngx_table_elt_t                      *cookie;
    ngx_http_request_t                   *r;
    ngx_http_upstream_sticky_srv_conf_t  *stcf;

    stcf = stp->conf;
    r = stp->request;

    if (pc->sid == NULL) {
        ngx_log_error(NGX_LOG_WARN, pc->log, 0,
                      "balancer does not support sticky");
        return NGX_OK;
    }

#if (NGX_DEBUG)

    if (stp->id.len) {

        /* check that the selected peer matches SID from request */

        if (pc->sid->len != stp->id.len
            || ngx_memcmp(pc->sid->data, stp->id.data, stp->id.len) != 0)
        {
            ngx_log_debug0(NGX_LOG_DEBUG_HTTP, pc->log, 0,
                           "sticky: server with requested SID is unavailable");
        }
    }

#endif

    len = stcf->cookie_name.len + 1 + pc->sid->len + stcf->cookie_domain.len
          + stcf->cookie_path.len;

    if (stcf->cookie_expires != (time_t) NGX_CONF_UNSET) {
        len += sizeof(expires) - 1;
    }

    data = ngx_pnalloc(r->pool, len);
    if (data == NULL) {
        return NGX_ERROR;
    }

    p = ngx_copy(data, stcf->cookie_name.data, stcf->cookie_name.len);
    *p++ = '=';
    p = ngx_copy(p, pc->sid->data, pc->sid->len);

    if (stcf->cookie_expires != (time_t) NGX_CONF_UNSET) {

        if (stcf->cookie_expires == NGX_HTTP_STICKY_COOKIE_MAX_EXPIRES) {
            p = ngx_cpymem(p, expires, sizeof(expires) - 1);

        } else {
            p = ngx_cpymem(p, "; expires=", 10);
            p = ngx_http_cookie_time(p, ngx_time() + stcf->cookie_expires);
        }
    }

    p = ngx_copy(p, stcf->cookie_domain.data, stcf->cookie_domain.len);
    ngx_memcpy(p, stcf->cookie_path.data, stcf->cookie_path.len);

    cookie = stp->cookie;

    if (cookie == NULL) {

        cookie = ngx_list_push(&r->headers_out.headers);
        if (cookie == NULL) {
            return NGX_ERROR;
        }

        cookie->hash = 1;
        cookie->next = NULL;
        ngx_str_set(&cookie->key, "Set-Cookie");

        stp->cookie = cookie;
    }

    cookie->value.len = len;
    cookie->value.data = data;

    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "sticky: set cookie: \"%V\"", &cookie->value);

    return NGX_OK;
}


static void *
ngx_http_upstream_sticky_create_conf(ngx_conf_t *cf)
{
    ngx_http_upstream_sticky_srv_conf_t  *stcf;

    stcf = ngx_pcalloc(cf->pool, sizeof(ngx_http_upstream_sticky_srv_conf_t));
    if (stcf == NULL) {
        return NULL;
    }

    /*
     * set by ngx_pcalloc():
     *
     *     stcf->original_init_upstream = NULL;
     *     stcf->original_init_peer = NULL;
     *
     *     stcf->lookup_vars = NULL;
     *
     *     stcf->cookie_name = { 0, NULL };
     *     stcf->cookie_domain = { 0, NULL };
     *     stcf->cookie_path = { 0, NULL };
     */

    stcf->cookie_expires = NGX_CONF_UNSET;

    return stcf;
}


static char *
ngx_http_upstream_sticky(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    u_char                               *p;
    ngx_str_t                            *value, varname;
    ngx_int_t                             index, *indexp;
    ngx_uint_t                            i;
    ngx_http_upstream_srv_conf_t         *us;
    ngx_http_upstream_sticky_srv_conf_t  *stcf;

    us = ngx_http_conf_get_module_srv_conf(cf, ngx_http_upstream_module);
    stcf = ngx_http_conf_upstream_srv_conf(us, ngx_http_upstream_sticky_module);

    if (stcf->lookup_vars != NULL) {
        return "is duplicate";
    }

    stcf->lookup_vars = ngx_array_create(cf->pool, 1, sizeof(ngx_int_t));
    if (stcf->lookup_vars == NULL) {
        return NGX_CONF_ERROR;
    }

    value = cf->args->elts;

    if (ngx_strcmp(value[1].data, "route") == 0) {

        for (i = 2; i < cf->args->nelts; i++) {

            if (value[i].data[0] != '$') {
                ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                                   "invalid variable name \"%V\"", &value[i]);
                return NGX_CONF_ERROR;
            }

            value[i].len--;
            value[i].data++;

            index = ngx_http_get_variable_index(cf, &value[i]);
            if (index == NGX_ERROR) {
                return NGX_CONF_ERROR;
            }

            indexp = ngx_array_push(stcf->lookup_vars);
            if (indexp == NULL) {
                return NGX_CONF_ERROR;
            }

            *indexp = index;
        }

        /*
         * stcf->stick = NULL;
         */

    } else if (ngx_strcmp(value[1].data, "cookie") == 0) {

        if (value[2].len == 0) {
            return "empty cookie name";
        }

        stcf->cookie_name = value[2];

        for (i = 3; i < cf->args->nelts; i++) {

            if (ngx_strncmp(value[i].data, "domain=", 7) == 0) {

                if (stcf->cookie_domain.data != NULL) {
                    return "parameter \"domain\" is duplicate";
                }

                value[i].data += 7;
                value[i].len -= 7;

                if (value[i].len == 0) {
                    return "no value for \"domain\"";
                }

                stcf->cookie_domain.len = sizeof("; domain=") - 1
                                          + value[i].len;

                stcf->cookie_domain.data = ngx_pnalloc(cf->pool,
                                                       stcf->cookie_domain.len);
                if (stcf->cookie_domain.data == NULL) {
                    return NGX_CONF_ERROR;
                }

                p = ngx_cpymem(stcf->cookie_domain.data,
                               "; domain=", sizeof("; domain=") - 1);
                ngx_memcpy(p, value[i].data, value[i].len);


            } else if (ngx_strncmp(value[i].data, "path=", 5) == 0) {

                if (stcf->cookie_path.data != NULL) {
                    return "parameter \"path\" is duplicate";
                }

                value[i].data += 5;
                value[i].len -= 5;

                if (value[i].len == 0) {
                    return "no value for \"path\"";
                }

                stcf->cookie_path.len = sizeof("; path=") - 1 + value[i].len;

                stcf->cookie_path.data = ngx_pnalloc(cf->pool,
                                                     stcf->cookie_path.len);
                if (stcf->cookie_path.data == NULL) {
                    return NGX_CONF_ERROR;
                }

                p = ngx_cpymem(stcf->cookie_path.data,
                               "; path=", sizeof("; path=") - 1);
                ngx_memcpy(p, value[i].data, value[i].len);


            } else if (ngx_strncmp(value[i].data, "expires=", 8) == 0) {

                if (stcf->cookie_expires != (time_t) NGX_CONF_UNSET) {
                    return "parameter \"expires\" is duplicate";
                }

                value[i].data += 8;
                value[i].len -= 8;

                if (ngx_strcmp(value[i].data, "max") == 0) {
                    stcf->cookie_expires = NGX_HTTP_STICKY_COOKIE_MAX_EXPIRES;

                } else {
                    stcf->cookie_expires = ngx_parse_time(&value[i], 1);
                    if (stcf->cookie_expires == (time_t) NGX_ERROR) {
                        return "invalid \"expires\" parameter value";
                    }
                }

            } else {
                return "unknown parameter";
            }
        }

        varname.len = sizeof("cookie_") - 1  + stcf->cookie_name.len;
        varname.data = ngx_pnalloc(cf->pool, varname.len);
        if (varname.data == NULL) {
             return NGX_CONF_ERROR;
        }

        ngx_sprintf(varname.data, "cookie_%V", &stcf->cookie_name);

        index = ngx_http_get_variable_index(cf, &varname);
        if (index == NGX_ERROR) {
            return NGX_CONF_ERROR;
        }

        indexp = ngx_array_push(stcf->lookup_vars);
        if (indexp == NULL) {
            return NGX_CONF_ERROR;
        }

        *indexp = index;

    } else {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0, "unknown parameter \"%V\"",
                           &value[1]);
        return NGX_CONF_ERROR;
    }

    stcf->original_init_upstream = us->peer.init_upstream
                                   ? us->peer.init_upstream
                                   : ngx_http_upstream_init_round_robin;

    us->peer.init_upstream = ngx_http_upstream_sticky_init_upstream;

    return NGX_CONF_OK;
}
