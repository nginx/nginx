
/*
 * Copyright (C) Michał Dec
 * Copyright (C) Igor Sysoev
 * Copyright (C) Nginx, Inc.
 * 
 * Based on ngx_http_stub_status_module.c
 */


#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>


static ngx_int_t ngx_http_prometheus_metrics_handler(ngx_http_request_t *r);
static ngx_int_t ngx_http_prometheus_metrics_variable(ngx_http_request_t *r,
    ngx_http_variable_value_t *v, uintptr_t data);
static ngx_int_t ngx_http_prometheus_metrics_add_variables(ngx_conf_t *cf);
static char *ngx_http_set_prometheus_metrics(ngx_conf_t *cf, ngx_command_t *cmd,
    void *conf);


static ngx_command_t  ngx_http_status_commands[] = {

    { ngx_string("prometheus_metrics"),
      NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_NOARGS,
      ngx_http_set_prometheus_metrics,
      0,
      0,
      NULL },

      ngx_null_command
};


static ngx_http_module_t  ngx_http_prometheus_metrics_module_ctx = {
    ngx_http_prometheus_metrics_add_variables, /* preconfiguration */
    NULL,                                      /* postconfiguration */

    NULL,                                      /* create main configuration */
    NULL,                                      /* init main configuration */

    NULL,                                      /* create server configuration */
    NULL,                                      /* merge server configuration */

    NULL,                                      /* create location configuration */
    NULL                                       /* merge location configuration */
};


ngx_module_t  ngx_http_prometheus_metrics_module = {
    NGX_MODULE_V1,
    &ngx_http_prometheus_metrics_module_ctx, /* module context */
    ngx_http_status_commands,                /* module directives */
    NGX_HTTP_MODULE,                         /* module type */
    NULL,                                    /* init master */
    NULL,                                    /* init module */
    NULL,                                    /* init process */
    NULL,                                    /* init thread */
    NULL,                                    /* exit thread */
    NULL,                                    /* exit process */
    NULL,                                    /* exit master */
    NGX_MODULE_V1_PADDING
};


static ngx_http_variable_t  ngx_http_prometheus_metrics_vars[] = {

    { ngx_string("connections_active"), NULL, ngx_http_prometheus_metrics_variable,
      0, NGX_HTTP_VAR_NOCACHEABLE, 0 },

    { ngx_string("connections_reading"), NULL, ngx_http_prometheus_metrics_variable,
      1, NGX_HTTP_VAR_NOCACHEABLE, 0 },

    { ngx_string("connections_writing"), NULL, ngx_http_prometheus_metrics_variable,
      2, NGX_HTTP_VAR_NOCACHEABLE, 0 },

    { ngx_string("connections_waiting"), NULL, ngx_http_prometheus_metrics_variable,
      3, NGX_HTTP_VAR_NOCACHEABLE, 0 },

      ngx_http_null_variable
};

#define METRICS_COUNT 7
static ngx_int_t
ngx_http_prometheus_metrics_handler(ngx_http_request_t *r)
{
    size_t             size;
    ngx_int_t          rc;
    ngx_buf_t         *b;
    ngx_chain_t        out;
    ngx_atomic_int_t   ap, hn, ac, rq, rd, wr, wa;

    if (!(r->method & (NGX_HTTP_GET|NGX_HTTP_HEAD))) {
        return NGX_HTTP_NOT_ALLOWED;
    }

    rc = ngx_http_discard_request_body(r);

    if (rc != NGX_OK) {
        return rc;
    }

    r->headers_out.content_type_len = sizeof("text/plain") - 1;
    ngx_str_set(&r->headers_out.content_type, "text/plain");
    r->headers_out.content_type_lowcase = NULL;

    size = METRICS_COUNT * NGX_ATOMIC_T_LEN +
           sizeof("# HELP nginx_connections_active Active client connections\n\
# TYPE nginx_connections_active gauge\n\
nginx_connections_active  \n") +
           sizeof("# HELP nginx_connections_accepted Accepted client connections\n\
# TYPE nginx_connections_accepted counter\n\
nginx_connections_accepted  \n") +
           sizeof("# HELP nginx_connections_handled Handled client connections\n\
# TYPE nginx_connections_handled counter\n\
nginx_connections_handled  \n") +
           sizeof("# HELP nginx_http_requests_total Total http requests\n\
# TYPE nginx_http_requests_total counter\n\
nginx_http_requests_total  \n") +
           sizeof("# HELP nginx_connections_reading Connections where NGINX is reading the request header\n\
# TYPE nginx_connections_reading gauge\n\
nginx_connections_reading  \n") +
           sizeof("# HELP nginx_connections_writing Connections where NGINX is writing the response back to the client\n\
# TYPE nginx_connections_writing gauge\n\
nginx_connections_writing  \n") +
           sizeof("# HELP nginx_connections_waiting Idle client connections\n\
# TYPE nginx_connections_waiting gauge\n\
nginx_connections_waiting  \n") + 1;

    b = ngx_create_temp_buf(r->pool, size);
    if (b == NULL) {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    out.buf = b;
    out.next = NULL;

    ap = *ngx_stat_accepted;
    hn = *ngx_stat_handled;
    ac = *ngx_stat_active;
    rq = *ngx_stat_requests;
    rd = *ngx_stat_reading;
    wr = *ngx_stat_writing;
    wa = *ngx_stat_waiting;

    b->last = ngx_sprintf(b->last, "# HELP nginx_connections_active Active client connections\n\
# TYPE nginx_connections_active gauge\n\
nginx_connections_active %uA\n", ac);
    b->last = ngx_sprintf(b->last, "# HELP nginx_connections_accepted Accepted client connections\n\
# TYPE nginx_connections_accepted counter\n\
nginx_connections_accepted %uA\n", ap);
    b->last = ngx_sprintf(b->last, "# HELP nginx_connections_handled Handled client connections\n\
# TYPE nginx_connections_handled counter\n\
nginx_connections_handled %uA\n", hn);
    b->last = ngx_sprintf(b->last, "# HELP nginx_http_requests_total Total http requests\n\
# TYPE nginx_http_requests_total counter\n\
nginx_http_requests_total %uA\n", rq);
    b->last = ngx_sprintf(b->last, "# HELP nginx_connections_reading Connections where NGINX is reading the request header\n\
# TYPE nginx_connections_reading gauge\n\
nginx_connections_reading %uA\n", rd);
    b->last = ngx_sprintf(b->last, "# HELP nginx_connections_writing Connections where NGINX is writing the response back to the client\n\
# TYPE nginx_connections_writing gauge\n\
nginx_connections_writing %uA\n", wr);
    b->last = ngx_sprintf(b->last, "# HELP nginx_connections_waiting Idle client connections\n\
# TYPE nginx_connections_waiting gauge\n\
nginx_connections_waiting %uA\n", wa);

    r->headers_out.status = NGX_HTTP_OK;
    r->headers_out.content_length_n = b->last - b->pos;

    b->last_buf = (r == r->main) ? 1 : 0;
    b->last_in_chain = 1;

    rc = ngx_http_send_header(r);

    if (rc == NGX_ERROR || rc > NGX_OK || r->header_only) {
        return rc;
    }

    return ngx_http_output_filter(r, &out);
}


static ngx_int_t
ngx_http_prometheus_metrics_variable(ngx_http_request_t *r,
    ngx_http_variable_value_t *v, uintptr_t data)
{
    u_char            *p;
    ngx_atomic_int_t   value;

    p = ngx_pnalloc(r->pool, NGX_ATOMIC_T_LEN);
    if (p == NULL) {
        return NGX_ERROR;
    }

    switch (data) {
    case 0:
        value = *ngx_stat_active;
        break;

    case 1:
        value = *ngx_stat_reading;
        break;

    case 2:
        value = *ngx_stat_writing;
        break;

    case 3:
        value = *ngx_stat_waiting;
        break;

    /* suppress warning */
    default:
        value = 0;
        break;
    }

    v->len = ngx_sprintf(p, "%uA", value) - p;
    v->valid = 1;
    v->no_cacheable = 0;
    v->not_found = 0;
    v->data = p;

    return NGX_OK;
}


static ngx_int_t
ngx_http_prometheus_metrics_add_variables(ngx_conf_t *cf)
{
#if !(NGX_STAT_STUB)
    ngx_http_variable_t  *var, *v;

    for (v = ngx_http_stub_status_vars; v->name.len; v++) {
        var = ngx_http_add_variable(cf, &v->name, v->flags);
        if (var == NULL) {
            return NGX_ERROR;
        }

        var->get_handler = v->get_handler;
        var->data = v->data;
    }
#endif
    return NGX_OK;
}


static char *
ngx_http_set_prometheus_metrics(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    ngx_http_core_loc_conf_t  *clcf;

    clcf = ngx_http_conf_get_module_loc_conf(cf, ngx_http_core_module);
    clcf->handler = ngx_http_prometheus_metrics_handler;

    return NGX_CONF_OK;
}
