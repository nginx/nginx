
#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>


#define NGX_HTTP_USERID_OFF   0
#define NGX_HTTP_USERID_LOG   1
#define NGX_HTTP_USERID_V1    2
#define NGX_HTTP_USERID_ON    3

/* 31 Dec 2037 23:55:55 GMT */
#define NGX_HTTP_USERID_MAX_EXPIRES  2145916555


typedef struct {
    ngx_flag_t  enable;

    ngx_int_t   service;

    ngx_str_t   name;
    ngx_str_t   domain;
    ngx_str_t   path;
    time_t      expires;

    ngx_int_t   p3p;
    ngx_str_t   p3p_string;
} ngx_http_userid_conf_t;


typedef struct {
    uint32_t          uid_got[4];
    uint32_t          uid_set[4];
} ngx_http_userid_ctx_t;


static ngx_int_t ngx_http_userid_get_uid(ngx_http_request_t *r,
                                         ngx_http_userid_ctx_t *ctx,
                                         ngx_http_userid_conf_t *conf);
static ngx_int_t ngx_http_userid_set_uid(ngx_http_request_t *r,
                                         ngx_http_userid_ctx_t *ctx,
                                         ngx_http_userid_conf_t *conf);

static u_char *ngx_http_userid_log_uid_got(ngx_http_request_t *r, u_char *buf,
                                           uintptr_t data);
static u_char *ngx_http_userid_log_uid_set(ngx_http_request_t *r, u_char *buf,
                                           uintptr_t data);

static ngx_int_t ngx_http_userid_pre_conf(ngx_conf_t *cf);
static void *ngx_http_userid_create_conf(ngx_conf_t *cf);
static char *ngx_http_userid_merge_conf(ngx_conf_t *cf, void *parent,
                                        void *child);
static ngx_int_t ngx_http_userid_init(ngx_cycle_t *cycle);


static uint32_t  sequencer_v1 = 1;
static uint32_t  sequencer_v2 = 0x03030302;


static u_char expires[] = "; expires=Thu, 31-Dec-37 23:55:55 GMT";


static ngx_http_output_header_filter_pt  ngx_http_next_header_filter;


static ngx_conf_enum_t  ngx_http_userid_state[] = {
    { ngx_string("off"), NGX_HTTP_USERID_OFF },
    { ngx_string("log"), NGX_HTTP_USERID_LOG },
    { ngx_string("v1"), NGX_HTTP_USERID_V1 },
    { ngx_string("on"), NGX_HTTP_USERID_ON },
    { ngx_null_string, 0 }
};


static ngx_command_t  ngx_http_userid_commands[] = {

    { ngx_string("userid"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_enum_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_userid_conf_t, enable),
      ngx_http_userid_state},

    { ngx_string("userid_service"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_FLAG,
      ngx_conf_set_num_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_userid_conf_t, service),
      NULL},

    { ngx_string("userid_name"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_FLAG,
      ngx_conf_set_str_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_userid_conf_t, name),
      NULL},

    { ngx_string("userid_domain"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_FLAG,
      ngx_conf_set_str_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_userid_conf_t, domain),
      NULL},

    { ngx_string("userid_path"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_FLAG,
      ngx_conf_set_str_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_userid_conf_t, path),
      NULL},

    { ngx_string("userid_expires"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_sec_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_userid_conf_t, expires),
      NULL},

    ngx_null_command
};


ngx_http_module_t  ngx_http_userid_filter_module_ctx = {
    ngx_http_userid_pre_conf,              /* pre conf */

    NULL,                                  /* create main configuration */
    NULL,                                  /* init main configuration */

    NULL,                                  /* create server configuration */
    NULL,                                  /* merge server configuration */

    ngx_http_userid_create_conf,           /* create location configration */
    ngx_http_userid_merge_conf             /* merge location configration */
};


ngx_module_t  ngx_http_userid_filter_module = {
    NGX_MODULE,
    &ngx_http_userid_filter_module_ctx,    /* module context */
    ngx_http_userid_commands,              /* module directives */
    NGX_HTTP_MODULE,                       /* module type */
    ngx_http_userid_init,                  /* init module */
    NULL                                   /* init process */
};


static ngx_http_log_op_name_t ngx_http_userid_log_fmt_ops[] = {
    { ngx_string("uid_got"), 0, ngx_http_userid_log_uid_got },
    { ngx_string("uid_set"), 0, ngx_http_userid_log_uid_set },
    { ngx_null_string, 0, NULL }
};


static ngx_int_t ngx_http_userid_filter(ngx_http_request_t *r)
{
    ngx_int_t                rc;
    ngx_http_userid_ctx_t   *ctx;
    ngx_http_userid_conf_t  *conf;

    conf = ngx_http_get_module_loc_conf(r, ngx_http_userid_filter_module);

    if (conf->enable == NGX_HTTP_USERID_OFF) {
        return ngx_http_next_header_filter(r);
    }

    ngx_http_create_ctx(r, ctx, ngx_http_userid_filter_module,
                        sizeof(ngx_http_userid_ctx_t),
                        NGX_HTTP_INTERNAL_SERVER_ERROR);

    rc = ngx_http_userid_get_uid(r, ctx, conf);

    if (rc != NGX_OK) {
        return rc;
    }

    if (conf->enable == NGX_HTTP_USERID_LOG /* || ctx->uid_got[3] != 0 */) {
        return NGX_OK;
    }

    rc = ngx_http_userid_set_uid(r, ctx, conf);

    if (rc != NGX_OK) {
        return rc;
    }

    return ngx_http_next_header_filter(r);
}


static ngx_int_t ngx_http_userid_get_uid(ngx_http_request_t *r,
                                         ngx_http_userid_ctx_t *ctx,
                                         ngx_http_userid_conf_t *conf)
{
    u_char           *start, *last, *end;
    ngx_uint_t       *cookies, i;
    ngx_str_t         src, dst;
    ngx_table_elt_t  *headers;

    headers = r->headers_in.headers.elts;
    cookies = r->headers_in.cookies.elts;

    for (i = 0; i < r->headers_in.cookies.nelts; i++) {
        ngx_log_debug2(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                       "cookie: %d:\"%s\"",
                       cookies[i],
                       headers[cookies[i]].value.data);

        end = headers[cookies[i]].value.data + headers[cookies[i]].value.len;

        for (start = headers[cookies[i]].value.data; start < end; /* void */) {

            if (conf->name.len >= headers[cookies[i]].value.len
                || ngx_strncmp(start, conf->name.data, conf->name.len) != 0)
            {
                start += conf->name.len;
                while (start < end && *start++ != ';') { /* void */ }

                for (/* void */; start < end && *start == ' '; start++) { /**/ }

                continue;
            }

            for (start += conf->name.len; start < end && *start == ' '; start++)
            {
                /* void */
            }

            if (*start != '=') {
                break;
            }

            for (start++; start < end && *start == ' '; start++) { /* void */ }

            for (last = start; last < end && *last != ';'; last++) { /**/ }

            if (last - start < 22) {
                ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                              "client sent too short userid cookie \"%s\"",
                              headers[cookies[i]].value.data);
                break;
            }

            /*
             * we have to limit encoded string to 22 characters
             * because there are already the millions cookies with a garbage
             * instead of the correct base64 trail "=="
             */

            src.len = 22;
            src.data = start;
            dst.data = (u_char *) ctx->uid_got;

            if (ngx_decode_base64(&src, &dst) == NGX_ERROR) {
                ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                              "client sent invalid userid cookie \"%s\"",
                              headers[cookies[i]].value.data);
                break;
            }

            ngx_log_debug4(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                           "uid: %08X%08X%08X%08X",
                           ctx->uid_got[0], ctx->uid_got[1],
                           ctx->uid_got[2], ctx->uid_got[3]);

            return NGX_OK;
        }
    }

    return NGX_OK;
}


static ngx_int_t ngx_http_userid_set_uid(ngx_http_request_t *r,
                                         ngx_http_userid_ctx_t *ctx,
                                         ngx_http_userid_conf_t *conf)

{
    u_char           *cookie, *p;
    size_t            len;
    ngx_str_t         src, dst;
    ngx_table_elt_t  *set_cookie;

    /* TODO: mutex for sequencers */

    if (conf->enable == NGX_HTTP_USERID_V1) {
        ctx->uid_set[0] = conf->service;
        ctx->uid_set[1] = ngx_time();
        ctx->uid_set[2] = ngx_pid;
        ctx->uid_set[3] = sequencer_v1;
        sequencer_v1 += 0x100;

    } else {
        ctx->uid_set[0] = htonl(conf->service);
        ctx->uid_set[1] = htonl(ngx_time());
        ctx->uid_set[2] = htonl(ngx_pid);
        ctx->uid_set[3] = htonl(sequencer_v2);
        sequencer_v2 += 0x100;
        if (sequencer_v2 < 0x03030302) {
            sequencer_v2 = 0x03030302;
        }
    }

    len = conf->name.len + 1 + ngx_base64_encoded_length(16) + 1;

    if (conf->expires) {
        len += sizeof(expires) - 1 + 2;
    }

    if (conf->domain.len > 1) {
        len += sizeof("; domain=") - 1 + conf->domain.len;
    }

    if (conf->path.len) {
        len += sizeof("; path=") - 1 + conf->path.len;
    }

    if (!(cookie = ngx_palloc(r->pool, len))) {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    p = ngx_cpymem(cookie, conf->name.data, conf->name.len);
    *p++ = '=';

    src.len = 16;
    src.data = (u_char *) ctx->uid_set;
    dst.data = p;

    ngx_encode_base64(&src, &dst);

    p += dst.len;

    if (conf->expires == NGX_HTTP_USERID_MAX_EXPIRES) {
        p = ngx_cpymem(p, expires, sizeof(expires) - 1);

    } else if (conf->expires) {
        p = ngx_cpymem(p, expires, sizeof("; expires=") - 1);
        p += ngx_http_cookie_time(p, ngx_time() + conf->expires);
    }

    if (conf->domain.len > 1) {
        p = ngx_cpymem(p, "; domain=", sizeof("; domain=") - 1);
        p = ngx_cpymem(p, conf->domain.data, conf->domain.len);
    }

    if (conf->path.len) {
        p = ngx_cpymem(p, "; path=", sizeof("; path=") - 1);
        p = ngx_cpymem(p, conf->path.data, conf->path.len);
    }

    *p = '\0';

    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "uid cookie: \"%s\"", cookie);

    set_cookie = ngx_http_add_header(&r->headers_out, ngx_http_headers_out);
    if (set_cookie == NULL) {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    set_cookie->key.len = sizeof("Set-Cookie") - 1;
    set_cookie->key.data = (u_char *) "Set-Cookie";
    set_cookie->value.len = p - cookie;
    set_cookie->value.data = cookie;

    return NGX_OK;
}


static u_char *ngx_http_userid_log_uid_got(ngx_http_request_t *r, u_char *buf,
                                           uintptr_t data)
{
    ngx_http_userid_ctx_t   *ctx;
    ngx_http_userid_conf_t  *conf;

    ctx = ngx_http_get_module_ctx(r, ngx_http_userid_filter_module);

    if (ctx == NULL || ctx->uid_got[3] == 0) {
        if (buf == NULL) {
            return (u_char *) 1;
        }

        *buf = '-';
        return buf + 1;
    }

    conf = ngx_http_get_module_loc_conf(r, ngx_http_userid_filter_module);

    if (buf == NULL) {
        return (u_char *) (conf->name.len + 1 + 32);
    }

    buf = ngx_cpymem(buf, conf->name.data, conf->name.len);

    *buf++ = '=';

    return buf + ngx_snprintf((char *) buf, 33, "%08X%08X%08X%08X",
                              ctx->uid_got[0], ctx->uid_got[1],
                              ctx->uid_got[2], ctx->uid_got[3]);
}


static u_char *ngx_http_userid_log_uid_set(ngx_http_request_t *r, u_char *buf,
                                           uintptr_t data)
{
    ngx_http_userid_ctx_t   *ctx;
    ngx_http_userid_conf_t  *conf;

    ctx = ngx_http_get_module_ctx(r, ngx_http_userid_filter_module);

    if (ctx == NULL || ctx->uid_set[3] == 0) {
        if (buf == NULL) {
            return (u_char *) 1;
        }

        *buf = '-';
        return buf + 1;
    }

    conf = ngx_http_get_module_loc_conf(r, ngx_http_userid_filter_module);

    if (buf == NULL) {
        return (u_char *) (conf->name.len + 1 + 32);
    }

    buf = ngx_cpymem(buf, conf->name.data, conf->name.len);

    *buf++ = '=';

    return buf + ngx_snprintf((char *) buf, 33, "%08X%08X%08X%08X",
                              ctx->uid_set[0], ctx->uid_set[1],
                              ctx->uid_set[2], ctx->uid_set[3]);
}


static ngx_int_t ngx_http_userid_pre_conf(ngx_conf_t *cf)
{
    ngx_http_log_op_name_t  *op;

    for (op = ngx_http_userid_log_fmt_ops; op->name.len; op++) { /* void */ }
    op->op = NULL;

    op = ngx_http_log_fmt_ops;

    for (op = ngx_http_log_fmt_ops; op->op; op++) {
        if (op->name.len == 0) {
            op = (ngx_http_log_op_name_t *) op->op;
        }
    }

    op->op = (ngx_http_log_op_pt) ngx_http_userid_log_fmt_ops;

    return NGX_OK;
}


static void *ngx_http_userid_create_conf(ngx_conf_t *cf)
{   
    ngx_http_userid_conf_t  *conf;

    if (!(conf = ngx_pcalloc(cf->pool, sizeof(ngx_http_userid_conf_t)))) {
        return NGX_CONF_ERROR;
    }

    /* set by ngx_pcalloc():

    conf->name.len = 0;
    conf->name.date = NULL;
    conf->domain.len = 0;
    conf->domain.date = NULL;
    conf->path.len = 0;
    conf->path.date = NULL;

    */

    conf->enable = NGX_CONF_UNSET;
    conf->expires = NGX_CONF_UNSET;

    return conf;
}   


static char *ngx_http_userid_merge_conf(ngx_conf_t *cf, void *parent,
                                        void *child)
{
    ngx_http_userid_conf_t *prev = parent;
    ngx_http_userid_conf_t *conf = child;

    ngx_conf_merge_value(conf->enable, prev->enable, NGX_HTTP_USERID_OFF);

    ngx_conf_merge_str_value(conf->name, prev->name, "uid");
    ngx_conf_merge_str_value(conf->domain, prev->domain, ".");
    ngx_conf_merge_str_value(conf->path, prev->path, "/");

    ngx_conf_merge_sec_value(conf->expires, prev->expires, 0);

    return NGX_CONF_OK;
}   


static ngx_int_t ngx_http_userid_init(ngx_cycle_t *cycle)
{
    ngx_http_next_header_filter = ngx_http_top_header_filter;
    ngx_http_top_header_filter = ngx_http_userid_filter;

    return NGX_OK;
}
