
#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>


#define NGX_HTTP_USERID_OFF       0x0002
#define NGX_HTTP_USERID_ON        0x0004
#define NGX_HTTP_USERID_LOGONLY   0x0008
#define NGX_HTTP_USERID_TIME      0x0010


typedef struct {
    ngx_flag_t  enable;

    ngx_int_t   version;
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
    struct timeval    tv;
} ngx_http_userid_ctx_t;


static ngx_int_t ngx_http_userid_get_uid(ngx_http_request_t *r,
                                         ngx_http_userid_ctx_t *ctx,
                                         ngx_http_userid_conf_t *conf);

static u_char *ngx_http_userid_log_uid_got(ngx_http_request_t *r, u_char *buf,
                                           uintptr_t data);
static u_char *ngx_http_userid_log_uid_set(ngx_http_request_t *r, u_char *buf,
                                           uintptr_t data);
static u_char *ngx_http_userid_log_uid_time(ngx_http_request_t *r, u_char *buf,
                                            uintptr_t data);

static ngx_int_t ngx_http_userid_pre_conf(ngx_conf_t *cf);
static void *ngx_http_userid_create_conf(ngx_conf_t *cf);
static char *ngx_http_userid_merge_conf(ngx_conf_t *cf, void *parent,
                                        void *child);
static ngx_int_t ngx_http_userid_init(ngx_cycle_t *cycle);


static ngx_conf_enum_t  ngx_http_userid_mask[] = {
    { ngx_string("off"), NGX_HTTP_USERID_OFF },
    { ngx_string("on"), NGX_HTTP_USERID_ON },
    { ngx_string("logonly"), NGX_HTTP_USERID_LOGONLY },
    { ngx_string("time"), NGX_HTTP_USERID_TIME },
    { ngx_null_string, 0 }
};


static ngx_command_t  ngx_http_userid_commands[] = {

    { ngx_string("userid"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_ANY,
      ngx_conf_set_bitmask_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_userid_conf_t, enable),
      ngx_http_userid_mask},

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
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_FLAG,
      ngx_conf_set_sec_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_userid_conf_t, expires),
      NULL},

    ngx_null_command
};


ngx_http_module_t  ngx_http_userid_module_ctx = {
    ngx_http_userid_pre_conf,              /* pre conf */

    NULL,                                  /* create main configuration */
    NULL,                                  /* init main configuration */

    NULL,                                  /* create server configuration */
    NULL,                                  /* merge server configuration */

    ngx_http_userid_create_conf,           /* create location configration */
    ngx_http_userid_merge_conf             /* merge location configration */
};


ngx_module_t  ngx_http_userid_module = {
    NGX_MODULE,
    &ngx_http_userid_module_ctx,           /* module context */
    ngx_http_userid_commands,              /* module directives */
    NGX_HTTP_MODULE,                       /* module type */
    ngx_http_userid_init,                  /* init module */
    NULL                                   /* init process */
};


static ngx_http_log_op_name_t ngx_http_userid_log_fmt_ops[] = {
    { ngx_string("uid_got"), 0, ngx_http_userid_log_uid_got },
    { ngx_string("uid_set"), 0, ngx_http_userid_log_uid_set },
    { ngx_string("uid_time"), TIME_T_LEN + 4, ngx_http_userid_log_uid_time },
    { ngx_null_string, 0, NULL }
};


static ngx_int_t ngx_http_userid_handler(ngx_http_request_t *r)
{
    ngx_int_t                rc;
    struct timeval           tv;
    ngx_http_userid_ctx_t   *ctx;
    ngx_http_userid_conf_t  *conf;

    conf = ngx_http_get_module_loc_conf(r, ngx_http_userid_module);

    if (conf->enable & NGX_HTTP_USERID_OFF) {
        return NGX_OK;
    }

    ctx = ngx_http_get_module_ctx(r, ngx_http_userid_module);

    if (ctx) {
        return NGX_OK;
    }

    ngx_http_create_ctx(r, ctx, ngx_http_userid_module,
                        sizeof(ngx_http_userid_ctx_t),
                        NGX_HTTP_INTERNAL_SERVER_ERROR);

    if (conf->enable & (NGX_HTTP_USERID_ON|NGX_HTTP_USERID_LOGONLY)) {
        rc = ngx_http_userid_get_uid(r, ctx, conf);

        if (rc != NGX_OK) {
            return rc;
        }
    }

    if (conf->enable & NGX_HTTP_USERID_TIME) {
        ngx_gettimeofday(&ctx->tv);
    }

    return NGX_OK;
}


static ngx_int_t ngx_http_userid_get_uid(ngx_http_request_t *r,
                                         ngx_http_userid_ctx_t *ctx,
                                         ngx_http_userid_conf_t *conf)
{
    u_char           *start, *last, *end;
    uint32_t         *uid;
    ngx_int_t         rc;
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

            rc = ngx_decode_base64(r->pool, &src, &dst);

            if (rc == NGX_ABORT) {
                return NGX_HTTP_INTERNAL_SERVER_ERROR;
            }

            if (rc == NGX_ERROR) {
                ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                              "client sent invalid userid cookie \"%s\"",
                              headers[cookies[i]].value.data);
                break;
            }

            uid = (uint32_t *) dst.data;
            ctx->uid_got[0] = uid[0];
            ctx->uid_got[1] = uid[1];
            ctx->uid_got[2] = uid[2];
            ctx->uid_got[3] = uid[3];

            ngx_log_debug4(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                           "uid: %08X%08X%08X%08X",
                           uid[0], uid[1], uid[2], uid[3]);

            return NGX_OK;
        }
    }

    return NGX_OK;
}


static u_char *ngx_http_userid_log_uid_got(ngx_http_request_t *r, u_char *buf,
                                           uintptr_t data)
{
    ngx_http_userid_ctx_t   *ctx;
    ngx_http_userid_conf_t  *conf;

    ctx = ngx_http_get_module_ctx(r, ngx_http_userid_module);

    if (ctx == NULL || ctx->uid_got[3] == 0) {
        if (buf == NULL) {
            return (u_char *) 1;
        }

        *buf = '-';
        return buf + 1;
    }

    conf = ngx_http_get_module_loc_conf(r, ngx_http_userid_module);

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
    if (buf == NULL) {
        return (u_char *) 1;
    }

    *buf = '-';

    return buf + 1;
}


static u_char *ngx_http_userid_log_uid_time(ngx_http_request_t *r, u_char *buf,
                                            uintptr_t data)
{
    ngx_http_userid_ctx_t   *ctx;

    ctx = ngx_http_get_module_ctx(r, ngx_http_userid_module);

    if (ctx == NULL || ctx->tv.tv_sec == 0) {
        *buf = '-';
        return buf + 1;
    }

    return buf + ngx_snprintf((char *) buf, TIME_T_LEN + 5,
                              "%ld.%03ld",
                              ctx->tv.tv_sec, ctx->tv.tv_usec / 1000);
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

    conf->enable = 0;

    conf->name.len = 0;
    conf->name.date = NULL;
    conf->domain.len = 0;
    conf->domain.date = NULL;
    conf->path.len = 0;
    conf->path.date = NULL;

    */


    return conf;
}   


static char *ngx_http_userid_merge_conf(ngx_conf_t *cf, void *parent,
                                        void *child)
{
    ngx_http_userid_conf_t *prev = parent;
    ngx_http_userid_conf_t *conf = child;

    ngx_conf_merge_bitmask_value(conf->enable, prev->enable,
                                 (NGX_CONF_BITMASK_SET
                                  |NGX_HTTP_USERID_OFF));

    ngx_conf_merge_str_value(conf->name, prev->name, "uid");
    ngx_conf_merge_str_value(conf->domain, prev->domain, ".");
    ngx_conf_merge_str_value(conf->path, prev->path, "/");

    return NGX_CONF_OK;
}   


static ngx_int_t ngx_http_userid_init(ngx_cycle_t *cycle)
{
    ngx_http_handler_pt        *h;
    ngx_http_core_main_conf_t  *cmcf;

    cmcf = ngx_http_cycle_get_module_main_conf(cycle, ngx_http_core_module);

    h = ngx_push_array(&cmcf->phases[NGX_HTTP_MISC_PHASE].handlers);
    if (h == NULL) {
        return NGX_ERROR;
    }

    *h = ngx_http_userid_handler;

    return NGX_OK;
}
