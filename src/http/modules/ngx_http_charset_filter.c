
/*
 * Copyright (C) Igor Sysoev
 */


#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>


typedef struct {
    char       **tables;
    ngx_str_t    name;
    unsigned     server;
} ngx_http_charset_t;


typedef struct {
    ngx_int_t   src;
    ngx_int_t   dst;
    char       *src2dst;
    char       *dst2src;
} ngx_http_charset_tables_t;


typedef struct {
    ngx_array_t  charsets;               /* ngx_http_charset_t */
    ngx_array_t  tables;                 /* ngx_http_charset_tables_t */
} ngx_http_charset_main_conf_t;


typedef struct {
    ngx_flag_t  enable;
    ngx_flag_t  autodetect;

    ngx_int_t   default_charset;
    ngx_int_t   source_charset;
} ngx_http_charset_loc_conf_t;


typedef struct {
    ngx_int_t   server;
    ngx_int_t   client;
} ngx_http_charset_ctx_t;


static void ngx_charset_recode(ngx_buf_t *b, char *table);

static char *ngx_charset_map_block(ngx_conf_t *cf, ngx_command_t *cmd,
                                   void *conf);
static char *ngx_charset_map(ngx_conf_t *cf, ngx_command_t *dummy, void *conf);

static char *ngx_http_set_charset_slot(ngx_conf_t *cf, ngx_command_t *cmd,
                                       void *conf);
static ngx_int_t ngx_http_add_charset(ngx_array_t *charsets, ngx_str_t *name);

static ngx_int_t ngx_http_charset_filter_init(ngx_cycle_t *cycle);

static void *ngx_http_charset_create_main_conf(ngx_conf_t *cf);
static char *ngx_http_charset_init_main_conf(ngx_conf_t *cf, void *conf);
static void *ngx_http_charset_create_loc_conf(ngx_conf_t *cf);
static char *ngx_http_charset_merge_loc_conf(ngx_conf_t *cf,
                                             void *parent, void *child);


static ngx_command_t  ngx_http_charset_filter_commands[] = {

    { ngx_string("charset_map"),
      NGX_HTTP_MAIN_CONF|NGX_CONF_BLOCK|NGX_CONF_TAKE2,
      ngx_charset_map_block,
      NGX_HTTP_MAIN_CONF_OFFSET,
      0,
      NULL },

    { ngx_string("default_charset"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
      ngx_http_set_charset_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_charset_loc_conf_t, default_charset),
      NULL },

    { ngx_string("source_charset"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
      ngx_http_set_charset_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_charset_loc_conf_t, source_charset),
      NULL },

    { ngx_string("charset"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_FLAG,
      ngx_conf_set_flag_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_charset_loc_conf_t, enable),
      NULL },

    { ngx_string("autodetect_charset"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_FLAG,
      ngx_conf_set_flag_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_charset_loc_conf_t, autodetect),
      NULL },

      ngx_null_command
};


static ngx_http_module_t  ngx_http_charset_filter_module_ctx = {
    NULL,                                  /* pre conf */

    ngx_http_charset_create_main_conf,     /* create main configuration */
    ngx_http_charset_init_main_conf,       /* init main configuration */

    NULL,                                  /* create server configuration */
    NULL,                                  /* merge server configuration */

    ngx_http_charset_create_loc_conf,      /* create location configuration */
    ngx_http_charset_merge_loc_conf        /* merge location configuration */
};


ngx_module_t  ngx_http_charset_filter_module = {
    NGX_MODULE,
    &ngx_http_charset_filter_module_ctx,   /* module context */
    ngx_http_charset_filter_commands,      /* module directives */
    NGX_HTTP_MODULE,                       /* module type */
    ngx_http_charset_filter_init,          /* init module */
    NULL                                   /* init child */
};


static ngx_http_output_header_filter_pt  ngx_http_next_header_filter;
static ngx_http_output_body_filter_pt    ngx_http_next_body_filter;


static ngx_int_t ngx_http_charset_header_filter(ngx_http_request_t *r)
{
    ngx_http_charset_t            *charsets;
    ngx_http_charset_ctx_t        *ctx;
    ngx_http_charset_loc_conf_t   *lcf;
    ngx_http_charset_main_conf_t  *mcf;

    mcf = ngx_http_get_module_main_conf(r, ngx_http_charset_filter_module);
    lcf = ngx_http_get_module_loc_conf(r, ngx_http_charset_filter_module);

    if (lcf->enable == 0) {
        return ngx_http_next_header_filter(r);
    }

#if 0
    if (lcf->default_charset.len == 0) {
        return ngx_http_next_header_filter(r);
    }
#endif

    if (r->headers_out.content_type == NULL) {
        return ngx_http_next_header_filter(r);
    }

    if (ngx_strncasecmp(r->headers_out.content_type->value.data,
                                                              "text/", 5) != 0
        && ngx_strncasecmp(r->headers_out.content_type->value.data,
                                          "application/x-javascript", 24) != 0)
    {
        return ngx_http_next_header_filter(r);
    }

    if (ngx_strstr(r->headers_out.content_type->value.data, "charset") != NULL)
    {
        return ngx_http_next_header_filter(r);
    }

    if (r->headers_out.status == NGX_HTTP_MOVED_PERMANENTLY
        && r->headers_out.status == NGX_HTTP_MOVED_TEMPORARILY)
    {
        /*
         * do not set charset for the redirect because NN 4.x uses this
         * charset instead of the next page charset
         */

        r->headers_out.charset.len = 0;
        return ngx_http_next_header_filter(r);
    }

    if (r->headers_out.charset.len) {
        return ngx_http_next_header_filter(r);
    }

    charsets = mcf->charsets.elts;
    r->headers_out.charset = charsets[lcf->default_charset].name;

    if (lcf->default_charset == lcf->source_charset) {
        return ngx_http_next_header_filter(r);
    }

    ngx_http_create_ctx(r, ctx, ngx_http_charset_filter_module,
                        sizeof(ngx_http_charset_ctx_t), NGX_ERROR);

    r->filter_need_in_memory = 1;

    return ngx_http_next_header_filter(r);
}


static ngx_int_t ngx_http_charset_body_filter(ngx_http_request_t *r,
                                              ngx_chain_t *in)
{
    char                          *table;
    ngx_chain_t                   *cl;
    ngx_http_charset_t            *charsets;
    ngx_http_charset_ctx_t        *ctx;
    ngx_http_charset_loc_conf_t   *lcf;
    ngx_http_charset_main_conf_t  *mcf;

    ctx = ngx_http_get_module_ctx(r, ngx_http_charset_filter_module);

    if (ctx == NULL) {
        return ngx_http_next_body_filter(r, in);
    }

    mcf = ngx_http_get_module_main_conf(r, ngx_http_charset_filter_module);
    lcf = ngx_http_get_module_loc_conf(r, ngx_http_charset_filter_module);

    charsets = mcf->charsets.elts;
    table = charsets[lcf->source_charset].tables[lcf->default_charset];

    for (cl = in; cl; cl = cl->next) {
        ngx_charset_recode(cl->buf, table);
    }

    return ngx_http_next_body_filter(r, in);
}


static void ngx_charset_recode(ngx_buf_t *b, char *table)
{
    u_char  *p, c;

    for (p = b->pos; p < b->last; p++) {
        c = *p;
        *p = table[c];
    }
}


static char *ngx_charset_map_block(ngx_conf_t *cf, ngx_command_t *cmd,
                                   void *conf)
{
    ngx_http_charset_main_conf_t  *mcf = conf;

    char                       *rv;
    ngx_int_t                   src, dst;
    ngx_uint_t                  i;
    ngx_str_t                  *value;
    ngx_conf_t                  pvcf;
    ngx_http_charset_tables_t  *table;

    value = cf->args->elts;

    src = ngx_http_add_charset(&mcf->charsets, &value[1]);
    if (src == NGX_ERROR) {
        return NGX_CONF_ERROR;
    }

    dst = ngx_http_add_charset(&mcf->charsets, &value[2]);
    if (dst == NGX_ERROR) {
        return NGX_CONF_ERROR;
    }

    if (src == dst) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                           "\"charset_map\" between the same charsets "
                           "\"%s\" and \"%s\"",
                           value[1].data, value[2].data);
        return NGX_CONF_ERROR;
    }

    table = mcf->tables.elts;
    for (i = 0; i < mcf->tables.nelts; i++) {
        if ((src == table->src && dst == table->dst)
             || (src == table->dst && dst == table->src))
        {
            ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                               "duplicate \"charset_map\" between "
                               "\"%s\" and \"%s\"",
                               value[1].data, value[2].data);
            return NGX_CONF_ERROR;
        }
    }

    if (!(table = ngx_push_array(&mcf->tables))) {
        return NGX_CONF_ERROR;
    }

    table->src = src;
    table->dst = dst;

    if (!(table->src2dst = ngx_palloc(cf->pool, 256))) {
        return NGX_CONF_ERROR;
    }

    if (!(table->dst2src = ngx_palloc(cf->pool, 256))) {
        return NGX_CONF_ERROR;
    }

    for (i = 0; i < 128; i++) {
        table->src2dst[i] = (char) i;
        table->dst2src[i] = (char) i;
    }

    for (/* void */; i < 256; i++) {
        table->src2dst[i] = '?';
        table->dst2src[i] = '?';
    }

    pvcf = *cf;
    cf->ctx = table;
    cf->handler = ngx_charset_map;
    cf->handler_conf = conf;
    rv = ngx_conf_parse(cf, NULL);
    *cf = pvcf;

    return rv;
}


static char *ngx_charset_map(ngx_conf_t *cf, ngx_command_t *dummy, void *conf)
{
    ngx_int_t                   src, dst;
    ngx_str_t                  *value;
    ngx_http_charset_tables_t  *table;

    if (cf->args->nelts != 2) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0, "invalid parameters number");
        return NGX_CONF_ERROR;
    }

    value = cf->args->elts;

    src = ngx_hextoi(value[0].data, value[0].len);
    if (src == NGX_ERROR || src > 255) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                           "invalid value \"%s\"", value[0].data);
        return NGX_CONF_ERROR;
    }

    dst = ngx_hextoi(value[1].data, value[1].len);
    if (dst == NGX_ERROR || dst > 255) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                           "invalid value \"%s\"", value[1].data);
        return NGX_CONF_ERROR;
    }

    table = cf->ctx;

    table->src2dst[src] = (char) dst;
    table->dst2src[dst] = (char) src;

    return NGX_CONF_OK;
}


static char *ngx_http_set_charset_slot(ngx_conf_t *cf, ngx_command_t *cmd,
                                       void *conf)
{
    char  *p = conf;

    ngx_int_t                     *cp;
    ngx_str_t                     *value;
    ngx_http_charset_t            *charset;
    ngx_http_charset_main_conf_t  *mcf;

    cp = (ngx_int_t *) (p + cmd->offset);

    if (*cp != NGX_CONF_UNSET) {
        return "is duplicate";
    }

    mcf = ngx_http_conf_get_module_main_conf(cf,
                                             ngx_http_charset_filter_module);

    value = cf->args->elts;

    *cp = ngx_http_add_charset(&mcf->charsets, &value[1]);
    if (*cp == NGX_ERROR) {
        return NGX_CONF_ERROR;
    }

    if (cmd->offset == offsetof(ngx_http_charset_loc_conf_t, source_charset)) {
        charset = mcf->charsets.elts;
        charset[*cp].server = 1;
    }

    return NGX_CONF_OK;
}


static ngx_int_t ngx_http_add_charset(ngx_array_t *charsets, ngx_str_t *name)
{
    ngx_uint_t           i;
    ngx_http_charset_t  *c;

    c = charsets->elts;
    for (i = 0; i < charsets->nelts; i++) {
        if (name->len != c[i].name.len) {
            continue;
        }

        if (ngx_strcasecmp(name->data, c[i].name.data) == 0) {
            break;
        }
    }

    if (i < charsets->nelts) {
        return i;
    }

    if (!(c = ngx_push_array(charsets))) {
        return NGX_ERROR;
    }

    c->name = *name;

    return i;
}


static ngx_int_t ngx_http_charset_filter_init(ngx_cycle_t *cycle)
{
    ngx_http_next_header_filter = ngx_http_top_header_filter;
    ngx_http_top_header_filter = ngx_http_charset_header_filter;

    ngx_http_next_body_filter = ngx_http_top_body_filter;
    ngx_http_top_body_filter = ngx_http_charset_body_filter;

    return NGX_OK;
}


static void *ngx_http_charset_create_main_conf(ngx_conf_t *cf)
{
    ngx_http_charset_main_conf_t  *mcf;

    if (!(mcf = ngx_pcalloc(cf->pool, sizeof(ngx_http_charset_main_conf_t)))) {
        return NGX_CONF_ERROR;
    }

    ngx_init_array(mcf->charsets, cf->pool, 5, sizeof(ngx_http_charset_t),
                   NGX_CONF_ERROR);

    ngx_init_array(mcf->tables, cf->pool, 10, sizeof(ngx_http_charset_tables_t),
                   NGX_CONF_ERROR);

    return mcf;
}


static char *ngx_http_charset_init_main_conf(ngx_conf_t *cf, void *conf)
{
    ngx_http_charset_main_conf_t *mcf = conf;

    ngx_uint_t                  i, n;
    ngx_http_charset_t         *charset;
    ngx_http_charset_tables_t  *tables;

    tables = mcf->tables.elts;
    charset = mcf->charsets.elts;

    for (i = 0; i < mcf->charsets.nelts; i++) {
        if (!charset[i].server) {
            continue;
        }

        charset[i].tables = ngx_pcalloc(cf->pool,
                                        sizeof(char *) * mcf->charsets.nelts);

        if (charset[i].tables == NULL) {
            return NGX_CONF_ERROR;
        }

        for (n = 0; n < mcf->tables.nelts; n++) {
            if ((ngx_int_t) i == tables[n].src) {
                charset[i].tables[tables[n].dst] = tables[n].src2dst;
                continue;
            }

            if ((ngx_int_t) i == tables[n].dst) {
                charset[i].tables[tables[n].src] = tables[n].dst2src;
            }
        }
    }

    for (i = 0; i < mcf->charsets.nelts; i++) {
        if (!charset[i].server) {
            continue;
        }

        for (n = 0; n < mcf->charsets.nelts; n++) {
            if (i == n) {
                continue;
            }

            if (charset[i].tables[n]) {
                continue;
            }

            ngx_log_error(NGX_LOG_EMERG, cf->log, 0,
                          " no \"charset_map\" between the charsets "
                          "\"%s\" and \"%s\"",
                          charset[i].name.data, charset[n].name.data);
            return NGX_CONF_ERROR;
        }
    }

    return NGX_CONF_OK;
}


static void *ngx_http_charset_create_loc_conf(ngx_conf_t *cf)
{
    ngx_http_charset_loc_conf_t  *lcf;

    if (!(lcf = ngx_pcalloc(cf->pool, sizeof(ngx_http_charset_loc_conf_t)))) {
        return NGX_CONF_ERROR;
    }

    lcf->enable = NGX_CONF_UNSET;
    lcf->autodetect = NGX_CONF_UNSET;
    lcf->default_charset = NGX_CONF_UNSET;
    lcf->source_charset = NGX_CONF_UNSET;

    return lcf;
}


static char *ngx_http_charset_merge_loc_conf(ngx_conf_t *cf,
                                             void *parent, void *child)
{
    ngx_http_charset_loc_conf_t *prev = parent;
    ngx_http_charset_loc_conf_t *conf = child;

    ngx_conf_merge_value(conf->enable, prev->enable, 0);
    ngx_conf_merge_value(conf->autodetect, prev->autodetect, 0);

    if (conf->source_charset == NGX_CONF_UNSET) {
        conf->source_charset = prev->source_charset;
    }

    ngx_conf_merge_value(conf->default_charset, prev->default_charset,
                         conf->source_charset);

    return NGX_CONF_OK;
}
