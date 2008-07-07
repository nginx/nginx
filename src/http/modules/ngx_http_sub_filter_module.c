
/*
 * Copyright (C) Igor Sysoev
 */


#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>


typedef struct {
    ngx_str_t      match;
    ngx_str_t      sub;

    ngx_array_t   *types;     /* array of ngx_str_t */

    ngx_array_t   *sub_lengths;
    ngx_array_t   *sub_values;

    ngx_flag_t     once;
} ngx_http_sub_loc_conf_t;


typedef enum {
    sub_start_state = 0,
    sub_match_state,
} ngx_http_sub_state_e;


typedef struct {
    ngx_str_t      match;

    ngx_uint_t     once;   /* unsigned  once:1 */

    ngx_buf_t     *buf;

    u_char        *pos;
    u_char        *copy_start;
    u_char        *copy_end;

    ngx_chain_t   *in;
    ngx_chain_t   *out;
    ngx_chain_t  **last_out;
    ngx_chain_t   *busy;
    ngx_chain_t   *free;

    ngx_str_t      sub;

    ngx_uint_t     state;
    size_t         saved;
    size_t         looked;
} ngx_http_sub_ctx_t;


static ngx_int_t ngx_http_sub_output(ngx_http_request_t *r,
    ngx_http_sub_ctx_t *ctx);
static ngx_int_t ngx_http_sub_parse(ngx_http_request_t *r,
    ngx_http_sub_ctx_t *ctx);

static char * ngx_http_sub_filter(ngx_conf_t *cf, ngx_command_t *cmd,
    void *conf);
static char *ngx_http_sub_types(ngx_conf_t *cf, ngx_command_t *cmd, void *conf);
static void *ngx_http_sub_create_conf(ngx_conf_t *cf);
static char *ngx_http_sub_merge_conf(ngx_conf_t *cf,
    void *parent, void *child);
static ngx_int_t ngx_http_sub_filter_init(ngx_conf_t *cf);


static ngx_command_t  ngx_http_sub_filter_commands[] = {

    { ngx_string("sub_filter"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE2,
      ngx_http_sub_filter,
      NGX_HTTP_LOC_CONF_OFFSET,
      0,
      NULL },

    { ngx_string("sub_filter_types"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_1MORE,
      ngx_http_sub_types,
      NGX_HTTP_LOC_CONF_OFFSET,
      0,
      NULL },

    { ngx_string("sub_filter_once"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_FLAG,
      ngx_conf_set_flag_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_sub_loc_conf_t, once),
      NULL },

      ngx_null_command
};


static ngx_http_module_t  ngx_http_sub_filter_module_ctx = {
    NULL,                                  /* preconfiguration */
    ngx_http_sub_filter_init,              /* postconfiguration */

    NULL,                                  /* create main configuration */
    NULL,                                  /* init main configuration */

    NULL,                                  /* create server configuration */
    NULL,                                  /* merge server configuration */

    ngx_http_sub_create_conf,              /* create location configuration */
    ngx_http_sub_merge_conf                /* merge location configuration */
};


ngx_module_t  ngx_http_sub_filter_module = {
    NGX_MODULE_V1,
    &ngx_http_sub_filter_module_ctx,       /* module context */
    ngx_http_sub_filter_commands,          /* module directives */
    NGX_HTTP_MODULE,                       /* module type */
    NULL,                                  /* init master */
    NULL,                                  /* init module */
    NULL,                                  /* init process */
    NULL,                                  /* init thread */
    NULL,                                  /* exit thread */
    NULL,                                  /* exit process */
    NULL,                                  /* exit master */
    NGX_MODULE_V1_PADDING
};


static ngx_http_output_header_filter_pt  ngx_http_next_header_filter;
static ngx_http_output_body_filter_pt    ngx_http_next_body_filter;


static ngx_int_t
ngx_http_sub_header_filter(ngx_http_request_t *r)
{
    ngx_str_t                *type;
    ngx_uint_t                i;
    ngx_http_sub_ctx_t        *ctx;
    ngx_http_sub_loc_conf_t  *slcf;

    slcf = ngx_http_get_module_loc_conf(r, ngx_http_sub_filter_module);

    if (slcf->match.len == 0
        || r->headers_out.content_type.len == 0
        || r->headers_out.content_length_n == 0)
    {
        return ngx_http_next_header_filter(r);
    }

    type = slcf->types->elts;
    for (i = 0; i < slcf->types->nelts; i++) {
        if (r->headers_out.content_type.len >= type[i].len
            && ngx_strncasecmp(r->headers_out.content_type.data,
                               type[i].data, type[i].len) == 0)
        {
            goto found;
        }
    }

    return ngx_http_next_header_filter(r);

found:

    ctx = ngx_pcalloc(r->pool, sizeof(ngx_http_sub_ctx_t));
    if (ctx == NULL) {
        return NGX_ERROR;
    }

    ngx_http_set_ctx(r, ctx, ngx_http_sub_filter_module);

    ctx->match = slcf->match;
    ctx->last_out = &ctx->out;
    ctx->sub = slcf->sub;

    r->filter_need_in_memory = 1;

    if (r == r->main) {
        ngx_http_clear_content_length(r);
        ngx_http_clear_last_modified(r);
    }

    return ngx_http_next_header_filter(r);
}


static ngx_int_t
ngx_http_sub_body_filter(ngx_http_request_t *r, ngx_chain_t *in)
{
    ngx_int_t                  rc;
    ngx_buf_t                 *b;
    ngx_chain_t               *cl;
    ngx_http_sub_ctx_t        *ctx;
    ngx_http_sub_loc_conf_t   *slcf;

    ctx = ngx_http_get_module_ctx(r, ngx_http_sub_filter_module);

    if (ctx == NULL) {
        return ngx_http_next_body_filter(r, in);
    }

    if ((in == NULL
         && ctx->buf == NULL
         && ctx->in == NULL
         && ctx->busy == NULL))
    {
        return ngx_http_next_body_filter(r, in);
    }

    if (ctx->once && (ctx->buf == NULL || ctx->in == NULL)) {

        if (ctx->busy) {
            if (ngx_http_sub_output(r, ctx) == NGX_ERROR) {
                return NGX_ERROR;
            }
        }

        return ngx_http_next_body_filter(r, in);
    }

    /* add the incoming chain to the chain ctx->in */

    if (in) {
        if (ngx_chain_add_copy(r->pool, &ctx->in, in) == NGX_ERROR) {
            return NGX_ERROR;
        }
    }

    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "http sub filter \"%V\"", &r->uri);

    while (ctx->in || ctx->buf) {

        if (ctx->buf == NULL ){
            ctx->buf = ctx->in->buf;
            ctx->in = ctx->in->next;
            ctx->pos = ctx->buf->pos;
        }

        if (ctx->state == sub_start_state) {
            ctx->copy_start = ctx->pos;
            ctx->copy_end = ctx->pos;
        }

        b = NULL;

        while (ctx->pos < ctx->buf->last) {

            ngx_log_debug2(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                           "saved: %d state: %d", ctx->saved, ctx->state);

            rc = ngx_http_sub_parse(r, ctx);

            ngx_log_debug4(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                           "parse: %d, looked: %d %p-%p",
                           rc, ctx->looked, ctx->copy_start, ctx->copy_end);

            if (rc == NGX_ERROR) {
                return rc;
            }

            if (ctx->copy_start != ctx->copy_end) {

                ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                               "saved: %d", ctx->saved);

                if (ctx->saved) {

                    if (ctx->free) {
                        cl = ctx->free;
                        ctx->free = ctx->free->next;
                        b = cl->buf;
                        ngx_memzero(b, sizeof(ngx_buf_t));

                    } else {
                        b = ngx_calloc_buf(r->pool);
                        if (b == NULL) {
                            return NGX_ERROR;
                        }

                        cl = ngx_alloc_chain_link(r->pool);
                        if (cl == NULL) {
                            return NGX_ERROR;
                        }

                        cl->buf = b;
                    }

                    b->memory = 1;
                    b->pos = ctx->match.data;
                    b->last = ctx->match.data + ctx->saved;

                    *ctx->last_out = cl;
                    ctx->last_out = &cl->next;

                    ctx->saved = 0;
                }

                if (ctx->free) {
                    cl = ctx->free;
                    ctx->free = ctx->free->next;
                    b = cl->buf;

                } else {
                    b = ngx_alloc_buf(r->pool);
                    if (b == NULL) {
                        return NGX_ERROR;
                    }

                    cl = ngx_alloc_chain_link(r->pool);
                    if (cl == NULL) {
                        return NGX_ERROR;
                    }

                    cl->buf = b;
                }

                ngx_memcpy(b, ctx->buf, sizeof(ngx_buf_t));

                b->pos = ctx->copy_start;
                b->last = ctx->copy_end;
                b->shadow = NULL;
                b->last_buf = 0;
                b->recycled = 0;

                if (b->in_file) {
                    b->file_last = b->file_pos + (b->last - ctx->buf->pos);
                    b->file_pos += b->pos - ctx->buf->pos;
                }

                cl->next = NULL;
                *ctx->last_out = cl;
                ctx->last_out = &cl->next;
            }

            if (ctx->state == sub_start_state) {
                ctx->copy_start = ctx->pos;
                ctx->copy_end = ctx->pos;

            } else {
                ctx->copy_start = NULL;
                ctx->copy_end = NULL;
            }

            if (rc == NGX_AGAIN) {
                continue;
            }


            /* rc == NGX_OK */

            b = ngx_calloc_buf(r->pool);
            if (b == NULL) {
                return NGX_ERROR;
            }

            cl = ngx_alloc_chain_link(r->pool);
            if (cl == NULL) {
                return NGX_ERROR;
            }

            slcf = ngx_http_get_module_loc_conf(r, ngx_http_sub_filter_module);

            if (ctx->sub.data == NULL) {

                if (ngx_http_script_run(r, &ctx->sub, slcf->sub_lengths->elts,
                                        0, slcf->sub_values->elts)
                    == NULL)
                {
                    return NGX_ERROR;
                }
            }

            if (ctx->sub.len) {
                b->memory = 1;
                b->pos = ctx->sub.data;
                b->last = ctx->sub.data + ctx->sub.len;

            } else {
                b->sync = 1;
            }

            cl->buf = b;
            cl->next = NULL;
            *ctx->last_out = cl;
            ctx->last_out = &cl->next;

            ctx->once = slcf->once;

            continue;
        }

        if (ctx->buf->last_buf || ngx_buf_in_memory(ctx->buf)) {
            if (b == NULL) {
                if (ctx->free) {
                    cl = ctx->free;
                    ctx->free = ctx->free->next;
                    b = cl->buf;
                    ngx_memzero(b, sizeof(ngx_buf_t));

                } else {
                    b = ngx_calloc_buf(r->pool);
                    if (b == NULL) {
                        return NGX_ERROR;
                    }

                    cl = ngx_alloc_chain_link(r->pool);
                    if (cl == NULL) {
                        return NGX_ERROR;
                    }

                    cl->buf = b;
                }

                b->sync = 1;

                cl->next = NULL;
                *ctx->last_out = cl;
                ctx->last_out = &cl->next;
            }

            b->last_buf = ctx->buf->last_buf;
            b->shadow = ctx->buf;

            b->recycled = ctx->buf->recycled;
        }

        ctx->buf = NULL;

        ctx->saved = ctx->looked;
    }

    if (ctx->out == NULL && ctx->busy == NULL) {
        return NGX_OK;
    }

    return ngx_http_sub_output(r, ctx);
}


static ngx_int_t
ngx_http_sub_output(ngx_http_request_t *r, ngx_http_sub_ctx_t *ctx)
{
    ngx_int_t     rc;
    ngx_buf_t    *b;
    ngx_chain_t  *cl;

#if 1
    b = NULL;
    for (cl = ctx->out; cl; cl = cl->next) {
        ngx_log_debug2(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                       "sub out: %p %p", cl->buf, cl->buf->pos);
        if (cl->buf == b) {
            ngx_log_error(NGX_LOG_ALERT, r->connection->log, 0,
                          "the same buf was used in sub");
            ngx_debug_point();
            return NGX_ERROR;
        }
        b = cl->buf;
    }
#endif

    rc = ngx_http_next_body_filter(r, ctx->out);

    if (ctx->busy == NULL) {
        ctx->busy = ctx->out;

    } else {
        for (cl = ctx->busy; cl->next; cl = cl->next) { /* void */ }
        cl->next = ctx->out;
    }

    ctx->out = NULL;
    ctx->last_out = &ctx->out;

    while (ctx->busy) {

        cl = ctx->busy;
        b = cl->buf;

        if (ngx_buf_size(b) != 0) {
            break;
        }

#if (NGX_HAVE_WRITE_ZEROCOPY)
        if (b->zerocopy_busy) {
            break;
        }
#endif

        if (b->shadow) {
            b->shadow->pos = b->shadow->last;
        }

        ctx->busy = cl->next;

        if (ngx_buf_in_memory(b) || b->in_file) {
            /* add data bufs only to the free buf chain */

            cl->next = ctx->free;
            ctx->free = cl;
        }
    }

    if (ctx->in || ctx->buf) {
        r->buffered |= NGX_HTTP_SUB_BUFFERED;

    } else {
        r->buffered &= ~NGX_HTTP_SUB_BUFFERED;
    }

    return rc;
}


static ngx_int_t
ngx_http_sub_parse(ngx_http_request_t *r, ngx_http_sub_ctx_t *ctx)
{
    u_char                *p, *last, *copy_end, ch, match;
    size_t                 looked;
    ngx_http_sub_state_e   state;

    if (ctx->once) {
        ctx->copy_start = ctx->pos;
        ctx->copy_end = ctx->buf->last;
        ctx->pos = ctx->buf->last;
        ctx->looked = 0;

        ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "once");

        return NGX_AGAIN;
    }

    state = ctx->state;
    looked = ctx->looked;
    last = ctx->buf->last;
    copy_end = ctx->copy_end;

    for (p = ctx->pos; p < last; p++) {

        ch = *p;
        ch = ngx_tolower(ch);

        if (state == sub_start_state) {

            /* the tight loop */

            match = ctx->match.data[0];

            for ( ;; ) {
                if (ch == match) {
                    copy_end = p;
                    looked = 1;
                    state = sub_match_state;

                    goto match_started;
                }

                if (++p == last) {
                    break;
                }

                ch = *p;
                ch = ngx_tolower(ch);
            }

            ctx->state = state;
            ctx->pos = p;
            ctx->looked = looked;
            ctx->copy_end = p;

            if (ctx->copy_start == NULL) {
                ctx->copy_start = ctx->buf->pos;
            }

            return NGX_AGAIN;

        match_started:

            continue;
        }

        /* state == sub_match_state */

        if (ch == ctx->match.data[looked]) {
            looked++;

            if (looked == ctx->match.len) {
                if ((size_t) (p - ctx->pos) < looked) {
                    ctx->saved = 0;
                }

                ctx->state = sub_start_state;
                ctx->pos = p + 1;
                ctx->looked = 0;
                ctx->copy_end = copy_end;

                if (ctx->copy_start == NULL && copy_end) {
                    ctx->copy_start = ctx->buf->pos;
                }

                return NGX_OK;
            }

        } else if (ch == ctx->match.data[0]) {
            copy_end = p;
            looked = 1;

        } else {
            copy_end = p;
            looked = 0;
            state = sub_start_state;
        }
    }

    ctx->state = state;
    ctx->pos = p;
    ctx->looked = looked;

    ctx->copy_end = (state == sub_start_state) ? p : copy_end;

    if (ctx->copy_start == NULL && ctx->copy_end) {
        ctx->copy_start = ctx->buf->pos;
    }

    return NGX_AGAIN;
}


static char *
ngx_http_sub_filter(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    ngx_http_sub_loc_conf_t *slcf = conf;

    ngx_str_t                  *value;
    ngx_int_t                   n;
    ngx_uint_t                  i;
    ngx_http_script_compile_t   sc;

    if (slcf->match.len) {
        return "is duplicate";
    }

    value = cf->args->elts;

    slcf->match = value[1];

    for (i = 0; i < value[1].len; i++) {
        value[1].data[i] = ngx_tolower(value[1].data[i]);
    }

    n = ngx_http_script_variables_count(&value[2]);

    if (n == 0) {
        slcf->sub = value[2];
        return NGX_CONF_OK;
    }

    ngx_memzero(&sc, sizeof(ngx_http_script_compile_t));

    sc.cf = cf;
    sc.source = &value[2];
    sc.lengths = &slcf->sub_lengths;
    sc.values = &slcf->sub_values;
    sc.variables = n;
    sc.complete_lengths = 1;
    sc.complete_values = 1;

    if (ngx_http_script_compile(&sc) != NGX_OK) {
        return NGX_CONF_ERROR;
    }

    return NGX_CONF_OK;
}


static char *
ngx_http_sub_types(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    ngx_http_sub_loc_conf_t *slcf = conf;

    ngx_str_t   *value, *type;
    ngx_uint_t   i;

    if (slcf->types == NULL) {
        slcf->types = ngx_array_create(cf->pool, 4, sizeof(ngx_str_t));
        if (slcf->types == NULL) {
            return NGX_CONF_ERROR;
        }

        type = ngx_array_push(slcf->types);
        if (type == NULL) {
            return NGX_CONF_ERROR;
        }

        type->len = sizeof("text/html") - 1;
        type->data = (u_char *) "text/html";
    }

    value = cf->args->elts;

    for (i = 1; i < cf->args->nelts; i++) {

        if (ngx_strcmp(value[i].data, "text/html") == 0) {
            continue;
        }

        type = ngx_array_push(slcf->types);
        if (type == NULL) {
            return NGX_CONF_ERROR;
        }

        type->len = value[i].len;

        type->data = ngx_palloc(cf->pool, type->len + 1);
        if (type->data == NULL) {
            return NGX_CONF_ERROR;
        }

        ngx_cpystrn(type->data, value[i].data, type->len + 1);
    }

    return NGX_CONF_OK;
}


static void *
ngx_http_sub_create_conf(ngx_conf_t *cf)
{
    ngx_http_sub_loc_conf_t  *slcf;

    slcf = ngx_pcalloc(cf->pool, sizeof(ngx_http_sub_loc_conf_t));
    if (slcf == NULL) {
        return NGX_CONF_ERROR;
    }

    /*
     * set by ngx_pcalloc():
     *
     *     conf->match.len = 0;
     *     conf->match.data = NULL;
     *     conf->sub.len = 0;
     *     conf->sub.data = NULL;
     *     conf->sub_lengths = NULL;
     *     conf->sub_values = NULL;
     *     conf->types = NULL;
     */

    slcf->once = NGX_CONF_UNSET;

    return slcf;
}


static char *
ngx_http_sub_merge_conf(ngx_conf_t *cf, void *parent, void *child)
{
    ngx_http_sub_loc_conf_t *prev = parent;
    ngx_http_sub_loc_conf_t *conf = child;

    ngx_str_t  *type;

    ngx_conf_merge_value(conf->once, prev->once, 1);
    ngx_conf_merge_str_value(conf->match, prev->match, "");

    if (conf->sub.data == NULL && conf->sub_lengths == NULL) {
        conf->sub = prev->sub;
        conf->sub_lengths = prev->sub_lengths;
        conf->sub_values = prev->sub_values;
    }

    if (conf->types == NULL) {
        if (prev->types == NULL) {
            conf->types = ngx_array_create(cf->pool, 1, sizeof(ngx_str_t));
            if (conf->types == NULL) {
                return NGX_CONF_ERROR;
            }

            type = ngx_array_push(conf->types);
            if (type == NULL) {
                return NGX_CONF_ERROR;
            }

            type->len = sizeof("text/html") - 1;
            type->data = (u_char *) "text/html";

        } else {
            conf->types = prev->types;
        }
    }

    return NGX_CONF_OK;
}


static ngx_int_t
ngx_http_sub_filter_init(ngx_conf_t *cf)
{
    ngx_http_next_header_filter = ngx_http_top_header_filter;
    ngx_http_top_header_filter = ngx_http_sub_header_filter;

    ngx_http_next_body_filter = ngx_http_top_body_filter;
    ngx_http_top_body_filter = ngx_http_sub_body_filter;

    return NGX_OK;
}
