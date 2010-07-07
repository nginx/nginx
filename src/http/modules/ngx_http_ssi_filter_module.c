
/*
 * Copyright (C) Igor Sysoev
 */


#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>

#define NGX_HTTP_SSI_ERROR          1

#define NGX_HTTP_SSI_DATE_LEN       2048

#define NGX_HTTP_SSI_ADD_PREFIX     1
#define NGX_HTTP_SSI_ADD_ZERO       2


typedef struct {
    ngx_flag_t    enable;
    ngx_flag_t    silent_errors;
    ngx_flag_t    ignore_recycled_buffers;

    ngx_hash_t    types;

    size_t        min_file_chunk;
    size_t        value_len;

    ngx_array_t  *types_keys;
} ngx_http_ssi_loc_conf_t;


typedef struct {
    ngx_str_t     name;
    ngx_uint_t    key;
    ngx_str_t     value;
} ngx_http_ssi_var_t;


typedef struct {
    ngx_str_t     name;
    ngx_chain_t  *bufs;
    ngx_uint_t    count;
} ngx_http_ssi_block_t;


typedef enum {
    ssi_start_state = 0,
    ssi_tag_state,
    ssi_comment0_state,
    ssi_comment1_state,
    ssi_sharp_state,
    ssi_precommand_state,
    ssi_command_state,
    ssi_preparam_state,
    ssi_param_state,
    ssi_preequal_state,
    ssi_prevalue_state,
    ssi_double_quoted_value_state,
    ssi_quoted_value_state,
    ssi_quoted_symbol_state,
    ssi_postparam_state,
    ssi_comment_end0_state,
    ssi_comment_end1_state,
    ssi_error_state,
    ssi_error_end0_state,
    ssi_error_end1_state
} ngx_http_ssi_state_e;


static ngx_int_t ngx_http_ssi_output(ngx_http_request_t *r,
    ngx_http_ssi_ctx_t *ctx);
static void ngx_http_ssi_buffered(ngx_http_request_t *r,
    ngx_http_ssi_ctx_t *ctx);
static ngx_int_t ngx_http_ssi_parse(ngx_http_request_t *r,
    ngx_http_ssi_ctx_t *ctx);
static ngx_str_t *ngx_http_ssi_get_variable(ngx_http_request_t *r,
    ngx_str_t *name, ngx_uint_t key);
static ngx_int_t ngx_http_ssi_evaluate_string(ngx_http_request_t *r,
    ngx_http_ssi_ctx_t *ctx, ngx_str_t *text, ngx_uint_t flags);

static ngx_int_t ngx_http_ssi_include(ngx_http_request_t *r,
    ngx_http_ssi_ctx_t *ctx, ngx_str_t **params);
static ngx_int_t ngx_http_ssi_stub_output(ngx_http_request_t *r, void *data,
    ngx_int_t rc);
static ngx_int_t ngx_http_ssi_set_variable(ngx_http_request_t *r, void *data,
    ngx_int_t rc);
static ngx_int_t ngx_http_ssi_echo(ngx_http_request_t *r,
    ngx_http_ssi_ctx_t *ctx, ngx_str_t **params);
static ngx_int_t ngx_http_ssi_config(ngx_http_request_t *r,
    ngx_http_ssi_ctx_t *ctx, ngx_str_t **params);
static ngx_int_t ngx_http_ssi_set(ngx_http_request_t *r,
    ngx_http_ssi_ctx_t *ctx, ngx_str_t **params);
static ngx_int_t ngx_http_ssi_if(ngx_http_request_t *r,
    ngx_http_ssi_ctx_t *ctx, ngx_str_t **params);
static ngx_int_t ngx_http_ssi_else(ngx_http_request_t *r,
    ngx_http_ssi_ctx_t *ctx, ngx_str_t **params);
static ngx_int_t ngx_http_ssi_endif(ngx_http_request_t *r,
    ngx_http_ssi_ctx_t *ctx, ngx_str_t **params);
static ngx_int_t ngx_http_ssi_block(ngx_http_request_t *r,
    ngx_http_ssi_ctx_t *ctx, ngx_str_t **params);
static ngx_int_t ngx_http_ssi_endblock(ngx_http_request_t *r,
    ngx_http_ssi_ctx_t *ctx, ngx_str_t **params);

static ngx_int_t ngx_http_ssi_date_gmt_local_variable(ngx_http_request_t *r,
    ngx_http_variable_value_t *v, uintptr_t gmt);

static ngx_int_t ngx_http_ssi_preconfiguration(ngx_conf_t *cf);
static void *ngx_http_ssi_create_main_conf(ngx_conf_t *cf);
static char *ngx_http_ssi_init_main_conf(ngx_conf_t *cf, void *conf);
static void *ngx_http_ssi_create_loc_conf(ngx_conf_t *cf);
static char *ngx_http_ssi_merge_loc_conf(ngx_conf_t *cf,
    void *parent, void *child);
static ngx_int_t ngx_http_ssi_filter_init(ngx_conf_t *cf);


static ngx_command_t  ngx_http_ssi_filter_commands[] = {

    { ngx_string("ssi"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_HTTP_LIF_CONF
                        |NGX_CONF_FLAG,
      ngx_conf_set_flag_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_ssi_loc_conf_t, enable),
      NULL },

    { ngx_string("ssi_silent_errors"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_FLAG,
      ngx_conf_set_flag_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_ssi_loc_conf_t, silent_errors),
      NULL },

    { ngx_string("ssi_ignore_recycled_buffers"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_FLAG,
      ngx_conf_set_flag_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_ssi_loc_conf_t, ignore_recycled_buffers),
      NULL },

    { ngx_string("ssi_min_file_chunk"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_FLAG,
      ngx_conf_set_size_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_ssi_loc_conf_t, min_file_chunk),
      NULL },

    { ngx_string("ssi_value_length"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_FLAG,
      ngx_conf_set_size_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_ssi_loc_conf_t, value_len),
      NULL },

    { ngx_string("ssi_types"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_1MORE,
      ngx_http_types_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_ssi_loc_conf_t, types_keys),
      &ngx_http_html_default_types[0] },

      ngx_null_command
};



static ngx_http_module_t  ngx_http_ssi_filter_module_ctx = {
    ngx_http_ssi_preconfiguration,         /* preconfiguration */
    ngx_http_ssi_filter_init,              /* postconfiguration */

    ngx_http_ssi_create_main_conf,         /* create main configuration */
    ngx_http_ssi_init_main_conf,           /* init main configuration */

    NULL,                                  /* create server configuration */
    NULL,                                  /* merge server configuration */

    ngx_http_ssi_create_loc_conf,          /* create location configuration */
    ngx_http_ssi_merge_loc_conf            /* merge location configuration */
};


ngx_module_t  ngx_http_ssi_filter_module = {
    NGX_MODULE_V1,
    &ngx_http_ssi_filter_module_ctx,       /* module context */
    ngx_http_ssi_filter_commands,          /* module directives */
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


static u_char ngx_http_ssi_string[] = "<!--";

static ngx_str_t ngx_http_ssi_none = ngx_string("(none)");
static ngx_str_t ngx_http_ssi_null_string = ngx_null_string;


#define  NGX_HTTP_SSI_INCLUDE_VIRTUAL  0
#define  NGX_HTTP_SSI_INCLUDE_FILE     1
#define  NGX_HTTP_SSI_INCLUDE_WAIT     2
#define  NGX_HTTP_SSI_INCLUDE_SET      3
#define  NGX_HTTP_SSI_INCLUDE_STUB     4

#define  NGX_HTTP_SSI_ECHO_VAR         0
#define  NGX_HTTP_SSI_ECHO_DEFAULT     1
#define  NGX_HTTP_SSI_ECHO_ENCODING    2

#define  NGX_HTTP_SSI_CONFIG_ERRMSG    0
#define  NGX_HTTP_SSI_CONFIG_TIMEFMT   1

#define  NGX_HTTP_SSI_SET_VAR          0
#define  NGX_HTTP_SSI_SET_VALUE        1

#define  NGX_HTTP_SSI_IF_EXPR          0

#define  NGX_HTTP_SSI_BLOCK_NAME       0


static ngx_http_ssi_param_t  ngx_http_ssi_include_params[] = {
    { ngx_string("virtual"), NGX_HTTP_SSI_INCLUDE_VIRTUAL, 0, 0 },
    { ngx_string("file"), NGX_HTTP_SSI_INCLUDE_FILE, 0, 0 },
    { ngx_string("wait"), NGX_HTTP_SSI_INCLUDE_WAIT, 0, 0 },
    { ngx_string("set"), NGX_HTTP_SSI_INCLUDE_SET, 0, 0 },
    { ngx_string("stub"), NGX_HTTP_SSI_INCLUDE_STUB, 0, 0 },
    { ngx_null_string, 0, 0, 0 }
};


static ngx_http_ssi_param_t  ngx_http_ssi_echo_params[] = {
    { ngx_string("var"), NGX_HTTP_SSI_ECHO_VAR, 1, 0 },
    { ngx_string("default"), NGX_HTTP_SSI_ECHO_DEFAULT, 0, 0 },
    { ngx_string("encoding"), NGX_HTTP_SSI_ECHO_ENCODING, 0, 0 },
    { ngx_null_string, 0, 0, 0 }
};


static ngx_http_ssi_param_t  ngx_http_ssi_config_params[] = {
    { ngx_string("errmsg"), NGX_HTTP_SSI_CONFIG_ERRMSG, 0, 0 },
    { ngx_string("timefmt"), NGX_HTTP_SSI_CONFIG_TIMEFMT, 0, 0 },
    { ngx_null_string, 0, 0, 0 }
};


static ngx_http_ssi_param_t  ngx_http_ssi_set_params[] = {
    { ngx_string("var"), NGX_HTTP_SSI_SET_VAR, 1, 0 },
    { ngx_string("value"), NGX_HTTP_SSI_SET_VALUE, 1, 0 },
    { ngx_null_string, 0, 0, 0 }
};


static ngx_http_ssi_param_t  ngx_http_ssi_if_params[] = {
    { ngx_string("expr"), NGX_HTTP_SSI_IF_EXPR, 1, 0 },
    { ngx_null_string, 0, 0, 0 }
};


static ngx_http_ssi_param_t  ngx_http_ssi_block_params[] = {
    { ngx_string("name"), NGX_HTTP_SSI_BLOCK_NAME, 1, 0 },
    { ngx_null_string, 0, 0, 0 }
};


static ngx_http_ssi_param_t  ngx_http_ssi_no_params[] = {
    { ngx_null_string, 0, 0, 0 }
};


static ngx_http_ssi_command_t  ngx_http_ssi_commands[] = {
    { ngx_string("include"), ngx_http_ssi_include,
                       ngx_http_ssi_include_params, 0, 0, 1 },
    { ngx_string("echo"), ngx_http_ssi_echo,
                       ngx_http_ssi_echo_params, 0, 0, 0 },
    { ngx_string("config"), ngx_http_ssi_config,
                       ngx_http_ssi_config_params, 0, 0, 0 },
    { ngx_string("set"), ngx_http_ssi_set, ngx_http_ssi_set_params, 0, 0, 0 },

    { ngx_string("if"), ngx_http_ssi_if, ngx_http_ssi_if_params, 0, 0, 0 },
    { ngx_string("elif"), ngx_http_ssi_if, ngx_http_ssi_if_params,
                       NGX_HTTP_SSI_COND_IF, 0, 0 },
    { ngx_string("else"), ngx_http_ssi_else, ngx_http_ssi_no_params,
                       NGX_HTTP_SSI_COND_IF, 0, 0 },
    { ngx_string("endif"), ngx_http_ssi_endif, ngx_http_ssi_no_params,
                       NGX_HTTP_SSI_COND_ELSE, 0, 0 },

    { ngx_string("block"), ngx_http_ssi_block,
                       ngx_http_ssi_block_params, 0, 0, 0 },
    { ngx_string("endblock"), ngx_http_ssi_endblock,
                       ngx_http_ssi_no_params, 0, 1, 0 },

    { ngx_null_string, NULL, NULL, 0, 0, 0 }
};


static ngx_http_variable_t  ngx_http_ssi_vars[] = {

    { ngx_string("date_local"), NULL, ngx_http_ssi_date_gmt_local_variable, 0,
      NGX_HTTP_VAR_NOCACHEABLE, 0 },

    { ngx_string("date_gmt"), NULL, ngx_http_ssi_date_gmt_local_variable, 1,
      NGX_HTTP_VAR_NOCACHEABLE, 0 },

    { ngx_null_string, NULL, NULL, 0, 0, 0 }
};



static ngx_int_t
ngx_http_ssi_header_filter(ngx_http_request_t *r)
{
    ngx_http_ssi_ctx_t       *ctx;
    ngx_http_ssi_loc_conf_t  *slcf;

    slcf = ngx_http_get_module_loc_conf(r, ngx_http_ssi_filter_module);

    if (!slcf->enable
        || r->headers_out.content_length_n == 0
        || ngx_http_test_content_type(r, &slcf->types) == NULL)
    {
        return ngx_http_next_header_filter(r);
    }

    ctx = ngx_pcalloc(r->pool, sizeof(ngx_http_ssi_ctx_t));
    if (ctx == NULL) {
        return NGX_ERROR;
    }

    ngx_http_set_ctx(r, ctx, ngx_http_ssi_filter_module);


    ctx->value_len = slcf->value_len;
    ctx->last_out = &ctx->out;

    ctx->encoding = NGX_HTTP_SSI_ENTITY_ENCODING;
    ctx->output = 1;

    ctx->params.elts = ctx->params_array;
    ctx->params.size = sizeof(ngx_table_elt_t);
    ctx->params.nalloc = NGX_HTTP_SSI_PARAMS_N;
    ctx->params.pool = r->pool;

    ngx_str_set(&ctx->timefmt, "%A, %d-%b-%Y %H:%M:%S %Z");
    ngx_str_set(&ctx->errmsg,
                "[an error occurred while processing the directive]");

    r->filter_need_in_memory = 1;

    if (r == r->main) {
        ngx_http_clear_content_length(r);
        ngx_http_clear_last_modified(r);
        ngx_http_clear_accept_ranges(r);
    }

    return ngx_http_next_header_filter(r);
}


static ngx_int_t
ngx_http_ssi_body_filter(ngx_http_request_t *r, ngx_chain_t *in)
{
    size_t                     len;
    ngx_int_t                  rc;
    ngx_buf_t                 *b;
    ngx_uint_t                 i, index;
    ngx_chain_t               *cl, **ll;
    ngx_table_elt_t           *param;
    ngx_http_ssi_ctx_t        *ctx, *mctx;
    ngx_http_ssi_block_t      *bl;
    ngx_http_ssi_param_t      *prm;
    ngx_http_ssi_command_t    *cmd;
    ngx_http_ssi_loc_conf_t   *slcf;
    ngx_http_ssi_main_conf_t  *smcf;
    ngx_str_t                 *params[NGX_HTTP_SSI_MAX_PARAMS + 1];

    ctx = ngx_http_get_module_ctx(r, ngx_http_ssi_filter_module);

    if (ctx == NULL
        || (in == NULL
            && ctx->buf == NULL
            && ctx->in == NULL
            && ctx->busy == NULL))
    {
        return ngx_http_next_body_filter(r, in);
    }

    /* add the incoming chain to the chain ctx->in */

    if (in) {
        if (ngx_chain_add_copy(r->pool, &ctx->in, in) != NGX_OK) {
            return NGX_ERROR;
        }
    }

    ngx_log_debug2(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "http ssi filter \"%V?%V\"", &r->uri, &r->args);

    if (ctx->wait) {

        if (r != r->connection->data) {
            ngx_log_debug2(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                           "http ssi filter wait \"%V?%V\" non-active",
                           &ctx->wait->uri, &ctx->wait->args);

            return NGX_AGAIN;
        }

        if (ctx->wait->done) {
            ngx_log_debug2(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                           "http ssi filter wait \"%V?%V\" done",
                           &ctx->wait->uri, &ctx->wait->args);

            ctx->wait = NULL;

        } else {
            ngx_log_debug2(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                           "http ssi filter wait \"%V?%V\"",
                           &ctx->wait->uri, &ctx->wait->args);

            return ngx_http_next_body_filter(r, NULL);
        }
    }

    slcf = ngx_http_get_module_loc_conf(r, ngx_http_ssi_filter_module);

    while (ctx->in || ctx->buf) {

        if (ctx->buf == NULL) {
            ctx->buf = ctx->in->buf;
            ctx->in = ctx->in->next;
            ctx->pos = ctx->buf->pos;
        }

        if (ctx->state == ssi_start_state) {
            ctx->copy_start = ctx->pos;
            ctx->copy_end = ctx->pos;
        }

        b = NULL;

        while (ctx->pos < ctx->buf->last) {

            ngx_log_debug2(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                           "saved: %d state: %d", ctx->saved, ctx->state);

            rc = ngx_http_ssi_parse(r, ctx);

            ngx_log_debug4(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                           "parse: %d, looked: %d %p-%p",
                           rc, ctx->looked, ctx->copy_start, ctx->copy_end);

            if (rc == NGX_ERROR) {
                return rc;
            }

            if (ctx->copy_start != ctx->copy_end) {

                if (ctx->output) {

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
                        b->pos = ngx_http_ssi_string;
                        b->last = ngx_http_ssi_string + ctx->saved;

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
                        if (slcf->min_file_chunk < (size_t) (b->last - b->pos))
                        {
                            b->file_last = b->file_pos
                                                   + (b->last - ctx->buf->pos);
                            b->file_pos += b->pos - ctx->buf->pos;

                        } else {
                            b->in_file = 0;
                        }
                    }

                    cl->next = NULL;
                    *ctx->last_out = cl;
                    ctx->last_out = &cl->next;

                } else {
                    if (ctx->block
                        && ctx->saved + (ctx->copy_end - ctx->copy_start))
                    {
                        b = ngx_create_temp_buf(r->pool,
                               ctx->saved + (ctx->copy_end - ctx->copy_start));

                        if (b == NULL) {
                            return NGX_ERROR;
                        }

                        if (ctx->saved) {
                            b->last = ngx_cpymem(b->pos, ngx_http_ssi_string,
                                                 ctx->saved);
                        }

                        b->last = ngx_cpymem(b->last, ctx->copy_start,
                                             ctx->copy_end - ctx->copy_start);

                        cl = ngx_alloc_chain_link(r->pool);
                        if (cl == NULL) {
                            return NGX_ERROR;
                        }

                        cl->buf = b;
                        cl->next = NULL;

                        b = NULL;

                        mctx = ngx_http_get_module_ctx(r->main,
                                                   ngx_http_ssi_filter_module);
                        bl = mctx->blocks->elts;
                        for (ll = &bl[mctx->blocks->nelts - 1].bufs;
                             *ll;
                             ll = &(*ll)->next)
                        {
                            /* void */
                        }

                        *ll = cl;
                    }

                    ctx->saved = 0;
                }
            }

            if (ctx->state == ssi_start_state) {
                ctx->copy_start = ctx->pos;
                ctx->copy_end = ctx->pos;

            } else {
                ctx->copy_start = NULL;
                ctx->copy_end = NULL;
            }

            if (rc == NGX_AGAIN) {
                continue;
            }


            b = NULL;

            if (rc == NGX_OK) {

                smcf = ngx_http_get_module_main_conf(r,
                                                   ngx_http_ssi_filter_module);

                cmd = ngx_hash_find(&smcf->hash, ctx->key, ctx->command.data,
                                    ctx->command.len);

                if (cmd == NULL) {
                    if (ctx->output) {
                        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                                      "invalid SSI command: \"%V\"",
                                      &ctx->command);
                        goto ssi_error;
                    }

                    continue;
                }

                if (cmd->conditional
                    && (ctx->conditional == 0
                        || ctx->conditional > cmd->conditional))
                {
                    ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                                  "invalid context of SSI command: \"%V\"",
                                  &ctx->command);
                    goto ssi_error;
                }

                if (!ctx->output && !cmd->block) {

                    if (ctx->block) {

                        /* reconstruct the SSI command text */

                        len = 5 + ctx->command.len + 4;

                        param = ctx->params.elts;
                        for (i = 0; i < ctx->params.nelts; i++) {
                            len += 1 + param[i].key.len + 2
                                + param[i].value.len + 1;
                        }

                        b = ngx_create_temp_buf(r->pool, len);

                        if (b == NULL) {
                            return NGX_ERROR;
                        }

                        cl = ngx_alloc_chain_link(r->pool);
                        if (cl == NULL) {
                            return NGX_ERROR;
                        }

                        cl->buf = b;
                        cl->next = NULL;

                        *b->last++ = '<';
                        *b->last++ = '!';
                        *b->last++ = '-';
                        *b->last++ = '-';
                        *b->last++ = '#';

                        b->last = ngx_cpymem(b->last, ctx->command.data,
                                             ctx->command.len);

                        for (i = 0; i < ctx->params.nelts; i++) {
                            *b->last++ = ' ';
                            b->last = ngx_cpymem(b->last, param[i].key.data,
                                                 param[i].key.len);
                            *b->last++ = '=';
                            *b->last++ = '"';
                            b->last = ngx_cpymem(b->last, param[i].value.data,
                                                 param[i].value.len);
                            *b->last++ = '"';
                        }

                        *b->last++ = ' ';
                        *b->last++ = '-';
                        *b->last++ = '-';
                        *b->last++ = '>';

                        mctx = ngx_http_get_module_ctx(r->main,
                                                   ngx_http_ssi_filter_module);
                        bl = mctx->blocks->elts;
                        for (ll = &bl[mctx->blocks->nelts - 1].bufs;
                             *ll;
                             ll = &(*ll)->next)
                        {
                            /* void */
                        }

                        *ll = cl;

                        b = NULL;

                        continue;
                    }

                    if (cmd->conditional == 0) {
                        continue;
                    }
                }

                if (ctx->params.nelts > NGX_HTTP_SSI_MAX_PARAMS) {
                    ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                                  "too many SSI command paramters: \"%V\"",
                                  &ctx->command);
                    goto ssi_error;
                }

                ngx_memzero(params,
                           (NGX_HTTP_SSI_MAX_PARAMS + 1) * sizeof(ngx_str_t *));

                param = ctx->params.elts;

                for (i = 0; i < ctx->params.nelts; i++) {

                    for (prm = cmd->params; prm->name.len; prm++) {

                        if (param[i].key.len != prm->name.len
                            || ngx_strncmp(param[i].key.data, prm->name.data,
                                           prm->name.len) != 0)
                        {
                            continue;
                        }

                        if (!prm->multiple) {
                            if (params[prm->index]) {
                                ngx_log_error(NGX_LOG_ERR,
                                              r->connection->log, 0,
                                              "duplicate \"%V\" parameter "
                                              "in \"%V\" SSI command",
                                              &param[i].key, &ctx->command);

                                goto ssi_error;
                            }

                            params[prm->index] = &param[i].value;

                            break;
                        }

                        for (index = prm->index; params[index]; index++) {
                            /* void */
                        }

                        params[index] = &param[i].value;

                        break;
                    }

                    if (prm->name.len == 0) {
                        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                                      "invalid parameter name: \"%V\" "
                                      "in \"%V\" SSI command",
                                      &param[i].key, &ctx->command);

                        goto ssi_error;
                    }
                }

                for (prm = cmd->params; prm->name.len; prm++) {
                    if (prm->mandatory && params[prm->index] == 0) {
                        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                                      "mandatory \"%V\" parameter is absent "
                                      "in \"%V\" SSI command",
                                      &prm->name, &ctx->command);

                        goto ssi_error;
                    }
                }

                if (cmd->flush && ctx->out) {

                    ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                                   "ssi flush");

                    if (ngx_http_ssi_output(r, ctx) == NGX_ERROR) {
                        return NGX_ERROR;
                    }
                }

                rc = cmd->handler(r, ctx, params);

                if (rc == NGX_OK) {
                    continue;
                }

                if (rc == NGX_DONE || rc == NGX_AGAIN || rc == NGX_ERROR) {
                    ngx_http_ssi_buffered(r, ctx);
                    return rc;
                }
            }


            /* rc == NGX_HTTP_SSI_ERROR */

    ssi_error:

            if (slcf->silent_errors) {
                continue;
            }

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
            b->pos = ctx->errmsg.data;
            b->last = ctx->errmsg.data + ctx->errmsg.len;

            cl->next = NULL;
            *ctx->last_out = cl;
            ctx->last_out = &cl->next;

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

            if (slcf->ignore_recycled_buffers == 0)  {
                b->recycled = ctx->buf->recycled;
            }
        }

        ctx->buf = NULL;

        ctx->saved = ctx->looked;
    }

    if (ctx->out == NULL && ctx->busy == NULL) {
        return NGX_OK;
    }

    return ngx_http_ssi_output(r, ctx);
}


static ngx_int_t
ngx_http_ssi_output(ngx_http_request_t *r, ngx_http_ssi_ctx_t *ctx)
{
    ngx_int_t     rc;
    ngx_buf_t    *b;
    ngx_chain_t  *cl;

#if 1
    b = NULL;
    for (cl = ctx->out; cl; cl = cl->next) {
        ngx_log_debug2(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                       "ssi out: %p %p", cl->buf, cl->buf->pos);
        if (cl->buf == b) {
            ngx_log_error(NGX_LOG_ALERT, r->connection->log, 0,
                          "the same buf was used in ssi");
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

    ngx_http_ssi_buffered(r, ctx);

    return rc;
}


static void
ngx_http_ssi_buffered(ngx_http_request_t *r, ngx_http_ssi_ctx_t *ctx)
{
    if (ctx->in || ctx->buf) {
        r->buffered |= NGX_HTTP_SSI_BUFFERED;

    } else {
        r->buffered &= ~NGX_HTTP_SSI_BUFFERED;
    }
}


static ngx_int_t
ngx_http_ssi_parse(ngx_http_request_t *r, ngx_http_ssi_ctx_t *ctx)
{
    u_char                *p, *value, *last, *copy_end, ch;
    size_t                 looked;
    ngx_http_ssi_state_e   state;

    state = ctx->state;
    looked = ctx->looked;
    last = ctx->buf->last;
    copy_end = ctx->copy_end;

    for (p = ctx->pos; p < last; p++) {

        ch = *p;

        if (state == ssi_start_state) {

            /* the tight loop */

            for ( ;; ) {
                if (ch == '<') {
                    copy_end = p;
                    looked = 1;
                    state = ssi_tag_state;

                    goto tag_started;
                }

                if (++p == last) {
                    break;
                }

                ch = *p;
            }

            ctx->state = state;
            ctx->pos = p;
            ctx->looked = looked;
            ctx->copy_end = p;

            if (ctx->copy_start == NULL) {
                ctx->copy_start = ctx->buf->pos;
            }

            return NGX_AGAIN;

        tag_started:

            continue;
        }

        switch (state) {

        case ssi_start_state:
            break;

        case ssi_tag_state:
            switch (ch) {
            case '!':
                looked = 2;
                state = ssi_comment0_state;
                break;

            case '<':
                copy_end = p;
                break;

            default:
                copy_end = p;
                looked = 0;
                state = ssi_start_state;
                break;
            }

            break;

        case ssi_comment0_state:
            switch (ch) {
            case '-':
                looked = 3;
                state = ssi_comment1_state;
                break;

            case '<':
                copy_end = p;
                looked = 1;
                state = ssi_tag_state;
                break;

            default:
                copy_end = p;
                looked = 0;
                state = ssi_start_state;
                break;
            }

            break;

        case ssi_comment1_state:
            switch (ch) {
            case '-':
                looked = 4;
                state = ssi_sharp_state;
                break;

            case '<':
                copy_end = p;
                looked = 1;
                state = ssi_tag_state;
                break;

            default:
                copy_end = p;
                looked = 0;
                state = ssi_start_state;
                break;
            }

            break;

        case ssi_sharp_state:
            switch (ch) {
            case '#':
                if (p - ctx->pos < 4) {
                    ctx->saved = 0;
                }
                looked = 0;
                state = ssi_precommand_state;
                break;

            case '<':
                copy_end = p;
                looked = 1;
                state = ssi_tag_state;
                break;

            default:
                copy_end = p;
                looked = 0;
                state = ssi_start_state;
                break;
            }

            break;

        case ssi_precommand_state:
            switch (ch) {
            case ' ':
            case CR:
            case LF:
            case '\t':
                break;

            default:
                ctx->command.len = 1;
                ctx->command.data = ngx_pnalloc(r->pool,
                                                NGX_HTTP_SSI_COMMAND_LEN);
                if (ctx->command.data == NULL) {
                    return NGX_ERROR;
                }

                ctx->command.data[0] = ch;

                ctx->key = 0;
                ctx->key = ngx_hash(ctx->key, ch);

                ctx->params.nelts = 0;

                state = ssi_command_state;
                break;
            }

            break;

        case ssi_command_state:
            switch (ch) {
            case ' ':
            case CR:
            case LF:
            case '\t':
                state = ssi_preparam_state;
                break;

            case '-':
                state = ssi_comment_end0_state;
                break;

            default:
                if (ctx->command.len == NGX_HTTP_SSI_COMMAND_LEN) {
                    ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                                  "the \"%V%c...\" SSI command is too long",
                                  &ctx->command, ch);

                    state = ssi_error_state;
                    break;
                }

                ctx->command.data[ctx->command.len++] = ch;
                ctx->key = ngx_hash(ctx->key, ch);
            }

            break;

        case ssi_preparam_state:
            switch (ch) {
            case ' ':
            case CR:
            case LF:
            case '\t':
                break;

            case '-':
                state = ssi_comment_end0_state;
                break;

            default:
                ctx->param = ngx_array_push(&ctx->params);
                if (ctx->param == NULL) {
                    return NGX_ERROR;
                }

                ctx->param->key.len = 1;
                ctx->param->key.data = ngx_pnalloc(r->pool,
                                                   NGX_HTTP_SSI_PARAM_LEN);
                if (ctx->param->key.data == NULL) {
                    return NGX_ERROR;
                }

                ctx->param->key.data[0] = ch;

                ctx->param->value.len = 0;

                if (ctx->value_buf == NULL) {
                    ctx->param->value.data = ngx_pnalloc(r->pool,
                                                         ctx->value_len);
                    if (ctx->param->value.data == NULL) {
                        return NGX_ERROR;
                    }

                } else {
                    ctx->param->value.data = ctx->value_buf;
                }

                state = ssi_param_state;
                break;
            }

            break;

        case ssi_param_state:
            switch (ch) {
            case ' ':
            case CR:
            case LF:
            case '\t':
                state = ssi_preequal_state;
                break;

            case '=':
                state = ssi_prevalue_state;
                break;

            case '-':
                state = ssi_error_end0_state;

                ctx->param->key.data[ctx->param->key.len++] = ch;
                ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                              "invalid \"%V\" parameter in \"%V\" SSI command",
                              &ctx->param->key, &ctx->command);
                break;

            default:
                if (ctx->param->key.len == NGX_HTTP_SSI_PARAM_LEN) {
                    state = ssi_error_state;
                    ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                                  "too long \"%V%c...\" parameter in "
                                  "\"%V\" SSI command",
                                  &ctx->param->key, ch, &ctx->command);
                    break;
                }

                ctx->param->key.data[ctx->param->key.len++] = ch;
            }

            break;

        case ssi_preequal_state:
            switch (ch) {
            case ' ':
            case CR:
            case LF:
            case '\t':
                break;

            case '=':
                state = ssi_prevalue_state;
                break;

            default:
                if (ch == '-') {
                    state = ssi_error_end0_state;
                } else {
                    state = ssi_error_state;
                }

                ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                              "unexpected \"%c\" symbol after \"%V\" "
                              "parameter in \"%V\" SSI command",
                              ch, &ctx->param->key, &ctx->command);
                break;
            }

            break;

        case ssi_prevalue_state:
            switch (ch) {
            case ' ':
            case CR:
            case LF:
            case '\t':
                break;

            case '"':
                state = ssi_double_quoted_value_state;
                break;

            case '\'':
                state = ssi_quoted_value_state;
                break;

            default:
                if (ch == '-') {
                    state = ssi_error_end0_state;
                } else {
                    state = ssi_error_state;
                }

                ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                              "unexpected \"%c\" symbol before value of "
                              "\"%V\" parameter in \"%V\" SSI command",
                              ch, &ctx->param->key, &ctx->command);
                break;
            }

            break;

        case ssi_double_quoted_value_state:
            switch (ch) {
            case '"':
                state = ssi_postparam_state;
                break;

            case '\\':
                ctx->saved_state = ssi_double_quoted_value_state;
                state = ssi_quoted_symbol_state;

                /* fall through */

            default:
                if (ctx->param->value.len == ctx->value_len) {
                    ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                                  "too long \"%V%c...\" value of \"%V\" "
                                  "parameter in \"%V\" SSI command",
                                  &ctx->param->value, ch, &ctx->param->key,
                                  &ctx->command);
                    state = ssi_error_state;
                    break;
                }

                ctx->param->value.data[ctx->param->value.len++] = ch;
            }

            break;

        case ssi_quoted_value_state:
            switch (ch) {
            case '\'':
                state = ssi_postparam_state;
                break;

            case '\\':
                ctx->saved_state = ssi_quoted_value_state;
                state = ssi_quoted_symbol_state;

                /* fall through */

            default:
                if (ctx->param->value.len == ctx->value_len) {
                    ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                                  "too long \"%V%c...\" value of \"%V\" "
                                  "parameter in \"%V\" SSI command",
                                  &ctx->param->value, ch, &ctx->param->key,
                                  &ctx->command);
                    state = ssi_error_state;
                    break;
                }

                ctx->param->value.data[ctx->param->value.len++] = ch;
            }

            break;

        case ssi_quoted_symbol_state:
            state = ctx->saved_state;

            ctx->param->value.data[ctx->param->value.len++] = ch;

            break;

        case ssi_postparam_state:

            if (ctx->param->value.len + 1 < ctx->value_len / 2) {
                value = ngx_pnalloc(r->pool, ctx->param->value.len + 1);
                if (value == NULL) {
                    return NGX_ERROR;
                }

                ngx_memcpy(value, ctx->param->value.data,
                           ctx->param->value.len);

                ctx->value_buf = ctx->param->value.data;
                ctx->param->value.data = value;

            } else {
                ctx->value_buf = NULL;
            }

            switch (ch) {
            case ' ':
            case CR:
            case LF:
            case '\t':
                state = ssi_preparam_state;
                break;

            case '-':
                state = ssi_comment_end0_state;
                break;

            default:
                ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                              "unexpected \"%c\" symbol after \"%V\" value "
                              "of \"%V\" parameter in \"%V\" SSI command",
                              ch, &ctx->param->value, &ctx->param->key,
                              &ctx->command);
                state = ssi_error_state;
                break;
            }

            break;

        case ssi_comment_end0_state:
            switch (ch) {
            case '-':
                state = ssi_comment_end1_state;
                break;

            default:
                ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                              "unexpected \"%c\" symbol in \"%V\" SSI command",
                              ch, &ctx->command);
                state = ssi_error_state;
                break;
            }

            break;

        case ssi_comment_end1_state:
            switch (ch) {
            case '>':
                ctx->state = ssi_start_state;
                ctx->pos = p + 1;
                ctx->looked = looked;
                ctx->copy_end = copy_end;

                if (ctx->copy_start == NULL && copy_end) {
                    ctx->copy_start = ctx->buf->pos;
                }

                return NGX_OK;

            default:
                ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                              "unexpected \"%c\" symbol in \"%V\" SSI command",
                              ch, &ctx->command);
                state = ssi_error_state;
                break;
            }

            break;

        case ssi_error_state:
            switch (ch) {
            case '-':
                state = ssi_error_end0_state;
                break;

            default:
                break;
            }

            break;

        case ssi_error_end0_state:
            switch (ch) {
            case '-':
                state = ssi_error_end1_state;
                break;

            default:
                state = ssi_error_state;
                break;
            }

            break;

        case ssi_error_end1_state:
            switch (ch) {
            case '>':
                ctx->state = ssi_start_state;
                ctx->pos = p + 1;
                ctx->looked = looked;
                ctx->copy_end = copy_end;

                if (ctx->copy_start == NULL && copy_end) {
                    ctx->copy_start = ctx->buf->pos;
                }

                return NGX_HTTP_SSI_ERROR;

            default:
                state = ssi_error_state;
                break;
            }

            break;
        }
    }

    ctx->state = state;
    ctx->pos = p;
    ctx->looked = looked;

    ctx->copy_end = (state == ssi_start_state) ? p : copy_end;

    if (ctx->copy_start == NULL && ctx->copy_end) {
        ctx->copy_start = ctx->buf->pos;
    }

    return NGX_AGAIN;
}


static ngx_str_t *
ngx_http_ssi_get_variable(ngx_http_request_t *r, ngx_str_t *name,
    ngx_uint_t key)
{
    ngx_uint_t           i;
    ngx_list_part_t     *part;
    ngx_http_ssi_var_t  *var;
    ngx_http_ssi_ctx_t  *ctx;

    ctx = ngx_http_get_module_ctx(r->main, ngx_http_ssi_filter_module);

    if (ctx->variables == NULL) {
        return NULL;
    }

    part = &ctx->variables->part;
    var = part->elts;

    for (i = 0; /* void */ ; i++) {

        if (i >= part->nelts) {
            if (part->next == NULL) {
                break;
            }

            part = part->next;
            var = part->elts;
            i = 0;
        }

        if (name->len != var[i].name.len) {
            continue;
        }

        if (key != var[i].key) {
            continue;
        }

        if (ngx_strncmp(name->data, var[i].name.data, name->len) == 0) {
            return &var[i].value;
        }
    }

    return NULL;
}


static ngx_int_t
ngx_http_ssi_evaluate_string(ngx_http_request_t *r, ngx_http_ssi_ctx_t *ctx,
    ngx_str_t *text, ngx_uint_t flags)
{
    u_char                      ch, *p, **value, *data, *part_data;
    size_t                     *size, len, prefix, part_len;
    ngx_str_t                   var, *val;
    ngx_int_t                   key;
    ngx_uint_t                  i, n, bracket, quoted;
    ngx_array_t                 lengths, values;
    ngx_http_variable_value_t  *vv;

    n = ngx_http_script_variables_count(text);

    if (n == 0) {

        data = text->data;
        p = data;

        if ((flags & NGX_HTTP_SSI_ADD_PREFIX) && text->data[0] != '/') {

            for (prefix = r->uri.len; prefix; prefix--) {
                if (r->uri.data[prefix - 1] == '/') {
                    break;
                }
            }

            if (prefix) {
                len = prefix + text->len;

                data = ngx_pnalloc(r->pool, len);
                if (data == NULL) {
                    return NGX_ERROR;
                }

                p = ngx_copy(data, r->uri.data, prefix);
            }
        }

        quoted = 0;

        for (i = 0; i < text->len; i++) {
            ch = text->data[i];

            if (!quoted) {

                if (ch == '\\') {
                    quoted = 1;
                    continue;
                }

            } else {
                quoted = 0;

                if (ch != '\\' && ch != '\'' && ch != '"' && ch != '$') {
                    *p++ = '\\';
                }
            }

            *p++ = ch;
        }

        text->len = p - data;
        text->data = data;

        return NGX_OK;
    }

    if (ngx_array_init(&lengths, r->pool, 8, sizeof(size_t *)) != NGX_OK) {
        return NGX_ERROR;
    }

    if (ngx_array_init(&values, r->pool, 8, sizeof(u_char *)) != NGX_OK) {
        return NGX_ERROR;
    }

    len = 0;
    i = 0;

    while (i < text->len) {

        if (text->data[i] == '$') {

            var.len = 0;

            if (++i == text->len) {
                goto invalid_variable;
            }

            if (text->data[i] == '{') {
                bracket = 1;

                if (++i == text->len) {
                    goto invalid_variable;
                }

                var.data = &text->data[i];

            } else {
                bracket = 0;
                var.data = &text->data[i];
            }

            for ( /* void */ ; i < text->len; i++, var.len++) {
                ch = text->data[i];

                if (ch == '}' && bracket) {
                    i++;
                    bracket = 0;
                    break;
                }

                if ((ch >= 'A' && ch <= 'Z')
                    || (ch >= 'a' && ch <= 'z')
                    || (ch >= '0' && ch <= '9')
                    || ch == '_')
                {
                    continue;
                }

                break;
            }

            if (bracket) {
                ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                              "the closing bracket in \"%V\" "
                              "variable is missing", &var);
                return NGX_HTTP_SSI_ERROR;
            }

            if (var.len == 0) {
                goto invalid_variable;
            }

            key = ngx_hash_strlow(var.data, var.data, var.len);

            val = ngx_http_ssi_get_variable(r, &var, key);

            if (val == NULL) {
                vv = ngx_http_get_variable(r, &var, key);
                if (vv == NULL) {
                    return NGX_ERROR;
                }

                if (vv->not_found) {
                    continue;
                }

                part_data = vv->data;
                part_len = vv->len;

            } else {
                part_data = val->data;
                part_len = val->len;
            }

        } else {
            part_data = &text->data[i];
            quoted = 0;

            for (p = part_data; i < text->len; i++) {
                ch = text->data[i];

                if (!quoted) {

                    if (ch == '\\') {
                        quoted = 1;
                        continue;
                    }

                    if (ch == '$') {
                        break;
                    }

                } else {
                    quoted = 0;

                    if (ch != '\\' && ch != '\'' && ch != '"' && ch != '$') {
                        *p++ = '\\';
                    }
                }

                *p++ = ch;
            }

            part_len = p - part_data;
        }

        len += part_len;

        size = ngx_array_push(&lengths);
        if (size == NULL) {
            return NGX_ERROR;
        }

        *size = part_len;

        value = ngx_array_push(&values);
        if (value == NULL) {
            return NGX_ERROR;
        }

        *value = part_data;
    }

    prefix = 0;

    size = lengths.elts;
    value = values.elts;

    if (flags & NGX_HTTP_SSI_ADD_PREFIX) {
        for (i = 0; i < values.nelts; i++) {
            if (size[i] != 0) {
                if (*value[i] != '/') {
                    for (prefix = r->uri.len; prefix; prefix--) {
                        if (r->uri.data[prefix - 1] == '/') {
                            len += prefix;
                            break;
                        }
                    }
                }

                break;
            }
        }
    }

    p = ngx_pnalloc(r->pool, len + ((flags & NGX_HTTP_SSI_ADD_ZERO) ? 1 : 0));
    if (p == NULL) {
        return NGX_ERROR;
    }

    text->len = len;
    text->data = p;

    p = ngx_copy(p, r->uri.data, prefix);

    for (i = 0; i < values.nelts; i++) {
        p = ngx_copy(p, value[i], size[i]);
    }

    return NGX_OK;

invalid_variable:

    ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                  "invalid variable name in \"%V\"", text);

    return NGX_HTTP_SSI_ERROR;
}


static ngx_int_t
ngx_http_ssi_include(ngx_http_request_t *r, ngx_http_ssi_ctx_t *ctx,
    ngx_str_t **params)
{
    u_char                      *dst, *src;
    size_t                       len;
    ngx_int_t                    rc, key;
    ngx_str_t                   *uri, *file, *wait, *set, *stub, args;
    ngx_buf_t                   *b;
    ngx_uint_t                   flags, i;
    ngx_chain_t                 *cl, *tl, **ll, *out;
    ngx_http_request_t          *sr;
    ngx_http_ssi_var_t          *var;
    ngx_http_ssi_ctx_t          *mctx;
    ngx_http_ssi_block_t        *bl;
    ngx_http_post_subrequest_t  *psr;

    uri = params[NGX_HTTP_SSI_INCLUDE_VIRTUAL];
    file = params[NGX_HTTP_SSI_INCLUDE_FILE];
    wait = params[NGX_HTTP_SSI_INCLUDE_WAIT];
    set = params[NGX_HTTP_SSI_INCLUDE_SET];
    stub = params[NGX_HTTP_SSI_INCLUDE_STUB];

    if (uri && file) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                      "inlcusion may be either virtual=\"%V\" or file=\"%V\"",
                      uri, file);
        return NGX_HTTP_SSI_ERROR;
    }

    if (uri == NULL && file == NULL) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                      "no parameter in \"include\" SSI command");
        return NGX_HTTP_SSI_ERROR;
    }

    if (set && stub) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                      "\"set\" and \"stub\" may not be used together "
                      "in \"include\" SSI command");
        return NGX_HTTP_SSI_ERROR;
    }

    if (wait) {
        if (uri == NULL) {
            ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                          "\"wait\" may not be used with file=\"%V\"", file);
            return NGX_HTTP_SSI_ERROR;
        }

        if (wait->len == 2
            && ngx_strncasecmp(wait->data, (u_char *) "no", 2) == 0)
        {
            wait = NULL;

        } else if (wait->len != 3
                   || ngx_strncasecmp(wait->data, (u_char *) "yes", 3) != 0)
        {
            ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                          "invalid value \"%V\" in the \"wait\" parameter",
                          wait);
            return NGX_HTTP_SSI_ERROR;
        }
    }

    if (uri == NULL) {
        uri = file;
        wait = (ngx_str_t *) -1;
    }

    rc = ngx_http_ssi_evaluate_string(r, ctx, uri, NGX_HTTP_SSI_ADD_PREFIX);

    if (rc != NGX_OK) {
        return rc;
    }

    dst = uri->data;
    src = uri->data;

    ngx_unescape_uri(&dst, &src, uri->len, NGX_UNESCAPE_URI);

    len = (uri->data + uri->len) - src;
    if (len) {
        dst = ngx_copy(dst, src, len);
    }

    uri->len = dst - uri->data;

    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "ssi include: \"%V\"", uri);

    ngx_str_null(&args);
    flags = NGX_HTTP_LOG_UNSAFE;

    if (ngx_http_parse_unsafe_uri(r, uri, &args, &flags) != NGX_OK) {
        return NGX_HTTP_SSI_ERROR;
    }

    psr = NULL;

    mctx = ngx_http_get_module_ctx(r->main, ngx_http_ssi_filter_module);

    if (stub) {
        if (mctx->blocks) {
            bl = mctx->blocks->elts;
            for (i = 0; i < mctx->blocks->nelts; i++) {
                if (stub->len == bl[i].name.len
                    && ngx_strncmp(stub->data, bl[i].name.data, stub->len) == 0)
                {
                    goto found;
                }
            }
        }

        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                      "\"stub\"=\"%V\" for \"include\" not found", stub);
        return NGX_HTTP_SSI_ERROR;

    found:

        psr = ngx_palloc(r->pool, sizeof(ngx_http_post_subrequest_t));
        if (psr == NULL) {
            return NGX_ERROR;
        }

        psr->handler = ngx_http_ssi_stub_output;

        if (bl[i].count++) {

            out = NULL;
            ll = &out;

            for (tl = bl[i].bufs; tl; tl = tl->next) {

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

                ngx_memcpy(b, tl->buf, sizeof(ngx_buf_t));

                b->pos = b->start;

                *ll = cl;
                cl->next = NULL;
                ll = &cl->next;
            }

            psr->data = out;

        } else {
            psr->data = bl[i].bufs;
        }
    }

    if (wait) {
        flags |= NGX_HTTP_SUBREQUEST_WAITED;
    }

    if (set) {
        key = ngx_hash_strlow(set->data, set->data, set->len);

        psr = ngx_palloc(r->pool, sizeof(ngx_http_post_subrequest_t));
        if (psr == NULL) {
            return NGX_ERROR;
        }

        psr->handler = ngx_http_ssi_set_variable;
        psr->data = ngx_http_ssi_get_variable(r, set, key);

        if (psr->data == NULL) {

            if (mctx->variables == NULL) {
                mctx->variables = ngx_list_create(r->pool, 4,
                                                  sizeof(ngx_http_ssi_var_t));
                if (mctx->variables == NULL) {
                    return NGX_ERROR;
                }
            }

            var = ngx_list_push(mctx->variables);
            if (var == NULL) {
                return NGX_ERROR;
            }

            var->name = *set;
            var->key = key;
            var->value = ngx_http_ssi_null_string;
            psr->data = &var->value;
        }

        flags |= NGX_HTTP_SUBREQUEST_IN_MEMORY|NGX_HTTP_SUBREQUEST_WAITED;
    }

    if (ngx_http_subrequest(r, uri, &args, &sr, psr, flags) != NGX_OK) {
        return NGX_HTTP_SSI_ERROR;
    }

    if (wait == NULL && set == NULL) {
        return NGX_OK;
    }

    if (ctx->wait == NULL) {
        ctx->wait = sr;

        return NGX_AGAIN;

    } else {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                      "only one subrequest may be waited at the same time");
    }

    return NGX_OK;
}


static ngx_int_t
ngx_http_ssi_stub_output(ngx_http_request_t *r, void *data, ngx_int_t rc)
{
    ngx_chain_t  *out;

    if (rc == NGX_ERROR || r->connection->error || r->request_output) {
        return rc;
    }

    ngx_log_debug2(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "ssi stub output: \"%V?%V\"", &r->uri, &r->args);

    out = data;

    if (!r->header_sent) {
        r->headers_out.content_type_len =
                                      r->parent->headers_out.content_type_len;
        r->headers_out.content_type = r->parent->headers_out.content_type;

        if (ngx_http_send_header(r) == NGX_ERROR) {
            return NGX_ERROR;
        }
    }

    return ngx_http_output_filter(r, out);
}


static ngx_int_t
ngx_http_ssi_set_variable(ngx_http_request_t *r, void *data, ngx_int_t rc)
{
    ngx_str_t  *value = data;

    if (r->upstream) {
        value->len = r->upstream->buffer.last - r->upstream->buffer.pos;
        value->data = r->upstream->buffer.pos;
    }

    return rc;
}


static ngx_int_t
ngx_http_ssi_echo(ngx_http_request_t *r, ngx_http_ssi_ctx_t *ctx,
    ngx_str_t **params)
{
    u_char                     *p;
    uintptr_t                   len;
    ngx_int_t                   key;
    ngx_buf_t                  *b;
    ngx_str_t                  *var, *value, *enc, text;
    ngx_chain_t                *cl;
    ngx_http_variable_value_t  *vv;

    var = params[NGX_HTTP_SSI_ECHO_VAR];

    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "ssi echo \"%V\"", var);

    key = ngx_hash_strlow(var->data, var->data, var->len);

    value = ngx_http_ssi_get_variable(r, var, key);

    if (value == NULL) {
        vv = ngx_http_get_variable(r, var, key);

        if (vv == NULL) {
            return NGX_HTTP_SSI_ERROR;
        }

        if (!vv->not_found) {
            text.data = vv->data;
            text.len = vv->len;
            value = &text;
        }
    }

    if (value == NULL) {
        value = params[NGX_HTTP_SSI_ECHO_DEFAULT];

        if (value == NULL) {
            value = &ngx_http_ssi_none;

        } else if (value->len == 0) {
            return NGX_OK;
        }

    } else {
        if (value->len == 0) {
            return NGX_OK;
        }
    }

    enc = params[NGX_HTTP_SSI_ECHO_ENCODING];

    if (enc) {
        if (enc->len == 4 && ngx_strncmp(enc->data, "none", 4) == 0) {

            ctx->encoding = NGX_HTTP_SSI_NO_ENCODING;

        } else if (enc->len == 3 && ngx_strncmp(enc->data, "url", 3) == 0) {

            ctx->encoding = NGX_HTTP_SSI_URL_ENCODING;

        } else if (enc->len == 6 && ngx_strncmp(enc->data, "entity", 6) == 0) {

            ctx->encoding = NGX_HTTP_SSI_ENTITY_ENCODING;

        } else {
            ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                          "unknown encoding \"%V\" in the \"echo\" command",
                          enc);
        }
    }

    p = value->data;

    switch (ctx->encoding) {

    case NGX_HTTP_SSI_URL_ENCODING:
        len = 2 * ngx_escape_uri(NULL, value->data, value->len,
                                 NGX_ESCAPE_HTML);

        if (len) {
            p = ngx_pnalloc(r->pool, value->len + len);
            if (p == NULL) {
                return NGX_HTTP_SSI_ERROR;
            }

            (void) ngx_escape_uri(p, value->data, value->len, NGX_ESCAPE_HTML);
        }

        len += value->len;
        break;

    case NGX_HTTP_SSI_ENTITY_ENCODING:
        len = ngx_escape_html(NULL, value->data, value->len);

        if (len) {
            p = ngx_pnalloc(r->pool, value->len + len);
            if (p == NULL) {
                return NGX_HTTP_SSI_ERROR;
            }

            (void) ngx_escape_html(p, value->data, value->len);
        }

        len += value->len;
        break;

    default: /* NGX_HTTP_SSI_NO_ENCODING */
        len = value->len;
        break;
    }

    b = ngx_calloc_buf(r->pool);
    if (b == NULL) {
        return NGX_HTTP_SSI_ERROR;
    }

    cl = ngx_alloc_chain_link(r->pool);
    if (cl == NULL) {
        return NGX_HTTP_SSI_ERROR;
    }

    b->memory = 1;
    b->pos = p;
    b->last = p + len;

    cl->buf = b;
    cl->next = NULL;
    *ctx->last_out = cl;
    ctx->last_out = &cl->next;

    return NGX_OK;
}


static ngx_int_t
ngx_http_ssi_config(ngx_http_request_t *r, ngx_http_ssi_ctx_t *ctx,
    ngx_str_t **params)
{
    ngx_str_t  *value;

    value = params[NGX_HTTP_SSI_CONFIG_TIMEFMT];

    if (value) {
        ctx->timefmt.len = value->len;
        ctx->timefmt.data = ngx_pnalloc(r->pool, value->len + 1);
        if (ctx->timefmt.data == NULL) {
            return NGX_HTTP_SSI_ERROR;
        }

        ngx_cpystrn(ctx->timefmt.data, value->data, value->len + 1);
    }

    value = params[NGX_HTTP_SSI_CONFIG_ERRMSG];

    if (value) {
        ctx->errmsg = *value;
    }

    return NGX_OK;
}


static ngx_int_t
ngx_http_ssi_set(ngx_http_request_t *r, ngx_http_ssi_ctx_t *ctx,
    ngx_str_t **params)
{
    ngx_int_t            key, rc;
    ngx_str_t           *name, *value, *vv;
    ngx_http_ssi_var_t  *var;
    ngx_http_ssi_ctx_t  *mctx;

    mctx = ngx_http_get_module_ctx(r->main, ngx_http_ssi_filter_module);

    if (mctx->variables == NULL) {
        mctx->variables = ngx_list_create(r->pool, 4,
                                          sizeof(ngx_http_ssi_var_t));
        if (mctx->variables == NULL) {
            return NGX_ERROR;
        }
    }

    name = params[NGX_HTTP_SSI_SET_VAR];
    value = params[NGX_HTTP_SSI_SET_VALUE];

    ngx_log_debug2(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "ssi set \"%V\" \"%V\"", name, value);

    rc = ngx_http_ssi_evaluate_string(r, ctx, value, 0);

    if (rc != NGX_OK) {
        return rc;
    }

    key = ngx_hash_strlow(name->data, name->data, name->len);

    vv = ngx_http_ssi_get_variable(r, name, key);

    if (vv) {
        *vv = *value;
        return NGX_OK;
    }

    var = ngx_list_push(mctx->variables);
    if (var == NULL) {
        return NGX_ERROR;
    }

    var->name = *name;
    var->key = key;
    var->value = *value;

    ngx_log_debug2(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "set: \"%V\"=\"%V\"", name, value);

    return NGX_OK;
}


static ngx_int_t
ngx_http_ssi_if(ngx_http_request_t *r, ngx_http_ssi_ctx_t *ctx,
    ngx_str_t **params)
{
    u_char       *p, *last;
    ngx_str_t    *expr, left, right;
    ngx_int_t     rc;
    ngx_uint_t    negative, noregex, flags;

    if (ctx->command.len == 2) {
        if (ctx->conditional) {
            ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                          "the \"if\" command inside the \"if\" command");
            return NGX_HTTP_SSI_ERROR;
        }
    }

    if (ctx->output_chosen) {
        ctx->output = 0;
        return NGX_OK;
    }

    expr = params[NGX_HTTP_SSI_IF_EXPR];

    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "ssi if expr=\"%V\"", expr);

    left.data = expr->data;
    last = expr->data + expr->len;

    for (p = left.data; p < last; p++) {
        if (*p >= 'A' && *p <= 'Z') {
            *p |= 0x20;
            continue;
        }

        if ((*p >= 'a' && *p <= 'z')
             || (*p >= '0' && *p <= '9')
             || *p == '$' || *p == '{' || *p == '}' || *p == '_'
             || *p == '"' || *p == '\'')
        {
            continue;
        }

        break;
    }

    left.len = p - left.data;

    while (p < last && *p == ' ') {
        p++;
    }

    flags = 0;

    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "left: \"%V\"", &left);

    rc = ngx_http_ssi_evaluate_string(r, ctx, &left, flags);

    if (rc != NGX_OK) {
        return rc;
    }

    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "evaluted left: \"%V\"", &left);

    if (p == last) {
        if (left.len) {
            ctx->output = 1;
            ctx->output_chosen = 1;

        } else {
            ctx->output = 0;
        }

        ctx->conditional = NGX_HTTP_SSI_COND_IF;

        return NGX_OK;
    }

    if (p < last && *p == '=') {
        negative = 0;
        p++;

    } else if (p + 1 < last && *p == '!' && *(p + 1) == '=') {
        negative = 1;
        p += 2;

    } else {
        goto invalid_expression;
    }

    while (p < last && *p == ' ') {
        p++;
    }

    if (p < last - 1 && *p == '/') {
        if (*(last - 1) != '/') {
            goto invalid_expression;
        }

        noregex = 0;
        flags = NGX_HTTP_SSI_ADD_ZERO;
        last--;
        p++;

    } else {
        noregex = 1;
        flags = 0;

        if (p < last - 1 && p[0] == '\\' && p[1] == '/') {
            p++;
        }
    }

    right.len = last - p;
    right.data = p;

    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "right: \"%V\"", &right);

    rc = ngx_http_ssi_evaluate_string(r, ctx, &right, flags);

    if (rc != NGX_OK) {
        return rc;
    }

    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "evaluted right: \"%V\"", &right);

    if (noregex) {
        if (left.len != right.len) {
            rc = -1;

        } else {
            rc = ngx_strncmp(left.data, right.data, right.len);
        }

    } else {
#if (NGX_PCRE)
        ngx_regex_compile_t  rgc;
        u_char               errstr[NGX_MAX_CONF_ERRSTR];

        right.data[right.len] = '\0';

        ngx_memzero(&rgc, sizeof(ngx_regex_compile_t));

        rgc.pattern = right;
        rgc.pool = r->pool;
        rgc.err.len = NGX_MAX_CONF_ERRSTR;
        rgc.err.data = errstr;

        if (ngx_regex_compile(&rgc) != NGX_OK) {
            ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "%V", &rgc.err);
            return NGX_HTTP_SSI_ERROR;
        }

        rc = ngx_regex_exec(rgc.regex, &left, NULL, 0);

        if (rc < NGX_REGEX_NO_MATCHED) {
            ngx_log_error(NGX_LOG_ALERT, r->connection->log, 0,
                          ngx_regex_exec_n " failed: %i on \"%V\" using \"%V\"",
                          rc, &left, &right);
            return NGX_HTTP_SSI_ERROR;
        }
#else
        ngx_log_error(NGX_LOG_ALERT, r->connection->log, 0,
                      "the using of the regex \"%V\" in SSI "
                      "requires PCRE library", &right);

        return NGX_HTTP_SSI_ERROR;
#endif
    }

    if ((rc == 0 && !negative) || (rc != 0 && negative)) {
        ctx->output = 1;
        ctx->output_chosen = 1;

    } else {
        ctx->output = 0;
    }

    ctx->conditional = NGX_HTTP_SSI_COND_IF;

    return NGX_OK;

invalid_expression:

    ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                  "invalid expression in \"%V\"", expr);

    return NGX_HTTP_SSI_ERROR;
}


static ngx_int_t
ngx_http_ssi_else(ngx_http_request_t *r, ngx_http_ssi_ctx_t *ctx,
    ngx_str_t **params)
{
    ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "ssi else");

    if (ctx->output_chosen) {
        ctx->output = 0;
    } else {
        ctx->output = 1;
    }

    ctx->conditional = NGX_HTTP_SSI_COND_ELSE;

    return NGX_OK;
}


static ngx_int_t
ngx_http_ssi_endif(ngx_http_request_t *r, ngx_http_ssi_ctx_t *ctx,
    ngx_str_t **params)
{
    ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "ssi endif");

    ctx->output = 1;
    ctx->output_chosen = 0;
    ctx->conditional = 0;

    return NGX_OK;
}


static ngx_int_t
ngx_http_ssi_block(ngx_http_request_t *r, ngx_http_ssi_ctx_t *ctx,
    ngx_str_t **params)
{
    ngx_http_ssi_ctx_t    *mctx;
    ngx_http_ssi_block_t  *bl;

    ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "ssi block");

    mctx = ngx_http_get_module_ctx(r->main, ngx_http_ssi_filter_module);

    if (mctx->blocks == NULL) {
        mctx->blocks = ngx_array_create(r->pool, 4,
                                        sizeof(ngx_http_ssi_block_t));
        if (mctx->blocks == NULL) {
            return NGX_HTTP_SSI_ERROR;
        }
    }

    bl = ngx_array_push(mctx->blocks);
    if (bl == NULL) {
        return NGX_HTTP_SSI_ERROR;
    }

    bl->name = *params[NGX_HTTP_SSI_BLOCK_NAME];
    bl->bufs = NULL;
    bl->count = 0;

    ctx->output = 0;
    ctx->block = 1;

    return NGX_OK;
}


static ngx_int_t
ngx_http_ssi_endblock(ngx_http_request_t *r, ngx_http_ssi_ctx_t *ctx,
    ngx_str_t **params)
{
    ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "ssi endblock");

    ctx->output = 1;
    ctx->block = 0;

    return NGX_OK;
}


static ngx_int_t
ngx_http_ssi_date_gmt_local_variable(ngx_http_request_t *r,
    ngx_http_variable_value_t *v, uintptr_t gmt)
{
    ngx_http_ssi_ctx_t  *ctx;
    ngx_time_t          *tp;
    struct tm            tm;
    char                 buf[NGX_HTTP_SSI_DATE_LEN];

    v->valid = 1;
    v->no_cacheable = 0;
    v->not_found = 0;

    tp = ngx_timeofday();

    ctx = ngx_http_get_module_ctx(r, ngx_http_ssi_filter_module);

    if (ctx == NULL
        || (ctx->timefmt.len == sizeof("%s") - 1
            && ctx->timefmt.data[0] == '%' && ctx->timefmt.data[1] == 's'))
    {
        v->data = ngx_pnalloc(r->pool, NGX_TIME_T_LEN);
        if (v->data == NULL) {
            return NGX_ERROR;
        }

        v->len = ngx_sprintf(v->data, "%T", tp->sec) - v->data;

        return NGX_OK;
    }

    if (gmt) {
        ngx_libc_gmtime(tp->sec, &tm);
    } else {
        ngx_libc_localtime(tp->sec, &tm);
    }

    v->len = strftime(buf, NGX_HTTP_SSI_DATE_LEN,
                      (char *) ctx->timefmt.data, &tm);
    if (v->len == 0) {
        return NGX_ERROR;
    }

    v->data = ngx_pnalloc(r->pool, v->len);
    if (v->data == NULL) {
        return NGX_ERROR;
    }

    ngx_memcpy(v->data, buf, v->len);

    return NGX_OK;
}


static ngx_int_t
ngx_http_ssi_preconfiguration(ngx_conf_t *cf)
{
    ngx_int_t                  rc;
    ngx_http_variable_t       *var, *v;
    ngx_http_ssi_command_t    *cmd;
    ngx_http_ssi_main_conf_t  *smcf;

    for (v = ngx_http_ssi_vars; v->name.len; v++) {
        var = ngx_http_add_variable(cf, &v->name, v->flags);
        if (var == NULL) {
            return NGX_ERROR;
        }

        var->get_handler = v->get_handler;
        var->data = v->data;
    }

    smcf = ngx_http_conf_get_module_main_conf(cf, ngx_http_ssi_filter_module);

    for (cmd = ngx_http_ssi_commands; cmd->name.len; cmd++) {
        rc = ngx_hash_add_key(&smcf->commands, &cmd->name, cmd,
                              NGX_HASH_READONLY_KEY);

        if (rc == NGX_OK) {
            continue;
        }

        if (rc == NGX_BUSY) {
            ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                               "conflicting SSI command \"%V\"", &cmd->name);
        }

        return NGX_ERROR;
    }

    return NGX_OK;
}


static void *
ngx_http_ssi_create_main_conf(ngx_conf_t *cf)
{
    ngx_http_ssi_main_conf_t  *smcf;

    smcf = ngx_pcalloc(cf->pool, sizeof(ngx_http_ssi_main_conf_t));
    if (smcf == NULL) {
        return NULL;
    }

    smcf->commands.pool = cf->pool;
    smcf->commands.temp_pool = cf->temp_pool;

    if (ngx_hash_keys_array_init(&smcf->commands, NGX_HASH_SMALL) != NGX_OK) {
        return NULL;
    }

    return smcf;
}


static char *
ngx_http_ssi_init_main_conf(ngx_conf_t *cf, void *conf)
{
    ngx_http_ssi_main_conf_t *smcf = conf;

    ngx_hash_init_t  hash;

    hash.hash = &smcf->hash;
    hash.key = ngx_hash_key;
    hash.max_size = 1024;
    hash.bucket_size = ngx_cacheline_size;
    hash.name = "ssi_command_hash";
    hash.pool = cf->pool;
    hash.temp_pool = NULL;

    if (ngx_hash_init(&hash, smcf->commands.keys.elts,
                      smcf->commands.keys.nelts)
        != NGX_OK)
    {
        return NGX_CONF_ERROR;
    }

    return NGX_CONF_OK;
}


static void *
ngx_http_ssi_create_loc_conf(ngx_conf_t *cf)
{
    ngx_http_ssi_loc_conf_t  *slcf;

    slcf = ngx_pcalloc(cf->pool, sizeof(ngx_http_ssi_loc_conf_t));
    if (slcf == NULL) {
        return NULL;
    }

    /*
     * set by ngx_pcalloc():
     *
     *     conf->types = { NULL };
     *     conf->types_keys = NULL;
     */

    slcf->enable = NGX_CONF_UNSET;
    slcf->silent_errors = NGX_CONF_UNSET;
    slcf->ignore_recycled_buffers = NGX_CONF_UNSET;

    slcf->min_file_chunk = NGX_CONF_UNSET_SIZE;
    slcf->value_len = NGX_CONF_UNSET_SIZE;

    return slcf;
}


static char *
ngx_http_ssi_merge_loc_conf(ngx_conf_t *cf, void *parent, void *child)
{
    ngx_http_ssi_loc_conf_t *prev = parent;
    ngx_http_ssi_loc_conf_t *conf = child;

    ngx_conf_merge_value(conf->enable, prev->enable, 0);
    ngx_conf_merge_value(conf->silent_errors, prev->silent_errors, 0);
    ngx_conf_merge_value(conf->ignore_recycled_buffers,
                         prev->ignore_recycled_buffers, 0);

    ngx_conf_merge_size_value(conf->min_file_chunk, prev->min_file_chunk, 1024);
    ngx_conf_merge_size_value(conf->value_len, prev->value_len, 256);

    if (ngx_http_merge_types(cf, &conf->types_keys, &conf->types,
                             &prev->types_keys, &prev->types,
                             ngx_http_html_default_types)
        != NGX_OK)
    {
        return NGX_CONF_ERROR;
    }

    return NGX_CONF_OK;
}


static ngx_int_t
ngx_http_ssi_filter_init(ngx_conf_t *cf)
{
    ngx_http_next_header_filter = ngx_http_top_header_filter;
    ngx_http_top_header_filter = ngx_http_ssi_header_filter;

    ngx_http_next_body_filter = ngx_http_top_body_filter;
    ngx_http_top_body_filter = ngx_http_ssi_body_filter;

    return NGX_OK;
}
