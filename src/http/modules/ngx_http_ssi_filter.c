
/*
 * Copyright (C) Igor Sysoev
 */


#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>


#define NGX_HTTP_SSI_COMMAND_LEN      31
#define NGX_HTTP_SSI_PARAM_LEN        31

#define NGX_HTTP_SSI_COPY             1
#define NGX_HTTP_SSI_INVALID_COMMAND  2
#define NGX_HTTP_SSI_INVALID_PARAM    3
#define NGX_HTTP_SSI_INVALID_VALUE    4
#define NGX_HTTP_SSI_LONG_VALUE       5


typedef struct {
    ngx_flag_t        enable;
    size_t            value_len;
} ngx_http_ssi_conf_t;


typedef struct {
    int               dummy;
} ngx_http_ssi_command_t;


typedef struct {
    ngx_hunk_t        *buf;

    u_char            *start;
    u_char            *last;
    u_char            *pos;

    ngx_str_t          command;
    ngx_array_t        params;
    ngx_table_elt_t   *param;

    ngx_chain_t       *in;
    ngx_chain_t       *out;
    ngx_chain_t      **last_out;
    ngx_chain_t       *busy;

    ngx_uint_t         state;
    size_t             saved;
} ngx_http_ssi_ctx_t;


typedef ngx_int_t (*ngx_http_ssi_opcode_pt) (ngx_http_request_t *r,
                                             ngx_http_ssi_ctx_t *ctx);

typedef struct {
    ngx_str_t               name;
    ngx_http_ssi_opcode_pt  op;
} ngx_http_ssi_op_t;


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
    ssi_double_quoted_value_quote_state,
    ssi_quoted_value_state,
    ssi_quoted_value_quote_state,
    ssi_comment_end0_state,
    ssi_comment_end1_state,
    ssi_error_state,
    ssi_error_end0_state,
    ssi_error_end1_state
} ngx_http_ssi_state_e;


static ngx_int_t ngx_http_ssi_error(ngx_http_request_t *r,
                                    ngx_http_ssi_ctx_t *ctx);
static ngx_int_t ngx_http_ssi_parse(ngx_http_request_t *r,
                                    ngx_http_ssi_ctx_t *ctx);

static ngx_int_t ngx_http_ssi_echo(ngx_http_request_t *r,
                                   ngx_http_ssi_ctx_t *ctx);

static void *ngx_http_ssi_create_conf(ngx_conf_t *cf);
static char *ngx_http_ssi_merge_conf(ngx_conf_t *cf,
                                     void *parent, void *child);
static int ngx_http_ssi_filter_init(ngx_cycle_t *cycle);


static ngx_http_ssi_op_t  ngx_http_ssi_commands[] = {
    { ngx_string("echo"), ngx_http_ssi_echo },
    { ngx_null_string, NULL }
};


static ngx_command_t  ngx_http_ssi_filter_commands[] = {

    { ngx_string("ssi"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_FLAG,
      ngx_conf_set_flag_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_ssi_conf_t, enable),
      NULL },

     ngx_null_command
};


    
static ngx_http_module_t  ngx_http_ssi_filter_module_ctx = {
    NULL,                                  /* pre conf */

    NULL,                                  /* create main configuration */
    NULL,                                  /* init main configuration */

    NULL,                                  /* create server configuration */
    NULL,                                  /* merge server configuration */

    ngx_http_ssi_create_conf,              /* create location configuration */
    ngx_http_ssi_merge_conf                /* merge location configuration */
};  


ngx_module_t  ngx_http_ssi_filter_module = {
    NGX_MODULE,
    &ngx_http_ssi_filter_module_ctx,       /* module context */
    ngx_http_ssi_filter_commands,          /* module directives */
    NGX_HTTP_MODULE,                       /* module type */
    ngx_http_ssi_filter_init,              /* init module */
    NULL                                   /* init child */
};


static int (*ngx_http_next_header_filter) (ngx_http_request_t *r);
static int (*ngx_http_next_body_filter) (ngx_http_request_t *r,
                                         ngx_chain_t *in);


static char ssi_string[] = "<!--#";
static char error_string[] = "[an error occurred while processing "
                             "the directive]";
static char stub_string[] = "[a stub ssi string]";


static int ngx_http_ssi_header_filter(ngx_http_request_t *r)
{
    ngx_http_ssi_ctx_t   *ctx;
    ngx_http_ssi_conf_t  *conf;

    conf = ngx_http_get_module_loc_conf(r, ngx_http_ssi_filter_module);

    if (!conf->enable) {
        return ngx_http_next_header_filter(r);
    }

    /* TODO: "text/html" -> custom types */

    if (r->headers_out.content_type
        && ngx_strncasecmp(r->headers_out.content_type->value.data,
                                                          "text/html", 5) != 0)
    {
        return ngx_http_next_header_filter(r);
    }

    ngx_http_create_ctx(r, ctx, ngx_http_ssi_filter_module,
                        sizeof(ngx_http_ssi_ctx_t), NGX_ERROR);

    ctx->last_out = &ctx->out;

    r->headers_out.content_length_n = -1;
    if (r->headers_out.content_length) {
        r->headers_out.content_length->key.len = 0;
        r->headers_out.content_length = NULL;
    }

    r->headers_out.last_modified_time = -1;
    if (r->headers_out.last_modified) {
        r->headers_out.last_modified->key.len = 0;
        r->headers_out.last_modified = NULL;
    }

    r->filter |= NGX_HTTP_FILTER_NEED_IN_MEMORY;

    return ngx_http_next_header_filter(r);
}


static int ngx_http_ssi_body_filter(ngx_http_request_t *r, ngx_chain_t *in)
{
    size_t               len;
    ngx_int_t            rc, found;
    ngx_hunk_t          *hunk;
    ngx_chain_t         *cl, *tl;
    ngx_http_ssi_op_t   *cmd;
    ngx_http_ssi_ctx_t  *ctx;

    ctx = ngx_http_get_module_ctx(r, ngx_http_ssi_filter_module);

    if (ctx == NULL || (in == NULL && ctx->in == NULL)) {
        return ngx_http_next_body_filter(r, in);
    }

    /* add the incoming hunk to the chain ctx->in */

    if (in) {
        if (ngx_chain_add_copy(r->pool, &ctx->in, in) == NGX_ERROR) {
            return NGX_ERROR;
        }
    }

    while (ctx->in) {
        if (ctx->buf == NULL) {
            ctx->buf = ctx->in->hunk;
            ctx->in = ctx->in->next;

            ctx->start = ctx->buf->pos;
            ctx->pos = ctx->buf->pos;
            ctx->last = ctx->buf->pos;

            if (ctx->saved) {
                len = ctx->buf->last - ctx->buf->pos;
                if (len > 5 - ctx->saved) {
                    len = 5 - ctx->saved;
                }

                if (ngx_strncmp(ctx->buf->pos, &ssi_string[ctx->saved], len)
                                                                          == 0)
                {
                    if (len < 5 - ctx->saved) {
                        ctx->buf = NULL;
                        continue;

                    } else {
                        ctx->saved = 0;
                        ctx->pos += len;
                        ctx->state = ssi_precommand_state;
                    }
                }
            }
        }

        while (ctx->pos < ctx->buf->last) {

            ngx_log_debug2(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                           "saved: %d state: %d", ctx->saved, ctx->state);

            rc = ngx_http_ssi_parse(r, ctx);

            ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                           "parse: %d", rc);

            if (rc == NGX_AGAIN) {
                continue;

            } else if (rc == NGX_ERROR) {
                return rc;

            } else if (rc == NGX_HTTP_SSI_COPY) {

                ngx_log_debug2(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                               "saved: %d copy: %d",
                               ctx->saved, ctx->last - ctx->start);

                if (ctx->saved) {

                    if (!(hunk = ngx_calloc_hunk(r->pool))) {
                        return NGX_ERROR;
                    }

                    hunk->type = NGX_HUNK_IN_MEMORY|NGX_HUNK_TEMP;
                    hunk->pos = ssi_string;
                    hunk->last = ssi_string + ctx->saved;

                    ngx_alloc_link_and_set_hunk(cl, hunk, r->pool, NGX_ERROR);

                    *ctx->last_out = cl;
                    ctx->last_out = &cl->next;

                    ctx->saved = 0;
                }

                if (!(hunk = ngx_calloc_hunk(r->pool))) {
                    return NGX_ERROR;
                }

                hunk->type = NGX_HUNK_IN_MEMORY|NGX_HUNK_TEMP|NGX_HUNK_RECYCLED;
                hunk->pos = ctx->start;
                hunk->last = ctx->last;
                hunk->shadow = ctx->buf;

                ngx_alloc_link_and_set_hunk(cl, hunk, r->pool, NGX_ERROR);

                *ctx->last_out = cl;
                ctx->last_out = &cl->next;

                if (ctx->pos == ctx->buf->last) {
                    ctx->saved = ctx->pos - ctx->last;
                }

                continue;

            } else if (rc >= NGX_HTTP_SSI_INVALID_COMMAND) {

                ngx_log_debug2(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                               "saved: %d error: %d",
                               ctx->saved, rc);

                if (ngx_http_ssi_error(r, ctx) == NGX_ERROR) {
                    return NGX_ERROR;
                }

                if (rc == NGX_HTTP_SSI_INVALID_COMMAND) {
                    ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                                  "invalid SSI command \"%s\" found",
                                  ctx->command.data);

                } else if (rc == NGX_HTTP_SSI_INVALID_PARAM) {
                    ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                                  "invalid parameter \"%s\" found "
                                  "in SSI command \"%s\"",
                                  ctx->param->key.data, ctx->command.data);
                }

#if 0
            } else if (rc == NGX_HTTP_SSI_INVALID_COMMAND) {
            } else if (rc == NGX_HTTP_SSI_INVALID_PARAM) {
            } else if (rc == NGX_HTTP_SSI_INVALID_VALUE) {
            } else if (rc == NGX_HTTP_SSI_LONG_VALUE) {
#endif

            } else {

                found = 0;

                for (cmd = ngx_http_ssi_commands; cmd->name.len; cmd++) {
                     if (ctx->command.len != cmd->name.len) {
                         continue;
                     }

                     if (ngx_strncmp(ctx->command.data, cmd->name.data,
                                                           cmd->name.len) != 0)
                     {
                         continue;
                     }

                     found = 1;

                     if (cmd->op(r, ctx) == NGX_ERROR) {
                         return NGX_ERROR;
                     }
                }

                if (!found) {
                    if (ngx_http_ssi_error(r, ctx) == NGX_ERROR) {
                        return NGX_ERROR;
                    }
                }

#if 0
                if (!(hunk = ngx_calloc_hunk(r->pool))) {
                    return NGX_ERROR;
                }

                hunk->type = NGX_HUNK_IN_MEMORY|NGX_HUNK_TEMP;
                hunk->pos = stub_string;
                hunk->last = stub_string + sizeof(stub_string) - 1;

                ngx_alloc_link_and_set_hunk(cl, hunk, r->pool, NGX_ERROR);

                *ctx->last_out = cl;
                ctx->last_out = &cl->next;
#endif
            }
        }

        ctx->buf = NULL;
    }

    if (ctx->out) {
        if (ngx_http_next_body_filter(r, ctx->out) == NGX_ERROR) {
            return NGX_ERROR;
        }

        if (ctx->busy == NULL) {
            ctx->busy = ctx->out;

        } else {
            for (tl = ctx->busy; /* void */ ; tl = tl->next) {
                if (tl->next == NULL) { 
                    tl->next = ctx->out;
                    break;
                }
            }
        }
    
        ctx->out = NULL;
        ctx->last_out = &ctx->out;

        while (ctx->busy) {
            if (ngx_hunk_size(ctx->busy->hunk) != 0) {
                break;
            }

            /* TODO: NGX_HUNK_ZEROCOPY_BUSY */

            hunk = ctx->busy->hunk->shadow;
            if (hunk) {
                hunk->pos = ctx->busy->hunk->pos;

                len = hunk->last - hunk->pos;
                if (len < 5 && ngx_strncmp(hunk->pos, ssi_string, len) == 0) {
                    hunk->pos = hunk->last;
                }
            }

            ctx->busy = ctx->busy->next;
        }
    }

    return NGX_OK;
}


static ngx_int_t ngx_http_ssi_error(ngx_http_request_t *r,
                                    ngx_http_ssi_ctx_t *ctx)
{
    ngx_hunk_t   *hunk;
    ngx_chain_t  *cl;

    if (!(hunk = ngx_calloc_hunk(r->pool))) {
        return NGX_ERROR;
    }

    hunk->type = NGX_HUNK_IN_MEMORY|NGX_HUNK_TEMP;
    hunk->pos = error_string;
    hunk->last = error_string + sizeof(error_string) - 1;

    ngx_alloc_link_and_set_hunk(cl, hunk, r->pool, NGX_ERROR);

    *ctx->last_out = cl;
    ctx->last_out = &cl->next;

    return NGX_OK;
}


#if 0

static int ngx_http_ssi_copy_opcode(ngx_http_request_t *r,
                                    ngx_http_ssi_ctx_t *ctx, void *data)
{
    ngx_http_ssi_copy_t *copy = data;

    ngx_hunk_t   *h;
    ngx_chain_t   chain;

    h = ctx->incoming->hunk;

    if (ctx->looked == 0 && ctx->pos == h->last) {
        chain.hunk = h;
        chain.next = NULL;

        return next_body_filter(r, &chain);
    }

    if (ctx->hunk == NULL) {
        ngx_test_null(ctx->hunk, ngx_calloc_hunk(r->pool), NGX_ERROR);
        ctx->hunk->type = h->type & NGX_HUNK_STORAGE;
    }


    if (h->type & NGX_HUNK_FILE) {
        if (copy->start <= h->file_pos) {
            ctx->hunk->file_pos = h->file_pos;
        } else if (copy->start < h->file_last) {
            ctx->hunk->file_pos = copy->file_pos;
        }

        if (copy->end >= h->file_last) {
            ctx->hunk->file_last = h->file_last;
        } else if (copy->end > h->file_pos) {
        }

    }

    if (h->type & NGX_HUNK_IN_MEMORY) {
        if (copy->start <= ctx->offset + (h->pos - h->start)) {
            ctx->hunk->pos = h->pos;
        } else if (copy->start < ctx->offset + (h->last - h->start)) {
            ctx->hunk->pos = h->start + (copy->start - ctx->offset);
        }

        if (copy->end >= ctx->offset + (h->last - h->start) {
            ctx->hunk->last = h->last;
        } else if (copy->end > ctx->offset + (h->pos - h->start)) {
            ctx->hunk->last = h->start + (copy->end - ctx->offset);
        }
    }

    /* TODO: NGX_HUNK_FLUSH */

    if ((h->type & NGX_HUNK_LAST) && ctx->hunk->last == h->last)

    /* LAST */
}

#endif


static ngx_int_t ngx_http_ssi_parse(ngx_http_request_t *r,
                                    ngx_http_ssi_ctx_t *ctx)
{
    char                  *p, *last, *end, ch;
    ngx_http_ssi_conf_t   *conf;
    ngx_http_ssi_state_e   state;

    conf = ngx_http_get_module_loc_conf(r, ngx_http_ssi_filter_module);

    state = ctx->state;
    p = ctx->pos;
    end = ctx->buf->last;
    last = NULL;

    while (p < end) {
        ch = *p++;

        switch (state) {

        case ssi_start_state:

            /* a tight loop */

            for ( ;; ) {

                if (ch == '<') {
                    last = p - 1;
                    state = ssi_tag_state;
                    break;
                }

                if (p == end) {
                    ctx->last = p;
                    ctx->pos = p;
                    ctx->state = ssi_start_state;

                    return NGX_HTTP_SSI_COPY;
                }

                ch = *p++;
            }

            break;

        case ssi_tag_state:
            switch (ch) {
            case '!':
                state = ssi_comment0_state;
                break;

            case '<':
                last = p - 1;
                break;

            default:
                state = ssi_start_state;
                break;
            }

            break;

        case ssi_comment0_state:
            switch (ch) {
            case '-':
                state = ssi_comment1_state;
                break;

            case '<':
                last = p - 1;
                state = ssi_tag_state;
                break;

            default:
                state = ssi_start_state;
                break;
            }

            break;

        case ssi_comment1_state:
            switch (ch) {
            case '-':
                state = ssi_sharp_state;
                break;

            case '<':
                last = p - 1;
                state = ssi_tag_state;
                break;

            default:
                state = ssi_start_state;
                break;
            }

            break;

        case ssi_sharp_state:
            switch (ch) {
            case '#':
                ctx->last = last;
                ctx->pos = p;
                ctx->state = ssi_precommand_state;

                return NGX_HTTP_SSI_COPY;

            case '<':
                last = p - 1;
                state = ssi_tag_state;
                break;

            default:
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
                ctx->command.data = 
                             ngx_palloc(r->pool, NGX_HTTP_SSI_COMMAND_LEN + 1);
                if (ctx->command.data == NULL) {
                    return NGX_ERROR;
                }

                ctx->command.data[0] = ch;
                ctx->command.len = 1;
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
                ctx->command.data[ctx->command.len] = 0;
                state = ssi_preparam_state;
                break;

            case '-':
                ctx->command.data[ctx->command.len] = 0;
                state = ssi_comment_end0_state;
                break;

            default:
                if (ctx->command.len >= NGX_HTTP_SSI_COMMAND_LEN) {
                    ctx->command.data[NGX_HTTP_SSI_COMMAND_LEN] = 0;

                    ctx->last = last;
                    ctx->pos = p;
                    ctx->state = ssi_error_state;

                    return NGX_HTTP_SSI_INVALID_COMMAND;
                }

                ctx->command.data[ctx->command.len++] = ch;
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
                if (ctx->params.elts == NULL) {
                    ngx_init_array(ctx->params, r->pool,
                                   5, sizeof(ngx_table_elt_t), NGX_ERROR);
                }

                if (!(ctx->param = ngx_push_array(&ctx->params))) {
                    return NGX_ERROR;
                }

                ctx->param->key.data =
                               ngx_palloc(r->pool, NGX_HTTP_SSI_PARAM_LEN + 1);
                if (ctx->param->key.data == NULL) {
                    return NGX_ERROR;
                }
                ctx->param->key.data[0] = ch;
                ctx->param->key.len = 1;

                ctx->param->value.data =
                                       ngx_palloc(r->pool, conf->value_len + 1);
                if (ctx->param->value.data == NULL) {
                    return NGX_ERROR;
                }
                ctx->param->value.len = 0;

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
                ctx->param->key.data[ctx->param->key.len] = 0;
                state = ssi_preequal_state;
                break;

            case '=':
                ctx->param->key.data[ctx->param->key.len] = 0;
                state = ssi_prevalue_state;
                break;

            case '-':
                ctx->last = last;
                ctx->pos = p;
                ctx->state = ssi_error_end0_state;

                return NGX_HTTP_SSI_INVALID_PARAM;

            default:
                if (ctx->param->key.len >= NGX_HTTP_SSI_PARAM_LEN) {
                    ctx->param->key.data[NGX_HTTP_SSI_PARAM_LEN] = 0;

                    ctx->last = last;
                    ctx->pos = p;
                    ctx->state = ssi_error_state;

                    return NGX_HTTP_SSI_INVALID_PARAM;
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

            case '-':
                ctx->last = last;
                ctx->pos = p;
                ctx->state = ssi_error_end0_state;

                return NGX_HTTP_SSI_INVALID_PARAM;

            default:
                ctx->last = last;
                ctx->pos = p;
                ctx->state = ssi_error_state;

                return NGX_HTTP_SSI_INVALID_PARAM;
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

            case '-':
                ctx->last = last;
                ctx->pos = p;
                ctx->state = ssi_error_end0_state;

                return NGX_HTTP_SSI_INVALID_VALUE;

            default:
                ctx->last = last;
                ctx->pos = p;
                ctx->state = ssi_error_state;

                return NGX_HTTP_SSI_INVALID_VALUE;
            }

            break;

        case ssi_double_quoted_value_state:
            switch (ch) {
            case '\\':
                state = ssi_double_quoted_value_quote_state;
                break;

            case '"':
                state = ssi_preparam_state;
                break;

            default:
                if (ctx->param->value.len >= conf->value_len) {
                    ctx->last = last;
                    ctx->pos = p;
                    ctx->state = ssi_error_state;

                    return NGX_HTTP_SSI_LONG_VALUE;
                }

                ctx->param->value.data[ctx->param->value.len++] = ch;
            }

            break;

        case ssi_double_quoted_value_quote_state:
            if (ctx->param->value.len >= conf->value_len) {
                ctx->last = last;
                ctx->pos = p;
                ctx->state = ssi_error_state;

                return NGX_HTTP_SSI_LONG_VALUE;
            }

            ctx->param->value.data[ctx->param->value.len++] = ch;

            state = ssi_double_quoted_value_state;
            break;

        case ssi_quoted_value_state:
            switch (ch) {
            case '\\':
                state = ssi_quoted_value_quote_state;
                break;

            case '\'':
                state = ssi_preparam_state;
                break;

            default:
                if (ctx->param->value.len >= conf->value_len) {
                    ctx->last = last;
                    ctx->pos = p;
                    ctx->state = ssi_error_state;

                    return NGX_HTTP_SSI_LONG_VALUE;
                }

                ctx->param->value.data[ctx->param->value.len++] = ch;
            }

            break;

        case ssi_quoted_value_quote_state:
            if (ctx->param->value.len >= conf->value_len) {
                ctx->last = last;
                ctx->pos = p;
                ctx->state = ssi_error_state;

                return NGX_HTTP_SSI_LONG_VALUE;
            }

            ctx->param->value.data[ctx->param->value.len++] = ch;

            state = ssi_quoted_value_state;
            break;

        case ssi_comment_end0_state:
            switch (ch) {
            case '-':
                state = ssi_comment_end1_state;
                break;

            default:
                ctx->last = last;
                ctx->pos = p;
                ctx->state = ssi_error_state;

                return NGX_HTTP_SSI_INVALID_COMMAND;
            }

            break;

        case ssi_comment_end1_state:
            switch (ch) {
            case '>':
                ctx->state = ssi_start_state;
                ctx->start = p;
                ctx->pos = p;

                return NGX_OK;

            default:
                ctx->last = last;
                ctx->pos = p;
                ctx->state = ssi_error_state;

                return NGX_HTTP_SSI_INVALID_COMMAND;
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
                ctx->start = p;
                ctx->pos = p;

                return NGX_AGAIN;

            default:
                state = ssi_error_state;
                break;
            }

            break;
        }
    }

    ctx->state = state;
    ctx->last = last;
    ctx->pos = p;

    return NGX_HTTP_SSI_COPY;
}


static ngx_int_t ngx_http_ssi_echo(ngx_http_request_t *r,
                                   ngx_http_ssi_ctx_t *ctx)
{
    return NGX_OK;
}


static void *ngx_http_ssi_create_conf(ngx_conf_t *cf)
{
    ngx_http_ssi_conf_t  *conf;

    if (!(conf = ngx_pcalloc(cf->pool, sizeof(ngx_http_ssi_conf_t)))) {
        return NGX_CONF_ERROR;
    }

    conf->enable = NGX_CONF_UNSET;
    conf->value_len = NGX_CONF_UNSET_SIZE;

    return conf;
}


static char *ngx_http_ssi_merge_conf(ngx_conf_t *cf,
                                     void *parent, void *child)
{
    ngx_http_ssi_conf_t *prev = parent;
    ngx_http_ssi_conf_t *conf = child;

    ngx_conf_merge_value(conf->enable, prev->enable, 0);
    ngx_conf_merge_size_value(conf->value_len, prev->value_len, 256);

    return NGX_CONF_OK;
}


static int ngx_http_ssi_filter_init(ngx_cycle_t *cycle)
{
    ngx_http_next_header_filter = ngx_http_top_header_filter;
    ngx_http_top_header_filter = ngx_http_ssi_header_filter;

    ngx_http_next_body_filter = ngx_http_top_body_filter;
    ngx_http_top_body_filter = ngx_http_ssi_body_filter;

    return NGX_OK;
}
