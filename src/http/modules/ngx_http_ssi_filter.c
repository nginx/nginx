
/*
 * Copyright (C) Igor Sysoev
 */


#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>

#define NGX_HTTP_SSI_MAX_PARAMS   16

#define NGX_HTTP_SSI_COMMAND_LEN  31
#define NGX_HTTP_SSI_PARAM_LEN    31
#define NGX_HTTP_SSI_PARAMS_N     4

#define NGX_HTTP_SSI_ERROR        1


typedef struct {
    ngx_flag_t        enable;
    ngx_flag_t        silent_errors;

    size_t            min_file_chunk;
    size_t            value_len;
} ngx_http_ssi_conf_t;


typedef struct {
    ngx_buf_t         *buf;

    u_char            *pos;
    u_char            *copy_start;
    u_char            *copy_end;

    ngx_str_t          command;
    ngx_array_t        params;
    ngx_table_elt_t   *param;
    ngx_table_elt_t    params_array[NGX_HTTP_SSI_PARAMS_N];

    ngx_chain_t       *in;
    ngx_chain_t       *out;
    ngx_chain_t      **last_out;

    ngx_uint_t         state;
    ngx_uint_t         saved_state;
    size_t             saved;
    size_t             looked;

    size_t             value_len;
} ngx_http_ssi_ctx_t;


typedef ngx_int_t (*ngx_http_ssi_command_pt) (ngx_http_request_t *r,
    ngx_http_ssi_ctx_t *ctx, ngx_str_t **);


typedef struct {
    ngx_str_t                 name;
    ngx_uint_t                index;

    ngx_uint_t                mandatory;
} ngx_http_ssi_param_t;


typedef struct {
    ngx_str_t                 name;
    ngx_http_ssi_command_pt   handler;
    ngx_http_ssi_param_t     *params;

    ngx_uint_t                flush;    /* unsigned  flush:1; */
} ngx_http_ssi_command_t;


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


static ngx_int_t ngx_http_ssi_error(ngx_http_request_t *r,
    ngx_http_ssi_ctx_t *ctx);
static ngx_int_t ngx_http_ssi_parse(ngx_http_request_t *r,
    ngx_http_ssi_ctx_t *ctx);

static ngx_int_t ngx_http_ssi_echo(ngx_http_request_t *r,
    ngx_http_ssi_ctx_t *ctx, ngx_str_t **params);

static void *ngx_http_ssi_create_conf(ngx_conf_t *cf);
static char *ngx_http_ssi_merge_conf(ngx_conf_t *cf,
    void *parent, void *child);
static ngx_int_t ngx_http_ssi_filter_init(ngx_cycle_t *cycle);


static ngx_command_t  ngx_http_ssi_filter_commands[] = {

    { ngx_string("ssi"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_FLAG,
      ngx_conf_set_flag_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_ssi_conf_t, enable),
      NULL },

    { ngx_string("ssi_silent_errors"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_FLAG,
      ngx_conf_set_flag_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_ssi_conf_t, silent_errors),
      NULL },

    { ngx_string("ssi_min_file_chunk"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_FLAG,
      ngx_conf_set_size_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_ssi_conf_t, min_file_chunk),
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


static ngx_int_t (*ngx_http_next_header_filter) (ngx_http_request_t *r);
static ngx_int_t (*ngx_http_next_body_filter) (ngx_http_request_t *r,
    ngx_chain_t *in);


static u_char ngx_http_ssi_string[] = "<!--";
static u_char ngx_http_ssi_error_string[] =
                          "[an error occurred while processing the directive]";

static ngx_str_t ngx_http_ssi_none = ngx_string("(none)");


#define  NGX_HTTP_SSI_ECHO_VAR      0
#define  NGX_HTTP_SSI_ECHO_DEFAULT  1

static ngx_http_ssi_param_t  ngx_http_ssi_echo_params[] = {
    { ngx_string("var"), NGX_HTTP_SSI_ECHO_VAR, 1 },
    { ngx_string("default"), NGX_HTTP_SSI_ECHO_DEFAULT, 0 },
    { ngx_null_string, 0, 0 }
};


static ngx_http_ssi_command_t  ngx_http_ssi_commands[] = {
    { ngx_string("echo"), ngx_http_ssi_echo, ngx_http_ssi_echo_params, 0 },
    { ngx_null_string, NULL, NULL, 0 }
};


static ngx_int_t
ngx_http_ssi_header_filter(ngx_http_request_t *r)
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


    if (!(ctx = ngx_pcalloc(r->pool, sizeof(ngx_http_ssi_ctx_t)))) {
        return NGX_ERROR;
    }

    ngx_http_set_ctx(r, ctx, ngx_http_ssi_filter_module);


    ctx->value_len = conf->value_len;
    ctx->last_out = &ctx->out;

    ctx->params.elts = ctx->params_array;
    ctx->params.size = sizeof(ngx_table_elt_t);
    ctx->params.nalloc = NGX_HTTP_SSI_PARAMS_N;
    ctx->params.pool = r->pool;

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

    r->filter_need_in_memory = 1;
    r->filter_ssi_need_in_memory = 1;

    return ngx_http_next_header_filter(r);
}


static ngx_int_t
ngx_http_ssi_body_filter(ngx_http_request_t *r, ngx_chain_t *in)
{
    ngx_int_t                rc;
    ngx_uint_t               i;
    ngx_buf_t               *b;
    ngx_chain_t             *cl;
    ngx_table_elt_t         *param;
    ngx_http_ssi_ctx_t      *ctx;
    ngx_http_ssi_conf_t     *conf;
    ngx_http_ssi_param_t    *prm;
    ngx_http_ssi_command_t  *cmd;
    ngx_str_t               *params[NGX_HTTP_SSI_MAX_PARAMS];

    ctx = ngx_http_get_module_ctx(r, ngx_http_ssi_filter_module);

    if (ctx == NULL || (in == NULL && ctx->in == NULL)) {
        return ngx_http_next_body_filter(r, in);
    }

    /* add the incoming chain to the chain ctx->in */

    if (in) {
        if (ngx_chain_add_copy(r->pool, &ctx->in, in) == NGX_ERROR) {
            return NGX_ERROR;
        }
    }

    conf = ngx_http_get_module_loc_conf(r, ngx_http_ssi_filter_module);

    ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "http ssi filter");

    b = NULL;

    while (ctx->in) {

        ctx->buf = ctx->in->buf;
        ctx->in = ctx->in->next;
        ctx->pos = ctx->buf->pos;

        if (ctx->state == ssi_start_state) {
            ctx->copy_start = ctx->pos;
            ctx->copy_end = ctx->pos;
        }

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

                ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                               "saved: %d", ctx->saved);

                if (ctx->saved) {
                    if (!(b = ngx_calloc_buf(r->pool))) {
                        return NGX_ERROR;
                    }

                    b->memory = 1;
                    b->pos = ngx_http_ssi_string;
                    b->last = ngx_http_ssi_string + ctx->saved;

                    if (!(cl = ngx_alloc_chain_link(r->pool))) {
                        return NGX_ERROR;
                    }

                    cl->buf = b;
                    *ctx->last_out = cl;
                    ctx->last_out = &cl->next;

                    ctx->saved = 0;
                }

                if (!(b = ngx_calloc_buf(r->pool))) {
                    return NGX_ERROR;
                }

                ngx_memcpy(b, ctx->buf, sizeof(ngx_buf_t));

                b->last_buf = 0;
                b->pos = ctx->copy_start;
                b->last = ctx->copy_end;

                if (b->in_file) {

                    if (conf->min_file_chunk < (size_t) (b->last - b->pos)) {
                        b->file_last = b->file_pos + (b->last - b->start);
                        b->file_pos += b->pos - b->start;

                    } else {
                        b->in_file = 0;
                    }
                }

                if (!(cl = ngx_alloc_chain_link(r->pool))) {
                    return NGX_ERROR;
                }

                cl->buf = b;
                cl->next = NULL;
                *ctx->last_out = cl;
                ctx->last_out = &cl->next;
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


            if (rc == NGX_OK) {

                for (cmd = ngx_http_ssi_commands; cmd->handler; cmd++) {
                    if (cmd->name.len == 0) {
                        cmd = (ngx_http_ssi_command_t *) cmd->handler;
                    }

                    if (cmd->name.len != ctx->command.len
                        || ngx_strncmp(cmd->name.data, ctx->command.data,
                                       ctx->command.len) != 0)
                    {
                        continue;
                    }

                    break;
                }

                if (cmd->name.len == 0) {
                    ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                                  "invalid SSI command: \"%V\"", &ctx->command);
                    goto ssi_error;
                }

                ngx_memzero(params,
                            NGX_HTTP_SSI_MAX_PARAMS * sizeof(ngx_str_t *));

                param = ctx->params.elts;


                for (i = 0; i < ctx->params.nelts; i++) {

                    for (prm = cmd->params; prm->name.len; prm++) {

                        if (param[i].key.len != prm->name.len
                            || ngx_strncmp(param[i].key.data, prm->name.data,
                                           prm->name.len) != 0)
                        {
                            continue;
                        }

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

                if (cmd->handler(r, ctx, params) == NGX_OK) {
                    continue;
                }
            }


            /* rc == NGX_HTTP_SSI_ERROR */

ssi_error:

            if (conf->silent_errors) {
                continue;
            }

            if (!(b = ngx_calloc_buf(r->pool))) {
                return NGX_ERROR;
            }

            b->memory = 1;
            b->pos = ngx_http_ssi_error_string;
            b->last = ngx_http_ssi_error_string
                      + sizeof(ngx_http_ssi_error_string) - 1;

            if (!(cl = ngx_alloc_chain_link(r->pool))) {
                return NGX_ERROR;
            }

            cl->buf = b;
            cl->next = NULL;
            *ctx->last_out = cl;
            ctx->last_out = &cl->next;

            continue;
        }

        ctx->buf->pos = ctx->buf->last;

        if (b && ctx->buf->last_buf) {
            b->last_buf = 1;
        }

        ctx->saved = ctx->looked;
    }

    if (ctx->out == NULL) {
        return NGX_OK;
    }

    rc = ngx_http_next_body_filter(r, ctx->out);

    ctx->out = NULL;
    ctx->last_out = &ctx->out;

    return rc;
}


static ngx_int_t
ngx_http_ssi_parse(ngx_http_request_t *r, ngx_http_ssi_ctx_t *ctx)
{
    u_char                *p, *last, *copy_end, ch;
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

            for ( /* void */ ; p < last; ch = *(++p)) {
                if (ch != '<') {
                    continue;
                }

                copy_end = p;
                looked = 1;
                state = ssi_tag_state;

                goto tag_started;
            }

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
                if (ctx->copy_start) {
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
                ctx->command.data = ngx_palloc(r->pool,
                                               NGX_HTTP_SSI_COMMAND_LEN + 1);
                if (ctx->command.data == NULL) {
                    return NGX_ERROR;
                }

                ctx->command.data[0] = ch;
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
                ctx->command.data[ctx->command.len++] = ch;

                if (ctx->command.len == NGX_HTTP_SSI_COMMAND_LEN) {
                    ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                                  "the \"%V\" SSI command is too long",
                                  &ctx->command);

                    state = ssi_error_state;
                    break;
                }
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
                if (!(ctx->param = ngx_array_push(&ctx->params))) {
                    return NGX_ERROR;
                }

                ctx->param->key.len = 1;
                ctx->param->key.data = ngx_palloc(r->pool,
                                                  NGX_HTTP_SSI_PARAM_LEN + 1);
                if (ctx->param->key.data == NULL) {
                    return NGX_ERROR;
                }

                ctx->param->key.data[0] = ch;

                ctx->param->value.len = 0;
                ctx->param->value.data = ngx_palloc(r->pool,
                                                    ctx->value_len + 1);
                if (ctx->param->value.data == NULL) {
                    return NGX_ERROR;
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
                ctx->param->key.data[ctx->param->key.len++] = ch;

                if (ctx->param->key.len == NGX_HTTP_SSI_PARAM_LEN) {
                    state = ssi_error_state;
                    ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                                  "too long \"%V\" parameter in "
                                  "\"%V\" SSI command",
                                  &ctx->param->key, &ctx->command);
                    break;
                }
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
            case '\\':
                ctx->saved_state = ssi_double_quoted_value_state;
                state = ssi_quoted_symbol_state;
                break;

            case '"':
                state = ssi_postparam_state;
                break;

            default:
                ctx->param->value.data[ctx->param->value.len++] = ch;

                if (ctx->param->value.len == ctx->value_len) {
                    ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                                  "too long \"%V\" value of \"%V\" parameter "
                                  "in \"%V\" SSI command",
                                  &ctx->param->value, &ctx->param->key,
                                  &ctx->command);
                    state = ssi_error_state;
                    break;
                }
            }

            break;

        case ssi_quoted_value_state:
            switch (ch) {
            case '\\':
                ctx->saved_state = ssi_quoted_value_state;
                state = ssi_quoted_symbol_state;
                break;

            case '\'':
                state = ssi_postparam_state;
                break;

            default:
                ctx->param->value.data[ctx->param->value.len++] = ch;

                if (ctx->param->value.len == ctx->value_len) {
                    ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                                  "too long \"%V\" value of \"%V\" parameter "
                                  "in \"%V\" SSI command",
                                  &ctx->param->value, &ctx->param->key,
                                  &ctx->command);
                    state = ssi_error_state;
                    break;
                }
            }

            break;

        case ssi_quoted_symbol_state:
            ctx->param->value.data[ctx->param->value.len++] = ch;

            if (ctx->param->value.len == ctx->value_len) {
                if (ctx->param->value.len == ctx->value_len) {
                    ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                                  "too long \"%V\" value of \"%V\" parameter "
                                  "in \"%V\" SSI command",
                                  &ctx->param->value, &ctx->param->key,
                                  &ctx->command);
                    state = ssi_error_state;
                    break;
                }
            }

            state = ctx->saved_state;
            break;

        case ssi_postparam_state:
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


static ngx_int_t
ngx_http_ssi_echo(ngx_http_request_t *r, ngx_http_ssi_ctx_t *ctx,
    ngx_str_t **params)
{
    u_char            ch;
    ngx_uint_t        i, n;
    ngx_buf_t        *b;
    ngx_str_t        *var, *value;
    ngx_chain_t      *cl;
    ngx_list_part_t  *part;
    ngx_table_elt_t  *header;

    var = params[NGX_HTTP_SSI_ECHO_VAR];
    value = NULL;

    if (var->len > 5 && ngx_strncmp(var->data, "HTTP_", 5) == 0) {

        part = &r->headers_in.headers.part;
        header = part->elts;

        for (i = 0; /* void */ ; i++) {

            if (i >= part->nelts) {
                if (part->next == NULL) {
                    break;
                }

                part = part->next;
                header = part->elts;
                i = 0; 
            }

            for (n = 0; n + 5 < var->len && n < header[i].key.len; n++)
            {
                ch = header[i].key.data[n];

                if (ch >= 'a' && ch <= 'z') {
                    ch &= ~0x20;

                } else if (ch == '-') {
                    ch = '_';
                }

                if (var->data[n + 5] != ch) {
                    break;
                }
            }

            if (n + 5 == var->len) {
                value = &header[i].value;
                break;
            }
        }

    } else if (var->len == sizeof("REMOTE_ADDR") - 1
               && ngx_strncmp(var->data, "REMOTE_ADDR",
                              sizeof("REMOTE_ADDR") - 1) == 0)
    {
        value = &r->connection->addr_text;
    }


    if (value == NULL) {
        value = params[NGX_HTTP_SSI_ECHO_DEFAULT];
    }

    if (value == NULL) {
        value = &ngx_http_ssi_none;

    } else if (value->len == 0) {
        return NGX_OK;
    }

    if (!(b = ngx_calloc_buf(r->pool))) {
        return NGX_HTTP_SSI_ERROR;
    }

    if (!(cl = ngx_alloc_chain_link(r->pool))) {
        return NGX_HTTP_SSI_ERROR;
    }

    b->memory = 1;
    b->pos = value->data;
    b->last = value->data + value->len;

    cl->buf = b;
    cl->next = NULL;
    *ctx->last_out = cl;
    ctx->last_out = &cl->next;

    return NGX_OK;
}


static void *
ngx_http_ssi_create_conf(ngx_conf_t *cf)
{
    ngx_http_ssi_conf_t  *conf;

    if (!(conf = ngx_pcalloc(cf->pool, sizeof(ngx_http_ssi_conf_t)))) {
        return NGX_CONF_ERROR;
    }

    conf->enable = NGX_CONF_UNSET;
    conf->silent_errors = NGX_CONF_UNSET;

    conf->min_file_chunk = NGX_CONF_UNSET_SIZE;
    conf->value_len = NGX_CONF_UNSET_SIZE;

    return conf;
}


static char *
ngx_http_ssi_merge_conf(ngx_conf_t *cf, void *parent, void *child)
{
    ngx_http_ssi_conf_t *prev = parent;
    ngx_http_ssi_conf_t *conf = child;

    ngx_conf_merge_value(conf->enable, prev->enable, 0);
    ngx_conf_merge_value(conf->silent_errors, prev->silent_errors, 0);

    ngx_conf_merge_size_value(conf->min_file_chunk, prev->min_file_chunk, 1024);
    ngx_conf_merge_size_value(conf->value_len, prev->value_len, 256);

    return NGX_CONF_OK;
}


static ngx_int_t
ngx_http_ssi_filter_init(ngx_cycle_t *cycle)
{
    ngx_http_next_header_filter = ngx_http_top_header_filter;
    ngx_http_top_header_filter = ngx_http_ssi_header_filter;

    ngx_http_next_body_filter = ngx_http_top_body_filter;
    ngx_http_top_body_filter = ngx_http_ssi_body_filter;

    return NGX_OK;
}
