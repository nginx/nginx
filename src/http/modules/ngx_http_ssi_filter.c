
#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>


#define NGX_HTTP_SSI_COMMAND_LEN      31
#define NGX_HTTP_SSI_PARAM_LEN        31

#define NGX_HTTP_SSI_DONE             1
#define NGX_HTTP_SSI_INVALID_COMMAND  2
#define NGX_HTTP_SSI_INVALID_PARAM    3
#define NGX_HTTP_SSI_INVALID_VALUE    4
#define NGX_HTTP_SSI_LONG_VALUE       5


typedef struct {
    ngx_table_elt_t  *param;
    ngx_str_t         command;
    ngx_array_t       params;
    int               state;
    int               looked;
    char             *pos;
    ngx_chain_t      *out;
    int               new_hunk;
    u_int             value_len;
} ngx_http_ssi_ctx_t;


static int ngx_http_ssi_filter_init(ngx_cycle_t *cycle);

    
static ngx_http_module_t  ngx_http_ssi_filter_module_ctx = {
    NULL,                                  /* create main configuration */
    NULL,                                  /* init main configuration */

    NULL,                                  /* create server configuration */
    NULL,                                  /* merge server configuration */

    NULL,                                  /* create location configuration */
    NULL,                                  /* merge location configuration */
};  


ngx_module_t  ngx_http_ssi_filter_module = {
    NGX_MODULE,
    &ngx_http_ssi_filter_module_ctx,       /* module context */
    NULL,                                  /* module directives */
    NGX_HTTP_MODULE,                       /* module type */
    ngx_http_ssi_filter_init,              /* init module */
    NULL                                   /* init child */
};


static int (*next_header_filter) (ngx_http_request_t *r);
static int (*next_body_filter) (ngx_http_request_t *r, ngx_chain_t *ch);



static char comment_string[] = "<!--";


static int ngx_http_ssi_body_filter(ngx_http_request_t *r, ngx_chain_t *in)
{
    ngx_chain_t          chain;
    ngx_http_ssi_ctx_t  *ctx;

    ctx = ngx_http_get_module_ctx(r, ngx_http_ssi_filter_module);

    if (ctx == NULL) {
        ngx_http_create_ctx(r, ctx, ngx_http_ssi_filter_module,
                            sizeof(ngx_http_ssi_ctx_t), NGX_ERROR);
    }

    if (in == NULL && ctx->out == NULL) {
        return next_body_filter(r, NULL);
    }

#if 0

    add in to ctx->out chain

    while (ctx->out) {
        rc = ngx_http_ssi_parse(r, ctx, ctx->out->hunk);

        if (rc == NGX_HTTP_SSI_DONE) {
            chain.hunk = ctx->out->hunk;
            chain.next = NULL;

            rc = next_body_filter(r, &chain);
            if (rc != NGX_OK) {
                return rc;
            }
        }

        ctx->out = ctx->out->next;
    }

#endif

    return NGX_OK;
}






static int ngx_http_ssi_parse(ngx_http_request_t *r, ngx_http_ssi_ctx_t *ctx,
                              ngx_hunk_t *h)
{
    int           looked;
    char         *p, ch;
    ngx_hunk_t   *temp;
    ngx_chain_t   chain;

    enum {
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
        ssi_comment_end1_state
    } state;


    looked = ctx->looked;
    state = ctx->state;
    p = ctx->pos;

    while (p < h->last) {
        ch = *p++;

        switch (state) {

        case ssi_start_state:

            if (ctx->new_hunk) {

                if (looked) {
                    ngx_test_null(temp, ngx_calloc_hunk(r->pool), NGX_ERROR);
                    temp->type = NGX_HUNK_IN_MEMORY|NGX_HUNK_TEMP;
                    temp->pos = comment_string;
                    temp->last = comment_string + looked;

                    chain.hunk = temp;
                    chain.next = NULL;

                    if (next_body_filter(r, &chain) == NGX_ERROR) {
                        return NGX_ERROR;
                    }
                }

                ctx->new_hunk = 0;
            }

            /* tight loop */
            for ( ;; ) {

                if (ch == '<') {
                    state = ssi_tag_state;
                    looked = 1;
                    break;
                }

                if (p < h->last) {
                    ctx->state = ssi_start_state;
                    ctx->looked = 0;
                    ctx->pos = p;
                    return NGX_HTTP_SSI_DONE;
                }

                ch = *p++;
            }

            break;

        case ssi_tag_state:
            switch (ch) {
            case '!':
                state = ssi_comment0_state;
                looked = 2;
                break;

            case '<':
                break;

            default:
                state = ssi_start_state;
                looked = 0;
                break;
            }

            break;

        case ssi_comment0_state:
            switch (ch) {
            case '-':
                state = ssi_comment1_state;
                looked = 3;
                break;

            case '<':
                state = ssi_tag_state;
                looked = 1;
                break;

            default:
                state = ssi_start_state;
                looked = 0;
                break;
            }

            break;

        case ssi_comment1_state:
            switch (ch) {
            case '-':
                state = ssi_sharp_state;
                looked = 4;
                break;

            case '<':
                state = ssi_tag_state;
                looked = 1;
                break;

            default:
                state = ssi_start_state;
                looked = 0;
                break;
            }

            break;

        case ssi_sharp_state:
            switch (ch) {
            case '#':
                state = ssi_precommand_state;
                looked = 0;
                break;

            case '<':
                state = ssi_tag_state;
                looked = 1;
                break;

            default:
                state = ssi_start_state;
                looked = 0;
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
                ngx_test_null(ctx->command.data,
                              ngx_palloc(r->pool, NGX_HTTP_SSI_COMMAND_LEN + 1),
                              NGX_ERROR);
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
                ngx_test_null(ctx->param, ngx_push_array(&ctx->params),
                              NGX_ERROR);

                ngx_test_null(ctx->param->key.data,
                              ngx_palloc(r->pool, NGX_HTTP_SSI_PARAM_LEN + 1),
                              NGX_ERROR);
                ctx->param->key.data[0] = ch;
                ctx->param->key.len = 1;

                ngx_test_null(ctx->param->value.data,
                              ngx_palloc(r->pool, ctx->value_len + 1),
                              NGX_ERROR);
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

            default:
                if (ctx->param->key.len >= NGX_HTTP_SSI_PARAM_LEN) {
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

            default:
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

            default:
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
                if (ctx->param->value.len >= ctx->value_len) {
                    return NGX_HTTP_SSI_LONG_VALUE;
                }

                ctx->param->value.data[ctx->param->value.len++] = ch;
            }

            break;

        case ssi_double_quoted_value_quote_state:
            if (ctx->param->value.len >= ctx->value_len) {
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
                if (ctx->param->value.len >= ctx->value_len) {
                    return NGX_HTTP_SSI_LONG_VALUE;
                }

                ctx->param->value.data[ctx->param->value.len++] = ch;
            }

            break;

        case ssi_quoted_value_quote_state:
            if (ctx->param->value.len >= ctx->value_len) {
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
                return NGX_HTTP_SSI_INVALID_COMMAND;
            }

            break;

        case ssi_comment_end1_state:
            switch (ch) {
            case '>':
                ctx->state = ssi_start_state;
                ctx->pos = p;
                return NGX_OK;

            default:
                return NGX_HTTP_SSI_INVALID_COMMAND;
            }

            break;
        }
    }

    ctx->state = state;
    ctx->looked = looked;
    ctx->pos = p;

    return NGX_HTTP_SSI_DONE;
}


static int ngx_http_ssi_filter_init(ngx_cycle_t *cycle)
{
#if 0
    next_header_filter = ngx_http_top_header_filter;
    ngx_http_top_header_filter = ngx_http_ssi_header_filter;
#endif

    next_body_filter = ngx_http_top_body_filter;
    ngx_http_top_body_filter = ngx_http_ssi_body_filter;

    return NGX_OK;
}
