
#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>


typedef struct {
} ngx_http_ssi_filter_ctx_t;


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


static comment_string = "<!--";


static int ngx_http_ssi_body_filter(ngx_http_request_t *r, ngx_chain_t *in)
{

}






static int ngx_http_ssi_parse(ngx_http_request_t *r, ngx_http_ssi_ctx_t *ctx,
                              ngx_hunk_t *h)
{
    int           looked, state;
    char         *p;
    ngx_hunk_t   *temp;
    ngx_chain_t   chain;

    looked = ctx->looked;
    state = ctx->state;
    p = h->pos;

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
                              ngx_palloc(r->pool, NGX_HTTP_SSI_COMMAND_LEN),
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
                ngx_test_null(param, ngx_push_array(&ctx->params), NGX_ERROR);

                ngx_test_null(param->name.data,
                              ngx_palloc(r->pool, NGX_HTTP_SSI_PARAM_LEN),
                              NGX_ERROR);
                param->name.data[0] = ch;
                param->name.len = 1;

                ngx_test_null(param->value.data,
                              ngx_palloc(r->pool, NGX_HTTP_SSI_VALUE_LEN),
                              NGX_ERROR);
                param->value.len = 0;

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
                ctx->param.data[ctx->param.len] = 0;
                state = ssi_preequal_state;
                break;

            case '=':
                ctx->param.data[ctx->param.len] = 0;
                state = ssi_prevalue_state;
                break;

            default:
                if (ctx->param.len >= NGX_HTTP_SSI_PARAM_LEN) {
                    return NGX_HTTP_SSI_INVALID_PARAM;
                }

                ctx->param.data[ctx->param.len++] = ch;
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
                return NGX_HTTP_SSI_PARSE_INVALID_PARAM;
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
                state = ssi_value_state;
                break;

            default:
                return NGX_HTTP_SSI_PARSE_INVALID_PARAM;
            }

            break;

        case ssi_value_state:
            switch (ch) {
            case '\':
                state = ssi_quote_state;
                break;

            case '"':
                state = ssi_postvalue_state;
                break;

            default:
                return NGX_SSI_PARSE_INVALID_PARAM;
            }

            break;

        case ssi_quote_state:
            state = ssi_expression_state;

            break;

        }
    }

    ctx->state = state;
    ctx->looked = looked;

    return NGX_HTTP_SSI_DONE;
}


static int ngx_http_ssi_filter_init(ngx_cycle_t *cycle)
{
    next_header_filter = ngx_http_top_header_filter;
    ngx_http_top_header_filter = ngx_http_ssi_header_filter;

    next_body_filter = ngx_http_top_body_filter;
    ngx_http_top_body_filter = ngx_http_ssi_body_filter;

    return NGX_OK;
}
