
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


static int ngx_http_ssi_body_filter(ngx_http_request_t *r, ngx_chain_t *in)
{

}


static int ngx_http_ssi_parse()
{

    ctx

    new_hunk = 1;
    looked = ctx->looked;
    state = ctx->state;


    while (p < h->last) {
        ch = *p++;

        switch (state) {

        case ssi_start_state:

            if (new_hunk) {
                if (looked) {
                    send looked hunk
                }
                new_hunk = 0;
            }

            /* tight loop */
            for ( ;; ) {

                if (ch == '<') {
                    state = ssi_tag_state;
                    looked = 1;
                    break;
                }

                if (p < h->last) {
                    state = ssi_start_state;
                    looked = 0;
                    break;
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
                              ngx_palloc(r->pool, NGX_SSI_COMMAND_LEN),
                              NGX_ERROR);
                ctx->command.data[0] = ch;
                ctx->command.len = 1;
                state = ssi_command_state;
                break;
            }

            break;

        case ssi_command_state:
            if ((ch >= 'a' && ch =< 'z') || (ch >= 'A' && ch <= 'Z')
                || (ch == '_') || (ch >= '0' && ch <= '9'))
            {
                ctx->command.data[ctx->command.len++] = ch;

            } else if (ch == ' ' || ch == CR || ch == LF || ch == '\t') {
                state = ssi_postcommand_state;

#if 0
            } else if (ch == '=') {
                state = ssi_preexpression_state;
#endif

            } else {
                return NGX_SSI_PARSE_INVALID_COMMAND;
            }

            break;

        case ssi_postcommand_state:
            switch (ch) {
            case ' ':
            case CR:
            case LF:
            case '\t':
                break;

            case '=':
                state = ssi_preexpression_state;
                break;

            default:
                return NGX_SSI_PARSE_INVALID_PARAM;
            }

            break;

        case ssi_preexpression_state:
            switch (ch) {
            case ' ':
            case CR:
            case LF:
            case '\t':
                break;

            case '"':
                state = ssi_expression_state;
                break;

            default:
                return NGX_SSI_PARSE_INVALID_PARAM;
            }

            break;

        case ssi_expression_state:
            switch (ch) {
            case '\':
                state = ssi_quote_state;
                break;

            case '"':
                state = ssi_expression_state;
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

    send hunk (size - looked);

    return;
}


static int ngx_http_ssi_filter_init(ngx_cycle_t *cycle)
{
    next_header_filter = ngx_http_top_header_filter;
    ngx_http_top_header_filter = ngx_http_ssi_header_filter;

    next_body_filter = ngx_http_top_body_filter;
    ngx_http_top_body_filter = ngx_http_ssi_body_filter;

    return NGX_OK;
}
