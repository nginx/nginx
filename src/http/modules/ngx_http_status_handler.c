
#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>


static char *ngx_http_status(ngx_conf_t *cf, ngx_command_t *cmd, void *conf);

static ngx_command_t  ngx_http_status_commands[] = {

    { ngx_string("status"),
      NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_FLAG,
      ngx_http_status,
      0,
      0,
      NULL },

      ngx_null_command
};



ngx_http_module_t  ngx_http_status_module_ctx = {
    NULL,                                  /* pre conf */

    NULL,                                  /* create main configuration */
    NULL,                                  /* init main configuration */

    NULL,                                  /* create server configuration */
    NULL,                                  /* merge server configuration */

    NULL,                                  /* create location configuration */
    NULL                                   /* merge location configuration */
};


ngx_module_t  ngx_http_status_module = {
    NGX_MODULE,
    &ngx_http_status_module_ctx,           /* module context */
    ngx_http_status_commands,              /* module directives */
    NGX_HTTP_MODULE,                       /* module type */
    NULL,                                  /* init module */
    NULL                                   /* init process */
};


static ngx_int_t ngx_http_status_handler(ngx_http_request_t *r)
{
    u_char               ch;
    size_t               len;
    ngx_int_t            rc;
    ngx_uint_t           i, dash;
    ngx_buf_t           *b;
    ngx_chain_t          out;
    ngx_connection_t    *c;
    ngx_http_request_t  *rq;

    if (r->method != NGX_HTTP_GET && r->method != NGX_HTTP_HEAD) {
        return NGX_HTTP_NOT_ALLOWED;
    }

    rc = ngx_http_discard_body(r);

    if (rc != NGX_OK && rc != NGX_AGAIN) {
        return rc;
    }

    if (!(r->headers_out.content_type =
                   ngx_http_add_header(&r->headers_out, ngx_http_headers_out)))
    {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    } 

    r->headers_out.content_type->key.len = 0;
    r->headers_out.content_type->key.data = NULL;
    r->headers_out.content_type->value.len = sizeof("text/plain") - 1;
    r->headers_out.content_type->value.data = (u_char *) "text/plain";

    if (r->method == NGX_HTTP_HEAD) {
        r->headers_out.status = NGX_HTTP_OK;

        rc = ngx_http_send_header(r);

        if (rc == NGX_ERROR || rc > NGX_OK || r->header_only) {
            return rc;
        }
    }

    len = 0;
    dash = 0;

    c = ngx_cycle->connections;
    for (i = 0; i < ngx_cycle->connection_n; i++) {
        rq = c[i].data;
        if (rq && rq->signature == NGX_HTTP_MODULE) {

                   /* STUB: should be NGX_PID_T_LEN */
            len += NGX_INT64_LEN                       /* pid */
                   + 1 + NGX_INT32_LEN                 /* connection */
                   + 1 + 1                             /* state */
                   + 1 + c[i].addr_text.len
                   + 1 + rq->server_name->len
                   + 2;                                /* "\r\n" */

            if (rq->request_line.len) {
                len += 1 + rq->request_line.len + 2;
            }

            dash = 0;

            continue;
        }

        if (!dash) {
            len += 3;
            dash = 1;
        }
    }

    if (!(b = ngx_create_temp_buf(r->pool, len))) {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    dash = 0;

    for (i = 0; i < ngx_cycle->connection_n; i++) {
        rq = c[i].data;
        if (rq && rq->signature == NGX_HTTP_MODULE) {

            b->last += ngx_snprintf((char *) b->last,
                                    /* STUB: should be NGX_PID_T_LEN */
                                    NGX_INT64_LEN + NGX_INT32_LEN,
                                    PID_T_FMT " %u", ngx_pid, i);

            switch (rq->http_state) {
            case NGX_HTTP_INITING_REQUEST_STATE:
                ch = 'I';
                break;

            case NGX_HTTP_READING_REQUEST_STATE:
                ch = 'R';
                break;

            case NGX_HTTP_PROCESS_REQUEST_STATE:
                ch = 'P';
                break;

            case NGX_HTTP_WRITING_REQUEST_STATE:
                ch = 'W';
                break;

            case NGX_HTTP_KEEPALIVE_STATE:
                ch = 'K';
                break;

            default:
                ch = '?';
            }

            *(b->last++) = ' ';
            *(b->last++) = ch;

            *(b->last++) = ' ';
            b->last = ngx_cpymem(b->last, c[i].addr_text.data,
                                 c[i].addr_text.len);

            *(b->last++) = ' ';
            b->last = ngx_cpymem(b->last, rq->server_name->data,
                                 rq->server_name->len);

            if (rq->request_line.len) {
                *(b->last++) = ' ';
                *(b->last++) = '"';
                b->last = ngx_cpymem(b->last, r->request_line.data,
                                     r->request_line.len);
                *(b->last++) = '"';

            }

            *(b->last++) = CR; *(b->last++) = LF;

            dash = 0;

            continue;
        }

        if (!dash) {
            *(b->last++) = '-'; *(b->last++) = CR; *(b->last++) = LF;
            dash = 1;
        }
    }

    r->headers_out.status = NGX_HTTP_OK;
    r->headers_out.content_length_n = b->last - b->pos;

    rc = ngx_http_send_header(r);

    if (rc == NGX_ERROR || rc > NGX_OK || r->header_only) {
        return rc;
    }

    if (!r->main) {
        b->last_buf = 1;
    }

    out.buf = b;
    out.next = NULL;

    return ngx_http_output_filter(r, &out);
}


static char *ngx_http_status(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    ngx_http_conf_ctx_t       *ctx;
    ngx_http_core_loc_conf_t  *clcf;

    ctx = cf->ctx;
    clcf = ctx->loc_conf[ngx_http_core_module.ctx_index];
    clcf->handler = ngx_http_status_handler;

    return NGX_CONF_OK;
}
