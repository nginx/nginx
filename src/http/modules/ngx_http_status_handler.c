
/*
 * Copyright (C) Igor Sysoev
 */


#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>


typedef struct {
    ngx_http_request_t  *request;
    ngx_pool_t          *pool;
    ngx_chain_t         *head;
    ngx_buf_t           *last;
    size_t               size;
} ngx_http_status_ctx_t;


static ngx_int_t ngx_http_status(ngx_http_status_ctx_t *ctx);
static char *ngx_http_set_status(ngx_conf_t *cf, ngx_command_t *cmd,
                                 void *conf);

static ngx_command_t  ngx_http_status_commands[] = {

    { ngx_string("status"),
      NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_FLAG,
      ngx_http_set_status,
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
    ngx_int_t              rc;
    ngx_http_status_ctx_t  ctx;

    if (r->method != NGX_HTTP_GET && r->method != NGX_HTTP_HEAD) {
        return NGX_HTTP_NOT_ALLOWED;
    }

    rc = ngx_http_discard_body(r);

    if (rc != NGX_OK && rc != NGX_AGAIN) {
        return rc;
    }

    r->headers_out.content_type = ngx_list_push(&r->headers_out.headers);
    if (r->headers_out.content_type == NULL) {
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

    ctx.request = r;
    ctx.pool = r->pool;
    ctx.head = NULL;
    ctx.size = 0;

    if (ngx_http_status(&ctx) != NGX_OK) {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    r->headers_out.status = NGX_HTTP_OK;
    r->headers_out.content_length_n = ctx.size;

    rc = ngx_http_send_header(r);

    if (rc == NGX_ERROR || rc > NGX_OK || r->header_only) {
        return rc;
    }

    if (!r->main) {
        ctx.last->last_buf = 1;
    }

    return ngx_http_output_filter(r, ctx.head);
}


static ngx_int_t ngx_http_status(ngx_http_status_ctx_t *ctx)
{
    u_char                      ch;
    size_t                      len, n;
    ngx_uint_t                  i, dash;
    ngx_buf_t                  *b;
    ngx_chain_t                *cl, **ll;
    ngx_connection_t           *c;
    ngx_http_request_t         *r;
    ngx_http_core_main_conf_t  *cmcf;

    cmcf = ngx_http_get_module_main_conf(ctx->request, ngx_http_core_module);

#if (NGX_SUPPRESS_WARN)
    b = NULL;
    ll = NULL;
#endif

    dash = 0;

    /* TODO: old connections */

    c = ngx_cycle->connections;
    for (i = 0; i < ngx_cycle->connection_n; i++) {

        /* TODO: trylock connection mutex */

        r = c[i].data;
        if (r && r->signature == NGX_HTTP_MODULE) {

                   /* STUB: should be NGX_PID_T_LEN */
            len = NGX_INT64_LEN                       /* pid */
                  + 1 + NGX_INT32_LEN                 /* connection */
                  + 1 + 1                             /* state */
                  + 1 + INET_ADDRSTRLEN
                  + 1 + (r->server_name ? cmcf->max_server_name_len : 1)
                  + 2;                                /* "\r\n" */

            if (r->request_line.len) {
                len += 1 + 1 + r->request_line.len + 1;
            }

            if (!(b = ngx_create_temp_buf(ctx->pool, len))) {
                /* TODO: unlock mutex */
                return NGX_ERROR;
            }

            b->last += ngx_snprintf((char *) b->last,
                                    /* STUB: should be NGX_PID_T_LEN */
                                    NGX_INT64_LEN + NGX_INT32_LEN,
                                    PID_T_FMT " %4u", ngx_pid, i);

            switch (r->http_state) {
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
            for (n = c[i].addr_text.len; n < INET_ADDRSTRLEN; n++) {
                 *(b->last++) = ' ';
            }

            *(b->last++) = ' ';
            if (r->server_name) {
                b->last = ngx_cpymem(b->last, r->server_name->data,
                                     r->server_name->len);
                for (n = r->server_name->len;
                     n < cmcf->max_server_name_len;
                     n++)
                {
                     *(b->last++) = ' ';
                }

            } else {
                *(b->last++) = '?';
            }

            if (r->request_line.len) {
                *(b->last++) = ' ';
                *(b->last++) = '"';
                b->last = ngx_cpymem(b->last, r->request_line.data,
                                     r->request_line.len);
                *(b->last++) = '"';

            }

            *(b->last++) = CR; *(b->last++) = LF;

            dash = 0;

        } else if (c[i].fd != -1) {
            len = NGX_INT64_LEN                       /* pid */
                  + 1 + NGX_INT32_LEN                 /* connection */
                  + 1 + 1                             /* state */
                  + 2;                                /* "\r\n" */

            if (!(b = ngx_create_temp_buf(ctx->pool, len))) {
                /* TODO: unlock mutex */
                return NGX_ERROR;
            }

            b->last += ngx_snprintf((char *) b->last,
                                    /* STUB: should be NGX_PID_T_LEN */
                                    NGX_INT64_LEN + NGX_INT32_LEN,
                                    PID_T_FMT " %4u", ngx_pid, i);

            *(b->last++) = ' ';
            *(b->last++) = 's';

            *(b->last++) = CR; *(b->last++) = LF;

            dash = 0;

       } else if (!dash) {
            len = 3;

            if (!(b = ngx_create_temp_buf(ctx->pool, len))) {
                /* TODO: unlock mutex */
                return NGX_ERROR;
            }

            *(b->last++) = '-'; *(b->last++) = CR; *(b->last++) = LF;

            dash = 1;

        } else {
            continue;
        }

        /* TODO: unlock mutex */

        if (!(cl = ngx_alloc_chain_link(ctx->pool))) {
            return NGX_ERROR;
        }

        if (ctx->head) {
            *ll = cl;

        } else { 
            ctx->head = cl;
        }

        cl->buf = b;
        cl->next = NULL;
        ll = &cl->next;

        ctx->size += b->last - b->pos;
    }

    ctx->last = b;

    return NGX_OK;
}


static char *ngx_http_set_status(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    ngx_http_core_loc_conf_t  *clcf;

    clcf = ngx_http_conf_get_module_loc_conf(cf, ngx_http_core_module);
    clcf->handler = ngx_http_status_handler;

    return NGX_CONF_OK;
}
