
#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>


typedef struct {
    size_t        buffer_output;
} ngx_http_write_filter_conf_t;


typedef struct {
    ngx_chain_t  *out;
} ngx_http_write_filter_ctx_t;


static void *ngx_http_write_filter_create_conf(ngx_pool_t *pool);
static char *ngx_http_write_filter_merge_conf(ngx_pool_t *pool,
                                              void *parent, void *child);
static int ngx_http_write_filter_init(ngx_pool_t *pool);


static ngx_command_t ngx_http_write_filter_commands[] = {

    {ngx_string("buffer_output"),
     NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
     ngx_conf_set_size_slot,
     NGX_HTTP_LOC_CONF_OFFSET,
     offsetof(ngx_http_write_filter_conf_t, buffer_output),
     NULL},

    ngx_null_command
};


ngx_http_module_t  ngx_http_write_filter_module_ctx = {
    NULL,                                  /* create main configuration */
    NULL,                                  /* init main configuration */

    NULL,                                  /* create server configuration */
    NULL,                                  /* merge server configuration */

    ngx_http_write_filter_create_conf,     /* create location configuration */
    ngx_http_write_filter_merge_conf       /* merge location configuration */
};


ngx_module_t  ngx_http_write_filter_module = {
    NGX_MODULE,
    &ngx_http_write_filter_module_ctx,     /* module context */
    ngx_http_write_filter_commands,        /* module directives */
    NGX_HTTP_MODULE,                       /* module type */
    ngx_http_write_filter_init             /* init module */
};


int ngx_http_write_filter(ngx_http_request_t *r, ngx_chain_t *in)
{
    int                            last;
    off_t                          size, flush;
    ngx_chain_t                   *ce, **le, *chain;
    ngx_http_write_filter_ctx_t   *ctx;
    ngx_http_write_filter_conf_t  *conf;

    ctx = ngx_http_get_module_ctx(r->main ? r->main : r,
                                  ngx_http_write_filter_module);

    if (ctx == NULL) {
        ngx_http_create_ctx(r, ctx, ngx_http_write_filter_module,
                            sizeof(ngx_http_write_filter_ctx_t), NGX_ERROR);
    }

    size = flush = 0;
    last = 0;
    le = &ctx->out;

    /* find the size, the flush point and the last entry of the saved chain */

    for (ce = ctx->out; ce; ce = ce->next) {
        le = &ce->next;

        if (ce->hunk->type & NGX_HUNK_IN_MEMORY) {
            size += ce->hunk->last - ce->hunk->pos;
        } else {
            size += ce->hunk->file_last - ce->hunk->file_pos;
        }

        if (ce->hunk->type & (NGX_HUNK_FLUSH|NGX_HUNK_RECYCLED)) {
            flush = size;
        }

        if (ce->hunk->type & NGX_HUNK_LAST) {
            last = 1;
        }
    }

    /* add the new chain to the existent one */

    for (/* void */; in; in = in->next) {
        ngx_test_null(ce, ngx_alloc_chain_entry(r->pool), NGX_ERROR);

        ce->hunk = in->hunk;
        ce->next = NULL;
        *le = ce;
        le = &ce->next;

        if (ce->hunk->type & NGX_HUNK_IN_MEMORY) {
            size += ce->hunk->last - ce->hunk->pos;
        } else {
            size += ce->hunk->file_last - ce->hunk->file_pos;
        }

        if (ce->hunk->type & (NGX_HUNK_FLUSH|NGX_HUNK_RECYCLED)) {
            flush = size;
        }

        if (ce->hunk->type & NGX_HUNK_LAST) {
            last = 1;
        }
    }

    conf = ngx_http_get_module_loc_conf(r->main ? r->main : r,
                                        ngx_http_write_filter_module);

#if (NGX_DEBUG_WRITE_FILTER)
    ngx_log_debug(r->connection->log,
                  "write filter: last:%d flush:%qd size:%qd" _
                  last _ flush _ size);
#endif

    /* avoid the output if there is no last hunk, no flush point and
       size of the hunks is smaller then "buffer_output" */

    if (!last && flush == 0 && size < conf->buffer_output) {
        return NGX_OK;
    }

    if (r->connection->write->delayed) {
        return NGX_AGAIN;
    }

#if 1
    chain = ngx_write_chain(r->connection, ctx->out);
#else
    chain = ngx_write_chain(r->connection, ctx->out, flush);
#endif

#if (NGX_DEBUG_WRITE_FILTER)
    ngx_log_debug(r->connection->log, "write filter %x" _ chain);
#endif

    if (chain == NGX_CHAIN_ERROR) {
        return NGX_ERROR;
    }

    ctx->out = chain;

    if (chain == NULL) {
        return NGX_OK;

    } else {
        return NGX_AGAIN;
    }
}


static void *ngx_http_write_filter_create_conf(ngx_pool_t *pool)
{
    ngx_http_write_filter_conf_t *conf;

    ngx_test_null(conf,
                  ngx_palloc(pool, sizeof(ngx_http_write_filter_conf_t)),
                  NULL);

    conf->buffer_output = NGX_CONF_UNSET;

    return conf;
}


static char *ngx_http_write_filter_merge_conf(ngx_pool_t *pool,
                                              void *parent, void *child)
{
    ngx_http_write_filter_conf_t *prev = parent;
    ngx_http_write_filter_conf_t *conf = child;

    ngx_conf_merge_size_value(conf->buffer_output, prev->buffer_output, 1460);

    return NULL;
}


static int ngx_http_write_filter_init(ngx_pool_t *pool)
{
    ngx_http_top_body_filter = ngx_http_write_filter;

    return NGX_OK;
}
