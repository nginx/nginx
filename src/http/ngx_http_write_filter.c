
#include <ngx_config.h>

#include <ngx_core.h>
#include <ngx_hunk.h>
#include <ngx_conf_file.h>

#include <ngx_event_write.h>

#include <ngx_http.h>
#include <ngx_http_config.h>
#include <ngx_http_write_filter.h>


static void *ngx_http_write_filter_create_conf(ngx_pool_t *pool);
static char *ngx_http_write_filter_merge_conf(ngx_pool_t *pool,
                                              void *parent, void *child);


static ngx_command_t ngx_http_write_filter_commands[] = {

    {ngx_string("write_buffer"),
     NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
     ngx_conf_set_size_slot,
     NGX_HTTP_LOC_CONF_OFFSET,
     offsetof(ngx_http_write_filter_conf_t, buffer_output)},

    {ngx_string(""), 0, NULL, 0, 0}
};


ngx_http_module_t  ngx_http_write_filter_module_ctx = {
    NGX_HTTP_MODULE,

    NULL,                                  /* create server config */
    NULL,                                  /* init server config */
    ngx_http_write_filter_create_conf,     /* create location config */
    ngx_http_write_filter_merge_conf,      /* merge location config */

    NULL,                                  /* translate handler */

    NULL,                                  /* output header filter */
    NULL,                                  /* next output header filter */
    ngx_http_write_filter,                 /* output body filter */
    NULL,                                  /* next output body filter */
};


ngx_module_t  ngx_http_write_filter_module = {
    0,                                     /* module index */
    &ngx_http_write_filter_module_ctx,     /* module context */
    ngx_http_write_filter_commands,        /* module directives */
    NGX_HTTP_MODULE_TYPE,                  /* module type */
    NULL                                   /* init module */
};


int ngx_http_write_filter(ngx_http_request_t *r, ngx_chain_t *in)
{
    int                           last;
    off_t                         size, flush;
    ngx_chain_t                  *ce, **le, *chain;
    ngx_http_write_filter_ctx_t  *ctx;
    ngx_http_write_filter_conf_t *conf;


    ctx = (ngx_http_write_filter_ctx_t *)
                     ngx_http_get_module_ctx(r->main ? r->main : r,
                                             ngx_http_write_filter_module);
    if (ctx == NULL) {
        ngx_http_create_ctx(r, ctx, ngx_http_write_filter_module,
                            sizeof(ngx_http_write_filter_ctx_t));
    }

    size = flush = 0;
    last = 0;
    le = &ctx->out;

    /* find the size, the flush point and the last entry of saved chain */
    for (ce = ctx->out; ce; ce = ce->next) {
        le = &ce->next;
        size += ce->hunk->last.file - ce->hunk->pos.file;

#if (NGX_DEBUG_WRITE_FILTER0)
        ngx_log_debug(r->connection->log, "write filter: old chunk: %x "
                      QX_FMT " " QD_FMT _
                      ce->hunk->type _ ce->hunk->pos.file _
                      ce->hunk->last.file - ce->hunk->pos.file);
#endif

        if (ce->hunk->type & (NGX_HUNK_FLUSH|NGX_HUNK_RECYCLED)) {
            flush = size;
        }

        if (ce->hunk->type & NGX_HUNK_LAST) {
            last = 1;
        }
    }

    /* add the new chain to the existent one */
    for (/* void */; in; in = in->next) {
        ngx_test_null(ce, ngx_palloc(r->pool, sizeof(ngx_chain_t)), NGX_ERROR);

        ce->hunk = in->hunk;
        ce->next = NULL;
        *le = ce;
        le = &ce->next;
        size += ce->hunk->last.file - ce->hunk->pos.file;

#if (NGX_DEBUG_WRITE_FILTER0)
        ngx_log_debug(r->connection->log, "write filter: new hunk: %x "
                      QX_FMT " " QD_FMT _
                      ce->hunk->type _ ce->hunk->pos.file _
                      ce->hunk->last.file - ce->hunk->pos.file);
#endif

        if (ce->hunk->type & (NGX_HUNK_FLUSH|NGX_HUNK_RECYCLED)) {
            flush = size;
        }

        if (ce->hunk->type & NGX_HUNK_LAST) {
            last = 1;
        }
    }

    conf = (ngx_http_write_filter_conf_t *)
                ngx_http_get_module_loc_conf(r->main ? r->main : r,
                                             ngx_http_write_filter_module);

#if (NGX_DEBUG_WRITE_FILTER0)
    ngx_log_debug(r->connection->log, "write filter: last:%d flush:%d" _
                  last _ flush);
#endif

    /* avoid the output if there is no last hunk, no flush point and
       size of the hunks is smaller then 'write_buffer' */
    if (!last && flush == 0 && size < conf->buffer_output) {
        return NGX_OK;
    }

    chain = ngx_event_write(r->connection, ctx->out, flush);

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
    ngx_http_write_filter_conf_t *prev =
                                      (ngx_http_write_filter_conf_t *) parent;
    ngx_http_write_filter_conf_t *conf =
                                       (ngx_http_write_filter_conf_t *) child;

    ngx_conf_size_merge(conf->buffer_output, prev->buffer_output, 1460);

    return NULL;
}

