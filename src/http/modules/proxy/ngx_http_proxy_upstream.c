
#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_event.h>
#include <ngx_event_connect.h>
#include <ngx_event_pipe.h>
#include <ngx_http.h>
#include <ngx_http_proxy_handler.h>


void ngx_http_proxy_reinit_upstream(ngx_http_proxy_ctx_t *p)
{
    ngx_chain_t             *cl;
    ngx_output_chain_ctx_t  *octx;

    octx = p->output_chain_ctx;

    /* reinit the request chain */

    for (cl = p->request->request_hunks; cl; cl = cl->next) {
        cl->hunk->pos = cl->hunk->start;
    }

    /* reinit ngx_output_chain() context */

    octx->hunk = NULL;
    octx->in = NULL;
    octx->free = NULL;
    octx->busy = NULL;

    /* reinit r->header_in buffer */

    if (p->header_in) {
        if (p->cache) {
            p->header_in->pos = p->header_in->start + p->cache->ctx.header.size;
            p->header_in->last = p->header_in->pos;

        } else {
            p->header_in->pos = p->header_in->start;
            p->header_in->last = p->header_in->start;
        }
    }
}
