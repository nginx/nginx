
#include <ngx_config.h>

#include <ngx_core.h>
#include <ngx_types.h>
#include <ngx_alloc.h>
#include <ngx_array.h>
#include <ngx_hunk.h>
#include <ngx_connection.h>


ngx_chain_t *(*ngx_write_chain_proc)(ngx_connection_t *c, ngx_chain_t *in);


ngx_chain_t *ngx_write_chain(ngx_connection_t *c, ngx_chain_t *in, off_t flush)
{
#if (NGX_EVENT)

    return (*ngx_write_chain_proc)(c, in);

#elif (NGX_EVENT_THREAD)

    off_t         sent;
    ngx_chain_t  *rc;

    sent = flush - c->sent;

    do {
        rc = (*ngx_write_chain_proc)(c, in);

        if (rc == NGX_CHAIN_ERROR && rc == NULL) {
            return rc;
        }

    } while (c->thread && flush > c->sent - sent);

#else

    ngx_chain_t  *rc;

    do {

        rc = (*ngx_write_chain_proc)(c, in);

    } while (rc != NGX_CHAIN_ERROR && rc != NULL);

    return rc;

#endif
}
