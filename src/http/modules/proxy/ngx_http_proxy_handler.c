
#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_event.h>
/* STUB */ #include <ngx_event_connect.h>
#include <ngx_http.h>
#include <ngx_http_proxy_handler.h>



static void ngx_http_proxy_send_request(ngx_event_t *wev);
static void ngx_http_proxy_close_connection(ngx_connection_t *c);
static ngx_chain_t *ngx_http_proxy_copy_request_hunks(ngx_http_proxy_ctx_t *p);
static void *ngx_http_proxy_create_loc_conf(ngx_conf_t *cf);


static ngx_command_t ngx_http_proxy_commands[] = {
    ngx_null_command
};


ngx_http_module_t  ngx_http_proxy_module_ctx = {
    NULL,                                  /* create main configuration */
    NULL,                                  /* init main configuration */

    NULL,                                  /* create server configuration */
    NULL,                                  /* merge server configuration */

    ngx_http_proxy_create_loc_conf,        /* create location configration */
#if 0
    ngx_http_proxy_merge_conf              /* merge location configration */
#endif

    NULL
};


ngx_module_t  ngx_http_proxy_module = {
    NGX_MODULE,
    &ngx_http_proxy_module_ctx,            /* module context */
    ngx_http_proxy_commands,               /* module directives */
    NGX_HTTP_MODULE,                       /* module type */
    NULL,                                  /* init module */
    NULL                                   /* init child */
};


#if 0
static
#endif

int ngx_http_proxy_handler(ngx_http_request_t *r)
{
    int                         rc;
    ngx_http_proxy_ctx_t       *p;
    ngx_http_proxy_loc_conf_t  *lcf;

    ngx_http_create_ctx(r, p, ngx_http_proxy_module,
                        sizeof(ngx_http_proxy_ctx_t),
                        NGX_HTTP_INTERNAL_SERVER_ERROR);

    p->lcf = ngx_http_get_module_loc_conf(r, ngx_http_proxy_module);

#if 0
    create_request;
#endif

    p->action = "connecting to upstream";
    p->request = r;
    p->upstream.peers = p->lcf->peers;
    p->upstream.tries = p->lcf->peers->number;

    /* TODO: log->data would be changed, how to restore log->data ? */
    p->upstream.log = r->connection->log;

    for ( ;; ) {
        rc = ngx_event_connect_peer(&p->upstream);

        if (rc == NGX_ERROR) {
            return NGX_HTTP_INTERNAL_SERVER_ERROR;
        }

        if (rc == NGX_CONNECT_ERROR) {
            ngx_event_connect_peer_failed(&p->upstream);

            if (p->upstream.tries == 0) {
                return NGX_HTTP_BAD_GATEWAY;
            }
        }

        p->upstream.connection->data = p;
        p->upstream.connection->write->event_handler =
                                                   ngx_http_proxy_send_request;
        p->upstream.connection->read->event_handler = /* STUB */ NULL;

        if (p->upstream.tries > 1) {
            ngx_test_null(p->work_request_hunks,
                          ngx_http_proxy_copy_request_hunks(p),
                          NGX_HTTP_INTERNAL_SERVER_ERROR);
        } else {
            p->work_request_hunks = p->request_hunks;
        }

        if (rc == NGX_OK) {
            ngx_http_proxy_send_request(p->upstream.connection->write);
            return NGX_OK;
        }

        /* rc == NGX_AGAIN */

        /* timer */

        /* TODO */ return NGX_OK;
    }
}


static void ngx_http_proxy_send_request(ngx_event_t *wev)
{
    int                    rc;
    ngx_chain_t           *chain;
    ngx_connection_t      *c;
    ngx_http_proxy_ctx_t  *p;

    c = wev->data;
    p = c->data;

    for ( ;; ) {
        chain = ngx_write_chain(c, p->request_hunks);

        if (chain == (ngx_chain_t *) -1) {
            ngx_http_proxy_close_connection(c);

            for ( ;; ) {
                rc = ngx_event_connect_peer(&p->upstream);

                if (rc == NGX_ERROR) {
                    ngx_http_finalize_request(p->request,
                                              NGX_HTTP_INTERNAL_SERVER_ERROR);
                    return;
                }

                if (rc == NGX_CONNECT_ERROR) {
                    ngx_event_connect_peer_failed(&p->upstream);

                    if (p->upstream.tries == 0) {
                        return;
                    }
                }

                if (p->upstream.tries > 1) {
                    ngx_test_null(p->work_request_hunks,
                                  ngx_http_proxy_copy_request_hunks(p),
                                  /* void */);
                } else {
                    p->work_request_hunks = p->request_hunks;
                }

                if (rc == NGX_OK) {
                    c = p->connection;
                    wev = c->write;

                    break;
                }

                /* rc == NGX_AGAIN */
                return;

            }

        } else {
            p->work_request_hunks = chain;

            ngx_del_timer(wev);

            if (chain) {
                ngx_add_timer(wev, p->lcf->send_timeout);
                wev->timer_set = 1;

            } else {
                wev->timer_set = 0;
                /* TODO: del event */
            }

            return;
        }
    }
}

static void ngx_http_proxy_close_connection(ngx_connection_t *c)
{
    return;
}

static ngx_chain_t *ngx_http_proxy_copy_request_hunks(ngx_http_proxy_ctx_t *p)
{
    ngx_chain_t  *ce, *te, *fe, **le;

#if (NGX_SUPPRESS_WARN)
    le = NULL;
#endif

    ngx_test_null(fe, ngx_alloc_chain_entry(p->request->pool), NULL);

    te = fe;

    for (ce = p->request_hunks; ce; ce = ce->next) {
        te->hunk = ce->hunk;
        *le = te;
        le = &te->next;
        ce->hunk->pos = ce->hunk->start;

        ngx_test_null(te, ngx_alloc_chain_entry(p->request->pool), NULL);
    }

    *le = NULL;

    return fe;
}


static size_t ngx_http_proxy_log_error(void *data, char *buf, size_t len)
{
    ngx_http_proxy_ctx_t *p = data;

    return ngx_snprintf(buf, len,
            " while %s, upstream: %s, client: %s, URL: %s",
            p->action,
            p->upstream.peers->peers[p->upstream.cur_peer].addr_port_text.data,
            p->request->connection->addr_text.data,
            p->request->unparsed_uri.data);
}


static void *ngx_http_proxy_create_loc_conf(ngx_conf_t *cf)
{
    ngx_http_proxy_loc_conf_t  *conf;

    ngx_test_null(conf,
                  ngx_pcalloc(cf->pool, sizeof(ngx_http_proxy_loc_conf_t)),
                  NGX_CONF_ERROR);

    /* STUB */
    ngx_test_null(conf->peers, ngx_pcalloc(cf->pool, sizeof(ngx_peers_t)),
                  NGX_CONF_ERROR);

    conf->peers->number = 1;
    conf->peers->peers[0].addr = inet_addr("127.0.0.1");
    conf->peers->peers[0].host.data = "localhost";
    conf->peers->peers[0].host.len = sizeof("localhost") - 1;
    conf->peers->peers[0].port = htons(9000);
    conf->peers->peers[0].addr_port_text.data = "127.0.0.1:9000";
    conf->peers->peers[0].addr_port_text.len = sizeof("127.0.0.1:9000") - 1;

    conf->send_timeout = 30000;
    /* */

    return conf;
}
