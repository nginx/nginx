
#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_event.h>
/* STUB */ #include <ngx_event_connect.h>
#include <ngx_http.h>
#include <ngx_http_proxy_handler.h>



static ngx_command_t ngx_http_proxy_commands[] = {
    ngx_null_command
};


ngx_http_module_t  ngx_http_proxy_module_ctx = {
    NULL,                                  /* create main configuration */
    NULL,                                  /* init main configuration */

    NULL,                                  /* create server configuration */
    NULL,                                  /* merge server configuration */

#if 0
    ngx_http_proxy_create_conf,            /* create location configration */
    ngx_http_proxy_merge_conf              /* merge location configration */
#endif

    NULL,
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
    int                     rc;
    ngx_http_proxy_ctx_t   *p;
    ngx_peer_connection_t  *pc;


    ngx_http_create_ctx(r, p, ngx_http_proxy_module,
                        sizeof(ngx_http_proxy_ctx_t),
                        NGX_HTTP_INTERNAL_SERVER_ERROR);


    p->action = "connecting to upstream";
    p->request = r;


#if 0
    pc->peers = lcf->peers;
#endif

    p->upstream.log = r->connection->log;

    do {
        rc = ngx_event_connect_peer(&p->upstream);

        if (rc == NGX_ERROR) {
            return NGX_HTTP_INTERNAL_SERVER_ERROR;
        }

        if (rc == NGX_OK) {
            send_proxy_request(p);
            return NGX_OK;
        }

        if (rc == NGX_AGAIN && p->upstream.connection) {
            return NGX_OK;
        }

    } while (p->upstream.tries);

    return NGX_HTTP_BAD_GATEWAY;
}


#if 0

ngx_http_proxy_connect()
    do {
        ngx_event_connect_peer()
        if error
            return error
        if ok
            return ok
        if again
            return again

        /* next */
    while (tries)
}


ngx_http_proxy_send_request(ngx_event_t *wev)
    for ( ;; ) {
       send
       if ok
          ???
       if again
          return
       if error
          close
          ngx_http_proxy_connect()
          if ok
              continue
          if error
              return
          if again
              return
    }

#endif


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
