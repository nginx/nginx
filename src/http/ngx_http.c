
#include <ngx_config.h>
#include <ngx_string.h>
#include <ngx_socket.h>
#include <ngx_listen.h>
#include <ngx_http.h>
#include <ngx_http_config.h>
#include <ngx_http_core_module.h>


static char *ngx_http_block(ngx_conf_t *cf, ngx_command_t *cmd, char *dummy);


int  ngx_http_max_module;

ngx_array_t  ngx_http_servers;   /* array of ngx_http_core_srv_conf_t */ 

int  ngx_http_post_accept_timeout = 10000;
int  ngx_http_connection_pool_size = 16384;
int  ngx_http_request_pool_size = 16384;
int  ngx_http_client_header_timeout = 20000;
int  ngx_http_client_header_buffer_size = 1024;

/* STUB: per location */
int  ngx_http_lingering_timeout = 5000;
int  ngx_http_lingering_time = 30;
/**/


ngx_array_t  ngx_http_index_handlers;


int  (*ngx_http_top_header_filter) (ngx_http_request_t *r);


static ngx_str_t  http_name = ngx_string("http");


static ngx_command_t  ngx_http_commands[] = {

    {ngx_string("http"),
     NGX_CONF_BLOCK|NGX_CONF_NOARGS,
     ngx_http_block,
     0,
     0},

    {ngx_string(""), 0, NULL, 0, 0}
};


ngx_module_t  ngx_http_module = {
    0,                                     /* module index */
    &http_name,                            /* module context */
    ngx_http_commands,                     /* module directives */
    NGX_CORE_MODULE_TYPE,                  /* module type */
    NULL                                   /* init module */
};


static char *ngx_http_block(ngx_conf_t *cf, ngx_command_t *cmd, char *dummy)
{
    int                         i, s, l, p, a, n, start;
    int                         port_found, addr_found, virtual_names;
    char                       *rv;
    struct sockaddr_in         *addr_in;
    ngx_array_t                 in_ports;
    ngx_listen_t               *ls;
    ngx_http_module_t          *module;
    ngx_http_conf_ctx_t        *ctx, *prev;
    ngx_http_in_port_t         *in_port;
    ngx_http_in_addr_t         *in_addr, *inaddr;
    ngx_http_core_srv_conf_t  **cscf;
    ngx_http_listen_t          *lscf;
    ngx_http_server_name_t     *s_name, *name;;

    ngx_init_array(ngx_http_servers, cf->pool, 10,
                   sizeof(ngx_http_core_srv_conf_t *), NGX_CONF_ERROR);

    ngx_test_null(ctx,
                  ngx_pcalloc(cf->pool, sizeof(ngx_http_conf_ctx_t)),
                  NGX_CONF_ERROR);

    for (i = 0; ngx_modules[i]; i++) {
        if (ngx_modules[i]->type != NGX_HTTP_MODULE_TYPE) {
            continue;
        }

        /* STUB */
        module = (ngx_http_module_t *) ngx_modules[i]->ctx;
        module->index = ngx_http_max_module;

        ngx_modules[i]->index = ngx_http_max_module++;
    }

    /* null loc_conf */
    ngx_test_null(ctx->loc_conf,
                  ngx_pcalloc(cf->pool, sizeof(void *) * ngx_http_max_module),
                  NGX_CONF_ERROR);

    for (i = 0; ngx_modules[i]; i++) {
        if (ngx_modules[i]->type != NGX_HTTP_MODULE_TYPE) {
            continue;
        }

        module = (ngx_http_module_t *) ngx_modules[i]->ctx;

        if (module->create_loc_conf) {
            ngx_test_null(ctx->loc_conf[module->index],
                          module->create_loc_conf(cf->pool),
                          NGX_CONF_ERROR);
        }
    }

    prev = cf->ctx;
    cf->ctx = ctx;
    cf->type = NGX_HTTP_MODULE_TYPE;

    rv = ngx_conf_parse(cf, NULL);
    cf->ctx = prev;

    if (rv != NGX_CONF_OK)
        return rv;


#if 0
    /* DEBUG STUFF */
    cscf = (ngx_http_core_srv_conf_t **) ngx_http_servers.elts;
    for (s = 0; s < ngx_http_servers.nelts; s++) {
        ngx_http_core_loc_conf_t **loc;

        ngx_log_debug(cf->log, "srv: %08x" _ cscf[s]);
        loc = (ngx_http_core_loc_conf_t **) cscf[s]->locations.elts;
        for (l = 0; l < cscf[s]->locations.nelts; l++) {
            ngx_log_debug(cf->log, "loc: %08x:%s, %08x:%s" _
                          loc[l] _ loc[l]->name.data _
                          &loc[l]->doc_root _ loc[l]->doc_root.data);
        }
    }
    /**/
#endif

    ngx_init_array(ngx_http_index_handlers,
                   cf->pool, 3, sizeof(ngx_http_handler_pt), NGX_CONF_ERROR);

    ngx_http_init_filters(cf->pool, ngx_modules);

    /* create lists of ports, addresses and server names */

    ngx_init_array(in_ports, cf->pool, 10, sizeof(ngx_http_in_port_t),
                   NGX_CONF_ERROR);

    cscf = (ngx_http_core_srv_conf_t **) ngx_http_servers.elts;
    for (s = 0; s < ngx_http_servers.nelts; s++) {

        lscf = (ngx_http_listen_t *) cscf[s]->listen.elts;
        for (l = 0; l < cscf[s]->listen.nelts; l++) {

            port_found = 0;

            /* AF_INET only */

            in_port = (ngx_http_in_port_t *) in_ports.elts;
            for (p = 0; p < in_ports.nelts; p++) {

                if (lscf[l].port == in_port[p].port) {

                    port_found = 1;
                    addr_found = 0;

                    in_addr = (ngx_http_in_addr_t *) in_port[p].addr.elts;
                    for (a = 0; a < in_port[p].addr.nelts; a++) {

                        if (lscf[l].addr == in_addr[a].addr) {
                            s_name = (ngx_http_server_name_t *)
                                                    cscf[s]->server_names.elts;
                            for (n = 0; n < cscf[s]->server_names.nelts; n++) {
                                ngx_test_null(name,
                                              ngx_push_array(&in_addr[a].names),
                                              NGX_CONF_ERROR);

                                name->name = s_name[n].name;
                                name->core_srv_conf = s_name[n].core_srv_conf;
                            }

                            if (lscf[l].flags & NGX_HTTP_DEFAULT_SERVER) {
                                if (in_addr[a].flags
                                                   & NGX_HTTP_DEFAULT_SERVER) {

                                    ngx_log_error(NGX_LOG_ERR, cf->log, 0,
                                        "duplicate default server in %s:%d",
                                        lscf[l].file_name.data,
                                        lscf[l].line);

                                    return NGX_CONF_ERROR;
                                }

                                in_addr[a].flags |= NGX_HTTP_DEFAULT_SERVER;
                                in_addr[a].core_srv_conf = cscf[s];
                            }

                            addr_found = 1;

                            break;

                        /* "*:XX" is the last resort */
                        } else if (in_addr[p].addr == INADDR_ANY) {
                            ngx_test_null(inaddr,
                                          ngx_push_array(&in_port[p].addr),
                                          NGX_CONF_ERROR);

                            ngx_memcpy(inaddr, &in_addr[a],
                                       sizeof(ngx_http_in_addr_t));

                            inaddr->addr = lscf[l].addr;
                            inaddr->flags = lscf[l].flags;   
                            inaddr->core_srv_conf = cscf[s];

                            ngx_init_array(inaddr->names, cf->pool, 10,
                                           sizeof(ngx_http_server_name_t),
                                           NGX_CONF_ERROR);

                            addr_found = 1;

                            break;
                        }
                    }

                    if (!addr_found) {
                        ngx_test_null(inaddr,
                                      ngx_push_array(&in_port[p].addr),
                                      NGX_CONF_ERROR);

                        inaddr->addr = lscf[l].addr;
                        inaddr->flags = lscf[l].flags;   
                        inaddr->core_srv_conf = cscf[s];

                        ngx_init_array(inaddr->names, cf->pool, 10,
                                       sizeof(ngx_http_server_name_t),
                                       NGX_CONF_ERROR);
                    }
                }
            }

            if (!port_found) {
                ngx_test_null(in_port,
                              ngx_push_array(&in_ports),
                              NGX_CONF_ERROR);

                in_port->port = lscf[l].port;

                ngx_init_array(in_port->addr, cf->pool, 10,
                               sizeof(ngx_http_in_addr_t),
                               NGX_CONF_ERROR);

                ngx_test_null(inaddr, ngx_push_array(&in_port->addr),
                              NGX_CONF_ERROR);

                inaddr->addr = lscf[l].addr;
                inaddr->flags = lscf[l].flags;   
                inaddr->core_srv_conf = cscf[s];

                ngx_init_array(inaddr->names, cf->pool, 10,
                               sizeof(ngx_http_server_name_t),
                               NGX_CONF_ERROR);
            }
        }
    }

    /* optimzie lists of ports, addresses and server names */

    /* AF_INET only */

    in_port = (ngx_http_in_port_t *) in_ports.elts;
    for (p = 0; p < in_ports.nelts; p++) {

        in_addr = (ngx_http_in_addr_t *) in_port[p].addr.elts;
        for (a = 0; a < in_port[p].addr.nelts; a++) {

            virtual_names = 0;

            name = (ngx_http_server_name_t *) in_addr[a].names.elts;
            for (n = 0; n < in_addr[a].names.nelts; n++) {
                if (in_addr[a].core_srv_conf != name[n].core_srv_conf) {
                    virtual_names = 1;
                    break;
                }
            }

            /* if all server names point to the same server
               then we do not need to check them at run time */
            if (!virtual_names) {
                in_addr[a].names.nelts = 0;
            }
        }

        /* if there is binding to "*:XX" then we need to bind to "*:XX" only
           and ignore other binding */
        if (in_addr[a - 1].addr == INADDR_ANY) {
            start = a - 1;

        } else {
            start = 0;
        }

        in_addr = (ngx_http_in_addr_t *) in_port[p].addr.elts;
        for (a = start; a < in_port[p].addr.nelts; a++) {

            ngx_test_null(ls, ngx_push_array(&ngx_listening_sockets),
                          NGX_CONF_ERROR);
            ngx_memzero(ls, sizeof(ngx_listen_t));

            ngx_test_null(addr_in,
                          ngx_pcalloc(cf->pool, sizeof(struct sockaddr_in)),
                          NGX_CONF_ERROR);

            addr_in->sin_family = AF_INET;
            addr_in->sin_addr.s_addr = in_addr[a].addr;
            addr_in->sin_port = htons(in_port[p].port);

            ngx_test_null(ls->addr_text.data,
                          ngx_palloc(cf->pool, INET_ADDRSTRLEN + 6),
                          NGX_CONF_ERROR);

            ls->addr_text.len =
                ngx_snprintf(ls->addr_text.data
                             + ngx_inet_ntop(AF_INET,
                                             &in_addr[a].addr,
                                             ls->addr_text.data,
                                             INET_ADDRSTRLEN),
                             6, ":%d", in_port[p].port);

            ls->family = AF_INET;
            ls->type = SOCK_STREAM;
            ls->protocol = IPPROTO_IP;
#if (NGX_OVERLAPPED)
            ls->flags = WSA_FLAG_OVERLAPPED;
#endif
            ls->sockaddr = (struct sockaddr *) addr_in;
            ls->socklen = sizeof(struct sockaddr_in);
            ls->addr = offsetof(struct sockaddr_in, sin_addr);
            ls->addr_text_max_len = INET_ADDRSTRLEN;
            ls->backlog = -1;
            ls->post_accept_timeout = ngx_http_post_accept_timeout;
            ls->nonblocking = 1;

            ls->handler = ngx_http_init_connection;
            ls->log = cf->log;
            ls->ctx = ctx;
            ls->servers = &in_port[p];

            if (in_port[p].addr.nelts == 1) {
                in_addr = (ngx_http_in_addr_t *) in_port[p].addr.elts;

                /* if there is the single address for this port and no virtual
                   name servers so we do not need to check addresses
                   at run time */
                if (in_addr[a].names.nelts == 0) {
                    ls->ctx = in_addr->core_srv_conf->ctx;
                    ls->servers = NULL;
                }
            }
ngx_log_debug(cf->log, "ls ctx: %d:%08x" _ in_port[p].port _ ls->ctx);
        }
    }

    return NGX_CONF_OK;
}


#if 0
/* STUB */

static struct sockaddr_in  addr;
static char addr_text[22];


int ngx_http_init(ngx_pool_t *pool, ngx_log_t *log)
{
    ngx_listen_t  *ls;

    ngx_http_server.connection_pool_size = 16384;
    ngx_http_server.request_pool_size = 16384;
    ngx_http_server.header_timeout = 20000;
    ngx_http_server.header_buffer_size = 1024;
    ngx_http_server.discarded_buffer_size = 1500;

    ngx_http_server.lingering_timeout = 5000;
    ngx_http_server.lingering_time = 30;

#if (WIN32)
    ngx_http_server.doc_root = "html";
#else
    ngx_http_server.doc_root = "/home/is/dox/";
    ngx_http_server.doc_root = "/home/is/work/xml/site-1.0.0/html";
    ngx_http_server.doc_root = "/spool/test/lperltk";
    ngx_http_server.doc_root = "/home/is/dox/ora/lperltk";
#endif
    ngx_http_server.doc_root_len = strlen(ngx_http_server.doc_root) + 1;


    ngx_http_config_modules(pool, ngx_modules);

#if 0
    /* STUB */
    ngx_http_output_filter_set_stub(pool, ngx_http_modules);
    ngx_http_write_filter_set_stub(pool, ngx_http_modules);
    ngx_http_index_set_stub(pool, ngx_http_modules);

    ngx_http_init_modules(pool, ngx_http_modules);
#endif

    ngx_http_init_filters(pool, ngx_modules);

    ls = ngx_push_array(&ngx_listening_sockets);
    ngx_memzero(ls, sizeof(ngx_listen_t));

    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = inet_addr("0.0.0.0");
    addr.sin_port = htons(8000);

    ngx_snprintf(ngx_cpystrn(addr_text, inet_ntoa(addr.sin_addr), 16),
                 7, ":%d", ntohs(addr.sin_port));

    ls->family = AF_INET;
    ls->type = SOCK_STREAM;
    ls->protocol = IPPROTO_IP;
#if (NGX_OVERLAPPED)
    ls->flags = WSA_FLAG_OVERLAPPED;
#endif
    ls->sockaddr = (struct sockaddr *) &addr;
    ls->socklen = sizeof(struct sockaddr_in);
    ls->addr = offsetof(struct sockaddr_in, sin_addr);
    ls->addr_text.len = INET_ADDRSTRLEN;
    ls->addr_text.data = addr_text;
    ls->backlog = -1;
    ls->post_accept_timeout = 10000;
    ls->nonblocking = 1;

    ls->handler = ngx_http_init_connection;
    ls->server = &ngx_http_server;
    ls->log = log;


    return 1;
}

/**/
#endif
