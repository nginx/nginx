
#include <ngx_config.h>

#include <ngx_string.h>
#include <ngx_socket.h>
#include <ngx_listen.h>
#include <ngx_inet.h>
#include <ngx_http.h>
#include <ngx_http_config.h>
#include <ngx_http_core_module.h>


static void ngx_http_init_filters(ngx_pool_t *pool, ngx_module_t **modules);
static char *ngx_http_block(ngx_conf_t *cf, ngx_command_t *cmd, char *dummy);


int  ngx_http_max_module;

ngx_array_t  ngx_http_servers;   /* array of ngx_http_core_srv_conf_t */ 

int  ngx_http_post_accept_timeout = 30000;
int  ngx_http_connection_pool_size = 16384;
int  ngx_http_request_pool_size = 16384;
int  ngx_http_client_header_timeout = 60000;
int  ngx_http_client_header_buffer_size = 1024;
int  ngx_http_large_client_header = 1;

int  ngx_http_url_in_error_log = 1;


ngx_array_t  ngx_http_translate_handlers;
ngx_array_t  ngx_http_index_handlers;


int  (*ngx_http_top_header_filter) (ngx_http_request_t *r);
int  (*ngx_http_top_body_filter) (ngx_http_request_t *r, ngx_chain_t *ch);


static ngx_str_t  http_name = ngx_string("http");


static ngx_command_t  ngx_http_commands[] = {

    {ngx_string("http"),
     NGX_MAIN_CONF|NGX_CONF_BLOCK|NGX_CONF_NOARGS,
     ngx_http_block,
     0,
     0,
     NULL},

    {ngx_string(""), 0, NULL, 0, 0, NULL}
};


ngx_module_t  ngx_http_module = {
    &http_name,                            /* module context */
    0,                                     /* module index */
    ngx_http_commands,                     /* module directives */
    NGX_CORE_MODULE_TYPE,                  /* module type */
    NULL                                   /* init module */
};


static char *ngx_http_block(ngx_conf_t *cf, ngx_command_t *cmd, char *conf)
{
    int                         i, s, l, p, a, n, start;
    int                         port_found, addr_found, virtual_names;
    char                       *rv;
    struct sockaddr_in         *addr_in;
    ngx_array_t                 in_ports;
    ngx_listen_t               *ls;
    ngx_http_module_t          *module;
    ngx_conf_t                  pcf;
    ngx_http_conf_ctx_t        *ctx;
    ngx_http_in_port_t         *in_port, *inport;
    ngx_http_in_addr_t         *in_addr, *inaddr;
    ngx_http_core_srv_conf_t  **cscf;
    ngx_http_listen_t          *lscf;
    ngx_http_server_name_t     *s_name, *name;

    ngx_init_array(ngx_http_servers, cf->pool, 10,
                   sizeof(ngx_http_core_srv_conf_t *), NGX_CONF_ERROR);

    ngx_test_null(ctx,
                  ngx_pcalloc(cf->pool, sizeof(ngx_http_conf_ctx_t)),
                  NGX_CONF_ERROR);

    *(ngx_http_conf_ctx_t **) conf = ctx;

    ngx_http_max_module = 0;
    for (i = 0; ngx_modules[i]; i++) {
        if (ngx_modules[i]->type != NGX_HTTP_MODULE_TYPE) {
            continue;
        }

        module = (ngx_http_module_t *) ngx_modules[i]->ctx;

        module->index = ngx_http_max_module++;
    }

    /* TODO: http main_conf */

    ngx_test_null(ctx->main_conf,
                  ngx_pcalloc(cf->pool, sizeof(void *) * ngx_http_max_module),
                  NGX_CONF_ERROR);

    /* TODO: http srv_conf */

    ngx_test_null(ctx->srv_conf,
                  ngx_pcalloc(cf->pool, sizeof(void *) * ngx_http_max_module),
                  NGX_CONF_ERROR);

    /* http null loc_conf */

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

    pcf = *cf;
    cf->ctx = ctx;
    cf->module_type = NGX_HTTP_MODULE_TYPE;
    cf->cmd_type = NGX_HTTP_MAIN_CONF;
    rv = ngx_conf_parse(cf, NULL);
    *cf = pcf;

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

    ngx_init_array(ngx_http_translate_handlers,
                   cf->pool, 10, sizeof(ngx_http_handler_pt), NGX_CONF_ERROR);

    ngx_init_array(ngx_http_index_handlers,
                   cf->pool, 3, sizeof(ngx_http_handler_pt), NGX_CONF_ERROR);


    /* create the lists of the ports, the addresses and the server names
       to allow quickly find the server core module configuration at run-time */

    ngx_init_array(in_ports, cf->pool, 10, sizeof(ngx_http_in_port_t),
                   NGX_CONF_ERROR);

    /* "server" directives */
    cscf = (ngx_http_core_srv_conf_t **) ngx_http_servers.elts;
    for (s = 0; s < ngx_http_servers.nelts; s++) {

        /* "listen" directives */
        lscf = (ngx_http_listen_t *) cscf[s]->listen.elts;
        for (l = 0; l < cscf[s]->listen.nelts; l++) {

            port_found = 0;

            /* AF_INET only */

            in_port = (ngx_http_in_port_t *) in_ports.elts;
            for (p = 0; p < in_ports.nelts; p++) {

                if (lscf[l].port == in_port[p].port) {

                    /* the port is already in the port list */

                    port_found = 1;
                    addr_found = 0;

                    in_addr = (ngx_http_in_addr_t *) in_port[p].addrs.elts;
                    for (a = 0; a < in_port[p].addrs.nelts; a++) {

                        if (lscf[l].addr == in_addr[a].addr) {

                            /* the address is already bound to this port */

                            /* "server_name" directives */
                            s_name = (ngx_http_server_name_t *)
                                                    cscf[s]->server_names.elts;
                            for (n = 0; n < cscf[s]->server_names.nelts; n++) {

                                /* add the server name and server core module
                                   configuration to the address:port */

                                /* TODO: duplicate names can be checked here */

                                ngx_test_null(name,
                                              ngx_push_array(&in_addr[a].names),
                                              NGX_CONF_ERROR);

                                name->name = s_name[n].name;
                                name->core_srv_conf = s_name[n].core_srv_conf;
                            }

                            /* check duplicate "default" server that
                               serves this address:port */

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

                        } else if (in_addr[a].addr == INADDR_ANY) {

                            /* "*:port" must be the last resort so move it
                               to the end of the address list and add
                               the new address at its place */

                            ngx_test_null(inaddr,
                                          ngx_push_array(&in_port[p].addrs),
                                          NGX_CONF_ERROR);

                            ngx_memcpy(inaddr, &in_addr[a],
                                       sizeof(ngx_http_in_addr_t));

                            in_addr[a].addr = lscf[l].addr;
                            in_addr[a].flags = lscf[l].flags;   
                            in_addr[a].core_srv_conf = cscf[s];

                            /* create the empty list of the server names that
                               can be served on this address:port */

                            ngx_init_array(inaddr->names, cf->pool, 10,
                                           sizeof(ngx_http_server_name_t),
                                           NGX_CONF_ERROR);

                            addr_found = 1;

                            break;
                        }
                    }

                    if (!addr_found) {

                        /* add the address to the addresses list that
                           bound to this port */

                        ngx_test_null(inaddr,
                                      ngx_push_array(&in_port[p].addrs),
                                      NGX_CONF_ERROR);

                        inaddr->addr = lscf[l].addr;
                        inaddr->flags = lscf[l].flags;   
                        inaddr->core_srv_conf = cscf[s];

                        /* create the empty list of the server names that
                           can be served on this address:port */

                        ngx_init_array(inaddr->names, cf->pool, 10,
                                       sizeof(ngx_http_server_name_t),
                                       NGX_CONF_ERROR);
                    }
                }
            }

            if (!port_found) {

                /* add the port to the in_port list */

                ngx_test_null(in_port,
                              ngx_push_array(&in_ports),
                              NGX_CONF_ERROR);

                in_port->port = lscf[l].port;

                /* create list of the addresses that bound to this port ... */

                ngx_init_array(in_port->addrs, cf->pool, 10,
                               sizeof(ngx_http_in_addr_t),
                               NGX_CONF_ERROR);

                ngx_test_null(inaddr, ngx_push_array(&in_port->addrs),
                              NGX_CONF_ERROR);

                /* ... and add the address to this list */

                inaddr->addr = lscf[l].addr;
                inaddr->flags = lscf[l].flags;   
                inaddr->core_srv_conf = cscf[s];

                /* create the empty list of the server names that
                   can be served on this address:port */

                ngx_init_array(inaddr->names, cf->pool, 10,
                               sizeof(ngx_http_server_name_t),
                               NGX_CONF_ERROR);
            }
        }
    }

    /* optimize the lists of the ports, the addresses and the server names */

    /* AF_INET only */

    in_port = (ngx_http_in_port_t *) in_ports.elts;
    for (p = 0; p < in_ports.nelts; p++) {

        /* check whether the all server names point to the same server */

        in_addr = (ngx_http_in_addr_t *) in_port[p].addrs.elts;
        for (a = 0; a < in_port[p].addrs.nelts; a++) {

            virtual_names = 0;

            name = (ngx_http_server_name_t *) in_addr[a].names.elts;
            for (n = 0; n < in_addr[a].names.nelts; n++) {
                if (in_addr[a].core_srv_conf != name[n].core_srv_conf) {
                    virtual_names = 1;
                    break;
                }
            }

            /* if the all server names point to the same server
               then we do not need to check them at run-time */

            if (!virtual_names) {
                in_addr[a].names.nelts = 0;
            }
        }

        /* if there's the binding to "*:port" then we need to bind()
           to "*:port" only and ignore the other bindings */

        if (in_addr[a - 1].addr == INADDR_ANY) {
            a--;

        } else {
            a = 0;
        }

        in_addr = (ngx_http_in_addr_t *) in_port[p].addrs.elts;
        while (a < in_port[p].addrs.nelts) {

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
                                                     (char *) &in_addr[a].addr,
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
            ls->pool_size = ngx_http_connection_pool_size;
            ls->ctx = ctx;

            if (in_port[p].addrs.nelts > 1) {

                in_addr = (ngx_http_in_addr_t *) in_port[p].addrs.elts;
                if (in_addr[in_port[p].addrs.nelts - 1].addr != INADDR_ANY) {

                    /* if this port has not the "*:port" binding then create
                       the separate ngx_http_in_port_t for the all bindings */

                    ngx_test_null(inport,
                                  ngx_palloc(cf->pool,
                                                   sizeof(ngx_http_in_port_t)),
                                  NGX_CONF_ERROR);

                    inport->port = in_port[p].port;

                    /* init list of the addresses ... */

                    ngx_init_array(inport->addrs, cf->pool, 1,
                                   sizeof(ngx_http_in_addr_t),
                                   NGX_CONF_ERROR);

                    /* ... and set up it with the first address */

                    inport->addrs.nelts = 1;
                    inport->addrs.elts = in_port[p].addrs.elts;

                    ls->servers = inport;

                    /* prepare for the next cycle */

                    in_port[p].addrs.elts += in_port[p].addrs.size;
                    in_port[p].addrs.nelts--;

                    in_addr = (ngx_http_in_addr_t *) in_port[p].addrs.elts;
                    a = 0;

                    continue;
                }
            }

            ls->servers = &in_port[p];
            a++;
        }
    }

    /* DEBUG STUFF */
    in_port = (ngx_http_in_port_t *) in_ports.elts;
    for (p = 0; p < in_ports.nelts; p++) {
ngx_log_debug(cf->log, "port: %d" _ in_port[p].port);
        in_addr = (ngx_http_in_addr_t *) in_port[p].addrs.elts;
        for (a = 0; a < in_port[p].addrs.nelts; a++) {
            char ip[20];
            ngx_inet_ntop(AF_INET, (char *) &in_addr[a].addr, ip, 20);
ngx_log_debug(cf->log, "%s %08x" _ ip _ in_addr[a].core_srv_conf);
        }
    }
    /**/

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
#else
    ls->nonblocking = 1;
#endif

    ls->sockaddr = (struct sockaddr *) &addr;
    ls->socklen = sizeof(struct sockaddr_in);
    ls->addr = offsetof(struct sockaddr_in, sin_addr);
    ls->addr_text.len = INET_ADDRSTRLEN;
    ls->addr_text.data = addr_text;
    ls->backlog = -1;
    ls->post_accept_timeout = 10000;

    ls->handler = ngx_http_init_connection;
    ls->server = &ngx_http_server;
    ls->log = log;


    return 1;
}

/**/
#endif
