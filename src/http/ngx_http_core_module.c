
#include <ngx_config.h>

#include <ngx_listen.h>

#include <ngx_core.h>
#include <ngx_conf_file.h>

#include <ngx_http.h>
#include <ngx_http_config.h>
#include <ngx_http_core_module.h>

/* STUB for r->filter = NGX_HTTP_FILTER_NEED_IN_MEMORY; */
#include <ngx_http_output_filter.h>

int ngx_http_static_handler(ngx_http_request_t *r);
int ngx_http_proxy_handler(ngx_http_request_t *r);
/**/

static int ngx_http_core_index_handler(ngx_http_request_t *r);

static int ngx_http_core_init(ngx_pool_t *pool);

static void *ngx_http_core_create_srv_conf(ngx_pool_t *pool);
static char *ngx_http_core_init_srv_conf(ngx_pool_t *pool, void *conf);
static void *ngx_http_core_create_loc_conf(ngx_pool_t *pool);
static char *ngx_http_core_merge_loc_conf(ngx_pool_t *pool,
                                          void *parent, void *child);

static char *ngx_server_block(ngx_conf_t *cf, ngx_command_t *cmd, char *dummy);
static char *ngx_location_block(ngx_conf_t *cf, ngx_command_t *cmd,
                                                                  char *dummy);
static char *ngx_set_listen(ngx_conf_t *cf, ngx_command_t *cmd, char *conf);


static ngx_command_t  ngx_http_core_commands[] = {

    {ngx_string("server"),
     NGX_HTTP_MAIN_CONF|NGX_CONF_BLOCK|NGX_CONF_NOARGS,
     ngx_server_block,
     0,
     0},

    {ngx_string("post_accept_timeout"),
     NGX_HTTP_MAIN_CONF|NGX_CONF_TAKE1,
     ngx_conf_set_time_slot,
     0,
     addressof(ngx_http_post_accept_timeout)},

    {ngx_string("connection_pool_size"),
     NGX_HTTP_MAIN_CONF|NGX_CONF_TAKE1,
     ngx_conf_set_size_slot,
     0,
     addressof(ngx_http_connection_pool_size)},

    {ngx_string("request_pool_size"),
     NGX_HTTP_MAIN_CONF|NGX_CONF_TAKE1,
     ngx_conf_set_size_slot,
     0,
     addressof(ngx_http_request_pool_size)},

    {ngx_string("client_header_timeout"),
     NGX_HTTP_MAIN_CONF|NGX_CONF_TAKE1,
     ngx_conf_set_time_slot,
     0,
     addressof(ngx_http_client_header_timeout)},

    {ngx_string("client_header_buffer_size"),
     NGX_HTTP_MAIN_CONF|NGX_CONF_TAKE1,
     ngx_conf_set_size_slot,
     0,
     addressof(ngx_http_client_header_buffer_size)},

    {ngx_string("large_client_header"),
     NGX_HTTP_MAIN_CONF|NGX_CONF_FLAG,
     ngx_conf_set_flag_slot,
     0,
     addressof(ngx_http_large_client_header)},

    {ngx_string("location"),
     NGX_HTTP_SRV_CONF|NGX_CONF_BLOCK|NGX_CONF_TAKE1,
     ngx_location_block,
     NGX_HTTP_SRV_CONF_OFFSET,
     0},

    {ngx_string("listen"),
     NGX_HTTP_SRV_CONF|NGX_CONF_TAKE1,
     ngx_set_listen,
     NGX_HTTP_SRV_CONF_OFFSET,
     0},

    {ngx_string("root"),
     NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
     ngx_conf_set_str_slot,
     NGX_HTTP_LOC_CONF_OFFSET,
     offsetof(ngx_http_core_loc_conf_t, doc_root)},

    {ngx_string("sendfile"),
     NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
     ngx_conf_set_flag_slot,
     NGX_HTTP_LOC_CONF_OFFSET,
     offsetof(ngx_http_core_loc_conf_t, sendfile)},

    {ngx_string("send_timeout"),
     NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
     ngx_conf_set_time_slot,
     NGX_HTTP_LOC_CONF_OFFSET,
     offsetof(ngx_http_core_loc_conf_t, send_timeout)},

    {ngx_string("lingering_time"),
     NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
     ngx_conf_set_time_slot,
     NGX_HTTP_LOC_CONF_OFFSET,
     offsetof(ngx_http_core_loc_conf_t, lingering_time)},

    {ngx_string("lingering_timeout"),
     NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
     ngx_conf_set_time_slot,
     NGX_HTTP_LOC_CONF_OFFSET,
     offsetof(ngx_http_core_loc_conf_t, lingering_timeout)},

    {ngx_null_string, 0, NULL, 0, 0}
};


ngx_http_module_t  ngx_http_core_module_ctx = {
    NGX_HTTP_MODULE,

    ngx_http_core_create_srv_conf,         /* create server config */
    ngx_http_core_init_srv_conf,           /* init server config */

    ngx_http_core_create_loc_conf,         /* create location config */
    ngx_http_core_merge_loc_conf           /* merge location config */
};


ngx_module_t  ngx_http_core_module = {
    0,                                     /* module index */
    &ngx_http_core_module_ctx,             /* module context */
    ngx_http_core_commands,                /* module directives */
    NGX_HTTP_MODULE_TYPE,                  /* module type */
    ngx_http_core_init                     /* init module */
};


int ngx_http_handler(ngx_http_request_t *r)
{
    int                         rc, a, n, i;
    ngx_http_handler_pt        *h;
    ngx_http_module_t          *module;
    ngx_http_conf_ctx_t        *ctx;
    ngx_http_in_port_t         *in_port;
    ngx_http_in_addr_t         *in_addr;
    ngx_http_server_name_t     *name;
    ngx_http_core_srv_conf_t   *scf;
    ngx_http_core_loc_conf_t   *lcf, **plcf;

    r->connection->unexpected_eof = 0;

    r->keepalive = 1;
    r->lingering_close = 1;

#if 0
ngx_log_debug(r->connection->log, "servers: %0x" _ r->connection->servers);
#endif

    /* find server config */

    if (r->connection->servers == NULL) {
        ctx = (ngx_http_conf_ctx_t *) r->connection->ctx;

    } else {

         /* AF_INET only */

        in_port = (ngx_http_in_port_t *) r->connection->servers;
        in_addr = (ngx_http_in_addr_t *) in_port->addr.elts;

        a = 0;

        if (in_port->addr.nelts > 1) {
            /* find r->in_addr, getsockname() */ 

            for ( /* void */ ; a < in_port->addr.nelts; a++) {

                if (in_addr[a].addr == INADDR_ANY) {
                    break;
                }

                if (in_addr[a].addr == r->in_addr) {
                    break;
                }
            }
        }

        ctx = in_addr[a].core_srv_conf->ctx;

        if (r->headers_in.host_name_len > 0) {

            name = (ngx_http_server_name_t *) in_addr[a].names.elts;
            for (n = 0; n < in_addr[a].names.nelts; n++) {
                if (r->headers_in.host_name_len != name[n].name.len) {
                    continue;
                }

                if (ngx_strncasecmp(r->headers_in.host->value.data,
                                    name[n].name.data,
                                    r->headers_in.host_name_len) == 0) {
                    ctx = name->core_srv_conf->ctx;
                    break;
                }
            }
        }
    }

    r->srv_conf = ctx->srv_conf;
    r->loc_conf = ctx->loc_conf;

#if 0
ngx_log_debug(r->connection->log, "cxt: %08x" _ ctx);
ngx_log_debug(r->connection->log, "srv_conf: %0x" _ r->srv_conf);
ngx_log_debug(r->connection->log, "loc_conf: %0x" _ r->loc_conf);
#endif

    /* run rewrite url phase */


    /* find location config */

    scf = (ngx_http_core_srv_conf_t *)
                     ngx_http_get_module_srv_conf(r, ngx_http_core_module_ctx);

    plcf = (ngx_http_core_loc_conf_t **) scf->locations.elts;
    for (i = 0; i < scf->locations.nelts; i++) {
#if 0
ngx_log_debug(r->connection->log, "trans: %s" _ plcf[i]->name.data);
#endif
         if (r->uri.len < plcf[i]->name.len) {
             continue;
         }

         rc = ngx_strncmp(r->uri.data, plcf[i]->name.data, plcf[i]->name.len);

         if (rc < 0) {
             break;
         }

         if (rc == 0) {
             r->loc_conf = plcf[i]->loc_conf;
         }
    }

    lcf = (ngx_http_core_loc_conf_t *)
                     ngx_http_get_module_loc_conf(r, ngx_http_core_module_ctx);

    if (lcf->sendfile == 0) {
        r->filter = NGX_HTTP_FILTER_NEED_IN_MEMORY;
    }

    /* run translation phase */

    h = (ngx_http_handler_pt *) ngx_http_translate_handlers.elts;
    for (i = ngx_http_translate_handlers.nelts; i > 0; /* void */) {
        rc = h[--i](r);

        if (rc == NGX_DECLINED) {
            continue;
        }

        if (rc == NGX_OK) {
            break;
        }

        if (rc >= NGX_HTTP_SPECIAL_RESPONSE) {
            return rc;
        }
    }

    return r->handler(r);
}


int ngx_http_core_translate_handler(ngx_http_request_t *r)
{
    int                         i, rc, len, port_len, f_offset, l_offset;
    char                       *buf, *location, *last;
    ngx_err_t                   err;
    ngx_table_elt_t            *h;
    ngx_http_server_name_t     *s_name;
    ngx_http_core_srv_conf_t   *scf;
    ngx_http_core_loc_conf_t   *lcf;

    lcf = (ngx_http_core_loc_conf_t *)
                     ngx_http_get_module_loc_conf(r, ngx_http_core_module_ctx);

    if (lcf->handler) {
        r->handler = lcf->handler;
        return NGX_OK;
    }

    scf = (ngx_http_core_srv_conf_t *)
                     ngx_http_get_module_srv_conf(r, ngx_http_core_module_ctx);

    if (r->uri.data[r->uri.len - 1] == '/') {
        r->handler = ngx_http_core_index_handler;
        return NGX_OK;
    }

ngx_log_debug(r->connection->log, "doc_root: %08x" _ &lcf->doc_root);

    s_name = (ngx_http_server_name_t *) scf->server_names.elts;

    if (r->port == 0) {
#if 0
        struct sockaddr_in  *addr_in;
        addr_in = (struct sockaddr_in *) r->connection->sockaddr;
        r->port = ntohs(addr_in->sin_port);
#else
        ngx_http_in_port_t  *in_port;
        in_port = (ngx_http_in_port_t *) r->connection->servers;
        r->port = in_port->port;
#endif
        if (r->port != 80) {
            ngx_test_null(r->port_name.data, ngx_palloc(r->pool, 7),
                          NGX_HTTP_INTERNAL_SERVER_ERROR);
            r->port_name.len = ngx_snprintf(r->port_name.data, 7, ":%d",
                                            r->port);
        }
    }

    port_len = (r->port != 80) ? r->port_name.len : 0;

    /* "+ 7" is "http://" */
    if (lcf->doc_root.len > 7 + s_name[0].name.len + port_len) {
        len = lcf->doc_root.len;
        f_offset = 0;
        l_offset = len - (7 + s_name[0].name.len + port_len);

    } else {
        len = 7 + s_name[0].name.len + port_len;
        f_offset = len - lcf->doc_root.len;
        l_offset = 0;
    }

    /* "+ 2" is for trailing '/' in redirect and '\0' */
    len += r->uri.len + 2;

    ngx_test_null(buf, ngx_palloc(r->pool, len),
                  NGX_HTTP_INTERNAL_SERVER_ERROR);

    r->file.name.data = buf + f_offset;
    location = buf + l_offset;

    last = ngx_cpystrn(ngx_cpystrn(r->file.name.data, lcf->doc_root.data,
                                   lcf->doc_root.len + 1),
                       r->uri.data, r->uri.len + 1);

    r->file.name.len = last - r->file.name.data;

ngx_log_debug(r->connection->log, "HTTP filename: '%s'" _ r->file.name.data);

#if (WIN9X)

    /* There is no way to open a file or a directory in Win9X with
       one syscall: Win9X has no FILE_FLAG_BACKUP_SEMANTICS flag.
       so we need to check its type before the opening */

    r->file.info.dwFileAttributes = GetFileAttributes(r->file.name.data);
    if (r->file.info.dwFileAttributes == INVALID_FILE_ATTRIBUTES) {
        err = ngx_errno;
        ngx_log_error(NGX_LOG_ERR, r->connection->log, err,
                      "ngx_http_core_translate_handler: "
                      ngx_file_type_n " %s failed", r->file.name.data);

        if (err == NGX_ENOENT) {
            return NGX_HTTP_NOT_FOUND;

        } else if (err == ERROR_PATH_NOT_FOUND) {
            return NGX_HTTP_NOT_FOUND;

        } else if (err == NGX_EACCES) {
            return NGX_HTTP_FORBIDDEN;

        } else {
            return NGX_HTTP_INTERNAL_SERVER_ERROR;
        }
    }

#else

    if (r->file.fd == NGX_INVALID_FILE) {
        r->file.fd = ngx_open_file(r->file.name.data, NGX_FILE_RDONLY);
    }

    if (r->file.fd == NGX_INVALID_FILE) {
        err = ngx_errno;
        ngx_log_error(NGX_LOG_ERR, r->connection->log, ngx_errno,
                      "ngx_http_core_handler: "
                      ngx_open_file_n " %s failed", r->file.name.data);

        if (err == NGX_ENOENT) {
            return NGX_HTTP_NOT_FOUND;
#if (WIN32)
        } else if (err == ERROR_PATH_NOT_FOUND) {
            return NGX_HTTP_NOT_FOUND;
#else
        } else if (err == NGX_ENOTDIR) {
            return NGX_HTTP_NOT_FOUND;
#endif
        } else if (err == NGX_EACCES) {
            return NGX_HTTP_FORBIDDEN;

        } else {
            return NGX_HTTP_INTERNAL_SERVER_ERROR;
        }
    }

    if (!r->file.info_valid) {
        if (ngx_stat_fd(r->file.fd, &r->file.info) == NGX_FILE_ERROR) {
            ngx_log_error(NGX_LOG_CRIT, r->connection->log, ngx_errno,
                          "ngx_http_core_handler: "
                          ngx_stat_fd_n " %s failed", r->file.name.data);

            if (ngx_close_file(r->file.fd) == NGX_FILE_ERROR) {
                ngx_log_error(NGX_LOG_ALERT, r->connection->log, ngx_errno,
                              "ngx_http_core_handler: "
                              ngx_close_file_n " %s failed", r->file.name.data);
            }

            return NGX_HTTP_INTERNAL_SERVER_ERROR;
        }

        r->file.info_valid = 1;
    }
#endif

    if (ngx_is_dir(r->file.info)) {
ngx_log_debug(r->connection->log, "HTTP DIR: '%s'" _ r->file.name.data);

#if !(WIN9X)
        if (ngx_close_file(r->file.fd) == NGX_FILE_ERROR) {
            ngx_log_error(NGX_LOG_ALERT, r->connection->log, ngx_errno,
                          "ngx_http_core_handler: "
                          ngx_close_file_n " %s failed", r->file.name.data);
        }
#endif

        /* BROKEN: need to include server name */

        ngx_test_null(h, ngx_push_table(r->headers_out.headers),
                      NGX_HTTP_INTERNAL_SERVER_ERROR);

        ngx_memcpy(location, "http://", 7);
        ngx_memcpy(location + 7, s_name[0].name.data, s_name[0].name.len);
        if (port_len) {
            ngx_memcpy(location + 7 + s_name[0].name.len, r->port_name.data,
                       port_len);
        }

        *last++ = '/';
        *last = '\0';
        h->key.len = 8;
        h->key.data = "Location" ;
        h->value.len = last - location;
        h->value.data = location;
        r->headers_out.location = h;

        return NGX_HTTP_MOVED_PERMANENTLY;
    }

    r->handler = ngx_http_static_handler;

    return NGX_OK;
}


static int ngx_http_core_index_handler(ngx_http_request_t *r)
{
    int  i, rc;
    ngx_http_handler_pt  *h;

    h = (ngx_http_handler_pt *) ngx_http_index_handlers.elts;
    for (i = ngx_http_index_handlers.nelts; i > 0; /* void */) {
        rc = h[--i](r);

        if (rc != NGX_DECLINED) {

            if (rc == NGX_HTTP_NOT_FOUND) {
                ngx_log_error(NGX_LOG_ERR, r->connection->log, r->path_err,
                              "%s is not found", r->path.data);
            }

            if (rc == NGX_HTTP_FORBIDDEN) {
                ngx_log_error(NGX_LOG_ERR, r->connection->log, r->path_err,
                          "%s is forbidden", r->path.data);
            }

            return rc;
        }
    }

    r->path.data[r->path.len] = '\0';
    ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                  "directory index of %s is forbidden", r->path.data);

    return NGX_HTTP_FORBIDDEN;
}


int ngx_http_send_header(ngx_http_request_t *r)
{
    return (*ngx_http_top_header_filter)(r);
}


int ngx_http_redirect(ngx_http_request_t *r, int redirect)
{
    /* STUB */

    /* log request */

    return ngx_http_close_request(r, 0);
}


int ngx_http_error(ngx_http_request_t *r, int error) 
{
    /* STUB */
    ngx_log_debug(r->connection->log, "http error: %d" _ error);

    /* log request */

    ngx_http_special_response_handler(r, error);
    return ngx_http_close_request(r, 0);
}


int ngx_http_close_request(ngx_http_request_t *r, int error)
{
    ngx_connection_t    *c;
    ngx_http_log_ctx_t  *ctx;

    c = r->connection;
    if (error) {
        r->headers_out.status = error;
    }

    ngx_http_log_handler(r);

    if (r->file.fd != NGX_INVALID_FILE) {
        if (ngx_close_file(r->file.fd) == NGX_FILE_ERROR) {
            ngx_log_error(NGX_LOG_ALERT, c->log, ngx_errno,
                          ngx_close_file_n " failed");
        }
    }

    /* ctx->url was allocated from r->pool */
    ctx = (ngx_http_log_ctx_t *) c->log->data;
    ctx->url = NULL;

    ngx_destroy_pool(r->pool);

    if (c->read->timer_set) {
        ngx_del_timer(c->read);
        c->read->timer_set = 0;
    }

    if (c->write->timer_set) {
        ngx_del_timer(c->write);
        c->write->timer_set = 0;
    }

    ngx_log_debug(c->log, "http closed");

    return NGX_ERROR;  /* to close connection */
}


int ngx_http_internal_redirect(ngx_http_request_t *r, ngx_str_t uri)
{
    ngx_log_debug(r->connection->log, "internal redirect: '%s'" _ uri.data);

    r->uri.len = uri.len;
    r->uri.data = uri.data;

    /* NEEDED ? */
    r->uri_start = uri.data;
    r->uri_end = uri.data + uri.len;
    /**/

    return ngx_http_handler(r);
}


static int ngx_http_core_init(ngx_pool_t *pool)
{
    ngx_http_handler_pt  *h;

    ngx_test_null(h, ngx_push_array(&ngx_http_translate_handlers), NGX_ERROR);

    *h = ngx_http_core_translate_handler;

    return NGX_OK;
}


static char *ngx_server_block(ngx_conf_t *cf, ngx_command_t *cmd, char *dummy)
{
    int                         i, j;
    char                       *rv;
    ngx_http_module_t          *module;
    ngx_http_conf_ctx_t        *ctx, *prev;
    ngx_http_core_srv_conf_t   *scf;
    ngx_http_core_loc_conf_t  **plcf;

    ngx_test_null(ctx,
                  ngx_pcalloc(cf->pool, sizeof(ngx_http_conf_ctx_t)),
                  NGX_CONF_ERROR);

    /* server config */
    ngx_test_null(ctx->srv_conf,
                  ngx_pcalloc(cf->pool, sizeof(void *) * ngx_http_max_module),
                  NGX_CONF_ERROR);

    /* server location config */
    ngx_test_null(ctx->loc_conf,
                  ngx_pcalloc(cf->pool, sizeof(void *) * ngx_http_max_module),
                  NGX_CONF_ERROR);

    for (i = 0; ngx_modules[i]; i++) {
        if (ngx_modules[i]->type != NGX_HTTP_MODULE_TYPE) {
            continue;
        }

        module = (ngx_http_module_t *) ngx_modules[i]->ctx;

        if (module->create_srv_conf) {
            ngx_test_null(ctx->srv_conf[module->index],
                          module->create_srv_conf(cf->pool),
                          NGX_CONF_ERROR);
        }

        if (module->create_loc_conf) {
            ngx_test_null(ctx->loc_conf[module->index],
                          module->create_loc_conf(cf->pool),
                          NGX_CONF_ERROR);
        }
    }

    prev = cf->ctx;
    cf->ctx = ctx;
    rv = ngx_conf_parse(cf, NULL);
    cf->ctx = prev;

    if (rv != NGX_CONF_OK)
        return rv;


    scf = ctx->srv_conf[ngx_http_core_module_ctx.index];
    scf->ctx = ctx;

    plcf = (ngx_http_core_loc_conf_t **)scf->locations.elts;

    for (i = 0; ngx_modules[i]; i++) {
        if (ngx_modules[i]->type != NGX_HTTP_MODULE_TYPE) {
            continue;
        }

        module = (ngx_http_module_t *) ngx_modules[i]->ctx;

        if (module->init_srv_conf) {
            if (module->init_srv_conf(cf->pool,
                                      ctx->srv_conf[module->index])
                                                           == NGX_CONF_ERROR) {
                return NGX_CONF_ERROR;
            }
        }

        if (module->merge_loc_conf) {
            if (module->merge_loc_conf(cf->pool,
                                       prev->loc_conf[module->index],
                                       ctx->loc_conf[module->index])
                                                           == NGX_CONF_ERROR) {
                return NGX_CONF_ERROR;
            }

            for (j = 0; j < scf->locations.nelts; j++) {
                if (module->merge_loc_conf(cf->pool,
                                      ctx->loc_conf[module->index],
                                      plcf[j]->loc_conf[module->index])
                                                           == NGX_CONF_ERROR) {
                    return NGX_CONF_ERROR;
                }
            }
        }
    }

    return NGX_CONF_OK;
}


static char *ngx_location_block(ngx_conf_t *cf, ngx_command_t *cmd, char *dummy)
{
    int                        i;
    char                      *rv;
    ngx_str_t                 *location;
    ngx_http_module_t         *module;
    ngx_http_conf_ctx_t       *ctx, *prev;
    ngx_http_core_srv_conf_t  *scf;
    ngx_http_core_loc_conf_t  *lcf, **plcf;

    ngx_test_null(ctx,
                  ngx_pcalloc(cf->pool, sizeof(ngx_http_conf_ctx_t)),
                  NGX_CONF_ERROR);

    prev = (ngx_http_conf_ctx_t *) cf->ctx;
    ctx->srv_conf = prev->srv_conf;

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

    lcf = (ngx_http_core_loc_conf_t *)
                                 ctx->loc_conf[ngx_http_core_module_ctx.index];
    location = (ngx_str_t *) cf->args->elts;
    lcf->name.len = location[1].len;
    lcf->name.data = location[1].data;
    lcf->loc_conf = ctx->loc_conf;

    scf = (ngx_http_core_srv_conf_t *)
                                 ctx->srv_conf[ngx_http_core_module_ctx.index];
    ngx_test_null(plcf, ngx_push_array(&scf->locations), NGX_CONF_ERROR);
    *plcf = lcf;

    cf->ctx = ctx;
    rv = ngx_conf_parse(cf, NULL);
    cf->ctx = prev;

    return rv;
}


static void *ngx_http_core_create_srv_conf(ngx_pool_t *pool)
{
    ngx_http_core_srv_conf_t *scf, **cf;

    ngx_test_null(scf,
                  ngx_pcalloc(pool, sizeof(ngx_http_core_srv_conf_t)), 
                  NGX_CONF_ERROR);

    ngx_init_array(scf->locations, pool, 5, sizeof(void *), NGX_CONF_ERROR);
    ngx_init_array(scf->listen, pool, 5, sizeof(ngx_http_listen_t),
                   NGX_CONF_ERROR);
    ngx_init_array(scf->server_names, pool, 5, sizeof(ngx_http_server_name_t),
                   NGX_CONF_ERROR);

    ngx_test_null(cf, ngx_push_array(&ngx_http_servers), NGX_CONF_ERROR);
    *cf = scf;

    return scf;
}


static char *ngx_http_core_init_srv_conf(ngx_pool_t *pool, void *conf)
{
    ngx_http_core_srv_conf_t *scf = (ngx_http_core_srv_conf_t *) conf;

    ngx_http_listen_t        *l;
    ngx_http_server_name_t   *n;

    if (scf->listen.nelts == 0) {
        ngx_test_null(l, ngx_push_array(&scf->listen), NGX_CONF_ERROR);
        l->addr = INADDR_ANY;
        l->port = 8000;
        l->family = AF_INET;
    }

    if (scf->server_names.nelts == 0) {
        ngx_test_null(n, ngx_push_array(&scf->server_names), NGX_CONF_ERROR);
        ngx_test_null(n->name.data, ngx_palloc(pool, NGX_MAXHOSTNAMELEN),
                      NGX_CONF_ERROR);
        if (gethostname(n->name.data, NGX_MAXHOSTNAMELEN) == -1) {
/* STUB: no log here */
#if 0
            ngx_log_error(NGX_LOG_EMERG, scf->log, ngx_errno,
                          "gethostname() failed");
#endif
            return NGX_CONF_ERROR;
        }
        n->name.len = ngx_strlen(n->name.data);
        n->core_srv_conf = conf;
    }

    return NGX_CONF_OK;
}


static void *ngx_http_core_create_loc_conf(ngx_pool_t *pool)
{
    ngx_http_core_loc_conf_t *lcf;

    ngx_test_null(lcf,
                  ngx_pcalloc(pool, sizeof(ngx_http_core_loc_conf_t)), 
                  NGX_CONF_ERROR);

    lcf->doc_root.len = 4;
    lcf->doc_root.data = "html";

    lcf->sendfile = 0;

    lcf->send_timeout = 10000;
    lcf->discarded_buffer_size = 1500;
    lcf->lingering_time = 30000;
    lcf->lingering_timeout = 5000;

/*
    lcf->send_timeout = NGX_CONF_UNSET;
*/

    return lcf;
}

static char *ngx_http_core_merge_loc_conf(ngx_pool_t *pool,
                                          void *parent, void *child)
{
    return NGX_CONF_OK;
}

static char *ngx_set_listen(ngx_conf_t *cf, ngx_command_t *cmd, char *conf)
{
    ngx_str_t          *args;
    ngx_http_listen_t  *ls;
    ngx_http_core_srv_conf_t *scf = (ngx_http_core_srv_conf_t *) conf;

    ngx_test_null(ls, ngx_push_array(&scf->listen), NGX_CONF_ERROR);

    /* AF_INET only */

    ls->family = AF_INET;
    ls->addr = INADDR_ANY;
    ls->flags = 0;
    ls->file_name = cf->conf_file->file.name;
    ls->line = cf->conf_file->line;

    args = (ngx_str_t *) cf->args->elts;

    ls->port = atoi(args[1].data);
    if (ls->port < 1 || ls->port > 65536) {
        return "port must be between 1 and 65535";
    }

    return NGX_CONF_OK;
}
