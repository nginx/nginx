
#include <ngx_config.h>

#include <ngx_listen.h>
#include <ngx_core.h>
#include <ngx_string.h>
#include <ngx_conf_file.h>

#include <nginx.h>

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

static void *ngx_http_core_create_main_conf(ngx_pool_t *pool);
static char *ngx_http_core_init_main_conf(ngx_pool_t *pool, void *conf);
static void *ngx_http_core_create_srv_conf(ngx_pool_t *pool);
static char *ngx_http_core_merge_srv_conf(ngx_pool_t *pool,
                                          void *parent, void *child);
static void *ngx_http_core_create_loc_conf(ngx_pool_t *pool);
static char *ngx_http_core_merge_loc_conf(ngx_pool_t *pool,
                                          void *parent, void *child);

static char *ngx_server_block(ngx_conf_t *cf, ngx_command_t *cmd, char *dummy);
static char *ngx_location_block(ngx_conf_t *cf, ngx_command_t *cmd,
                                                                  char *dummy);
static char *ngx_types_block(ngx_conf_t *cf, ngx_command_t *cmd, char *dummy);
static char *ngx_set_listen(ngx_conf_t *cf, ngx_command_t *cmd, char *conf);


static ngx_command_t  ngx_http_core_commands[] = {

    {ngx_string("server"),
     NGX_HTTP_MAIN_CONF|NGX_CONF_BLOCK|NGX_CONF_NOARGS,
     ngx_server_block,
     0,
     0,
     NULL,},

    {ngx_string("post_accept_timeout"),
     NGX_HTTP_MAIN_CONF|NGX_CONF_TAKE1,
     ngx_conf_set_msec_slot,
     NGX_HTTP_MAIN_CONF_OFFSET,
     offsetof(ngx_http_core_main_conf_t, post_accept_timeout),
     NULL},

    {ngx_string("connection_pool_size"),
     NGX_HTTP_MAIN_CONF|NGX_CONF_TAKE1,
     ngx_conf_set_size_slot,
     NGX_HTTP_MAIN_CONF_OFFSET,
     offsetof(ngx_http_core_main_conf_t, connection_pool_size),
     NULL},

    {ngx_string("request_pool_size"),
     NGX_HTTP_MAIN_CONF|NGX_CONF_TAKE1,
     ngx_conf_set_size_slot,
     NGX_HTTP_MAIN_CONF_OFFSET,
     offsetof(ngx_http_core_main_conf_t, request_pool_size),
     NULL},

    {ngx_string("client_header_timeout"),
     NGX_HTTP_MAIN_CONF|NGX_CONF_TAKE1,
     ngx_conf_set_msec_slot,
     NGX_HTTP_MAIN_CONF_OFFSET,
     offsetof(ngx_http_core_main_conf_t, client_header_timeout),
     NULL},

    {ngx_string("client_header_buffer_size"),
     NGX_HTTP_MAIN_CONF|NGX_CONF_TAKE1,
     ngx_conf_set_size_slot,
     NGX_HTTP_MAIN_CONF_OFFSET,
     offsetof(ngx_http_core_main_conf_t, client_header_buffer_size),
     NULL},

    {ngx_string("large_client_header"),
     NGX_HTTP_MAIN_CONF|NGX_CONF_FLAG,
     ngx_conf_set_flag_slot,
     NGX_HTTP_MAIN_CONF_OFFSET,
     offsetof(ngx_http_core_main_conf_t, large_client_header),
     NULL},

    {ngx_string("location"),
     NGX_HTTP_SRV_CONF|NGX_CONF_BLOCK|NGX_CONF_TAKE1,
     ngx_location_block,
     NGX_HTTP_SRV_CONF_OFFSET,
     0,
     NULL},

    {ngx_string("listen"),
     NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_CONF_TAKE1,
     ngx_set_listen,
     NGX_HTTP_SRV_CONF_OFFSET,
     0,
     NULL},

    {ngx_string("types"),
     NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF
                                         |NGX_CONF_BLOCK|NGX_CONF_NOARGS,
     ngx_types_block,
     NGX_HTTP_LOC_CONF_OFFSET,
     0,
     NULL},

    {ngx_string("root"),
     NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
     ngx_conf_set_str_slot,
     NGX_HTTP_LOC_CONF_OFFSET,
     offsetof(ngx_http_core_loc_conf_t, doc_root),
     NULL},

    {ngx_string("sendfile"),
     NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
     ngx_conf_set_flag_slot,
     NGX_HTTP_LOC_CONF_OFFSET,
     offsetof(ngx_http_core_loc_conf_t, sendfile),
     NULL},

    {ngx_string("send_timeout"),
     NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
     ngx_conf_set_msec_slot,
     NGX_HTTP_LOC_CONF_OFFSET,
     offsetof(ngx_http_core_loc_conf_t, send_timeout),
     NULL},

    {ngx_string("keepalive_timeout"),
     NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
     ngx_conf_set_msec_slot,
     NGX_HTTP_LOC_CONF_OFFSET,
     offsetof(ngx_http_core_loc_conf_t, keepalive_timeout),
     NULL},

    {ngx_string("lingering_time"),
     NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
     ngx_conf_set_msec_slot,
     NGX_HTTP_LOC_CONF_OFFSET,
     offsetof(ngx_http_core_loc_conf_t, lingering_time),
     NULL},

    {ngx_string("lingering_timeout"),
     NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
     ngx_conf_set_msec_slot,
     NGX_HTTP_LOC_CONF_OFFSET,
     offsetof(ngx_http_core_loc_conf_t, lingering_timeout),
     NULL},

    {ngx_null_string, 0, NULL, 0, 0, NULL}
};


ngx_http_module_t  ngx_http_core_module_ctx = {
    NGX_HTTP_MODULE,

    ngx_http_core_create_main_conf,        /* create main configuration */
    ngx_http_core_init_main_conf,          /* init main configuration */

    ngx_http_core_create_srv_conf,         /* create server configuration */
    ngx_http_core_merge_srv_conf,          /* merge server configuration */

    ngx_http_core_create_loc_conf,         /* create location configuration */
    ngx_http_core_merge_loc_conf           /* merge location configuration */
};


ngx_module_t  ngx_http_core_module = {
    &ngx_http_core_module_ctx,             /* module context */
    0,                                     /* module index */
    ngx_http_core_commands,                /* module directives */
    NGX_HTTP_MODULE_TYPE,                  /* module type */
    ngx_http_core_init                     /* init module */
};


int ngx_http_find_server_conf(ngx_http_request_t *r)
{
    int                      a, n;
    socklen_t                len;
    struct sockaddr_in       addr_in;
    ngx_http_in_port_t      *in_port;
    ngx_http_in_addr_t      *in_addr;
    ngx_http_conf_ctx_t     *ctx;
    ngx_http_server_name_t  *name;

    /* AF_INET only */

    in_port = (ngx_http_in_port_t *) r->connection->servers;
    in_addr = (ngx_http_in_addr_t *) in_port->addrs.elts;

    r->port = in_port->port;

    a = 0;

    if (in_port->addrs.nelts > 1) {

        /* there're the several addresses on this port and one of them
           is "*:port" so getsockname() is needed to determine
           the server address */

        len = sizeof(struct sockaddr_in);
        if (getsockname(r->connection->fd, (struct sockaddr *) &addr_in, &len)
                                                                       == -1) {
            ngx_log_error(NGX_LOG_CRIT, r->connection->log, ngx_socket_errno,
                          "getsockname() failed");
            return NGX_ERROR;
        }

        r->in_addr = addr_in.sin_addr.s_addr;

        for ( /* void */ ; a < in_port->addrs.nelts; a++) {
            if (in_addr[a].addr == r->in_addr) {
ngx_log_debug(r->connection->log, "FOUND");
                break;
            }
        }

/* DEBUG */
if (a == in_port->addrs.nelts) {
    ngx_log_error(NGX_LOG_ALERT, r->connection->log, 0,
                  "addr not found");
    exit(1);
}

    } else {
        r->in_addr = in_addr[0].addr;
    }

    /* the default server configuration for this address:port */
    ctx = in_addr[a].core_srv_conf->ctx;

    if (r->headers_in.host_name_len > 0) {

        /* find the name based server configuration */

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

    r->srv_conf = ctx->srv_conf;
    r->loc_conf = ctx->loc_conf;

#if 0
ngx_log_debug(r->connection->log, "cxt: %08x" _ ctx);
ngx_log_debug(r->connection->log, "srv_conf: %0x" _ r->srv_conf);
ngx_log_debug(r->connection->log, "loc_conf: %0x" _ r->loc_conf);
#endif

    return NGX_OK;
}


void ngx_http_handler(ngx_http_request_t *r)
{
    int                        rc, i;
    ngx_http_handler_pt       *h;
    ngx_http_core_loc_conf_t  *lcf, **lcfp;
    ngx_http_core_srv_conf_t  *scf;

    r->connection->unexpected_eof = 0;

    r->keepalive = 1;

    if (r->headers_in.content_length_n > 0) {
        r->lingering_close = 1;
    }

    /* TEST STUB */ r->lingering_close = 1;


    /* TODO: run rewrite url phase */


    /* find location config */

    scf = (ngx_http_core_srv_conf_t *)
                     ngx_http_get_module_srv_conf(r, ngx_http_core_module_ctx);

    lcfp = (ngx_http_core_loc_conf_t **) scf->locations.elts;
    for (i = 0; i < scf->locations.nelts; i++) {
#if 0
ngx_log_debug(r->connection->log, "trans: %s" _ lcfp[i]->name.data);
#endif
         if (r->uri.len < lcfp[i]->name.len) {
             continue;
         }

         rc = ngx_rstrncmp(r->uri.data, lcfp[i]->name.data, lcfp[i]->name.len);

         if (rc < 0) {
             break;
         }

         if (rc == 0) {
             r->loc_conf = lcfp[i]->loc_conf;
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

        if (rc >= NGX_HTTP_SPECIAL_RESPONSE) {
            ngx_http_finalize_request(r, rc);
            return;
        }

        if (rc == NGX_OK) {
            rc = r->handler(r);
            if (rc >= NGX_HTTP_SPECIAL_RESPONSE) {
                ngx_http_finalize_request(r, rc);
            }
            return;
        }
    }

    /* TODO: no handlers found ? */
    ngx_http_finalize_request(r, NGX_HTTP_INTERNAL_SERVER_ERROR);
    return;
}


int ngx_http_core_translate_handler(ngx_http_request_t *r)
{
    int                         len, port_len, f_offset, l_offset;
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
                      ngx_file_type_n " \"%s\" failed", r->file.name.data);

        if (err == NGX_ENOENT || err == NGX_ENOTDIR) {
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
                      ngx_open_file_n " \"%s\" failed", r->file.name.data);

        if (err == NGX_ENOENT || err == NGX_ENOTDIR) {
            return NGX_HTTP_NOT_FOUND;

        } else if (err == NGX_EACCES) {
            return NGX_HTTP_FORBIDDEN;

        } else {
            return NGX_HTTP_INTERNAL_SERVER_ERROR;
        }
    }

    if (!r->file.info_valid) {
        if (ngx_stat_fd(r->file.fd, &r->file.info) == NGX_FILE_ERROR) {
            ngx_log_error(NGX_LOG_CRIT, r->connection->log, ngx_errno,
                          ngx_stat_fd_n " \"%s\" failed", r->file.name.data);

            if (ngx_close_file(r->file.fd) == NGX_FILE_ERROR) {
                ngx_log_error(NGX_LOG_ALERT, r->connection->log, ngx_errno,
                              ngx_close_file_n " \"%s\" failed",
                              r->file.name.data);
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
                          ngx_close_file_n " \"%s\" failed", r->file.name.data);
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
                              "\"%s\" is not found", r->path.data);
            }

            if (rc == NGX_HTTP_FORBIDDEN) {
                ngx_log_error(NGX_LOG_ERR, r->connection->log, r->path_err,
                          "\"%s\" is forbidden", r->path.data);
            }

            return rc;
        }
    }

    r->path.data[r->path.len] = '\0';
    ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                  "directory index of \"%s\" is forbidden", r->path.data);

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

    ngx_http_close_request(r, 0);
    return NGX_OK;
}


int ngx_http_error(ngx_http_request_t *r, int error) 
{
    /* STUB */
    ngx_log_debug(r->connection->log, "http error: %d" _ error);

    /* log request */

    ngx_http_special_response_handler(r, error);
    ngx_http_close_request(r, 0);
    return NGX_OK;
}


int ngx_http_internal_redirect(ngx_http_request_t *r, ngx_str_t uri)
{
    ngx_log_debug(r->connection->log, "internal redirect: '%s'" _ uri.data);

    r->uri.len = uri.len;
    r->uri.data = uri.data;

    /* BROKEN, NEEDED ? */
    /* r->exten */
    r->uri_start = uri.data;
    r->uri_end = uri.data + uri.len;
    /**/

    ngx_http_handler(r);
    return 0;
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
    int                          m;
    char                        *rv;
    ngx_http_module_t           *module;
    ngx_conf_t                   pcf;
    ngx_http_conf_ctx_t         *ctx, *hctx, *pctx;
    ngx_http_core_main_conf_t   *cmcf;
    ngx_http_core_srv_conf_t    *cscf, **cscfp;

    ngx_test_null(ctx,
                  ngx_pcalloc(cf->pool, sizeof(ngx_http_conf_ctx_t)),
                  NGX_CONF_ERROR);

    hctx = (ngx_http_conf_ctx_t *) cf->ctx;
    ctx->main_conf = hctx->main_conf;

    /* the server{}'s srv_conf */

    ngx_test_null(ctx->srv_conf,
                  ngx_pcalloc(cf->pool, sizeof(void *) * ngx_http_max_module),
                  NGX_CONF_ERROR);

    /* the server{}'s loc_conf */

    ngx_test_null(ctx->loc_conf,
                  ngx_pcalloc(cf->pool, sizeof(void *) * ngx_http_max_module),
                  NGX_CONF_ERROR);

    for (m = 0; ngx_modules[m]; m++) {
        if (ngx_modules[m]->type != NGX_HTTP_MODULE_TYPE) {
            continue;
        }

        module = (ngx_http_module_t *) ngx_modules[m]->ctx;

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

    /* create links of the srv_conf's */

    cscf = ctx->srv_conf[ngx_http_core_module_ctx.index];
    cscf->ctx = ctx;

    cmcf = ctx->main_conf[ngx_http_core_module_ctx.index];
    ngx_test_null(cscfp, ngx_push_array(&cmcf->servers), NGX_CONF_ERROR);
    *cscfp = cscf;

    /* parse inside server{} */

    pcf = *cf;
    pctx = cf->ctx;
    cf->ctx = ctx;
    cf->cmd_type = NGX_HTTP_SRV_CONF;
    rv = ngx_conf_parse(cf, NULL);
    *cf = pcf;

    return rv;
}


static char *ngx_location_block(ngx_conf_t *cf, ngx_command_t *cmd, char *dummy)
{
    int                        i;
    char                      *rv;
    ngx_str_t                 *location;
    ngx_http_module_t         *module;
    ngx_conf_t                 pcf;
    ngx_http_conf_ctx_t       *ctx, *pctx;
    ngx_http_core_srv_conf_t  *cscf;
    ngx_http_core_loc_conf_t  *clcf, **clcfp;

    ngx_test_null(ctx,
                  ngx_pcalloc(cf->pool, sizeof(ngx_http_conf_ctx_t)),
                  NGX_CONF_ERROR);

    pctx = (ngx_http_conf_ctx_t *) cf->ctx;
    ctx->main_conf = pctx->main_conf;
    ctx->srv_conf = pctx->srv_conf;

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

    clcf = ctx->loc_conf[ngx_http_core_module_ctx.index];
    location = (ngx_str_t *) cf->args->elts;
    clcf->name.len = location[1].len;
    clcf->name.data = location[1].data;
    clcf->loc_conf = ctx->loc_conf;

    cscf = ctx->srv_conf[ngx_http_core_module_ctx.index];
    ngx_test_null(clcfp, ngx_push_array(&cscf->locations), NGX_CONF_ERROR);
    *clcfp = clcf;

    pcf = *cf;
    cf->ctx = ctx;
    cf->cmd_type = NGX_HTTP_LOC_CONF;
    rv = ngx_conf_parse(cf, NULL);
    *cf = pcf;

    return rv;
}


static char *ngx_set_type(ngx_conf_t *cf, ngx_command_t *dummy, char *conf)
{
    ngx_http_core_loc_conf_t *lcf = (ngx_http_core_loc_conf_t *) conf;

    int               i, key;
    ngx_str_t        *args;
    ngx_http_type_t  *t;

    if (lcf->types == NULL) {
        ngx_test_null(lcf->types,
                      ngx_palloc(cf->pool, NGX_HTTP_TYPES_HASH_PRIME
                                                        * sizeof(ngx_array_t)),
                      NGX_CONF_ERROR);

        for (i = 0; i < NGX_HTTP_TYPES_HASH_PRIME; i++) {
            ngx_init_array(lcf->types[i], cf->pool, 5, sizeof(ngx_http_type_t),
                           NGX_CONF_ERROR);
        }
    }

    args = (ngx_str_t *) cf->args->elts;

    for (i = 1; i < cf->args->nelts; i++) {
        ngx_http_types_hash_key(key, args[i]);

        ngx_test_null(t, ngx_push_array(&lcf->types[key]), NGX_CONF_ERROR);
        t->exten.len = args[i].len;
        t->exten.data = args[i].data;
        t->type.len = args[0].len;
        t->type.data = args[0].data;
    }

    return NGX_CONF_OK;
}


static char *ngx_types_block(ngx_conf_t *cf, ngx_command_t *cmd, char *conf)
{
    char        *rv;
    ngx_conf_t   pcf;

    pcf = *cf;
    cf->handler = ngx_set_type;
    cf->handler_conf = conf;
    rv = ngx_conf_parse(cf, NULL);
    *cf = pcf;

    return rv;
}


static void *ngx_http_core_create_main_conf(ngx_pool_t *pool)
{
    ngx_http_core_main_conf_t *cmcf;

    ngx_test_null(cmcf,
                  ngx_palloc(pool, sizeof(ngx_http_core_main_conf_t)), 
                  NGX_CONF_ERROR);

    cmcf->post_accept_timeout = NGX_CONF_UNSET;
    cmcf->connection_pool_size = NGX_CONF_UNSET;
    cmcf->request_pool_size = NGX_CONF_UNSET;
    cmcf->client_header_timeout = NGX_CONF_UNSET;
    cmcf->client_header_buffer_size = NGX_CONF_UNSET;
    cmcf->large_client_header = NGX_CONF_UNSET;

    ngx_init_array(cmcf->servers, pool, 5, sizeof(ngx_http_core_srv_conf_t *),
                   NGX_CONF_ERROR);

    return cmcf;
}


static char *ngx_http_core_init_main_conf(ngx_pool_t *pool, void *conf)
{
    ngx_http_core_main_conf_t *cmcf = (ngx_http_core_main_conf_t *) conf;

    ngx_conf_init_msec_value(cmcf->post_accept_timeout, 30000);
    ngx_conf_init_size_value(cmcf->connection_pool_size, 16384);
    ngx_conf_init_size_value(cmcf->request_pool_size, 16384);
    ngx_conf_init_msec_value(cmcf->client_header_timeout, 60000);
    ngx_conf_init_size_value(cmcf->client_header_buffer_size, 1024);
    ngx_conf_init_value(cmcf->large_client_header, 1);

    return NGX_CONF_OK;
}


static void *ngx_http_core_create_srv_conf(ngx_pool_t *pool)
{
    ngx_http_core_srv_conf_t  *cscf;

    ngx_test_null(cscf,
                  ngx_pcalloc(pool, sizeof(ngx_http_core_srv_conf_t)), 
                  NGX_CONF_ERROR);

    ngx_init_array(cscf->locations, pool, 5, sizeof(void *), NGX_CONF_ERROR);
    ngx_init_array(cscf->listen, pool, 5, sizeof(ngx_http_listen_t),
                   NGX_CONF_ERROR);
    ngx_init_array(cscf->server_names, pool, 5, sizeof(ngx_http_server_name_t),
                   NGX_CONF_ERROR);

    return cscf;
}


static char *ngx_http_core_merge_srv_conf(ngx_pool_t *pool,
                                          void *parent, void *child)
{
    ngx_http_core_srv_conf_t *prev = (ngx_http_core_srv_conf_t *) parent;
    ngx_http_core_srv_conf_t *conf = (ngx_http_core_srv_conf_t *) child;

    ngx_http_listen_t        *l;
    ngx_http_server_name_t   *n;

    /* TODO: it does not merge, it init only */

    if (conf->listen.nelts == 0) {
        ngx_test_null(l, ngx_push_array(&conf->listen), NGX_CONF_ERROR);
        l->addr = INADDR_ANY;
        l->port = 8000;
        l->family = AF_INET;
    }

    if (conf->server_names.nelts == 0) {
        ngx_test_null(n, ngx_push_array(&conf->server_names), NGX_CONF_ERROR);
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

    /* set by ngx_pcalloc():

    lcf->doc_root.len = 0;
    lcf->doc_root.data = NULL;
    lcf->types = NULL;

    */

    lcf->sendfile = NGX_CONF_UNSET;

    lcf->send_timeout = NGX_CONF_UNSET;
    lcf->discarded_buffer_size = NGX_CONF_UNSET;
    lcf->keepalive_timeout = NGX_CONF_UNSET;
    lcf->lingering_time = NGX_CONF_UNSET;
    lcf->lingering_timeout = NGX_CONF_UNSET;

    return lcf;
}


static ngx_http_type_t default_types[] = {
    { ngx_string("html"), ngx_string("text/html") },
    { ngx_string("gif"), ngx_string("image/gif") },
    { ngx_string("jpg"), ngx_string("image/jpeg") },
    { ngx_null_string, ngx_null_string }
};


static char *ngx_http_core_merge_loc_conf(ngx_pool_t *pool,
                                          void *parent, void *child)
{
    ngx_http_core_loc_conf_t *prev = (ngx_http_core_loc_conf_t *) parent;
    ngx_http_core_loc_conf_t *conf = (ngx_http_core_loc_conf_t *) child;

    int               i, key;
    ngx_http_type_t  *t;

    if (conf->doc_root.len == 0) {
        if (prev->doc_root.len) {
           conf->doc_root.len = prev->doc_root.len;
           conf->doc_root.data = prev->doc_root.data;

        } else {
           conf->doc_root.len = 4;
           conf->doc_root.data = "html";
        }
    }

    if (conf->types == NULL) {
        if (prev->types) {
            conf->types = prev->types;

        } else {
            ngx_test_null(conf->types,
                          ngx_palloc(pool, NGX_HTTP_TYPES_HASH_PRIME
                                                        * sizeof(ngx_array_t)),
                          NGX_CONF_ERROR);

            for (i = 0; i < NGX_HTTP_TYPES_HASH_PRIME; i++) {
                ngx_init_array(conf->types[i], pool, 5, sizeof(ngx_http_type_t),
                               NGX_CONF_ERROR);
            }

            for (i = 0; default_types[i].exten.len; i++) {
                ngx_http_types_hash_key(key, default_types[i].exten);

                ngx_test_null(t, ngx_push_array(&conf->types[key]),
                              NGX_CONF_ERROR);
                t->exten.len = default_types[i].exten.len;
                t->exten.data = default_types[i].exten.data;
                t->type.len = default_types[i].type.len;
                t->type.data = default_types[i].type.data;
            }
        }
    }

    ngx_conf_merge_value(conf->sendfile, prev->sendfile, 0);

    ngx_conf_merge_msec_value(conf->send_timeout, prev->send_timeout, 10000);

    ngx_conf_merge_size_value(conf->discarded_buffer_size,
                              prev->discarded_buffer_size, 1500);
    ngx_conf_merge_msec_value(conf->keepalive_timeout, prev->keepalive_timeout,
                              70000);
    ngx_conf_merge_msec_value(conf->lingering_time, prev->lingering_time,
                              30000);
    ngx_conf_merge_msec_value(conf->lingering_timeout, prev->lingering_timeout,
                              5000);

    return NGX_CONF_OK;
}


static char *ngx_set_listen(ngx_conf_t *cf, ngx_command_t *cmd, char *conf)
{
    ngx_http_core_srv_conf_t *scf = (ngx_http_core_srv_conf_t *) conf;

    char               *addr;
    u_int               p;
    ngx_str_t          *args;
    ngx_http_listen_t  *ls;

    /* TODO: check duplicate 'listen' directives */

    ngx_test_null(ls, ngx_push_array(&scf->listen), NGX_CONF_ERROR);

    /* AF_INET only */

    ls->family = AF_INET;
    ls->flags = 0;
    ls->file_name = cf->conf_file->file.name;
    ls->line = cf->conf_file->line;

    args = (ngx_str_t *) cf->args->elts;
    addr = args[1].data;

    for (p = 0; p < args[1].len; p++) {
        if (addr[p] == ':') {
            addr[p++] = '\0';

            ls->addr = inet_addr(addr);
            if (ls->addr == INADDR_NONE) {
                /* TODO: gethostbyname() */
                return "can not resolve host name";
            }

            break;
        }
    }

    if (p == args[1].len) {
        ls->addr = INADDR_ANY;
        p = 0;
    }

    ls->port = ngx_atoi(&addr[p], args[1].len - p);
    if (ls->port < 1 || ls->port > 65536) {
        return "port must be between 1 and 65535";
    }

    return NGX_CONF_OK;
}
