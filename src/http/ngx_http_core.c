
#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_config_file.h>
#include <ngx_http.h>
#include <ngx_http_core.h>
#include <ngx_http_config.h>

/* STUB */
int ngx_http_static_handler(ngx_http_request_t *r);
int ngx_http_index_handler(ngx_http_request_t *r);
int ngx_http_proxy_handler(ngx_http_request_t *r);
/**/

static void *ngx_http_core_create_srv_conf(ngx_pool_t *pool);
static void *ngx_http_core_create_loc_conf(ngx_pool_t *pool);
static int ngx_http_core_translate_handler(ngx_http_request_t *r);


int (*ngx_http_top_header_filter) (ngx_http_request_t *r);

int ngx_http_max_module;

#if 0
static ngx_command_t ngx_http_core_commands[] = {

    {ngx_string("send_timeout"),
     NGX_CONF_TAKE1, 
     ngx_conf_set_time_slot,
     NGX_HTTP_LOC_CONF,
     offsetof(ngx_http_core_loc_conf_t, send_timeout)},

    {ngx_string(""), 0, NULL, 0, 0}
};
#endif

ngx_http_module_t  ngx_http_core_module_ctx = {
    NGX_HTTP_MODULE,

    ngx_http_core_create_srv_conf,         /* create server config */
    NULL,                                  /* init server config */
    ngx_http_core_create_loc_conf,         /* create location config */
    NULL,                                  /* merge location config */

    ngx_http_core_translate_handler,       /* translate handler */

    NULL,                                  /* output header filter */
    NULL,                                  /* next output header filter */
    NULL,                                  /* output body filter */
    NULL,                                  /* next output body filter */
};

#if 0
ngx_module_t  ngx_http_core_module = {
    &ngx_http_core_module_ctx,             /* module context */
    ngx_http_core_commands,                /* module directives */
    NGX_HTTP_MODULE_TYPE,                  /* module type */
    NULL                                   /* init module */
};
#endif

int ngx_http_handler(ngx_http_request_t *r)
{
    int  rc, i;
    ngx_http_module_t *module;

    r->connection->unexpected_eof = 0;
    r->lingering_close = 1;
    r->keepalive = 0;

#if 0
    r->filter = NGX_HTTP_FILTER_NEED_IN_MEMORY;
#endif

    /* run translation phase */
    for (i = 0; ngx_modules[i]; i++) {
        if (ngx_modules[i]->type != NGX_HTTP_MODULE_TYPE) {
            continue;
        }

        module = (ngx_http_module_t *) ngx_modules[i]->ctx;
        if (module->translate_handler == NULL) {
            continue;
        }

        rc = module->translate_handler(r);
        if (rc == NGX_OK) {
            break;
        }

        if (rc >= NGX_HTTP_SPECIAL_RESPONSE) {
            return ngx_http_special_response(r, rc);
        }
    }

    rc = r->handler(r);

    if (rc >= NGX_HTTP_SPECIAL_RESPONSE) {
        return ngx_http_special_response(r, rc);
    }

    return rc;
}


static int ngx_http_core_translate_handler(ngx_http_request_t *r)
{
    char      *loc, *last;
    ngx_err_t  err;
    ngx_table_elt_t  *h;

    /* TODO: find location conf */

    if (r->uri.data[r->uri.len - 1] == '/') {
        /* TODO: find index handler */
        /* STUB */ r->handler = ngx_http_index_handler;

        return NGX_OK;
    }

    r->file.name.len = r->server->doc_root_len + r->uri.len + 2;

    ngx_test_null(r->file.name.data,
                  ngx_palloc(r->pool, r->file.name.len + 1),
                  NGX_HTTP_INTERNAL_SERVER_ERROR);

    loc = ngx_cpystrn(r->file.name.data, r->server->doc_root,
                      r->server->doc_root_len);
    last = ngx_cpystrn(loc, r->uri.data, r->uri.len + 1);

    ngx_log_debug(r->connection->log, "HTTP filename: '%s'" _
                  r->file.name.data);

#if (WIN9X)

    /* There is no way to open file or directory in Win9X with
       one syscall: Win9X has not FILE_FLAG_BACKUP_SEMANTICS flag.
       so we need to check its type before opening */

#if 0 /* OLD: ngx_file_type() is to be removed */
    if (ngx_file_type(r->file.name.data, &r->file.info) == -1) {
#endif

    r->file.info.dwFileAttributes = GetFileAttributes(r->file.name.data);
    if (r->file.info.dwFileAttributes == INVALID_FILE_ATTRIBUTES) {
        err = ngx_errno;
        ngx_log_error(NGX_LOG_ERR, r->connection->log, err,
                      "ngx_http_core_translate_handler: "
                      ngx_file_type_n " %s failed", r->file.name.data);

        if (err == ERROR_FILE_NOT_FOUND) {
            return NGX_HTTP_NOT_FOUND;
        } else if (err == ERROR_PATH_NOT_FOUND) {
            return NGX_HTTP_NOT_FOUND;
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
        } else {
            return NGX_HTTP_INTERNAL_SERVER_ERROR;
        }
    }

    if (!r->file.info_valid) {
        if (ngx_stat_fd(r->file.fd, &r->file.info) == NGX_FILE_ERROR) {
            ngx_log_error(NGX_LOG_ERR, r->connection->log, ngx_errno,
                          "ngx_http_core_handler: "
                          ngx_stat_fd_n " %s failed", r->file.name.data);

            if (ngx_close_file(r->file.fd) == NGX_FILE_ERROR) {
                ngx_log_error(NGX_LOG_ERR, r->connection->log, ngx_errno,
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
            ngx_log_error(NGX_LOG_ERR, r->connection->log, ngx_errno,
                          "ngx_http_core_handler: "
                          ngx_close_file_n " %s failed", r->file.name.data);
        }
#endif

        /* BROKEN: need to include server name */

        ngx_test_null(h, ngx_push_table(r->headers_out.headers),
                      NGX_HTTP_INTERNAL_SERVER_ERROR);

        *last++ = '/';
        *last = '\0';
        h->key.len = 8;
        h->key.data = "Location" ;
        h->value.len = last - loc;
        h->value.data = loc;
        r->headers_out.location = h;

        return NGX_HTTP_MOVED_PERMANENTLY;
    }

    /* TODO: r->handler = loc_conf->default_handler; */
    /* STUB */ r->handler = ngx_http_static_handler;

    return NGX_OK;
}


int ngx_http_send_header(ngx_http_request_t *r)
{
    return (*ngx_http_top_header_filter)(r);
}


int ngx_http_redirect(ngx_http_request_t *r, int redirect)
{
    /* STUB */

    /* log request */

    return ngx_http_close_request(r);
}


int ngx_http_error(ngx_http_request_t *r, int error) 
{
    /* STUB */
    ngx_log_debug(r->connection->log, "http error: %d" _ error);

    /* log request */

    ngx_http_special_response(r, error);
    return ngx_http_close_request(r);
}


int ngx_http_close_request(ngx_http_request_t *r)
{
    ngx_log_debug(r->connection->log, "CLOSE#: %d" _ r->file.fd);

    ngx_http_log_handler(r);

    ngx_assert((r->file.fd != NGX_INVALID_FILE), /* void */ ; ,
               r->connection->log, "file already closed");

    if (r->file.fd != NGX_INVALID_FILE) {
        if (ngx_close_file(r->file.fd) == NGX_FILE_ERROR) {
            ngx_log_error(NGX_LOG_ERR, r->connection->log, ngx_errno,
                          ngx_close_file_n " failed");
        }
    }

/*
    if (r->logging)
        ngx_http_log_request(r);
*/

    ngx_destroy_pool(r->pool);

    ngx_log_debug(r->connection->log, "http close");

    ngx_del_timer(r->connection->read);
    ngx_del_timer(r->connection->write);

    return NGX_DONE;
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


static void *ngx_http_core_create_srv_conf(ngx_pool_t *pool)
{
    ngx_http_core_srv_conf_t *conf;

    ngx_test_null(conf,
                  ngx_pcalloc(pool, sizeof(ngx_http_core_srv_conf_t)),
                  NULL);

    return conf;
}

static void *ngx_http_core_create_loc_conf(ngx_pool_t *pool)
{
    ngx_http_core_loc_conf_t *conf;

    ngx_test_null(conf,
                  ngx_pcalloc(pool, sizeof(ngx_http_core_loc_conf_t)),
                  NULL);

    conf->send_timeout = 10;
/*
    conf->send_timeout = NGX_CONF_UNSET;
*/

    return conf;
}
