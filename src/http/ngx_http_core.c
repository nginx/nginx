
#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_config_command.h>
#include <ngx_http.h>
#include <ngx_http_core.h>
#include <ngx_http_config.h>

/* STUB */
#include <ngx_http_output_filter.h>
int ngx_http_static_handler(ngx_http_request_t *r);
int ngx_http_index_handler(ngx_http_request_t *r);
int ngx_http_proxy_handler(ngx_http_request_t *r);
/**/

static void *ngx_http_core_create_srv_conf(ngx_pool_t *pool);
static void *ngx_http_core_create_loc_conf(ngx_pool_t *pool);
static int ngx_http_core_translate_handler(ngx_http_request_t *r);


static ngx_command_t ngx_http_core_commands[];


ngx_http_module_t  ngx_http_core_module = {
    NGX_HTTP_MODULE,

    ngx_http_core_create_srv_conf,         /* create server config */
    ngx_http_core_create_loc_conf,         /* create location config */
    ngx_http_core_commands,                /* module directives */

    /* STUB */ NULL,                                  /* init module */
    ngx_http_core_translate_handler,       /* translate handler */

    NULL                                   /* init output body filter */
};


static ngx_command_t ngx_http_core_commands[] = {

    {"send_timeout", ngx_conf_set_time_slot,
     offsetof(ngx_http_core_loc_conf_t, send_timeout),
     NGX_HTTP_LOC_CONF, NGX_CONF_TAKE1,
     "set timeout for sending response"},

    {NULL}

};


int ngx_http_handler(ngx_http_request_t *r)
{
    int  rc, i;

    r->connection->unexpected_eof = 0;
    r->lingering_close = 1;
    r->keepalive = 1;

#if 1
    r->filter = NGX_HTTP_FILTER_NEED_IN_MEMORY;
#endif

    /* run translation phase */
    for (i = 0; ngx_http_modules[i]; i++) {
        if (ngx_http_modules[i]->translate_handler) {
            rc = ngx_http_modules[i]->translate_handler(r);
            if (rc == NGX_OK)
                break;

            if (rc >= NGX_HTTP_SPECIAL_RESPONSE)
                return ngx_http_special_response(r, rc);
        }
    }

    rc = r->handler(r);

    if (rc >= NGX_HTTP_SPECIAL_RESPONSE)
        return ngx_http_special_response(r, rc);

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

    r->filename.len = r->server->doc_root_len + r->uri.len + 2;

    ngx_test_null(r->filename.data,
                  ngx_palloc(r->pool, r->filename.len + 1),
                  NGX_HTTP_INTERNAL_SERVER_ERROR);

    loc = ngx_cpystrn(r->filename.data, r->server->doc_root,
                      r->server->doc_root_len);
    last = ngx_cpystrn(loc, r->uri.data, r->uri.len + 1);

    ngx_log_debug(r->connection->log, "HTTP filename: '%s'" _ r->filename.data);

    if (ngx_file_type(r->filename.data, &r->fileinfo) == -1) {
        err = ngx_errno;
        ngx_log_error(NGX_LOG_ERR, r->connection->log, err,
                      ngx_file_type_n " %s failed", r->filename.data);

        if (err == NGX_ENOENT)
            return NGX_HTTP_NOT_FOUND;
        else
            return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    if (ngx_is_dir(r->fileinfo)) {
        ngx_log_debug(r->connection->log, "HTTP DIR: '%s'" _ r->filename.data);

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

    return ngx_http_close_request(r);
}


int ngx_http_close_request(ngx_http_request_t *r)
{
    ngx_assert((r->fd != -1), /* void */; , r->connection->log,
               "file already closed");

    if (r->fd != -1) {
        if (ngx_close_file(r->fd) == -1)
            ngx_log_error(NGX_LOG_ERR, r->connection->log, ngx_errno,
                          ngx_close_file_n " failed");
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

    conf->send_timeout = NGX_CONF_UNSET;

    return conf;
}

#if 0
static void *ngx_http_core_create_conf(ngx_pool_t *pool)
{

    ngx_test_null(conf, ngx_palloc(pool, sizeof(ngx_http_core_conf_t)), NULL);

    ngx_test_null(conf->srv, ngx_http_core_create_srv_conf_t(pool), NULL);
    ngx_test_null(conf->loc, ngx_http_core_create_loc_conf_t(pool), NULL);
    conf->parent = 
    conf->next = NULL;
}
#endif
