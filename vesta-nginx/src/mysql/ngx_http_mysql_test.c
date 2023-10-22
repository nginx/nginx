
/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) Nginx, Inc.
 */

#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_mysql.h>
#include <ngx_http.h>


typedef struct {
    ngx_addr_t  *peers;
    ngx_uint_t   npeers;
} ngx_http_mysql_test_conf_t;


static void ngx_http_mysql_auth(ngx_mysql_t *m);
static void ngx_http_mysql_done(ngx_mysql_t *m);
static void *ngx_http_mysql_test_create_loc_conf(ngx_conf_t *cf);
static char *ngx_http_mysql_test(ngx_conf_t *cf, ngx_command_t *cmd,
    void *conf);

static ngx_command_t  ngx_http_mysql_test_commands[] = {

    { ngx_string("mysql_test"),
      NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
      ngx_http_mysql_test,
      NGX_HTTP_LOC_CONF_OFFSET,
      0,
      NULL },

      ngx_null_command
};


static ngx_http_module_t  ngx_http_mysql_test_module_ctx = {
    NULL,                          /* preconfiguration */
    NULL,                          /* postconfiguration */

    NULL,                          /* create main configuration */
    NULL,                          /* init main configuration */

    NULL,                          /* create server configuration */
    NULL,                          /* merge server configuration */

    ngx_http_mysql_test_create_loc_conf,  /* create location configuration */
    NULL                           /* merge location configuration */
};


ngx_module_t  ngx_http_mysql_test_module = {
    NGX_MODULE_V1,
    &ngx_http_mysql_test_module_ctx, /* module context */
    ngx_http_mysql_test_commands,   /* module directives */
    NGX_HTTP_MODULE,               /* module type */
    NULL,                          /* init master */
    NULL,                          /* init module */
    NULL,                          /* init process */
    NULL,                          /* init thread */
    NULL,                          /* exit thread */
    NULL,                          /* exit process */
    NULL,                          /* exit master */
    NGX_MODULE_V1_PADDING
};


static ngx_str_t  ngx_mysql_login = ngx_string("root");
static ngx_str_t  ngx_mysql_passwd = ngx_string("tp");
static ngx_str_t  ngx_mysql_database = ngx_string("mysql");
static ngx_str_t  ngx_mysql_command_query =
    ngx_string("select * from user");


static ngx_int_t
ngx_http_mysql_test_handler(ngx_http_request_t *r)
{
    ngx_int_t                    rc;
    ngx_mysql_t                 *m;
    ngx_http_mysql_test_conf_t  *mtcf;

    mtcf = ngx_http_get_module_loc_conf(r, ngx_http_mysql_test_module);

    m = ngx_pcalloc(r->pool, sizeof(ngx_mysql_t));

    if (m == NULL) {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    m->pool = r->pool;
    m->handler = ngx_http_mysql_auth;
    m->data = r;

    m->login = &ngx_mysql_login;
    m->passwd = &ngx_mysql_passwd;
    m->database = &ngx_mysql_database;

    /* STUB */
    m->peer.sockaddr = mtcf->peers[0].sockaddr;
    m->peer.socklen = mtcf->peers[0].socklen;
    m->peer.name = &mtcf->peers[0].name;
    m->peer.tries = mtcf->npeers;
    m->peer.get = ngx_event_get_peer;
    /**/
    m->peer.log = r->connection->log;
    m->peer.log_error = NGX_ERROR_ERR;

    rc = ngx_mysql_connect(m);

    if (rc == NGX_OK || rc == NGX_AGAIN) {
        return NGX_DONE;
    }

    return NGX_HTTP_INTERNAL_SERVER_ERROR;
}


static void
ngx_http_mysql_auth(ngx_mysql_t *m)
{
    ngx_http_request_t  *r;

    r = m->data;

    if (m->state != NGX_OK) {
        ngx_http_finalize_request(r, NGX_HTTP_NO_CONTENT);
        return;
    }

    m->query.len = NGX_MYSQL_CMDPKT_LEN + ngx_mysql_command_query.len;

    m->query.data = ngx_pnalloc(r->pool, m->query.len);
    if (m->query.data == NULL) {
        ngx_http_finalize_request(r, NGX_HTTP_INTERNAL_SERVER_ERROR);
        return;
    }

    ngx_memcpy(m->query.data + NGX_MYSQL_CMDPKT_LEN,
               ngx_mysql_command_query.data, ngx_mysql_command_query.len);

    m->handler = ngx_http_mysql_done;

    ngx_mysql_query(m);
}


static void
ngx_http_mysql_done(ngx_mysql_t *m)
{
    ngx_http_request_t  *r;

    r = m->data;

    ngx_http_finalize_request(r, NGX_HTTP_NO_CONTENT);
}


static void *
ngx_http_mysql_test_create_loc_conf(ngx_conf_t *cf)
{
    ngx_http_mysql_test_conf_t  *conf;

    conf = ngx_pcalloc(cf->pool, sizeof(ngx_http_mysql_test_conf_t));
    if (conf == NULL) {
        return NGX_CONF_ERROR;
    }

    return conf;
}

static char *
ngx_http_mysql_test(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    ngx_http_mysql_test_conf_t  *mtcf = conf;

    ngx_str_t                 *value;
    ngx_url_t                  u;
    ngx_http_core_loc_conf_t  *clcf;

    clcf = ngx_http_conf_get_module_loc_conf(cf, ngx_http_core_module);
    clcf->handler = ngx_http_mysql_test_handler;

    value = cf->args->elts;

    ngx_memzero(&u, sizeof(ngx_url_t));

    u.url = value[1];
    u.default_port = 3306;

    if (ngx_parse_url(cf->pool, &u) != NGX_OK) {
        if (u.err) {
            ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                               "%s in upstream \"%V\"", u.err, &u.url);
        }

        return NGX_CONF_ERROR;
    }

    mtcf->peers = u.addrs;
    mtcf->npeers = u.naddrs;

    return NGX_CONF_OK;
}
