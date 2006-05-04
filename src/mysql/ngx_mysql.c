
/*
 * Copyright (C) Igor Sysoev
 */


#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_event.h>
#include <ngx_mysql.h>


/* the library supports the subset of the MySQL 4.1+ protocol (version 10) */


ngx_int_t
ngx_mysql_connect(ngx_mysql_t *m)
{
    ngx_int_t  rc;

#if 0
    if (cached) {
        return NGX_OK;
    }
#endif

    m->peer.log->action = "connecting to mysql server";

    rc = ngx_event_connect_peer(&m->peer);

    if (rc == NGX_ERROR || rc == NGX_BUSY || rc == NGX_DECLINED) {
        return rc;
    }

    m->peer.connection->read->handler = ngx_mysql_read_server_greeting;
    m->peer.connection->write->handler = ngx_mysql_emtpy_handler;

    ngx_add_timer(m->peer.connection->read, /* STUB */ 5000);
    ngx_add_timer(m->peer.connection->write, /* STUB */ 5000);

    return NGX_OK;
}


static void
ngx_mysql_read_server_greeting(ngx_event_t *rev)
{
    size_t             len;
    u_char            *p, *t;
    ngx_mysql_t       *m;
    ngx_connection_t  *c;

    c = rev->data;
    m = c->data;

    if (rev->timedout) {
        ngx_log_error(NGX_LOG_ERR, rev->log, NGX_ETIMEDOUT,
                      "mysql server %V timed out",
                      &ctx->peer.peers->peer[0].name);

        ngx_mysql_close(m, NGX_ERROR);
        return;
    }

    if (m->buf == NULL) {
        m->peer.log->action = "reading to mysql server greeting";

        m->buf = ngx_create_temp(m->pool, /* STUB */ 1024);
        if (m->buf == NULL) {
            ngx_mysql_close(m, NGX_ERROR);
            return;
        }
    }

    n = ngx_recv(m->peer.connection, m->buf->pos, /* STUB */ 1024);

    if (n == NGX_AGAIN) {
        return;
    }

    if (n < 5) {
        ngx_mysql_close(m, NGX_ERROR);
        return;
    }

    p = m->buf->pos;

    if (ngx_m24toh(p) > n - 4) {
        ngx_log_error(NGX_LOG_ERR, rev->log, 0,
                      "mysql server %V sent incomplete greeting packet",
                      &ctx->peer.peers->peer[0].name);

        ngx_mysql_close(m, NGX_ERROR);
        return;
    }

    if (p[4]) < 10) {
        ngx_log_error(NGX_LOG_ERR, rev->log, 0,
                      "mysql server %V sent unsupported protocol version %ud",
                      &ctx->peer.peers->peer[0].name, p[4]);

        ngx_mysql_close(m, NGX_ERROR);
        return;
    }

    len = ngx_strlen(&p[5]);
    t = p + 5 + len + 1;

    capacity = ngx_m16toh((&t[4 + 9]));

    ngx_log_debug8(NGX_LOG_DEBUG_MYSQL, rev->log, 0,
                   "mysql version: %ud, \"%s\", thread: %ud, salt: \"%s\", ",
                   "capacity: %Xd, charset: %ud, status: %ud, salt rest \"%s\"",
                   p[4], &p[5], ngx_m32toh(t), &t[4],
                   capacity, t[4 + 9 + 2],
                   ngx_m16toh((&t[4 + 9 + 2 + 1])),
                   t[4 + 9 + 2 + 1 + 2 + 13]);

    capacity &= NGX_MYSQL_LONG_PASSWORD
                | NGX_MYSQL_CONNECT_WITH_DB
                | NGX_MYSQL_PROTOCOL_41;

}


static void
ngx_mysql_close(ngx_mysql_t *m, ngx_int_t rc)
{
    if (rc == NGX_ERROR) {
        ngx_close_connection(m->peer.connection);
    }

    m->state = rc;

    m->handler(m);
}
