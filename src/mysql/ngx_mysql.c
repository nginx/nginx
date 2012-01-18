
/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) Nginx, Inc.
 */


/* the library supports the subset of the MySQL 4.1+ protocol (version 10) */


#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_event.h>
#include <ngx_event_connect.h>
#include <ngx_mysql.h>
#include <ngx_sha1.h>


#define NGX_MYSQL_LONG_PASSWORD       0x0001
#define NGX_MYSQL_CONNECT_WITH_DB     0x0008
#define NGX_MYSQL_PROTOCOL_41         0x0200
#define NGX_MYSQL_SECURE_CONNECTION   0x8000


#define NGX_MYSQL_CMD_QUERY           3


typedef struct {
    u_char      pktlen[3];
    u_char      pktn;

    u_char      protocol;
    u_char      version[1];       /* NULL-terminated string */
} ngx_mysql_greeting1_pkt_t;


typedef struct {
    u_char      thread[4];
    u_char      salt1[9];
    u_char      capacity[2];
    u_char      charset;
    u_char      status[2];
    u_char      zero[13];
    u_char      salt2[13];
} ngx_mysql_greeting2_pkt_t;


typedef struct {
    u_char      pktlen[3];
    u_char      pktn;

    u_char      capacity[4];
    u_char      max_packet[4];
    u_char      charset;
    u_char      zero[23];
    u_char      login[1];        /* NULL-terminated string */

 /*
  * u_char      passwd_len;         0 if no password
  * u_char      passwd[20];
  *
  * u_char      database[1];        NULL-terminated string
  */

} ngx_mysql_auth_pkt_t;


typedef struct {
    u_char      pktlen[3];
    u_char      pktn;
    u_char      fields;
} ngx_mysql_response_pkt_t;


typedef struct {
    u_char      pktlen[3];
    u_char      pktn;
    u_char      err;
    u_char      code[2];
    u_char      message[1];        /* string */
} ngx_mysql_error_pkt_t;


typedef struct {
    u_char      pktlen[3];
    u_char      pktn;
    u_char      command;
    u_char      arg[1];            /* string */
} ngx_mysql_command_pkt_t;


static void ngx_mysql_read_server_greeting(ngx_event_t *rev);
static void ngx_mysql_empty_handler(ngx_event_t *wev);
static void ngx_mysql_read_auth_result(ngx_event_t *rev);
static void ngx_mysql_read_query_result(ngx_event_t *rev);
static void ngx_mysql_close(ngx_mysql_t *m, ngx_int_t rc);


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

    m->peer.connection->data = m;

    m->peer.connection->read->handler = ngx_mysql_read_server_greeting;
    m->peer.connection->write->handler = ngx_mysql_empty_handler;

    ngx_add_timer(m->peer.connection->read, /* STUB */ 5000);

    return NGX_OK;
}


static void
ngx_mysql_read_server_greeting(ngx_event_t *rev)
{
    size_t                      len;
    u_char                     *p;
    ssize_t                     n;
    ngx_uint_t                  i, capacity;
    ngx_mysql_t                *m;
    ngx_connection_t           *c;
    ngx_mysql_greeting1_pkt_t  *gr1;
    ngx_mysql_greeting2_pkt_t  *gr2;
    ngx_mysql_auth_pkt_t       *auth;
    ngx_sha1_t                  sha;
    u_char                      hash1[20], hash2[20];

    c = rev->data;
    m = c->data;

    if (rev->timedout) {
        ngx_log_error(NGX_LOG_ERR, rev->log, NGX_ETIMEDOUT,
                      "mysql server %V timed out", m->peer.name);

        ngx_mysql_close(m, NGX_ERROR);
        return;
    }

    if (m->buf == NULL) {
        m->peer.log->action = "reading mysql server greeting";

        m->buf = ngx_create_temp_buf(m->pool, /* STUB */ 1024);
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

    gr1 = (ngx_mysql_greeting1_pkt_t *) m->buf->pos;

    if (ngx_m24toh(gr1->pktlen) > n - 4) {
        ngx_log_error(NGX_LOG_ERR, rev->log, 0,
                      "mysql server %V sent incomplete greeting packet",
                      m->peer.name);

        ngx_mysql_close(m, NGX_ERROR);
        return;
    }

    if (gr1->protocol < 10) {
        ngx_log_error(NGX_LOG_ERR, rev->log, 0,
                      "mysql server %V sent unsupported protocol version %ud",
                      m->peer.name, gr1->protocol);

        ngx_mysql_close(m, NGX_ERROR);
        return;
    }

    gr2 = (ngx_mysql_greeting2_pkt_t *)
                                 (gr1->version + ngx_strlen(gr1->version) + 1);

    capacity = ngx_m16toh(gr2->capacity);

    ngx_log_debug8(NGX_LOG_DEBUG_MYSQL, rev->log, 0,
                   "mysql version: %ud, \"%s\", thread: %ud, salt: \"%s\", "
                   "capacity: %Xd, charset: %ud, status: %ud, salt rest \"%s\"",
                   gr1->protocol, gr1->version, ngx_m32toh(gr2->thread),
                   gr2->salt1, capacity, gr2->charset,
                   ngx_m16toh(gr2->status), &gr2->salt2);

    capacity = NGX_MYSQL_LONG_PASSWORD
               | NGX_MYSQL_CONNECT_WITH_DB
               | NGX_MYSQL_PROTOCOL_41
               | NGX_MYSQL_SECURE_CONNECTION;

    len = 4 + 4 + 4 + 1 + 23 + m->login->len + 1 + 1 + m->database->len + 1;

    if (m->passwd->len) {
        len += 20;
    }

    auth = ngx_pnalloc(m->pool, len);
    if (auth == NULL) {
        ngx_mysql_close(m, NGX_ERROR);
        return;
    }

    ngx_htom24(auth->pktlen, len - 4);
    auth->pktn = (u_char) (gr1->pktn + 1);

    ngx_htom32(auth->capacity, capacity);
    ngx_htom32(auth->max_packet, 0x01000000);  /* max packet size 2^24 */
    ngx_memzero(auth->zero, 24);
    auth->charset = gr2->charset;

    p = ngx_copy(auth->login, m->login->data, m->login->len);
    *p++ = '\0';

    if (m->passwd->len) {

        *p++ = (u_char) 20;

        ngx_sha1_init(&sha);
        ngx_sha1_update(&sha, m->passwd->data, m->passwd->len);
        ngx_sha1_final(hash1, &sha);

        ngx_sha1_init(&sha);
        ngx_sha1_update(&sha, hash1, 20);
        ngx_sha1_final(hash2, &sha);

        ngx_sha1_init(&sha);
        ngx_sha1_update(&sha, gr2->salt1, 8);
        ngx_sha1_update(&sha, gr2->salt2, 12);
        ngx_sha1_update(&sha, hash2, 20);
        ngx_sha1_final(hash2, &sha);

        for (i = 0; i < 20; i++) {
            *p++ = (u_char) (hash1[i] ^ hash2[i]);
        }

    } else {
        *p++ = '\0';
    }

    p = ngx_copy(p, m->database->data, m->database->len);
    *p = '\0';


    n = ngx_send(m->peer.connection, (void *) auth, len);

    if (n < (ssize_t) len) {
        ngx_log_error(NGX_LOG_ERR, rev->log, 0,
                      "the incomplete packet was sent to mysql server %V",
                      m->peer.name);

        ngx_mysql_close(m, NGX_ERROR);
        return;
    }

    m->peer.connection->read->handler = ngx_mysql_read_auth_result;

    ngx_add_timer(m->peer.connection->read, /* STUB */ 5000);
}


static void
ngx_mysql_empty_handler(ngx_event_t *wev)
{
    ngx_log_debug0(NGX_LOG_DEBUG_HTTP, wev->log, 0, "mysql empty handler");

    return;
}


static void
ngx_mysql_read_auth_result(ngx_event_t *rev)
{
    ssize_t                    n, len;
    ngx_str_t                  msg;
    ngx_mysql_t               *m;
    ngx_connection_t          *c;
    ngx_mysql_error_pkt_t     *epkt;
    ngx_mysql_response_pkt_t  *pkt;

    ngx_log_debug0(NGX_LOG_DEBUG_HTTP, rev->log, 0, "mysql read auth");

    c = rev->data;
    m = c->data;

    m->peer.log->action = "reading mysql auth result";

    n = ngx_recv(m->peer.connection, m->buf->pos, /* STUB */ 1024);

    if (n == NGX_AGAIN) {
        return;
    }

    if (n < 5) {
        ngx_mysql_close(m, NGX_ERROR);
        return;
    }

    pkt = (ngx_mysql_response_pkt_t *) m->buf->pos;

    len = ngx_m24toh(pkt->pktlen);

    if (len > n - 4) {
        ngx_log_error(NGX_LOG_ERR, rev->log, 0,
                      "mysql server %V sent incomplete response packet",
                      m->peer.name);

        ngx_mysql_close(m, NGX_ERROR);
        return;
    }

    if (pkt->fields == 0) {
        ngx_log_debug0(NGX_LOG_DEBUG_HTTP, rev->log, 0, "mysql auth OK");

        m->state = NGX_OK;
        m->pktn = 0;

        m->handler(m);

        return;
    }

    epkt = (ngx_mysql_error_pkt_t *) pkt;

    msg.len = (u_char *) epkt + 4 + len - epkt->message;
    msg.data = epkt->message;

    ngx_log_error(NGX_LOG_ERR, rev->log, 0,
                  "mysql server %V sent error (%ud): \"%V\"",
                  m->peer.name, ngx_m16toh(epkt->code), &msg);

    ngx_mysql_close(m, NGX_ERROR);
}


ngx_int_t
ngx_mysql_query(ngx_mysql_t *m)
{
    ssize_t                   n;
    ngx_mysql_command_pkt_t  *pkt;

    pkt = (ngx_mysql_command_pkt_t *) m->query.data;

    ngx_htom24(pkt->pktlen, m->query.len - 4);
    pkt->pktn = (u_char) m->pktn++;
    pkt->command = NGX_MYSQL_CMD_QUERY;

    n = ngx_send(m->peer.connection, m->query.data, m->query.len);

    if (n < (ssize_t) m->query.len) {
        ngx_log_error(NGX_LOG_ERR, m->peer.log, 0,
                      "the incomplete packet was sent to mysql server %V",
                      m->peer.name);

        ngx_mysql_close(m, NGX_ERROR);
        return NGX_OK;
    }

    m->peer.connection->read->handler = ngx_mysql_read_query_result;

    ngx_add_timer(m->peer.connection->read, /* STUB */ 5000);

    /* STUB handle event */

    return NGX_OK;
}


static void
ngx_mysql_read_query_result(ngx_event_t *rev)
{
    ssize_t                    n, len;
    ngx_str_t                  msg;
    ngx_mysql_t               *m;
    ngx_connection_t          *c;
    ngx_mysql_error_pkt_t     *epkt;
    ngx_mysql_response_pkt_t  *pkt;

    ngx_log_debug0(NGX_LOG_DEBUG_HTTP, rev->log, 0, "mysql read query result");

    c = rev->data;
    m = c->data;

    m->peer.log->action = "reading mysql read query result";

    n = ngx_recv(m->peer.connection, m->buf->pos, /* STUB */ 1024);

    if (n == NGX_AGAIN) {
        return;
    }

    if (n < 5) {
        ngx_mysql_close(m, NGX_ERROR);
        return;
    }

    pkt = (ngx_mysql_response_pkt_t *) m->buf->pos;

    len = ngx_m24toh(pkt->pktlen);

    if (len > n - 4) {
        ngx_log_error(NGX_LOG_ERR, rev->log, 0,
                      "mysql server %V sent incomplete response packet",
                      m->peer.name);

        ngx_mysql_close(m, NGX_ERROR);
        return;
    }

    if (pkt->fields != 0xff) {
        ngx_log_debug0(NGX_LOG_DEBUG_HTTP, rev->log, 0, "mysql query OK");

        m->state = NGX_OK;
        m->pktn = pkt->pktn;

        m->handler(m);

        return;
    }

    epkt = (ngx_mysql_error_pkt_t *) pkt;

    msg.len = (u_char *) epkt + 4 + len - epkt->message;
    msg.data = epkt->message;

    ngx_log_error(NGX_LOG_ERR, rev->log, 0,
                  "mysql server %V sent error (%ud): \"%V\"",
                  m->peer.name, ngx_m16toh(epkt->code), &msg);

    ngx_mysql_close(m, NGX_ERROR);
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
