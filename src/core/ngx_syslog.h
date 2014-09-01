
/*
 * Copyright (C) Nginx, Inc.
 */


#ifndef _NGX_SYSLOG_H_INCLUDED_
#define _NGX_SYSLOG_H_INCLUDED_


typedef struct {
    ngx_pool_t       *pool;
    ngx_uint_t        facility;
    ngx_uint_t        severity;
    ngx_str_t         tag;

    ngx_addr_t        server;
    ngx_connection_t  conn;
    ngx_uint_t        busy;  /* unsigned busy:1; */
} ngx_syslog_peer_t;


char *ngx_syslog_process_conf(ngx_conf_t *cf, ngx_syslog_peer_t *peer);
u_char *ngx_syslog_add_header(ngx_syslog_peer_t *peer, u_char *buf);
void ngx_syslog_writer(ngx_log_t *log, ngx_uint_t level, u_char *buf,
    size_t len);
ssize_t ngx_syslog_send(ngx_syslog_peer_t *peer, u_char *buf, size_t len);


#endif /* _NGX_SYSLOG_H_INCLUDED_ */
