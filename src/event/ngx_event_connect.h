#ifndef _NGX_EVENT_CONNECT_H_INCLUDED_
#define _NGX_EVENT_CONNECT_H_INCLUDED_


#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_event.h>


#define NGX_CONNECT_ERROR   -10


typedef struct {
    in_addr_t          addr;
    ngx_str_t          host;
    int                port;
    ngx_str_t          addr_port_text;

    int                fails;
    time_t             accessed;
} ngx_peer_t;


typedef struct {
    int                 current;
    int                 number;
    int                 max_fails;
    int                 fail_timeout;
    int                 last_cached;

 /* ngx_mutex_t        *mutex; */
    ngx_connection_t  **cached;

    ngx_peer_t          peers[1];
} ngx_peers_t;


typedef struct {
    ngx_peers_t       *peers;
    int                cur_peer;
    int                tries;

    ngx_connection_t  *connection;

    int                rcvbuf;

    ngx_log_t         *log;

    unsigned           cached:1;
    unsigned           log_error:2;  /* ngx_connection_log_error_e */
} ngx_peer_connection_t;


int ngx_event_connect_peer(ngx_peer_connection_t *pc);
void ngx_event_connect_peer_failed(ngx_peer_connection_t *pc);


#endif /* _NGX_EVENT_CONNECT_H_INCLUDED_ */
