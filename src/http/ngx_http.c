
#include <ngx_config.h>
#include <ngx_string.h>
#include <ngx_socket.h>
#include <ngx_listen.h>
#include <ngx_http.h>
#include <ngx_http_config.h>

extern ngx_array_t *ngx_listening_sockets;

/* STUB */

static struct sockaddr_in  addr;
static char addr_text[22];

static ngx_http_server_t ngx_http_server;

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

    ls = ngx_push_array(ngx_listening_sockets);
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
#endif
    ls->sockaddr = (struct sockaddr *) &addr;
    ls->socklen = sizeof(struct sockaddr_in);
    ls->addr = offsetof(struct sockaddr_in, sin_addr);
    ls->addr_text.len = INET_ADDRSTRLEN;
    ls->addr_text.data = addr_text;
    ls->backlog = -1;
    ls->post_accept_timeout = 10000;
    ls->nonblocking = 1;

    ls->handler = ngx_http_init_connection;
    ls->server = &ngx_http_server;
    ls->log = log;


    return 1;
}

/* */
