
#include <ngx_http.h>


/* STUB */

static struct sockaddr_in  addr;
static char addr_text[22];

static ngx_http_server_t ngx_http_server;

int ngx_http_init(ngx_pool_t *pool)
{
    ngx_listen_t  *ls;

    ngx_http_server.handler = ngx_http_init_connection;

    ngx_http_server.buff_size = 1024;

    ngx_http_server.doc_root = "/home/is/work/xml/site-1.0.0/html";
    ngx_http_server.doc_root_len = strlen(server.doc_root);

    ls = ngx_push_array(ngx_listening_sockets);
    ngx_memzero(ls, sizeof(nxg_listen_t));

    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = inet_addr(optarg)
    addr.sin_port = htons(8000);

    ngx_snprintf(ngx_cpystrn(addr_text, inet_ntoa(addr.sin_addr), 16),
                 7, ":%d", ntohs(addr.sin_port));

    ls->family = AF_INET;
    ls->type = SOCK_STREAM;
    ls->protocol = 0;
    ls->addr = &addr;
    ls->addr_len = sizeof(sockaddr_in);
    ls->text = &addr_text;
    ls->backlog = -1;
    ls->nonblocking = 1;

    return 1;
}

/* */
