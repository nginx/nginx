#ifndef _NGX_CONNECTION_H_INCLUDED_
#define _NGX_CONNECTION_H_INCLUDED_


#include <ngx_config.h>
#include <ngx_core.h>


typedef struct {
    ngx_socket_t      fd;

    struct sockaddr  *sockaddr;
    socklen_t         socklen;    /* size of sockaddr */
    int               addr;       /* offset to address in sockaddr */
    int               addr_text_max_len;
    ngx_str_t         addr_text;

    int               family;
    int               type;
    int               protocol;
    int               flags;      /* Winsock2 flags */

    void            (*handler)(ngx_connection_t *c); /* handler of accepted
                                                        connection */
    void             *ctx;        /* ngx_http_conf_ctx_t, for example */
    void             *servers;    /* array of ngx_http_in_addr_t, for example */

    ngx_log_t        *log;
    int               backlog;

    int               pool_size;
    int               post_accept_buffer_size; /* should be here because
                                                  of the AcceptEx() preread */
    time_t            post_accept_timeout;     /* should be here because
                                                  of the deferred accept */

    unsigned          new:1;
    unsigned          remain:1;

    unsigned          bound:1;       /* already bound */
    unsigned          inherited:1;   /* inherited from previous process */
    unsigned          nonblocking_accept:1;
    unsigned          nonblocking:1;
#if 0
    unsigned          overlapped:1;  /* Winsock2 overlapped */
#endif
    unsigned          shared:1;    /* shared between threads or processes */
#if (HAVE_DEFERRED_ACCEPT)
    unsigned          deferred_accept:1;
#endif
} ngx_listening_t;


struct ngx_connection_s {
    void             *data;
    ngx_event_t      *read;
    ngx_event_t      *write;

    ngx_socket_t      fd;

    ngx_listening_t  *listening;

    off_t             sent;

#if 0
    void            (*handler)(ngx_connection_t *c);
#endif
    void             *ctx;
    void             *servers;


    ngx_log_t        *log;

    ngx_pool_t       *pool;
#if 0
    int               pool_size;

    int               family;
#endif

    struct sockaddr  *sockaddr;
    socklen_t         socklen;
    ngx_str_t         addr_text;

#if (HAVE_IOCP)
    struct sockaddr  *local_sockaddr;
    socklen_t         local_socklen;
#endif

#if 0
    int               addr;
    int               addr_text_max_len;
#endif

    ngx_hunk_t       *buffer;
#if 0
    unsigned int      post_accept_timeout;
#endif

    int               number;

    unsigned          pipeline:1;
    unsigned          unexpected_eof:1;
    unsigned          tcp_nopush:1;
    unsigned          tcp_nopush_enabled:1;
#if (HAVE_IOCP)
    unsigned          accept_context_updated:1;
#endif
};





#if 0
cached file
    int      fd;       -2 unused, -1 closed (but read or mmaped), >=0 open
    char    *name;

    void    *buf;      addr if read or mmaped
                       aiocb* if aio_read
                       OVERLAPPED if TransmitFile or TransmitPackets
                       NULL if sendfile

    size_t   buf_size; for plain read
    off_t    offset;   for plain read

    size_t   size;
    time_t   mod;
    char    *last_mod; "Sun, 17 Mar 2002 19:39:50 GMT"
    char    *etag;     ""a6d08-1302-3c94f106""
    char    *len;      "4866"

EV_VNODE        should notify by some signal if diretory tree is changed
                or stat if aged >= N seconds (big enough)
#endif


#if 0
typedef struct {
    ssize_t       (*recv)(ngx_connection_t *c, char *buf, size_t size);
    void           *dummy_recv_chain;
    void           *dummy_send;
    ngx_chain_t  *(*send_chain)(ngx_connection_t *c, ngx_chain_t *in);
} ngx_os_io_t;
#endif



extern ngx_array_t  ngx_listening_sockets;
extern ngx_os_io_t  ngx_io;


extern ngx_chain_t *(*ngx_write_chain_proc)
                                        (ngx_connection_t *c, ngx_chain_t *in);


ssize_t ngx_recv_chain(ngx_connection_t *c, ngx_chain_t *ce);
#if 0
ngx_chain_t *ngx_write_chain(ngx_connection_t *c, ngx_chain_t *in, off_t flush);
#endif


/* TODO: move it to OS specific file */
#if (__FreeBSD__)
ngx_chain_t *ngx_aio_write_chain(ngx_connection_t *c, ngx_chain_t *in);
#endif


#endif /* _NGX_CONNECTION_H_INCLUDED_ */
