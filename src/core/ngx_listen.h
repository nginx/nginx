#ifndef _NGX_LISTEN_H_INCLUDED_
#define _NGX_LISTEN_H_INCLUDED_


ngx_socket_t ngx_listen(struct sockaddr *addr, int backlog,
                        ngx_log_t *log, char *addr_text);


#endif /* _NGX_LISTEN_H_INCLUDED_ */
