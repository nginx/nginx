#ifndef _NGX_INET_H_INCLUDED_
#define _NGX_INET_H_INCLUDED_


size_t ngx_sock_ntop(int family, struct sockaddr *addr, char *text, size_t len);
size_t ngx_inet_ntop(int family, char *addr, char *text, size_t len);


#endif /* _NGX_INET_H_INCLUDED_ */
