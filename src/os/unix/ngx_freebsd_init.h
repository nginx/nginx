#ifndef _NGX_FREEBSD_INIT_H_INCLUDED_
#define _NGX_FREEBSD_INIT_H_INCLUDED_


#include <ngx_config.h>
#include <ngx_core.h>
#include <sys/sysctl.h>


/* STUB */
int ngx_posix_init(ngx_log_t *log);
ssize_t ngx_unix_recv(ngx_connection_t *c, char *buf, size_t size);
ssize_t ngx_readv_chain(ngx_connection_t *c, ngx_chain_t *entry);
/* */


extern int ngx_freebsd_kern_osreldate;
extern int ngx_freebsd_hw_ncpu;
extern int ngx_freebsd_net_inet_tcp_sendspace;
extern int ngx_freebsd_sendfile_nbytes_bug;


#endif /* _NGX_FREEBSD_INIT_H_INCLUDED_ */
