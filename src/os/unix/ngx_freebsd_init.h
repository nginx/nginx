#ifndef _NGX_FREEBSD_INIT_H_INCLUDED_
#define _NGX_FREEBSD_INIT_H_INCLUDED_


#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_log.h>
#include <sys/sysctl.h>


int ngx_os_init(ngx_log_t *log);


extern int ngx_freebsd_kern_osreldate;
extern int ngx_freebsd_hw_ncpu;
extern int ngx_freebsd_net_inet_tcp_sendspace;
extern int ngx_freebsd_sendfile_nbytes_bug;


#endif /* _NGX_FREEBSD_INIT_H_INCLUDED_ */
