#ifndef _NGX_OS_INIT_H_INCLUDED_
#define _NGX_OS_INIT_H_INCLUDED_


#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_log.h>
#include <sys/sysctl.h>


int ngx_os_init(ngx_log_t *log);


extern int freebsd_kern_osreldate;
extern int freebsd_hw_ncpu;


#endif /* _NGX_OS_INIT_H_INCLUDED_ */
