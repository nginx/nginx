
/*
 * Copyright (C) Igor Sysoev
 */


#ifndef _NGX_AIO_MODULE_H_INCLUDED_
#define _NGX_AIO_MODULE_H_INCLUDED_


#include <ngx_types.h>
#include <ngx_log.h>
#include <ngx_event.h>


int ngx_aio_init(int max_connections, ngx_log_t *log);
int ngx_aio_process_events(ngx_log_t *log);


#endif /* _NGX_AIO_MODULE_H_INCLUDED_ */
