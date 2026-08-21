
/*
 * Copyright (C) Nginx, Inc.
 */


#ifndef _NGX_CONTROL_H_INCLUDED_
#define _NGX_CONTROL_H_INCLUDED_


#include <ngx_config.h>
#include <ngx_core.h>


ngx_int_t ngx_control_init(u_char *addr);
void ngx_control_uninit(void);
void ngx_control_close_sockets(void);
char *ngx_control_handoff(void);
void ngx_control_reown(void);
ngx_int_t ngx_control_handle_events(void);


extern ngx_uint_t  ngx_control_api_enabled;


#endif /* _NGX_CONTROL_H_INCLUDED_ */
