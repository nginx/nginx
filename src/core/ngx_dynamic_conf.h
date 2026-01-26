
/*
 * Copyright (C) Roman Arutyunyan
 * Copyright (C) Nginx, Inc.
 */


#ifndef _NGX_DYNAMIC_CONF_H_INCLUDED_
#define _NGX_DYNAMIC_CONF_H_INCLUDED_


#include <ngx_config.h>
#include <ngx_core.h>
#include <nginx.h>


ngx_int_t ngx_dynamic_conf_update(ngx_cycle_t *cycle);
void ngx_dynamic_conf_reopen_files(ngx_cycle_t *cycle);


#endif /* _NGX_DYNAMIC_CONF_H_INCLUDED_ */
