
/*
 * Copyright (C) Maxim Dounin
 * Copyright (C) Nginx, Inc.
 */


#ifndef _NGX_DLOPEN_H_INCLUDED_
#define _NGX_DLOPEN_H_INCLUDED_


#include <ngx_config.h>
#include <ngx_core.h>


#define ngx_dlopen(path)           dlopen((char *) path, RTLD_NOW | RTLD_GLOBAL)
#define ngx_dlopen_n               "dlopen()"

#define ngx_dlsym(handle, symbol)  dlsym(handle, symbol)
#define ngx_dlsym_n                "dlsym()"

#define ngx_dlclose(handle)        dlclose(handle)
#define ngx_dlclose_n              "dlclose()"


#if (NGX_HAVE_DLOPEN)
char *ngx_dlerror(void);
#endif


#endif /* _NGX_DLOPEN_H_INCLUDED_ */
