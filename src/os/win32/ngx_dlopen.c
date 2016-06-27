
/*
 * Copyright (C) Maxim Dounin
 * Copyright (C) Nginx, Inc.
 */


#include <ngx_config.h>
#include <ngx_core.h>


char *
ngx_dlerror(void)
{
    u_char         *p;
    static u_char   errstr[NGX_MAX_ERROR_STR];

    p = ngx_strerror(ngx_errno, errstr, NGX_MAX_ERROR_STR);
    *p = '\0';

    return (char *) errstr;
}
