
/*
 * Copyright (C) Igor Sysoev
 */


#ifndef _NGX_GARBAGE_COLLECTOR_H_INCLUDED_
#define _NGX_GARBAGE_COLLECTOR_H_INCLUDED_


typedef struct ngx_gc_s  ngx_gc_t;

typedef ngx_int_t (*ngx_gc_handler_pt) (ngx_gc_t *ctx, ngx_str_t *name,
    ngx_dir_t *dir);


struct ngx_gc_s {
    ngx_path_t         *path;
    u_int               deleted;
    off_t               freed;
    ngx_gc_handler_pt   handler;
    ngx_log_t          *log;
};


ngx_int_t ngx_collect_garbage(ngx_gc_t *ctx, ngx_str_t *dname, ngx_int_t level);
ngx_int_t ngx_garbage_collector_temp_handler(ngx_gc_t *ctx, ngx_str_t *name,
    ngx_dir_t *dir);


#endif /* _NGX_GARBAGE_COLLECTOR_H_INCLUDED_ */
