#ifndef _NGX_HTTP_CACHE_H_INCLUDED_
#define _NGX_HTTP_CACHE_H_INCLUDED_


#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>


typedef struct {
    uint32_t       crc;
    ngx_str_t      key;
    time_t         accessed;

    unsigned       refs:20;    /* 1048576 references */
    unsigned       count:2;    /* lazy allocation: the 4 uses */
    unsigned       deleted:1;

    ngx_fd_t       fd;
    time_t         last_modified;
    time_t         updated;

    union {
        off_t      size;
        ngx_str_t  value;
    } data;
} ngx_http_cache_t;


typedef struct {
    time_t       expires;
    time_t       last_modified;
    time_t       date;
    off_t        length;
    size_t       key_len;
    char         key[1];
} ngx_http_cache_header_t;


#define NGX_HTTP_CACHE_HASH   7
#define NGX_HTTP_CACHE_NELTS  4

typedef struct {
    ngx_http_cache_t         *elts;
    size_t                    hash;
    size_t                    nelts;
    time_t                    life_time;
    time_t                    check_time;
    ngx_pool_t               *pool;
} ngx_http_cache_hash_t;


typedef struct {
    ngx_http_cache_hash_t    *hash;
    ngx_http_cache_t         *cache;
    ngx_file_t                file;
    ngx_str_t                 key;
    uint32_t                  crc;
    u_char                    md5[16];
    ngx_path_t               *path;
    ngx_hunk_t               *buf;
    time_t                    expires;
    time_t                    last_modified;
    time_t                    date;
    off_t                     length;
    ssize_t                   header_size;
    size_t                    file_start;
    ngx_log_t                *log;
} ngx_http_cache_ctx_t;


typedef struct {
    ngx_http_cache_hash_t    *open_files;
} ngx_http_cache_conf_t;


#define NGX_HTTP_CACHE_STALE     1
#define NGX_HTTP_CACHE_AGED      2
#define NGX_HTTP_CACHE_THE_SAME  3


int ngx_http_cache_get_file(ngx_http_request_t *r, ngx_http_cache_ctx_t *ctx);
int ngx_http_cache_open_file(ngx_http_cache_ctx_t *ctx, ngx_file_uniq_t uniq);
int ngx_http_cache_update_file(ngx_http_request_t *r,ngx_http_cache_ctx_t *ctx,
                               ngx_str_t *temp_file);

ngx_http_cache_t *ngx_http_cache_get(ngx_http_cache_hash_t *cache,
                                     ngx_str_t *key, uint32_t *crc);
ngx_http_cache_t *ngx_http_cache_alloc(ngx_http_cache_hash_t *cache,
                                       ngx_str_t *key, uint32_t crc,
                                       ngx_log_t *log);

int ngx_garbage_collector_http_cache_handler(ngx_gc_t *gc, ngx_str_t *name,
                                             ngx_dir_t *dir);

extern ngx_module_t  ngx_http_cache_module;



#endif /* _NGX_HTTP_CACHE_H_INCLUDED_ */
