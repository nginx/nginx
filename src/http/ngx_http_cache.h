#ifndef _NGX_HTTP_CACHE_H_INCLUDED_
#define _NGX_HTTP_CACHE_H_INCLUDED_


#include <ngx_config.h>
#include <ngx_core.h>


typedef struct {
    time_t       expires;
    time_t       last_modified;
    off_t        length;
} ngx_http_cache_header_t;


typedef struct {
    ngx_http_cache_header_t  header;
    size_t                   key_len;
    char                     key[0];
} ngx_http_cache_file_t;


typedef struct {
    u_int32_t    crc;
    ngx_str_t    key;
    ngx_fd_t     fd;
    off_t        size;
    void        *data;          /* mmap, memory */
    time_t       accessed;
    time_t       last_modified;
    time_t       updated;      /* no needed with kqueue */
    int          refs;
    int          flags;
} ngx_http_cache_entry_t;


typedef struct {
    ngx_file_t                file;
    ngx_str_t                 key;
    ngx_path_t               *path;
    ngx_hunk_t               *buf;
    ngx_http_cache_header_t   header;
    ssize_t                   header_size;
} ngx_http_cache_ctx_t;


#define NGX_STALE  1


int ngx_http_cache_get_file(ngx_http_request_t *r, ngx_http_cache_ctx_t *ctx);
int ngx_http_cache_update_file(ngx_http_request_t *r,ngx_http_cache_ctx_t *ctx,
                               ngx_str_t *temp_file);



#endif /* _NGX_HTTP_CACHE_H_INCLUDED_ */
