#ifndef _NGX_FILE_H_INCLUDED_
#define _NGX_FILE_H_INCLUDED_


#include <ngx_file.h>
#include <ngx_log.h>
#include <ngx_alloc.h>
#include <ngx_string.h>

typedef struct ngx_file_s  ngx_file_t;

struct ngx_file_s {
    ngx_fd_t         fd;
    ngx_str_t        name;
    ngx_file_info_t  info;

    off_t            offset;

    ngx_log_t       *log;

    unsigned         info_valid:1;
};


typedef struct {
    ngx_str_t  name;
    int        len;
    int        level[3];
} ngx_path_t;


int ngx_create_temp_file(ngx_file_t *file, ngx_path_t *path,
                         ngx_pool_t *pool, int persistent);
void ngx_create_hashed_filename(ngx_file_t *file, ngx_path_t *path);
int ngx_create_path(ngx_file_t *file, ngx_path_t *path);

void ngx_init_temp_number();
int ngx_next_temp_number(int collision);


#endif /* _NGX_FILE_H_INCLUDED_ */
