#ifndef _NGX_FILE_H_INCLUDED_
#define _NGX_FILE_H_INCLUDED_


#include <ngx_files.h>
#include <ngx_log.h>

typedef struct ngx_file_s  ngx_file_t;

struct ngx_file_s {
    ngx_fd_t      fd;
    ngx_log_t    *log;
};


#endif _NGX_FILE_H_INCLUDED_
