#ifndef _NGX_FILE_H_INCLUDED_
#define _NGX_FILE_H_INCLUDED_


#include <ngx_files.h>
#include <ngx_log.h>
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


#endif _NGX_FILE_H_INCLUDED_
