
/*
 * Copyright (C) Igor Sysoev
 */


#ifndef _NGX_TYPES_H_INCLUDED_
#define _NGX_TYPES_H_INCLUDED_


#include <ngx_config.h>
#include <ngx_core.h>


typedef HANDLE                      ngx_fd_t;
typedef BY_HANDLE_FILE_INFORMATION  ngx_file_info_t;
typedef uint64_t                    ngx_file_uniq_t;

typedef struct {
    HANDLE            dir;
    WIN32_FIND_DATA   fd;
    unsigned          info_valid;
    unsigned          ready;
} ngx_dir_t;


#endif /* _NGX_TYPES_H_INCLUDED_ */
