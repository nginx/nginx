
/*
 * Copyright (C) Igor Sysoev
 */


#ifndef _NGX_CORE_H_INCLUDED_
#define _NGX_CORE_H_INCLUDED_


typedef struct ngx_module_s      ngx_module_t;
typedef struct ngx_conf_s        ngx_conf_t;
typedef struct ngx_cycle_s       ngx_cycle_t;
typedef struct ngx_pool_s        ngx_pool_t;
typedef struct ngx_log_s         ngx_log_t;
typedef struct ngx_array_s       ngx_array_t;
typedef struct ngx_open_file_s   ngx_open_file_t;
typedef struct ngx_command_s     ngx_command_t;
typedef struct ngx_file_s        ngx_file_t;
typedef struct ngx_event_s       ngx_event_t;
typedef struct ngx_connection_s  ngx_connection_t;

typedef void (*ngx_event_handler_pt)(ngx_event_t *ev);



#define  NGX_OK          0
#define  NGX_ERROR      -1
#define  NGX_AGAIN      -2
#define  NGX_BUSY       -3
#define  NGX_DONE       -4
#define  NGX_DECLINED   -5
#define  NGX_ABORT      -6


#include <ngx_atomic.h>
#include <ngx_time.h>
#include <ngx_socket.h>
#include <ngx_errno.h>
#include <ngx_types.h>
#include <ngx_shared.h>
#include <ngx_process.h>
#include <ngx_thread.h>
#include <ngx_user.h>
#include <ngx_string.h>
#include <ngx_parse.h>
#include <ngx_log.h>
#include <ngx_alloc.h>
#include <ngx_palloc.h>
#include <ngx_buf.h>
#include <ngx_array.h>
#include <ngx_list.h>
#include <ngx_table.h>
#include <ngx_file.h>
#include <ngx_files.h>
#include <ngx_crc.h>
#if (HAVE_PCRE)
#include <ngx_regex.h>
#endif
#include <ngx_rbtree.h>
#include <ngx_times.h>
#include <ngx_inet.h>
#include <ngx_cycle.h>
#include <ngx_process_cycle.h>
#include <ngx_conf_file.h>
#include <ngx_os.h>
#if (NGX_OPENSSL)
#include <ngx_event_openssl.h>
#endif
#include <ngx_connection.h>


#define LF     (u_char) 10
#define CR     (u_char) 13
#define CRLF   "\x0d\x0a"


#endif /* _NGX_CORE_H_INCLUDED_ */
