#ifndef _NGX_CORE_H_INCLUDED_
#define _NGX_CORE_H_INCLUDED_


#include <ngx_types.h>
#include <ngx_time.h>
#include <ngx_socket.h>
#include <ngx_errno.h>
#include <ngx_process.h>

typedef struct ngx_module_s      ngx_module_t;
typedef struct ngx_conf_s        ngx_conf_t;
typedef struct ngx_open_file_s   ngx_open_file_t;;
typedef struct ngx_command_s     ngx_command_t;

typedef struct ngx_file_s        ngx_file_t;
typedef struct ngx_event_s       ngx_event_t;
typedef struct ngx_connection_s  ngx_connection_t;

#include <ngx_log.h>
#include <ngx_alloc.h>
#include <ngx_string.h>
#include <ngx_hunk.h>
#include <ngx_array.h>
#include <ngx_table.h>
#include <ngx_file.h>
#include <ngx_files.h>
#include <ngx_inet.h>
#include <ngx_conf_file.h>
#include <ngx_os_init.h>
#include <ngx_connection.h>



#define  NGX_OK          0
#define  NGX_ERROR      -1
#define  NGX_AGAIN      -2
#define  NGX_DONE       -3
/*
#define  NGX_BUSY       -3
*/
#define  NGX_DECLINED   -4
/*
#define  NGX_ALERT      -5
*/


#define LF     10
#define CR     13
#define CRLF   "\x0d\x0a"



#define NGX_MAXHOSTNAMELEN 64
/*
#define NGX_MAXHOSTNAMELEN MAXHOSTNAMELEN
*/


#if 0
/* STUB */
extern ngx_log_t  ngx_log;
#endif


#endif /* _NGX_CORE_H_INCLUDED_ */
