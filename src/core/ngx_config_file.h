#ifndef _NGX_HTTP_CONFIG_FILE_H_INCLUDED_
#define _NGX_HTTP_CONFIG_FILE_H_INCLUDED_


#include <ngx_config.h>
#include <ngx_files.h>
#include <ngx_log.h>
#include <ngx_file.h>
#include <ngx_alloc.h>
#include <ngx_hunk.h>
#include <ngx_array.h>

#define NGX_CONF_NOARGS    1
#define NGX_CONF_TAKE1     2
#define NGX_CONF_TAKE2     4

#define NGX_CONF_ITERATE   0

#define NGX_CONF_UNSET    -1


#define NGX_BLOCK_DONE     1
#define NGX_FILE_DONE      2


typedef struct {
    ngx_file_t   file;
    ngx_hunk_t  *hunk;
    int          line;
} ngx_conf_file_t;

typedef struct ngx_conf_s  ngx_conf_t;
struct ngx_conf_s {
    char             *name;
    ngx_array_t      *args;

    ngx_pool_t       *pool;
    ngx_conf_file_t  *conf_file;
    ngx_log_t        *log;

    void             *ctx;
    int             (*handler)(ngx_conf_t *cf);
};



typedef struct {
    char    *name;
    char  *(*set)();
    int      offset;
    int      zone;
    int      type;
    char    *description;
} ngx_command_t;

char *ngx_conf_set_size_slot(char *conf, int offset, char *value);
char *ngx_conf_set_time_slot(char *conf, int offset, char *value);


#endif _NGX_HTTP_CONFIG_FILE_H_INCLUDED_
