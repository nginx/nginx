#ifndef _NGX_HTTP_CONF_FILE_H_INCLUDED_
#define _NGX_HTTP_CONF_FILE_H_INCLUDED_


#include <ngx_config.h>
#include <ngx_files.h>
#include <ngx_log.h>
#include <ngx_file.h>
#include <ngx_string.h>
#include <ngx_alloc.h>
#include <ngx_hunk.h>
#include <ngx_array.h>


#define NGX_CONF_NOARGS      1
#define NGX_CONF_TAKE1       2
#define NGX_CONF_TAKE2       4
#define NGX_CONF_ARGS_NUMBER 0x00ffff
#define NGX_CONF_ANY         0x010000
#define NGX_CONF_BLOCK       0x020000
#define NGX_CONF_FLAG        0x040000


#define NGX_CONF_UNSET       -1


#define NGX_CONF_OK          NULL
#define NGX_CONF_ERROR       (void *) -1

#define NGX_CONF_BLOCK_DONE  1
#define NGX_CONF_FILE_DONE   2


#define NGX_CORE_MODULE_TYPE 0x45524F43  /* "CORE" */
#define NGX_CONF_MODULE_TYPE 0x464E4F43  /* "CONF" */


typedef struct ngx_conf_s  ngx_conf_t;


typedef struct ngx_command_s  ngx_command_t;
struct ngx_command_s {
    ngx_str_t  name;
    int        type;
    char    *(*set)(ngx_conf_t *cf, ngx_command_t *cmd, char *conf);
    int        conf;
    int        offset;
    void      *bounds;
};


typedef struct {
    int             index;
    void           *ctx;
    ngx_command_t  *commands;
    int             type;
    int           (*init_module)(ngx_pool_t *p);
} ngx_module_t;


typedef struct {
    ngx_file_t   file;
    ngx_hunk_t  *hunk;
    int          line;
} ngx_conf_file_t;


struct ngx_conf_s {
    char             *name;
    ngx_array_t      *args;

    ngx_pool_t       *pool;
    ngx_conf_file_t  *conf_file;
    ngx_log_t        *log;

    void             *ctx;
    int               type;
    char           *(*handler)(ngx_conf_t *cf);
};


#define ngx_conf_merge(conf, prev, default)                                  \
    if (conf == NGX_CONF_UNSET) {                                            \
        conf = (prev == NGX_CONF_UNSET) ? default : prev;                    \
    }


#define ngx_conf_size_merge(conf, prev, default)                             \
    if (conf == (size_t) NGX_CONF_UNSET) {                                   \
        conf = (prev == (size_t) NGX_CONF_UNSET) ? default : prev;           \
    }


#define addressof(addr)  ((int) &addr)


char *ngx_conf_parse(ngx_conf_t *cf, ngx_str_t *filename);


char *ngx_conf_set_flag_slot(ngx_conf_t *cf, ngx_command_t *cmd, char *conf);
char *ngx_conf_set_str_slot(ngx_conf_t *cf, ngx_command_t *cmd, char *conf);
char *ngx_conf_set_size_slot(ngx_conf_t *cf, ngx_command_t *cmd, char *conf);
char *ngx_conf_set_msec_slot(ngx_conf_t *cf, ngx_command_t *cmd, char *conf);
char *ngx_conf_set_time_slot(ngx_conf_t *cf, ngx_command_t *cmd, char *conf);


extern ngx_module_t *ngx_modules[];


#endif /* _NGX_HTTP_CONF_FILE_H_INCLUDED_ */
