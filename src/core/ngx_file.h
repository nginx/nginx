
/*
 * Copyright (C) Igor Sysoev
 */


#ifndef _NGX_FILE_H_INCLUDED_
#define _NGX_FILE_H_INCLUDED_


#include <ngx_config.h>
#include <ngx_core.h>

typedef struct ngx_path_s  ngx_path_t;

#include <ngx_garbage_collector.h>


struct ngx_file_s {
    ngx_fd_t            fd;
    ngx_str_t           name;
    ngx_file_info_t     info;

    off_t               offset;
    off_t               sys_offset;

    ngx_log_t          *log;

    ngx_uint_t          valid_info;  /* unsigned  valid_info:1; */
};

#define NGX_MAX_PATH_LEVEL  3

struct ngx_path_s {
    ngx_str_t           name;
    size_t              len;
    size_t              level[3];
    ngx_gc_handler_pt   cleaner;

    u_char             *conf_file;
    ngx_uint_t          line;
};


typedef struct {
    ngx_file_t          file;
    off_t               offset;
    ngx_path_t         *path;
    ngx_pool_t         *pool;
    char               *warn;

    ngx_uint_t          access;

    unsigned            log_level:8;
    unsigned            persistent:1;
    unsigned            clean:1;
} ngx_temp_file_t;


typedef struct ngx_tree_ctx_s  ngx_tree_ctx_t;

typedef ngx_int_t (*ngx_tree_init_handler_pt) (void *ctx, void *prev);
typedef ngx_int_t (*ngx_tree_handler_pt) (ngx_tree_ctx_t *ctx, ngx_str_t *name);

struct ngx_tree_ctx_s {
    off_t                      size;
    ngx_uint_t                 access;
    time_t                     mtime;

    ngx_tree_init_handler_pt   init_handler;
    ngx_tree_handler_pt        file_handler;
    ngx_tree_handler_pt        pre_tree_handler;
    ngx_tree_handler_pt        post_tree_handler;
    ngx_tree_handler_pt        spec_handler;

    void                      *data;
    size_t                     alloc;

    ngx_log_t                 *log;
};


ssize_t ngx_write_chain_to_temp_file(ngx_temp_file_t *tf, ngx_chain_t *chain);
ngx_int_t ngx_create_temp_file(ngx_file_t *file, ngx_path_t *path,
    ngx_pool_t *pool, ngx_uint_t persistent, ngx_uint_t clean,
    ngx_uint_t access);
void ngx_create_hashed_filename(ngx_file_t *file, ngx_path_t *path);
ngx_int_t ngx_create_path(ngx_file_t *file, ngx_path_t *path);
ngx_err_t ngx_create_full_path(u_char *dir, ngx_uint_t access);
ngx_int_t ngx_add_path(ngx_conf_t *cf, ngx_path_t **slot);
ngx_int_t ngx_create_pathes(ngx_cycle_t *cycle, ngx_uid_t user);
ngx_int_t ngx_walk_tree(ngx_tree_ctx_t *ctx, ngx_str_t *tree);

void ngx_init_temp_number(void);
ngx_atomic_uint_t ngx_next_temp_number(ngx_uint_t collision);

char *ngx_conf_set_path_slot(ngx_conf_t *cf, ngx_command_t *cmd, void *conf);
char *ngx_conf_set_access_slot(ngx_conf_t *cf, ngx_command_t *cmd, void *conf);


#define ngx_conf_merge_path_value(curr, prev, path, l1, l2, l3, clean, cf)    \
    if (curr == NULL) {                                                       \
        if (prev == NULL) {                                                   \
            curr = ngx_palloc(cf->pool, sizeof(ngx_path_t));                  \
            if (curr == NULL) {                                               \
                return NGX_CONF_ERROR;                                        \
            }                                                                 \
                                                                              \
            curr->name.len = sizeof(path) - 1;                                \
            curr->name.data = (u_char *) path;                                \
                                                                              \
            if (ngx_conf_full_name(cf->cycle, &curr->name) == NGX_ERROR) {    \
                return NGX_CONF_ERROR;                                        \
            }                                                                 \
                                                                              \
            curr->level[0] = l1;                                              \
            curr->level[1] = l2;                                              \
            curr->level[2] = l3;                                              \
            curr->len = l1 + l2 + l3 + (l1 ? 1:0) + (l2 ? 1:0) + (l3 ? 1:0);  \
            curr->cleaner = clean;                                            \
            curr->conf_file = NULL;                                           \
                                                                              \
            if (ngx_add_path(cf, &curr) == NGX_ERROR) {                       \
                return NGX_CONF_ERROR;                                        \
            }                                                                 \
                                                                              \
        } else {                                                              \
            curr = prev;                                                      \
        }                                                                     \
    }



#endif /* _NGX_FILE_H_INCLUDED_ */
