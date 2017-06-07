
/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) Nginx, Inc.
 */


#ifndef _NGX_PALLOC_H_INCLUDED_
#define _NGX_PALLOC_H_INCLUDED_


#include <ngx_config.h>
#include <ngx_core.h>


/*
 * NGX_MAX_ALLOC_FROM_POOL should be (ngx_pagesize - 1), i.e. 4095 on x86.
 * On Windows NT it decreases a number of locked pages in a kernel.
 */
#define NGX_MAX_ALLOC_FROM_POOL  (ngx_pagesize - 1)

#define NGX_DEFAULT_POOL_SIZE    (16 * 1024)

#define NGX_POOL_ALIGNMENT       16
#define NGX_MIN_POOL_SIZE                                                     \
    ngx_align((sizeof(ngx_pool_t) + 2 * sizeof(ngx_pool_large_t)),            \
              NGX_POOL_ALIGNMENT)


typedef void (*ngx_pool_cleanup_pt)(void *data);

typedef struct ngx_pool_cleanup_s  ngx_pool_cleanup_t;

struct ngx_pool_cleanup_s {
    ngx_pool_cleanup_pt   handler; //回调函数指针
    void                 *data; //指向要清除的数据,回调时，将此数据传入回调函数
    ngx_pool_cleanup_t   *next; //下一个cleanup callback
};


typedef struct ngx_pool_large_s  ngx_pool_large_t;
//大内存结构
struct ngx_pool_large_s {
    ngx_pool_large_t     *next; //下一个大块内存
    void                 *alloc; //nginx分配的大块内存空间
};


typedef struct {
    u_char               *last; //所管理的内存block中已使用的内存的末尾地址，这也是下次分配的起始地址
    u_char               *end; //所管理的内存block的尾地址，该指针在分配此block时确定，用来标记last的边界值
    ngx_pool_t           *next; //指向下一个ngx_pool_data_t的内存block地址，用于形成block链表
    ngx_uint_t            failed; //标记该block使用时分配失败次数
} ngx_pool_data_t;


struct ngx_pool_s {
    ngx_pool_data_t       d; //数据块
    size_t                max; //数据块大小，即小块内存的最大值
    ngx_pool_t           *current; //链表中当前正在使用的节点
    ngx_chain_t          *chain; //可以挂一个chain结构
    ngx_pool_large_t     *large; //分配大块内存用，即超过max的内存请求
    ngx_pool_cleanup_t   *cleanup; //释放内存池的callback
    ngx_log_t            *log;
};


typedef struct {
    ngx_fd_t              fd;
    u_char               *name;
    ngx_log_t            *log;
} ngx_pool_cleanup_file_t;


ngx_pool_t *ngx_create_pool(size_t size, ngx_log_t *log);
void ngx_destroy_pool(ngx_pool_t *pool);
void ngx_reset_pool(ngx_pool_t *pool);

void *ngx_palloc(ngx_pool_t *pool, size_t size);
void *ngx_pnalloc(ngx_pool_t *pool, size_t size);
void *ngx_pcalloc(ngx_pool_t *pool, size_t size);
void *ngx_pmemalign(ngx_pool_t *pool, size_t size, size_t alignment);
ngx_int_t ngx_pfree(ngx_pool_t *pool, void *p);


ngx_pool_cleanup_t *ngx_pool_cleanup_add(ngx_pool_t *p, size_t size);
void ngx_pool_run_cleanup_file(ngx_pool_t *p, ngx_fd_t fd);
void ngx_pool_cleanup_file(void *data);
void ngx_pool_delete_file(void *data);


#endif /* _NGX_PALLOC_H_INCLUDED_ */
