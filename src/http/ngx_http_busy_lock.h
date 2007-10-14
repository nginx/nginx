
/*
 * Copyright (C) Igor Sysoev
 */


#ifndef _NGX_HTTP_BUSY_LOCK_H_INCLUDED_
#define _NGX_HTTP_BUSY_LOCK_H_INCLUDED_


#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_event.h>
#include <ngx_http.h>


typedef struct {
    u_char             *md5_mask;
    char               *md5;
    int                 cacheable;

    int                 busy;
    int                 max_busy;

    int                 waiting;
    int                 max_waiting;

    time_t              timeout;

    ngx_event_mutex_t  *mutex;
} ngx_http_busy_lock_t;


typedef struct {
    time_t         time;
    ngx_event_t   *event;
    void         (*event_handler)(ngx_event_t *ev);
    u_char        *md5;
    int            slot;
} ngx_http_busy_lock_ctx_t;


int ngx_http_busy_lock(ngx_http_busy_lock_t *bl, ngx_http_busy_lock_ctx_t *bc);
int ngx_http_busy_lock_cacheable(ngx_http_busy_lock_t *bl,
                                 ngx_http_busy_lock_ctx_t *bc, int lock);
void ngx_http_busy_unlock(ngx_http_busy_lock_t *bl,
                          ngx_http_busy_lock_ctx_t *bc);

char *ngx_http_set_busy_lock_slot(ngx_conf_t *cf, ngx_command_t *cmd,
                                  void *conf);


#endif /* _NGX_HTTP_BUSY_LOCK_H_INCLUDED_ */
