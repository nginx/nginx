#ifndef _NGX_KQUEUE_MODULE_H_INCLUDED_
#define _NGX_KQUEUE_MODULE_H_INCLUDED_


typedef struct {
    int   changes;
    int   events;
} ngx_kqueue_conf_t;


extern int  ngx_kqueue;
/* STUB */ extern ngx_event_module_t  ngx_kqueue_module_ctx;



#endif /* _NGX_KQUEUE_MODULE_H_INCLUDED_ */
