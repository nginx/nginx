#ifndef _NGX_HTTP_BUSY_LOCK_H_INCLUDED_
#define _NGX_HTTP_BUSY_LOCK_H_INCLUDED_


#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>


typedef struct {
    char  *busy;
    int    busy_n;

    int    waiting_n;
    int    max_waiting;

    int    conn_n;
    int    max_conn;

    int    timeout;

 /* ngx_mutex_t  mutex; */

} ngx_http_busy_lock_t;


#endif /* _NGX_HTTP_BUSY_LOCK_H_INCLUDED_ */
