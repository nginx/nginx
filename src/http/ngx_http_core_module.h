#ifndef _NGX_HTTP_CORE_H_INCLUDED_
#define _NGX_HTTP_CORE_H_INCLUDED_


#include <ngx_string.h>
#include <ngx_array.h>
#include <ngx_http.h>


typedef struct {
    u_int32_t  addr;
    int        port;
    int        family;
    int        flags;             /* 'default' */
    ngx_str_t  file_name;
    int        line;
} ngx_http_listen_t;


typedef struct {
    ngx_array_t  locations;    /* array of ngx_http_core_loc_conf_t */

    ngx_array_t  listen;       /* 'listen', array of ngx_http_listen_t */
    ngx_array_t  server_names; /* 'server_name',
                                  array of ngx_http_server_name_t */
    ngx_http_conf_ctx_t *ctx;  /* server ctx */
} ngx_http_core_srv_conf_t;


/* list of structures to find core_srv_conf quickly at run time */

typedef struct {
    int           port;
    ngx_array_t   addr;        /* array of ngx_http_in_addr_t */
} ngx_http_in_port_t;

typedef struct {
    u_int32_t                  addr;
    ngx_array_t                names;     /* array of ngx_http_server_name_t */
    ngx_http_core_srv_conf_t  *core_srv_conf;  /* default server conf
                                                  for this address:port */
    int                        flags;    
} ngx_http_in_addr_t;

#define NGX_HTTP_DEFAULT_SERVER  1

typedef struct {
    ngx_str_t                  name;
    ngx_http_core_srv_conf_t  *core_srv_conf; /* virtual name server conf */
} ngx_http_server_name_t;




typedef struct {
    ngx_str_t   name;          /* location name */
    void      **loc_conf;      /* pointer to modules loc_conf,
                                  used in translation handler */

    int       (*handler) (ngx_http_request_t *r);

    ngx_str_t   doc_root;                /* root */

    int         sendfile;                /* sendfile */
    time_t      send_timeout;            /* send_timeout */
    size_t      send_lowat;              /* send_lowa */
    size_t      discarded_buffer_size;   /* discarded_buffer_size */
    time_t      lingering_time;          /* lingering_time */
    ngx_msec_t  lingering_timeout;       /* lingering_timeout */

} ngx_http_core_loc_conf_t;




#if 0
typedef struct {
    int dummy;
} ngx_http_core_conf_t;
#endif


#if 0
#define ngx_http_set_loc_handler(conf_ctx, ngx_http_handler)                  \
    {                                                                         \
        ngx_http_conf_ctx_t       *cx = conf_ctx;                             \
        ngx_http_core_loc_conf_t  *lcf;                                       \
        lcf = cx->loc_conf[ngx_http_core_module_ctx.index];                   \
        lcf->handler = ngx_http_handler;                                      \
    }
#endif


extern ngx_http_module_t  ngx_http_core_module_ctx;
extern ngx_module_t  ngx_http_core_module;

extern int ngx_http_max_module;



int ngx_http_core_translate_handler(ngx_http_request_t *r);

int ngx_http_internal_redirect(ngx_http_request_t *r, ngx_str_t uri);
int ngx_http_error(ngx_http_request_t *r, int error);


#endif /* _NGX_HTTP_CORE_H_INCLUDED_ */
