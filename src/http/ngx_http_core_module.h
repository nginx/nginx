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
    ngx_array_t          handlers;
    int                  type;                /* NGX_OK, NGX_DECLINED */
    ngx_http_handler_pt  post_handler;
} ngx_http_phase_t;

#define NGX_HTTP_REWRITE_PHASE    0
#define NGX_HTTP_TRANSLATE_PHASE  1
#define NGX_HTTP_LAST_PHASE       2

typedef struct {
    ngx_array_t       servers;         /* array of ngx_http_core_srv_conf_t */

    ngx_http_phase_t  phases[NGX_HTTP_LAST_PHASE];
    ngx_array_t       index_handlers;
} ngx_http_core_main_conf_t;


typedef struct {
    ngx_array_t  locations;    /* array of ngx_http_core_loc_conf_t,
                                  used in the translation handler
                                  and in the merge phase */

    ngx_array_t  listen;       /* 'listen', array of ngx_http_listen_t */
    ngx_array_t  server_names; /* 'server_name',
                                  array of ngx_http_server_name_t */

    ngx_http_conf_ctx_t *ctx;  /* server ctx */

    ngx_msec_t   post_accept_timeout;
    ssize_t      connection_pool_size;
    ssize_t      request_pool_size;
    ngx_msec_t   client_header_timeout;
    ssize_t      client_header_buffer_size;
    int          large_client_header;
} ngx_http_core_srv_conf_t;


/* list of structures to find core_srv_conf quickly at run time */

typedef struct {
    int           port;
    ngx_str_t     port_name;
    ngx_array_t   addrs;       /* array of ngx_http_in_addr_t */
} ngx_http_in_port_t;


typedef struct {
    u_int32_t                  addr;
    ngx_array_t                names;     /* array of ngx_http_server_name_t */
    ngx_http_core_srv_conf_t  *core_srv_conf;  /* default server conf
                                                  for this address:port */
    int                        flags;
} ngx_http_in_addr_t;

/* ngx_http_in_addr_t's flags */
#define NGX_HTTP_DEFAULT_SERVER  1


typedef struct {
    ngx_str_t                  name;
    ngx_http_core_srv_conf_t  *core_srv_conf; /* virtual name server conf */
} ngx_http_server_name_t;


#define NGX_HTTP_TYPES_HASH_PRIME  13

#define ngx_http_types_hash_key(key, ext)                                   \
        {                                                                   \
            u_int n;                                                        \
            for (key = 0, n = 0; n < ext.len; n++) {                        \
                key += ext.data[n];                                         \
            }                                                               \
            key %= NGX_HTTP_TYPES_HASH_PRIME;                               \
        }

typedef struct {
    ngx_str_t  exten;
    ngx_str_t  type;
} ngx_http_type_t;


typedef struct {
    ngx_str_t     name;          /* location name */
    void        **loc_conf ;     /* pointer to the modules' loc_conf */

    int         (*handler) (ngx_http_request_t *r);

    ngx_str_t     doc_root;                /* root */

    ngx_array_t  *types;
    ngx_str_t     default_type;

    ngx_msec_t    client_body_timeout;     /* client_body_timeout */
    int           sendfile;                /* sendfile */
    ngx_msec_t    send_timeout;            /* send_timeout */
    ssize_t       send_lowat;              /* send_lowat */
    ssize_t       discarded_buffer_size;   /* discarded_buffer_size */
    ngx_msec_t    keepalive_timeout;       /* keepalive_timeout */
    ngx_msec_t    lingering_time;          /* lingering_time */
    ngx_msec_t    lingering_timeout;       /* lingering_timeout */

    int           msie_padding;            /* msie_padding */

    ngx_log_t    *err_log;
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



int ngx_http_find_location_config(ngx_http_request_t *r);
int ngx_http_core_translate_handler(ngx_http_request_t *r);

int ngx_http_internal_redirect(ngx_http_request_t *r,
                               ngx_str_t *uri, ngx_str_t *args);
int ngx_http_error(ngx_http_request_t *r, int error);


#endif /* _NGX_HTTP_CORE_H_INCLUDED_ */
