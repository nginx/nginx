
/*
 * Copyright (C) Igor Sysoev
 */


#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>


/* AF_INET only */

typedef struct {
    in_addr_t     mask;
    in_addr_t     addr;
} ngx_http_realip_from_t;


typedef struct {
    ngx_array_t  *from;     /* array of ngx_http_realip_from_t */

    ngx_uint_t    xfwd;
} ngx_http_realip_loc_conf_t;


static ngx_int_t ngx_http_realip_handler(ngx_http_request_t *r);
static char *ngx_http_realip_from(ngx_conf_t *cf, ngx_command_t *cmd,
    void *conf);
static void *ngx_http_realip_create_loc_conf(ngx_conf_t *cf);
static char *ngx_http_realip_merge_loc_conf(ngx_conf_t *cf,
    void *parent, void *child);
static ngx_int_t ngx_http_realip_init(ngx_conf_t *cf);


static ngx_conf_enum_t  ngx_http_realip_header[] = {
    { ngx_string("X-Forwarded-For"), 1 },
    { ngx_string("X-Real-IP"), 0 },
    { ngx_null_string, 0 }
};


static ngx_command_t  ngx_http_realip_commands[] = {

    { ngx_string("set_real_ip_from"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
      ngx_http_realip_from,
      NGX_HTTP_LOC_CONF_OFFSET,
      0,
      NULL },

    { ngx_string("real_ip_header"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_enum_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_realip_loc_conf_t, xfwd),
      &ngx_http_realip_header },

      ngx_null_command
};



static ngx_http_module_t  ngx_http_realip_module_ctx = {
    NULL,                                  /* preconfiguration */
    ngx_http_realip_init,                  /* postconfiguration */

    NULL,                                  /* create main configuration */
    NULL,                                  /* init main configuration */

    NULL,                                  /* create server configuration */
    NULL,                                  /* merge server configuration */

    ngx_http_realip_create_loc_conf,       /* create location configuration */
    ngx_http_realip_merge_loc_conf         /* merge location configuration */
};


ngx_module_t  ngx_http_realip_module = {
    NGX_MODULE_V1,
    &ngx_http_realip_module_ctx,           /* module context */
    ngx_http_realip_commands,              /* module directives */
    NGX_HTTP_MODULE,                       /* module type */
    NULL,                                  /* init master */
    NULL,                                  /* init module */
    NULL,                                  /* init process */
    NULL,                                  /* init thread */
    NULL,                                  /* exit thread */
    NULL,                                  /* exit process */
    NULL,                                  /* exit master */
    NGX_MODULE_V1_PADDING
};


static ngx_int_t
ngx_http_realip_handler(ngx_http_request_t *r)
{
    u_char                      *ip, *p;
    size_t                       len;
    in_addr_t                    addr;
    ngx_uint_t                   i;
    struct sockaddr_in          *sin;
    ngx_http_realip_from_t      *from;
    ngx_http_realip_loc_conf_t  *rlcf;

    if (r->realip_set) {
        return NGX_DECLINED;
    }

    rlcf = ngx_http_get_module_loc_conf(r, ngx_http_realip_module);

    if (rlcf->from == NULL) {
        return NGX_DECLINED;
    }

    if (rlcf->xfwd == 0) {
        if (r->headers_in.x_real_ip == NULL) {
            return NGX_DECLINED;
        }

        len = r->headers_in.x_real_ip->value.len;
        ip = r->headers_in.x_real_ip->value.data;

    } else {
        if (r->headers_in.x_forwarded_for == NULL) {
            return NGX_DECLINED;
        }

        len = r->headers_in.x_forwarded_for->value.len;
        ip = r->headers_in.x_forwarded_for->value.data;

        for (p = ip + len - 1; p > ip; p--) {
            if (*p == ' ' || *p == ',') {
                p++;
                len -= p - ip;
                ip = p;
                break;
            }
        }
    }

    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "realip: \"%s\"", ip);

    /* AF_INET only */

    sin = (struct sockaddr_in *) r->connection->sockaddr;

    from = rlcf->from->elts;
    for (i = 0; i < rlcf->from->nelts; i++) {

        ngx_log_debug3(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                       "realip: %08XD %08XD %08XD",
                       sin->sin_addr.s_addr, from[i].mask, from[i].addr);

        if ((sin->sin_addr.s_addr & from[i].mask) == from[i].addr) {

            r->realip_set = 1;

            addr = inet_addr((char *) ip);

            if (addr == INADDR_NONE) {
                return NGX_DECLINED;
            }

            p = ngx_palloc(r->connection->pool, len);
            if (p == NULL) {
                return NGX_HTTP_INTERNAL_SERVER_ERROR;
            }

            ngx_memcpy(p, ip, len);

            sin->sin_addr.s_addr = addr;

            r->connection->addr_text.len = len;
            r->connection->addr_text.data = p;

            return NGX_DECLINED;
        }
    }

    return NGX_DECLINED;
}


static char *
ngx_http_realip_from(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    ngx_http_realip_loc_conf_t *rlcf = conf;

    ngx_int_t                 rc;
    ngx_str_t                *value;
    ngx_inet_cidr_t           in_cidr;
    ngx_http_realip_from_t   *from;

    if (rlcf->from == NULL) {
        rlcf->from = ngx_array_create(cf->pool, 2,
                                      sizeof(ngx_http_realip_from_t));
        if (rlcf->from == NULL) {
            return NGX_CONF_ERROR;
        }
    }

    from = ngx_array_push(rlcf->from);
    if (from == NULL) {
        return NGX_CONF_ERROR;
    }

    value = cf->args->elts;

    from->addr = inet_addr((char *) value[1].data);

    if (from->addr != INADDR_NONE) {
        from->mask = 0xffffffff;

        return NGX_CONF_OK;
    }

    rc = ngx_ptocidr(&value[1], &in_cidr);

    if (rc == NGX_ERROR) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0, "invalid parameter \"%V\"",
                           &value[1]);
        return NGX_CONF_ERROR;
    }

    if (rc == NGX_DONE) {
        ngx_conf_log_error(NGX_LOG_WARN, cf, 0,
                           "low address bits of %V are meaningless", &value[1]);
    }

    from->mask = in_cidr.mask;
    from->addr = in_cidr.addr;

    return NGX_CONF_OK;
}


static void *
ngx_http_realip_create_loc_conf(ngx_conf_t *cf)
{
    ngx_http_realip_loc_conf_t  *conf;

    conf = ngx_pcalloc(cf->pool, sizeof(ngx_http_realip_loc_conf_t));
    if (conf == NULL) {
        return NGX_CONF_ERROR;
    }

    /*
     * set by ngx_pcalloc():
     *
     *     conf->from = NULL;
     */

    conf->xfwd = NGX_CONF_UNSET_UINT;

    return conf;
}


static char *
ngx_http_realip_merge_loc_conf(ngx_conf_t *cf, void *parent, void *child)
{
    ngx_http_realip_loc_conf_t  *prev = parent;
    ngx_http_realip_loc_conf_t  *conf = child;

    if (conf->from == NULL) {
        conf->from = prev->from;
    }

    ngx_conf_merge_uint_value(conf->xfwd, prev->xfwd, 0);

    return NGX_CONF_OK;
}


static ngx_int_t
ngx_http_realip_init(ngx_conf_t *cf)
{
    ngx_http_handler_pt        *h;
    ngx_http_core_main_conf_t  *cmcf;

    cmcf = ngx_http_conf_get_module_main_conf(cf, ngx_http_core_module);

    h = ngx_array_push(&cmcf->phases[NGX_HTTP_POST_READ_PHASE].handlers);
    if (h == NULL) {
        return NGX_ERROR;
    }

    *h = ngx_http_realip_handler;

    h = ngx_array_push(&cmcf->phases[NGX_HTTP_PREACCESS_PHASE].handlers);
    if (h == NULL) {
        return NGX_ERROR;
    }

    *h = ngx_http_realip_handler;

    return NGX_OK;
}
