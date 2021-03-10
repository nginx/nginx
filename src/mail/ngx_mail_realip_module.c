
/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) Nginx, Inc.
 */


#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_mail.h>


typedef struct {
    ngx_array_t       *from;     /* array of ngx_cidr_t */
} ngx_mail_realip_srv_conf_t;


static ngx_int_t ngx_mail_realip_set_addr(ngx_mail_session_t *s,
    ngx_addr_t *addr);
static char *ngx_mail_realip_from(ngx_conf_t *cf, ngx_command_t *cmd,
    void *conf);
static void *ngx_mail_realip_create_srv_conf(ngx_conf_t *cf);
static char *ngx_mail_realip_merge_srv_conf(ngx_conf_t *cf, void *parent,
    void *child);


static ngx_command_t  ngx_mail_realip_commands[] = {

    { ngx_string("set_real_ip_from"),
      NGX_MAIL_MAIN_CONF|NGX_MAIL_SRV_CONF|NGX_CONF_TAKE1,
      ngx_mail_realip_from,
      NGX_MAIL_SRV_CONF_OFFSET,
      0,
      NULL },

      ngx_null_command
};


static ngx_mail_module_t  ngx_mail_realip_module_ctx = {
    NULL,                                  /* protocol */

    NULL,                                  /* create main configuration */
    NULL,                                  /* init main configuration */

    ngx_mail_realip_create_srv_conf,       /* create server configuration */
    ngx_mail_realip_merge_srv_conf         /* merge server configuration */
};


ngx_module_t  ngx_mail_realip_module = {
    NGX_MODULE_V1,
    &ngx_mail_realip_module_ctx,           /* module context */
    ngx_mail_realip_commands,              /* module directives */
    NGX_MAIL_MODULE,                       /* module type */
    NULL,                                  /* init master */
    NULL,                                  /* init module */
    NULL,                                  /* init process */
    NULL,                                  /* init thread */
    NULL,                                  /* exit thread */
    NULL,                                  /* exit process */
    NULL,                                  /* exit master */
    NGX_MODULE_V1_PADDING
};


ngx_int_t
ngx_mail_realip_handler(ngx_mail_session_t *s)
{
    ngx_addr_t                   addr;
    ngx_connection_t            *c;
    ngx_mail_realip_srv_conf_t  *rscf;

    rscf = ngx_mail_get_module_srv_conf(s, ngx_mail_realip_module);

    if (rscf->from == NULL) {
        return NGX_OK;
    }

    c = s->connection;

    if (c->proxy_protocol == NULL) {
        return NGX_OK;
    }

    if (ngx_cidr_match(c->sockaddr, rscf->from) != NGX_OK) {
        return NGX_OK;
    }

    if (ngx_parse_addr(c->pool, &addr, c->proxy_protocol->src_addr.data,
                       c->proxy_protocol->src_addr.len)
        != NGX_OK)
    {
        return NGX_OK;
    }

    ngx_inet_set_port(addr.sockaddr, c->proxy_protocol->src_port);

    return ngx_mail_realip_set_addr(s, &addr);
}


static ngx_int_t
ngx_mail_realip_set_addr(ngx_mail_session_t *s, ngx_addr_t *addr)
{
    size_t             len;
    u_char            *p;
    u_char             text[NGX_SOCKADDR_STRLEN];
    ngx_connection_t  *c;

    c = s->connection;

    len = ngx_sock_ntop(addr->sockaddr, addr->socklen, text,
                        NGX_SOCKADDR_STRLEN, 0);
    if (len == 0) {
        return NGX_ERROR;
    }

    p = ngx_pnalloc(c->pool, len);
    if (p == NULL) {
        return NGX_ERROR;
    }

    ngx_memcpy(p, text, len);

    c->sockaddr = addr->sockaddr;
    c->socklen = addr->socklen;
    c->addr_text.len = len;
    c->addr_text.data = p;

    return NGX_OK;
}


static char *
ngx_mail_realip_from(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    ngx_mail_realip_srv_conf_t *rscf = conf;

    ngx_int_t             rc;
    ngx_str_t            *value;
    ngx_url_t             u;
    ngx_cidr_t            c, *cidr;
    ngx_uint_t            i;
    struct sockaddr_in   *sin;
#if (NGX_HAVE_INET6)
    struct sockaddr_in6  *sin6;
#endif

    value = cf->args->elts;

    if (rscf->from == NULL) {
        rscf->from = ngx_array_create(cf->pool, 2,
                                      sizeof(ngx_cidr_t));
        if (rscf->from == NULL) {
            return NGX_CONF_ERROR;
        }
    }

#if (NGX_HAVE_UNIX_DOMAIN)

    if (ngx_strcmp(value[1].data, "unix:") == 0) {
        cidr = ngx_array_push(rscf->from);
        if (cidr == NULL) {
            return NGX_CONF_ERROR;
        }

        cidr->family = AF_UNIX;
        return NGX_CONF_OK;
    }

#endif

    rc = ngx_ptocidr(&value[1], &c);

    if (rc != NGX_ERROR) {
        if (rc == NGX_DONE) {
            ngx_conf_log_error(NGX_LOG_WARN, cf, 0,
                               "low address bits of %V are meaningless",
                               &value[1]);
        }

        cidr = ngx_array_push(rscf->from);
        if (cidr == NULL) {
            return NGX_CONF_ERROR;
        }

        *cidr = c;

        return NGX_CONF_OK;
    }

    ngx_memzero(&u, sizeof(ngx_url_t));
    u.host = value[1];

    if (ngx_inet_resolve_host(cf->pool, &u) != NGX_OK) {
        if (u.err) {
            ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                               "%s in set_real_ip_from \"%V\"",
                               u.err, &u.host);
        }

        return NGX_CONF_ERROR;
    }

    cidr = ngx_array_push_n(rscf->from, u.naddrs);
    if (cidr == NULL) {
        return NGX_CONF_ERROR;
    }

    ngx_memzero(cidr, u.naddrs * sizeof(ngx_cidr_t));

    for (i = 0; i < u.naddrs; i++) {
        cidr[i].family = u.addrs[i].sockaddr->sa_family;

        switch (cidr[i].family) {

#if (NGX_HAVE_INET6)
        case AF_INET6:
            sin6 = (struct sockaddr_in6 *) u.addrs[i].sockaddr;
            cidr[i].u.in6.addr = sin6->sin6_addr;
            ngx_memset(cidr[i].u.in6.mask.s6_addr, 0xff, 16);
            break;
#endif

        default: /* AF_INET */
            sin = (struct sockaddr_in *) u.addrs[i].sockaddr;
            cidr[i].u.in.addr = sin->sin_addr.s_addr;
            cidr[i].u.in.mask = 0xffffffff;
            break;
        }
    }

    return NGX_CONF_OK;
}


static void *
ngx_mail_realip_create_srv_conf(ngx_conf_t *cf)
{
    ngx_mail_realip_srv_conf_t  *conf;

    conf = ngx_pcalloc(cf->pool, sizeof(ngx_mail_realip_srv_conf_t));
    if (conf == NULL) {
        return NULL;
    }

    /*
     * set by ngx_pcalloc():
     *
     *     conf->from = NULL;
     */

    return conf;
}


static char *
ngx_mail_realip_merge_srv_conf(ngx_conf_t *cf, void *parent, void *child)
{
    ngx_mail_realip_srv_conf_t *prev = parent;
    ngx_mail_realip_srv_conf_t *conf = child;

    if (conf->from == NULL) {
        conf->from = prev->from;
    }

    return NGX_CONF_OK;
}
