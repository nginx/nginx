
/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) Nginx, Inc.
 */


#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>


typedef struct {
    in_addr_t         mask;
    in_addr_t         addr;
    ngx_uint_t        deny;      /* unsigned  deny:1; */
} ngx_http_access_rule_t;

#if (NGX_HAVE_INET6)

typedef struct {
    struct in6_addr   addr;
    struct in6_addr   mask;
    ngx_uint_t        deny;      /* unsigned  deny:1; */
} ngx_http_access_rule6_t;

#endif

#if (NGX_HAVE_UNIX_DOMAIN)

typedef struct {
    ngx_uint_t        deny;      /* unsigned  deny:1; */
} ngx_http_access_rule_un_t;

#endif

typedef struct {
    ngx_array_t      *rules;     /* array of ngx_http_access_rule_t */
#if (NGX_HAVE_INET6)
    ngx_array_t      *rules6;    /* array of ngx_http_access_rule6_t */
#endif
#if (NGX_HAVE_UNIX_DOMAIN)
    ngx_array_t      *rules_un;  /* array of ngx_http_access_rule_un_t */
#endif
} ngx_http_access_loc_conf_t;


static ngx_int_t ngx_http_access_handler(ngx_http_request_t *r);
static ngx_int_t ngx_http_access_inet(ngx_http_request_t *r,
    ngx_http_access_loc_conf_t *alcf, in_addr_t addr);
#if (NGX_HAVE_INET6)
static ngx_int_t ngx_http_access_inet6(ngx_http_request_t *r,
    ngx_http_access_loc_conf_t *alcf, u_char *p);
#endif
#if (NGX_HAVE_UNIX_DOMAIN)
static ngx_int_t ngx_http_access_unix(ngx_http_request_t *r,
    ngx_http_access_loc_conf_t *alcf);
#endif
static ngx_int_t ngx_http_access_found(ngx_http_request_t *r, ngx_uint_t deny);
static char *ngx_http_access_rule(ngx_conf_t *cf, ngx_command_t *cmd,
    void *conf);
static void *ngx_http_access_create_loc_conf(ngx_conf_t *cf);
static char *ngx_http_access_merge_loc_conf(ngx_conf_t *cf,
    void *parent, void *child);
static ngx_int_t ngx_http_access_init(ngx_conf_t *cf);


static ngx_command_t  ngx_http_access_commands[] = {

    { ngx_string("allow"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_HTTP_LMT_CONF
                        |NGX_CONF_TAKE1,
      ngx_http_access_rule,
      NGX_HTTP_LOC_CONF_OFFSET,
      0,
      NULL },

    { ngx_string("deny"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_HTTP_LMT_CONF
                        |NGX_CONF_TAKE1,
      ngx_http_access_rule,
      NGX_HTTP_LOC_CONF_OFFSET,
      0,
      NULL },

      ngx_null_command
};



static ngx_http_module_t  ngx_http_access_module_ctx = {
    NULL,                                  /* preconfiguration */
    ngx_http_access_init,                  /* postconfiguration */

    NULL,                                  /* create main configuration */
    NULL,                                  /* init main configuration */

    NULL,                                  /* create server configuration */
    NULL,                                  /* merge server configuration */

    ngx_http_access_create_loc_conf,       /* create location configuration */
    ngx_http_access_merge_loc_conf         /* merge location configuration */
};


ngx_module_t  ngx_http_access_module = {
    NGX_MODULE_V1,
    &ngx_http_access_module_ctx,           /* module context */
    ngx_http_access_commands,              /* module directives */
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
ngx_http_access_handler(ngx_http_request_t *r)
{
    struct sockaddr_in          *sin;
    ngx_http_access_loc_conf_t  *alcf;
#if (NGX_HAVE_INET6)
    u_char                      *p;
    in_addr_t                    addr;
    struct sockaddr_in6         *sin6;
#endif

    alcf = ngx_http_get_module_loc_conf(r, ngx_http_access_module);

    switch (r->connection->sockaddr->sa_family) {

    case AF_INET:
        if (alcf->rules) {
            sin = (struct sockaddr_in *) r->connection->sockaddr;
            return ngx_http_access_inet(r, alcf, sin->sin_addr.s_addr);
        }
        break;

#if (NGX_HAVE_INET6)

    case AF_INET6:
        sin6 = (struct sockaddr_in6 *) r->connection->sockaddr;
        p = sin6->sin6_addr.s6_addr;

        if (alcf->rules && IN6_IS_ADDR_V4MAPPED(&sin6->sin6_addr)) {
            addr = p[12] << 24;
            addr += p[13] << 16;
            addr += p[14] << 8;
            addr += p[15];
            return ngx_http_access_inet(r, alcf, htonl(addr));
        }

        if (alcf->rules6) {
            return ngx_http_access_inet6(r, alcf, p);
        }

        break;

#endif

#if (NGX_HAVE_UNIX_DOMAIN)

    case AF_UNIX:
        if (alcf->rules_un) {
            return ngx_http_access_unix(r, alcf);
        }

        break;

#endif
    }

    return NGX_DECLINED;
}


static ngx_int_t
ngx_http_access_inet(ngx_http_request_t *r, ngx_http_access_loc_conf_t *alcf,
    in_addr_t addr)
{
    ngx_uint_t               i;
    ngx_http_access_rule_t  *rule;

    rule = alcf->rules->elts;
    for (i = 0; i < alcf->rules->nelts; i++) {

        ngx_log_debug3(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                       "access: %08XD %08XD %08XD",
                       addr, rule[i].mask, rule[i].addr);

        if ((addr & rule[i].mask) == rule[i].addr) {
            return ngx_http_access_found(r, rule[i].deny);
        }
    }

    return NGX_DECLINED;
}


#if (NGX_HAVE_INET6)

static ngx_int_t
ngx_http_access_inet6(ngx_http_request_t *r, ngx_http_access_loc_conf_t *alcf,
    u_char *p)
{
    ngx_uint_t                n;
    ngx_uint_t                i;
    ngx_http_access_rule6_t  *rule6;

    rule6 = alcf->rules6->elts;
    for (i = 0; i < alcf->rules6->nelts; i++) {

#if (NGX_DEBUG)
        {
        size_t  cl, ml, al;
        u_char  ct[NGX_INET6_ADDRSTRLEN];
        u_char  mt[NGX_INET6_ADDRSTRLEN];
        u_char  at[NGX_INET6_ADDRSTRLEN];

        cl = ngx_inet6_ntop(p, ct, NGX_INET6_ADDRSTRLEN);
        ml = ngx_inet6_ntop(rule6[i].mask.s6_addr, mt, NGX_INET6_ADDRSTRLEN);
        al = ngx_inet6_ntop(rule6[i].addr.s6_addr, at, NGX_INET6_ADDRSTRLEN);

        ngx_log_debug6(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                       "access: %*s %*s %*s", cl, ct, ml, mt, al, at);
        }
#endif

        for (n = 0; n < 16; n++) {
            if ((p[n] & rule6[i].mask.s6_addr[n]) != rule6[i].addr.s6_addr[n]) {
                goto next;
            }
        }

        return ngx_http_access_found(r, rule6[i].deny);

    next:
        continue;
    }

    return NGX_DECLINED;
}

#endif


#if (NGX_HAVE_UNIX_DOMAIN)

static ngx_int_t
ngx_http_access_unix(ngx_http_request_t *r, ngx_http_access_loc_conf_t *alcf)
{
    ngx_uint_t                  i;
    ngx_http_access_rule_un_t  *rule_un;

    rule_un = alcf->rules_un->elts;
    for (i = 0; i < alcf->rules_un->nelts; i++) {

        /* TODO: check path */
        if (1) {
            return ngx_http_access_found(r, rule_un[i].deny);
        }
    }

    return NGX_DECLINED;
}

#endif


static ngx_int_t
ngx_http_access_found(ngx_http_request_t *r, ngx_uint_t deny)
{
    ngx_http_core_loc_conf_t  *clcf;

    if (deny) {
        clcf = ngx_http_get_module_loc_conf(r, ngx_http_core_module);

        if (clcf->satisfy == NGX_HTTP_SATISFY_ALL) {
            ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                          "access forbidden by rule");
        }

        return NGX_HTTP_FORBIDDEN;
    }

    return NGX_OK;
}


static char *
ngx_http_access_rule(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    ngx_http_access_loc_conf_t *alcf = conf;

    ngx_int_t                   rc;
    ngx_uint_t                  all;
    ngx_str_t                  *value;
    ngx_cidr_t                  cidr;
    ngx_http_access_rule_t     *rule;
#if (NGX_HAVE_INET6)
    ngx_http_access_rule6_t    *rule6;
#endif
#if (NGX_HAVE_UNIX_DOMAIN)
    ngx_http_access_rule_un_t  *rule_un;
#endif

    ngx_memzero(&cidr, sizeof(ngx_cidr_t));

    value = cf->args->elts;

    all = (value[1].len == 3 && ngx_strcmp(value[1].data, "all") == 0);

    if (!all) {

#if (NGX_HAVE_UNIX_DOMAIN)

        if (value[1].len == 5 && ngx_strcmp(value[1].data, "unix:") == 0) {
            cidr.family = AF_UNIX;
            rc = NGX_OK;

        } else {
            rc = ngx_ptocidr(&value[1], &cidr);
        }

#else
        rc = ngx_ptocidr(&value[1], &cidr);
#endif

        if (rc == NGX_ERROR) {
            ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                         "invalid parameter \"%V\"", &value[1]);
            return NGX_CONF_ERROR;
        }

        if (rc == NGX_DONE) {
            ngx_conf_log_error(NGX_LOG_WARN, cf, 0,
                         "low address bits of %V are meaningless", &value[1]);
        }
    }

    if (cidr.family == AF_INET || all) {

        if (alcf->rules == NULL) {
            alcf->rules = ngx_array_create(cf->pool, 4,
                                           sizeof(ngx_http_access_rule_t));
            if (alcf->rules == NULL) {
                return NGX_CONF_ERROR;
            }
        }

        rule = ngx_array_push(alcf->rules);
        if (rule == NULL) {
            return NGX_CONF_ERROR;
        }

        rule->mask = cidr.u.in.mask;
        rule->addr = cidr.u.in.addr;
        rule->deny = (value[0].data[0] == 'd') ? 1 : 0;
    }

#if (NGX_HAVE_INET6)
    if (cidr.family == AF_INET6 || all) {

        if (alcf->rules6 == NULL) {
            alcf->rules6 = ngx_array_create(cf->pool, 4,
                                            sizeof(ngx_http_access_rule6_t));
            if (alcf->rules6 == NULL) {
                return NGX_CONF_ERROR;
            }
        }

        rule6 = ngx_array_push(alcf->rules6);
        if (rule6 == NULL) {
            return NGX_CONF_ERROR;
        }

        rule6->mask = cidr.u.in6.mask;
        rule6->addr = cidr.u.in6.addr;
        rule6->deny = (value[0].data[0] == 'd') ? 1 : 0;
    }
#endif

#if (NGX_HAVE_UNIX_DOMAIN)
    if (cidr.family == AF_UNIX || all) {

        if (alcf->rules_un == NULL) {
            alcf->rules_un = ngx_array_create(cf->pool, 1,
                                            sizeof(ngx_http_access_rule_un_t));
            if (alcf->rules_un == NULL) {
                return NGX_CONF_ERROR;
            }
        }

        rule_un = ngx_array_push(alcf->rules_un);
        if (rule_un == NULL) {
            return NGX_CONF_ERROR;
        }

        rule_un->deny = (value[0].data[0] == 'd') ? 1 : 0;
    }
#endif

    return NGX_CONF_OK;
}


static void *
ngx_http_access_create_loc_conf(ngx_conf_t *cf)
{
    ngx_http_access_loc_conf_t  *conf;

    conf = ngx_pcalloc(cf->pool, sizeof(ngx_http_access_loc_conf_t));
    if (conf == NULL) {
        return NULL;
    }

    return conf;
}


static char *
ngx_http_access_merge_loc_conf(ngx_conf_t *cf, void *parent, void *child)
{
    ngx_http_access_loc_conf_t  *prev = parent;
    ngx_http_access_loc_conf_t  *conf = child;

    if (conf->rules == NULL
#if (NGX_HAVE_INET6)
        && conf->rules6 == NULL
#endif
#if (NGX_HAVE_UNIX_DOMAIN)
        && conf->rules_un == NULL
#endif
    ) {
        conf->rules = prev->rules;
#if (NGX_HAVE_INET6)
        conf->rules6 = prev->rules6;
#endif
#if (NGX_HAVE_UNIX_DOMAIN)
        conf->rules_un = prev->rules_un;
#endif
    }

    return NGX_CONF_OK;
}


static ngx_int_t
ngx_http_access_init(ngx_conf_t *cf)
{
    ngx_http_handler_pt        *h;
    ngx_http_core_main_conf_t  *cmcf;

    cmcf = ngx_http_conf_get_module_main_conf(cf, ngx_http_core_module);

    h = ngx_array_push(&cmcf->phases[NGX_HTTP_ACCESS_PHASE].handlers);
    if (h == NULL) {
        return NGX_ERROR;
    }

    *h = ngx_http_access_handler;

    return NGX_OK;
}
