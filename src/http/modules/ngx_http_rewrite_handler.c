
#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>


#define NGX_HTTP_REWRITE_COPY_MATCH  0
#define NGX_HTTP_REWRITE_COPY_SHORT  1
#define NGX_HTTP_REWRITE_COPY_LONG   2


typedef struct {
    ngx_int_t    op;
    size_t       len;
    uintptr_t    data;
} ngx_http_rewrite_op_t;


typedef struct {
    ngx_regex_t  *regex;
    ngx_uint_t    msize;

    ngx_array_t   ops;
    ngx_uint_t    size;

    ngx_str_t     re_name;
    ngx_str_t     s_name;

    unsigned      last:1;
} ngx_http_rewrite_rule_t;


typedef struct {
    ngx_array_t   rules;
    unsigned      log:1;
} ngx_http_rewrite_srv_conf_t;


static void *ngx_http_rewrite_create_loc_conf(ngx_conf_t *cf);
static char *ngx_http_rewrite_rule(ngx_conf_t *cf, ngx_command_t *cmd,
                                   void *conf);
static ngx_int_t ngx_http_rewrite_init(ngx_cycle_t *cycle);


static ngx_command_t  ngx_http_rewrite_commands[] = {

    { ngx_string("rewrite"),
      NGX_HTTP_SRV_CONF|NGX_CONF_TAKE23,
      ngx_http_rewrite_rule,
      NGX_HTTP_SRV_CONF_OFFSET,
      0,
      NULL },

      ngx_null_command
};


ngx_http_module_t  ngx_http_rewrite_module_ctx = {
    NULL,                                  /* pre conf */

    NULL,                                  /* create main configuration */
    NULL,                                  /* init main configuration */

    ngx_http_rewrite_create_loc_conf,      /* create server configuration */
    NULL,                                  /* merge server configuration */

    NULL,                                  /* create location configration */
    NULL,                                  /* merge location configration */
};


ngx_module_t  ngx_http_rewrite_module = {
    NGX_MODULE,
    &ngx_http_rewrite_module_ctx,          /* module context */
    ngx_http_rewrite_commands,             /* module directives */
    NGX_HTTP_MODULE,                       /* module type */
    ngx_http_rewrite_init,                 /* init module */
    NULL                                   /* init child */
};


static ngx_int_t ngx_http_rewrite_handler(ngx_http_request_t *r)
{
    int                          *matches;
    u_char                       *p;
    size_t                        len;
    uintptr_t                     data;
    ngx_int_t                     rc;
    ngx_uint_t                    i, m, n;
    ngx_str_t                     uri;
    ngx_http_rewrite_op_t        *op;
    ngx_http_rewrite_rule_t      *rule;
    ngx_http_rewrite_srv_conf_t  *scf;

    ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "http rewrite handler");

    scf = ngx_http_get_module_srv_conf(r, ngx_http_rewrite_module);

    rule = scf->rules.elts;
    for (i = 0; i < scf->rules.nelts; i++) {

        if (rule[i].msize) {
            if (!(matches = ngx_palloc(r->pool, rule[i].msize * sizeof(int)))) {
                return NGX_HTTP_INTERNAL_SERVER_ERROR;
            }

        } else {
            matches = NULL;
        }

        rc = ngx_regex_exec(rule[i].regex, &r->uri, matches, rule[i].msize);

        if (rc == NGX_DECLINED) {
            if (scf->log) {
                ngx_log_error(NGX_LOG_NOTICE, r->connection->log, 0,
                              "\"%s\" does not match", rule[i].re_name.data);
            }

            continue;
        }

        if (rc < 0) {
            ngx_log_error(NGX_LOG_ALERT, r->connection->log, 0,
                          ngx_regex_exec_n
                          " failed: %d on \"%s\" using \"%s\"",
                          rc, r->uri.data, rule[i].re_name.data);
            return NGX_HTTP_INTERNAL_SERVER_ERROR;
        }

        if (scf->log) {
            ngx_log_error(NGX_LOG_NOTICE, r->connection->log, 0,
                          "\"%s\" matches", rule[i].re_name.data);
        }

        uri.len = rule[i].size;

        for (n = 1; n < (ngx_uint_t) rc; n++) {
           uri.len += matches[2 * n + 1] - matches[2 * n];
        }

        if (!(uri.data = ngx_palloc(r->pool, uri.len + 1))) {
            return NGX_HTTP_INTERNAL_SERVER_ERROR;
        }

        p = uri.data;

        op = rule[i].ops.elts;
        for (n = 0; n < rule[i].ops.nelts; n++) {
            if (op[n].op == NGX_HTTP_REWRITE_COPY_SHORT) {
                len = op[n].len;
                data = op[n].data;
                while (len--) {
                    *p++ = (char) (data & 0xff);
                    data >>= 8;
                }

            } else if (op[n].op == NGX_HTTP_REWRITE_COPY_LONG) {
                p = ngx_cpymem(p, (void *) op[n].data, op[n].len);

            } else { /* NGX_HTTP_REWRITE_COPY_MATCH */
                m = 2 * op[n].data;
                p = ngx_cpymem(p, &r->uri.data[matches[m]],
                               matches[m + 1] - matches[m]);
            }
        }

        *p = '\0';

        if (scf->log) {
            ngx_log_error(NGX_LOG_NOTICE, r->connection->log, 0,
                          "rewritten uri: \"%s\"", uri.data);
        }

        r->uri = uri;

        if (ngx_http_set_exten(r) != NGX_OK) {
            return NGX_HTTP_INTERNAL_SERVER_ERROR;
        }

        if (rule[i].last) {
            return NGX_DECLINED;
        }
    }

    return NGX_DECLINED;
}


static void *ngx_http_rewrite_create_loc_conf(ngx_conf_t *cf)
{
    ngx_http_rewrite_srv_conf_t  *conf;

    if (!(conf = ngx_palloc(cf->pool, sizeof(ngx_http_rewrite_srv_conf_t)))) {
        return NGX_CONF_ERROR;
    }

    ngx_init_array(conf->rules, cf->pool, 5, sizeof(ngx_http_rewrite_rule_t),
                   NGX_CONF_ERROR);

    conf->log = 1;

    return conf;
}


static char *ngx_http_rewrite_rule(ngx_conf_t *cf, ngx_command_t *cmd,
                                   void *conf)
{
    ngx_http_rewrite_srv_conf_t *scf = conf;

    u_char                   *data, *p;
    size_t                    len;
    ngx_str_t                *value, err;
    ngx_uint_t                i;
    ngx_http_rewrite_op_t    *op;
    ngx_http_rewrite_rule_t  *rule;
    u_char                    errstr[NGX_MAX_CONF_ERRSTR];

    if (!(rule = ngx_push_array(&scf->rules))) {
        return NGX_CONF_ERROR;
    }

    ngx_init_array(rule->ops, cf->pool, 5, sizeof(ngx_http_rewrite_op_t),
                   NGX_CONF_ERROR);

    rule->msize = 0;
    rule->size = 0;

    value = cf->args->elts;

    /* STUB */ {
        err.len = NGX_MAX_CONF_ERRSTR;
        err.data = errstr;

        rule->regex = ngx_regex_compile(&value[1], 0, cf->pool, &err);
    
        if (rule->regex == NULL) {
            ngx_conf_log_error(NGX_LOG_EMERG, cf, 0, "%s", err.data);
            return NGX_CONF_ERROR;
        }
    
        rule->re_name = value[1];
        rule->s_name = value[2];

        for (i = 0; i < value[2].len; /* void */) {

            if (!(op = ngx_push_array(&rule->ops))) {
                return NGX_CONF_ERROR;
            }

            data = &value[2].data[i];

            if (value[2].data[i] == '$'
                && i < value[2].len
                && value[2].data[i + 1] >= '1'
                && value[2].data[i + 1] <= '9')
            {
                op->op = NGX_HTTP_REWRITE_COPY_MATCH; 
                op->data = value[2].data[++i] - '0';

                if (rule->msize < op->data) {
                    rule->msize = op->data;
                }

                i++;

            } else {
                i++;

                while (i < value[2].len && value[2].data[i] != '$') {
                    i++;
                }

                len = &value[2].data[i] - data;
                rule->size += len;

                if (len) {

                    op->len = len;

                    if (len <= sizeof(uintptr_t)) {
                        op->op = NGX_HTTP_REWRITE_COPY_SHORT; 
                        op->data = 0;

                        while (len--) {
                            op->data <<= 8;
                            op->data |= data[len];
                        }

                    } else {
                        op->op = NGX_HTTP_REWRITE_COPY_LONG;

                        if (!(p = ngx_palloc(cf->pool, len))) {
                            return NGX_CONF_ERROR;
                        }

                        ngx_memcpy(p, data, len);
                        op->data = (uintptr_t) p;
                    }
                }
            }
        }

        if (rule->msize) {
            rule->msize++;
            rule->msize *= 3;
        }

        if (cf->args->nelts > 3) {
            if (ngx_strcmp(value[3].data, "last") == 0) {
                rule->last = 1;

            } else {
                ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                                   "invalid parameter \"%s\"", value[3].data);
                return NGX_CONF_ERROR;
            }
        }
    }

    return NGX_CONF_OK;
}


static ngx_int_t ngx_http_rewrite_init(ngx_cycle_t *cycle)
{
    ngx_http_handler_pt        *h;
    ngx_http_conf_ctx_t        *ctx;
    ngx_http_core_main_conf_t  *cmcf;

    ctx = (ngx_http_conf_ctx_t *) cycle->conf_ctx[ngx_http_module.index];
    cmcf = ctx->main_conf[ngx_http_core_module.ctx_index];

    h = ngx_push_array(&cmcf->phases[NGX_HTTP_REWRITE_PHASE].handlers);
    if (h == NULL) {
        return NGX_ERROR;
    }

    *h = ngx_http_rewrite_handler;

    return NGX_OK;
}
