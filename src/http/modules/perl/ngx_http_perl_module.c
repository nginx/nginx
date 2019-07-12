
/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) Nginx, Inc.
 */


#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>
#include <ngx_http_perl_module.h>


typedef struct {
    PerlInterpreter   *perl;
    HV                *nginx;
    ngx_array_t       *modules;
    ngx_array_t       *requires;
} ngx_http_perl_main_conf_t;


typedef struct {
    SV                *sub;
    ngx_str_t          handler;
} ngx_http_perl_loc_conf_t;


typedef struct {
    SV                *sub;
    ngx_str_t          handler;
} ngx_http_perl_variable_t;


#if (NGX_HTTP_SSI)
static ngx_int_t ngx_http_perl_ssi(ngx_http_request_t *r,
    ngx_http_ssi_ctx_t *ssi_ctx, ngx_str_t **params);
#endif

static char *ngx_http_perl_init_interpreter(ngx_conf_t *cf,
    ngx_http_perl_main_conf_t *pmcf);
static PerlInterpreter *ngx_http_perl_create_interpreter(ngx_conf_t *cf,
    ngx_http_perl_main_conf_t *pmcf);
static ngx_int_t ngx_http_perl_run_requires(pTHX_ ngx_array_t *requires,
    ngx_log_t *log);
static ngx_int_t ngx_http_perl_call_handler(pTHX_ ngx_http_request_t *r,
    ngx_http_perl_ctx_t *ctx, HV *nginx, SV *sub, SV **args,
    ngx_str_t *handler, ngx_str_t *rv);
static void ngx_http_perl_eval_anon_sub(pTHX_ ngx_str_t *handler, SV **sv);

static ngx_int_t ngx_http_perl_preconfiguration(ngx_conf_t *cf);
static void *ngx_http_perl_create_main_conf(ngx_conf_t *cf);
static char *ngx_http_perl_init_main_conf(ngx_conf_t *cf, void *conf);
static void *ngx_http_perl_create_loc_conf(ngx_conf_t *cf);
static char *ngx_http_perl_merge_loc_conf(ngx_conf_t *cf, void *parent,
    void *child);
static char *ngx_http_perl(ngx_conf_t *cf, ngx_command_t *cmd, void *conf);
static char *ngx_http_perl_set(ngx_conf_t *cf, ngx_command_t *cmd, void *conf);

#if (NGX_HAVE_PERL_MULTIPLICITY)
static void ngx_http_perl_cleanup_perl(void *data);
#endif

static ngx_int_t ngx_http_perl_init_worker(ngx_cycle_t *cycle);
static void ngx_http_perl_exit(ngx_cycle_t *cycle);


static ngx_command_t  ngx_http_perl_commands[] = {

    { ngx_string("perl_modules"),
      NGX_HTTP_MAIN_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_str_array_slot,
      NGX_HTTP_MAIN_CONF_OFFSET,
      offsetof(ngx_http_perl_main_conf_t, modules),
      NULL },

    { ngx_string("perl_require"),
      NGX_HTTP_MAIN_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_str_array_slot,
      NGX_HTTP_MAIN_CONF_OFFSET,
      offsetof(ngx_http_perl_main_conf_t, requires),
      NULL },

    { ngx_string("perl"),
      NGX_HTTP_LOC_CONF|NGX_HTTP_LMT_CONF|NGX_CONF_TAKE1,
      ngx_http_perl,
      NGX_HTTP_LOC_CONF_OFFSET,
      0,
      NULL },

    { ngx_string("perl_set"),
      NGX_HTTP_MAIN_CONF|NGX_CONF_TAKE2,
      ngx_http_perl_set,
      NGX_HTTP_LOC_CONF_OFFSET,
      0,
      NULL },

      ngx_null_command
};


static ngx_http_module_t  ngx_http_perl_module_ctx = {
    ngx_http_perl_preconfiguration,        /* preconfiguration */
    NULL,                                  /* postconfiguration */

    ngx_http_perl_create_main_conf,        /* create main configuration */
    ngx_http_perl_init_main_conf,          /* init main configuration */

    NULL,                                  /* create server configuration */
    NULL,                                  /* merge server configuration */

    ngx_http_perl_create_loc_conf,         /* create location configuration */
    ngx_http_perl_merge_loc_conf           /* merge location configuration */
};


ngx_module_t  ngx_http_perl_module = {
    NGX_MODULE_V1,
    &ngx_http_perl_module_ctx,             /* module context */
    ngx_http_perl_commands,                /* module directives */
    NGX_HTTP_MODULE,                       /* module type */
    NULL,                                  /* init master */
    NULL,                                  /* init module */
    ngx_http_perl_init_worker,             /* init process */
    NULL,                                  /* init thread */
    NULL,                                  /* exit thread */
    NULL,                                  /* exit process */
    ngx_http_perl_exit,                    /* exit master */
    NGX_MODULE_V1_PADDING
};


#if (NGX_HTTP_SSI)

#define NGX_HTTP_PERL_SSI_SUB  0
#define NGX_HTTP_PERL_SSI_ARG  1


static ngx_http_ssi_param_t  ngx_http_perl_ssi_params[] = {
    { ngx_string("sub"), NGX_HTTP_PERL_SSI_SUB, 1, 0 },
    { ngx_string("arg"), NGX_HTTP_PERL_SSI_ARG, 0, 1 },
    { ngx_null_string, 0, 0, 0 }
};

static ngx_http_ssi_command_t  ngx_http_perl_ssi_command = {
    ngx_string("perl"), ngx_http_perl_ssi, ngx_http_perl_ssi_params, 0, 0, 1
};

#endif


static ngx_str_t         ngx_null_name = ngx_null_string;
static HV               *nginx_stash;

#if (NGX_HAVE_PERL_MULTIPLICITY)
static ngx_uint_t        ngx_perl_term;
#else
static PerlInterpreter  *perl;
#endif


static void
ngx_http_perl_xs_init(pTHX)
{
    newXS("DynaLoader::boot_DynaLoader", boot_DynaLoader, __FILE__);

    nginx_stash = gv_stashpv("nginx", TRUE);
}


static ngx_int_t
ngx_http_perl_handler(ngx_http_request_t *r)
{
    r->main->count++;

    ngx_http_perl_handle_request(r);

    return NGX_DONE;
}


void
ngx_http_perl_handle_request(ngx_http_request_t *r)
{
    SV                         *sub;
    ngx_int_t                   rc;
    ngx_str_t                   uri, args, *handler;
    ngx_http_perl_ctx_t        *ctx;
    ngx_http_perl_loc_conf_t   *plcf;
    ngx_http_perl_main_conf_t  *pmcf;

    ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "perl handler");

    ctx = ngx_http_get_module_ctx(r, ngx_http_perl_module);

    if (ctx == NULL) {
        ctx = ngx_pcalloc(r->pool, sizeof(ngx_http_perl_ctx_t));
        if (ctx == NULL) {
            ngx_http_finalize_request(r, NGX_ERROR);
            return;
        }

        ngx_http_set_ctx(r, ctx, ngx_http_perl_module);

        ctx->request = r;
    }

    pmcf = ngx_http_get_module_main_conf(r, ngx_http_perl_module);

    {

    dTHXa(pmcf->perl);
    PERL_SET_CONTEXT(pmcf->perl);
    PERL_SET_INTERP(pmcf->perl);

    if (ctx->next == NULL) {
        plcf = ngx_http_get_module_loc_conf(r, ngx_http_perl_module);
        sub = plcf->sub;
        handler = &plcf->handler;

    } else {
        sub = ctx->next;
        handler = &ngx_null_name;
        ctx->next = NULL;
    }

    rc = ngx_http_perl_call_handler(aTHX_ r, ctx, pmcf->nginx, sub, NULL,
                                    handler, NULL);

    }

    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "perl handler done: %i", rc);

    if (rc > 600) {
        rc = NGX_OK;
    }

    if (ctx->redirect_uri.len) {
        uri = ctx->redirect_uri;
        args = ctx->redirect_args;

    } else {
        uri.len = 0;
    }

    ctx->filename.data = NULL;
    ctx->redirect_uri.len = 0;

    if (rc == NGX_ERROR) {
        ngx_http_finalize_request(r, rc);
        return;
    }

    if (ctx->done || ctx->next) {
        ngx_http_finalize_request(r, NGX_DONE);
        return;
    }

    if (uri.len) {
        ngx_http_internal_redirect(r, &uri, &args);
        ngx_http_finalize_request(r, NGX_DONE);
        return;
    }

    if (rc == NGX_OK || rc == NGX_HTTP_OK) {
        ngx_http_send_special(r, NGX_HTTP_LAST);
        ctx->done = 1;
    }

    ngx_http_finalize_request(r, rc);
}


void
ngx_http_perl_sleep_handler(ngx_http_request_t *r)
{
    ngx_event_t  *wev;

    ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "perl sleep handler");

    wev = r->connection->write;

    if (wev->delayed) {

        if (ngx_handle_write_event(wev, 0) != NGX_OK) {
            ngx_http_finalize_request(r, NGX_HTTP_INTERNAL_SERVER_ERROR);
        }

        return;
    }

    ngx_http_perl_handle_request(r);
}


static ngx_int_t
ngx_http_perl_variable(ngx_http_request_t *r, ngx_http_variable_value_t *v,
    uintptr_t data)
{
    ngx_http_perl_variable_t *pv = (ngx_http_perl_variable_t *) data;

    ngx_int_t                   rc;
    ngx_str_t                   value;
    ngx_uint_t                  saved;
    ngx_http_perl_ctx_t        *ctx;
    ngx_http_perl_main_conf_t  *pmcf;

    ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "perl variable handler");

    ctx = ngx_http_get_module_ctx(r, ngx_http_perl_module);

    if (ctx == NULL) {
        ctx = ngx_pcalloc(r->pool, sizeof(ngx_http_perl_ctx_t));
        if (ctx == NULL) {
            return NGX_ERROR;
        }

        ngx_http_set_ctx(r, ctx, ngx_http_perl_module);

        ctx->request = r;
    }

    saved = ctx->variable;
    ctx->variable = 1;

    pmcf = ngx_http_get_module_main_conf(r, ngx_http_perl_module);

    value.data = NULL;

    {

    dTHXa(pmcf->perl);
    PERL_SET_CONTEXT(pmcf->perl);
    PERL_SET_INTERP(pmcf->perl);

    rc = ngx_http_perl_call_handler(aTHX_ r, ctx, pmcf->nginx, pv->sub, NULL,
                                    &pv->handler, &value);

    }

    if (value.data) {
        v->len = value.len;
        v->valid = 1;
        v->no_cacheable = 0;
        v->not_found = 0;
        v->data = value.data;

    } else {
        v->not_found = 1;
    }

    ctx->variable = saved;
    ctx->filename.data = NULL;
    ctx->redirect_uri.len = 0;

    ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "perl variable done");

    return rc;
}


#if (NGX_HTTP_SSI)

static ngx_int_t
ngx_http_perl_ssi(ngx_http_request_t *r, ngx_http_ssi_ctx_t *ssi_ctx,
    ngx_str_t **params)
{
    SV                         *sv, **asv;
    ngx_int_t                   rc;
    ngx_str_t                  *handler, **args;
    ngx_uint_t                  i;
    ngx_http_perl_ctx_t        *ctx;
    ngx_http_perl_main_conf_t  *pmcf;

    ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "perl ssi handler");

    ctx = ngx_http_get_module_ctx(r, ngx_http_perl_module);

    if (ctx == NULL) {
        ctx = ngx_pcalloc(r->pool, sizeof(ngx_http_perl_ctx_t));
        if (ctx == NULL) {
            return NGX_ERROR;
        }

        ngx_http_set_ctx(r, ctx, ngx_http_perl_module);

        ctx->request = r;
    }

    pmcf = ngx_http_get_module_main_conf(r, ngx_http_perl_module);

    ctx->ssi = ssi_ctx;

    handler = params[NGX_HTTP_PERL_SSI_SUB];
    handler->data[handler->len] = '\0';

    {

    dTHXa(pmcf->perl);
    PERL_SET_CONTEXT(pmcf->perl);
    PERL_SET_INTERP(pmcf->perl);

#if 0

    /* the code is disabled to force the precompiled perl code using only */

    ngx_http_perl_eval_anon_sub(aTHX_ handler, &sv);

    if (sv == &PL_sv_undef) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                      "eval_pv(\"%V\") failed", handler);
        return NGX_ERROR;
    }

    if (sv == NULL) {
        sv = newSVpvn((char *) handler->data, handler->len);
    }

#endif

    sv = newSVpvn((char *) handler->data, handler->len);

    args = &params[NGX_HTTP_PERL_SSI_ARG];

    if (args[0]) {

        for (i = 0; args[i]; i++) { /* void */ }

        asv = ngx_pcalloc(r->pool, (i + 1) * sizeof(SV *));

        if (asv == NULL) {
            SvREFCNT_dec(sv);
            return NGX_ERROR;
        }

        asv[0] = (SV *) (uintptr_t) i;

        for (i = 0; args[i]; i++) {
            asv[i + 1] = newSVpvn((char *) args[i]->data, args[i]->len);
        }

    } else {
        asv = NULL;
    }

    rc = ngx_http_perl_call_handler(aTHX_ r, ctx, pmcf->nginx, sv, asv,
                                    handler, NULL);

    SvREFCNT_dec(sv);

    }

    ctx->filename.data = NULL;
    ctx->redirect_uri.len = 0;
    ctx->ssi = NULL;

    ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "perl ssi done");

    return rc;
}

#endif


static char *
ngx_http_perl_init_interpreter(ngx_conf_t *cf, ngx_http_perl_main_conf_t *pmcf)
{
    ngx_str_t           *m;
    ngx_uint_t           i;
#if (NGX_HAVE_PERL_MULTIPLICITY)
    ngx_pool_cleanup_t  *cln;

    cln = ngx_pool_cleanup_add(cf->pool, 0);
    if (cln == NULL) {
        return NGX_CONF_ERROR;
    }

#endif

#ifdef NGX_PERL_MODULES
    if (pmcf->modules == NGX_CONF_UNSET_PTR) {

        pmcf->modules = ngx_array_create(cf->pool, 1, sizeof(ngx_str_t));
        if (pmcf->modules == NULL) {
            return NGX_CONF_ERROR;
        }

        m = ngx_array_push(pmcf->modules);
        if (m == NULL) {
            return NGX_CONF_ERROR;
        }

        ngx_str_set(m, NGX_PERL_MODULES);
    }
#endif

    if (pmcf->modules != NGX_CONF_UNSET_PTR) {
        m = pmcf->modules->elts;
        for (i = 0; i < pmcf->modules->nelts; i++) {
            if (ngx_conf_full_name(cf->cycle, &m[i], 0) != NGX_OK) {
                return NGX_CONF_ERROR;
            }
        }
    }

#if !(NGX_HAVE_PERL_MULTIPLICITY)

    if (perl) {

        if (ngx_set_environment(cf->cycle, NULL) == NULL) {
            return NGX_CONF_ERROR;
        }

        if (ngx_http_perl_run_requires(aTHX_ pmcf->requires, cf->log)
            != NGX_OK)
        {
            return NGX_CONF_ERROR;
        }

        pmcf->perl = perl;
        pmcf->nginx = nginx_stash;

        return NGX_CONF_OK;
    }

#endif

    if (nginx_stash == NULL) {
        PERL_SYS_INIT(&ngx_argc, &ngx_argv);
    }

    pmcf->perl = ngx_http_perl_create_interpreter(cf, pmcf);

    if (pmcf->perl == NULL) {
        return NGX_CONF_ERROR;
    }

    pmcf->nginx = nginx_stash;

#if (NGX_HAVE_PERL_MULTIPLICITY)

    cln->handler = ngx_http_perl_cleanup_perl;
    cln->data = pmcf->perl;

#else

    perl = pmcf->perl;

#endif

    return NGX_CONF_OK;
}


static PerlInterpreter *
ngx_http_perl_create_interpreter(ngx_conf_t *cf,
    ngx_http_perl_main_conf_t *pmcf)
{
    int                n;
    STRLEN             len;
    SV                *sv;
    char              *ver, **embedding;
    ngx_str_t         *m;
    ngx_uint_t         i;
    PerlInterpreter   *perl;

    ngx_log_debug0(NGX_LOG_DEBUG_HTTP, cf->log, 0, "create perl interpreter");

    if (ngx_set_environment(cf->cycle, NULL) == NULL) {
        return NULL;
    }

    perl = perl_alloc();
    if (perl == NULL) {
        ngx_log_error(NGX_LOG_ALERT, cf->log, 0, "perl_alloc() failed");
        return NULL;
    }

    {

    dTHXa(perl);
    PERL_SET_CONTEXT(perl);
    PERL_SET_INTERP(perl);

    perl_construct(perl);

#ifdef PERL_EXIT_DESTRUCT_END
    PL_exit_flags |= PERL_EXIT_DESTRUCT_END;
#endif

    n = (pmcf->modules != NGX_CONF_UNSET_PTR) ? pmcf->modules->nelts * 2 : 0;

    embedding = ngx_palloc(cf->pool, (5 + n) * sizeof(char *));
    if (embedding == NULL) {
        goto fail;
    }

    embedding[0] = "";

    if (n++) {
        m = pmcf->modules->elts;
        for (i = 0; i < pmcf->modules->nelts; i++) {
            embedding[2 * i + 1] = "-I";
            embedding[2 * i + 2] = (char *) m[i].data;
        }
    }

    embedding[n++] = "-Mnginx";
    embedding[n++] = "-e";
    embedding[n++] = "0";
    embedding[n] = NULL;

    n = perl_parse(perl, ngx_http_perl_xs_init, n, embedding, NULL);

    if (n != 0) {
        ngx_log_error(NGX_LOG_ALERT, cf->log, 0, "perl_parse() failed: %d", n);
        goto fail;
    }

    sv = get_sv("nginx::VERSION", FALSE);
    ver = SvPV(sv, len);

    if (ngx_strcmp(ver, NGINX_VERSION) != 0) {
        ngx_log_error(NGX_LOG_ALERT, cf->log, 0,
                      "version " NGINX_VERSION " of nginx.pm is required, "
                      "but %s was found", ver);
        goto fail;
    }

    if (ngx_http_perl_run_requires(aTHX_ pmcf->requires, cf->log) != NGX_OK) {
        goto fail;
    }

    }

    return perl;

fail:

    (void) perl_destruct(perl);

    perl_free(perl);

    return NULL;
}


static ngx_int_t
ngx_http_perl_run_requires(pTHX_ ngx_array_t *requires, ngx_log_t *log)
{
    u_char      *err;
    STRLEN       len;
    ngx_str_t   *script;
    ngx_uint_t   i;

    if (requires == NGX_CONF_UNSET_PTR) {
        return NGX_OK;
    }

    script = requires->elts;
    for (i = 0; i < requires->nelts; i++) {

        require_pv((char *) script[i].data);

        if (SvTRUE(ERRSV)) {

            err = (u_char *) SvPV(ERRSV, len);
            while (--len && (err[len] == CR || err[len] == LF)) { /* void */ }

            ngx_log_error(NGX_LOG_EMERG, log, 0,
                          "require_pv(\"%s\") failed: \"%*s\"",
                          script[i].data, len + 1, err);

            return NGX_ERROR;
        }
    }

    return NGX_OK;
}


static ngx_int_t
ngx_http_perl_call_handler(pTHX_ ngx_http_request_t *r,
    ngx_http_perl_ctx_t *ctx, HV *nginx, SV *sub, SV **args,
    ngx_str_t *handler, ngx_str_t *rv)
{
    SV                *sv;
    int                n, status;
    char              *line;
    u_char            *err;
    STRLEN             len, n_a;
    ngx_uint_t         i;
    ngx_connection_t  *c;

    dSP;

    status = 0;

    ctx->error = 0;
    ctx->status = NGX_OK;

    ENTER;
    SAVETMPS;

    PUSHMARK(sp);

    sv = sv_2mortal(sv_bless(newRV_noinc(newSViv(PTR2IV(ctx))), nginx));
    XPUSHs(sv);

    if (args) {
        EXTEND(sp, (intptr_t) args[0]);

        for (i = 1; i <= (uintptr_t) args[0]; i++) {
            PUSHs(sv_2mortal(args[i]));
        }
    }

    PUTBACK;

    c = r->connection;

    n = call_sv(sub, G_EVAL);

    SPAGAIN;

    if (n) {
        if (rv == NULL) {
            status = POPi;

            ngx_log_debug1(NGX_LOG_DEBUG_HTTP, c->log, 0,
                           "call_sv: %d", status);

        } else {
            line = SvPVx(POPs, n_a);
            rv->len = n_a;

            rv->data = ngx_pnalloc(r->pool, n_a);
            if (rv->data == NULL) {
                return NGX_ERROR;
            }

            ngx_memcpy(rv->data, line, n_a);
        }
    }

    PUTBACK;

    FREETMPS;
    LEAVE;

    if (ctx->error) {

        ngx_log_debug1(NGX_LOG_DEBUG_HTTP, c->log, 0,
                       "call_sv: error, %d", ctx->status);

        if (ctx->status != NGX_OK) {
            return ctx->status;
        }

        return NGX_ERROR;
    }

    /* check $@ */

    if (SvTRUE(ERRSV)) {

        err = (u_char *) SvPV(ERRSV, len);
        while (--len && (err[len] == CR || err[len] == LF)) { /* void */ }

        ngx_log_error(NGX_LOG_ERR, c->log, 0,
                      "call_sv(\"%V\") failed: \"%*s\"", handler, len + 1, err);

        if (rv) {
            return NGX_ERROR;
        }

        ctx->redirect_uri.len = 0;

        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    if (n != 1) {
        ngx_log_error(NGX_LOG_ALERT, c->log, 0,
                      "call_sv(\"%V\") returned %d results", handler, n);
        status = NGX_OK;
    }

    if (rv) {
        return NGX_OK;
    }

    return (ngx_int_t) status;
}


static void
ngx_http_perl_eval_anon_sub(pTHX_ ngx_str_t *handler, SV **sv)
{
    u_char  *p;

    for (p = handler->data; *p; p++) {
        if (*p != ' ' && *p != '\t' && *p != CR && *p != LF) {
            break;
        }
    }

    if (ngx_strncmp(p, "sub ", 4) == 0
        || ngx_strncmp(p, "sub{", 4) == 0
        || ngx_strncmp(p, "use ", 4) == 0)
    {
        *sv = eval_pv((char *) p, FALSE);

        /* eval_pv() does not set ERRSV on failure */

        return;
    }

    *sv = NULL;
}


static void *
ngx_http_perl_create_main_conf(ngx_conf_t *cf)
{
    ngx_http_perl_main_conf_t  *pmcf;

    pmcf = ngx_pcalloc(cf->pool, sizeof(ngx_http_perl_main_conf_t));
    if (pmcf == NULL) {
        return NULL;
    }

    pmcf->modules = NGX_CONF_UNSET_PTR;
    pmcf->requires = NGX_CONF_UNSET_PTR;

    return pmcf;
}


static char *
ngx_http_perl_init_main_conf(ngx_conf_t *cf, void *conf)
{
    ngx_http_perl_main_conf_t *pmcf = conf;

    if (pmcf->perl == NULL) {
        if (ngx_http_perl_init_interpreter(cf, pmcf) != NGX_CONF_OK) {
            return NGX_CONF_ERROR;
        }
    }

    return NGX_CONF_OK;
}


#if (NGX_HAVE_PERL_MULTIPLICITY)

static void
ngx_http_perl_cleanup_perl(void *data)
{
    PerlInterpreter  *perl = data;

    PERL_SET_CONTEXT(perl);
    PERL_SET_INTERP(perl);

    (void) perl_destruct(perl);

    perl_free(perl);

    if (ngx_perl_term) {
        ngx_log_debug0(NGX_LOG_DEBUG_HTTP, ngx_cycle->log, 0, "perl term");

        PERL_SYS_TERM();
    }
}

#endif


static ngx_int_t
ngx_http_perl_preconfiguration(ngx_conf_t *cf)
{
#if (NGX_HTTP_SSI)
    ngx_int_t                  rc;
    ngx_http_ssi_main_conf_t  *smcf;

    smcf = ngx_http_conf_get_module_main_conf(cf, ngx_http_ssi_filter_module);

    rc = ngx_hash_add_key(&smcf->commands, &ngx_http_perl_ssi_command.name,
                          &ngx_http_perl_ssi_command, NGX_HASH_READONLY_KEY);

    if (rc != NGX_OK) {
        if (rc == NGX_BUSY) {
            ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                               "conflicting SSI command \"%V\"",
                               &ngx_http_perl_ssi_command.name);
        }

        return NGX_ERROR;
    }
#endif

    return NGX_OK;
}


static void *
ngx_http_perl_create_loc_conf(ngx_conf_t *cf)
{
    ngx_http_perl_loc_conf_t *plcf;

    plcf = ngx_pcalloc(cf->pool, sizeof(ngx_http_perl_loc_conf_t));
    if (plcf == NULL) {
        return NULL;
    }

    /*
     * set by ngx_pcalloc():
     *
     *     plcf->handler = { 0, NULL };
     */

    return plcf;
}


static char *
ngx_http_perl_merge_loc_conf(ngx_conf_t *cf, void *parent, void *child)
{
    ngx_http_perl_loc_conf_t *prev = parent;
    ngx_http_perl_loc_conf_t *conf = child;

    if (conf->sub == NULL) {
        conf->sub = prev->sub;
        conf->handler = prev->handler;
    }

    return NGX_CONF_OK;
}


static char *
ngx_http_perl(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    ngx_http_perl_loc_conf_t *plcf = conf;

    ngx_str_t                  *value;
    ngx_http_core_loc_conf_t   *clcf;
    ngx_http_perl_main_conf_t  *pmcf;

    value = cf->args->elts;

    if (plcf->handler.data) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                           "duplicate perl handler \"%V\"", &value[1]);
        return NGX_CONF_ERROR;
    }

    pmcf = ngx_http_conf_get_module_main_conf(cf, ngx_http_perl_module);

    if (pmcf->perl == NULL) {
        if (ngx_http_perl_init_interpreter(cf, pmcf) != NGX_CONF_OK) {
            return NGX_CONF_ERROR;
        }
    }

    plcf->handler = value[1];

    {

    dTHXa(pmcf->perl);
    PERL_SET_CONTEXT(pmcf->perl);
    PERL_SET_INTERP(pmcf->perl);

    ngx_http_perl_eval_anon_sub(aTHX_ &value[1], &plcf->sub);

    if (plcf->sub == &PL_sv_undef) {
        ngx_conf_log_error(NGX_LOG_ERR, cf, 0,
                           "eval_pv(\"%V\") failed", &value[1]);
        return NGX_CONF_ERROR;
    }

    if (plcf->sub == NULL) {
        plcf->sub = newSVpvn((char *) value[1].data, value[1].len);
    }

    }

    clcf = ngx_http_conf_get_module_loc_conf(cf, ngx_http_core_module);
    clcf->handler = ngx_http_perl_handler;

    return NGX_CONF_OK;
}


static char *
ngx_http_perl_set(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    ngx_int_t                   index;
    ngx_str_t                  *value;
    ngx_http_variable_t        *v;
    ngx_http_perl_variable_t   *pv;
    ngx_http_perl_main_conf_t  *pmcf;

    value = cf->args->elts;

    if (value[1].data[0] != '$') {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                           "invalid variable name \"%V\"", &value[1]);
        return NGX_CONF_ERROR;
    }

    value[1].len--;
    value[1].data++;

    v = ngx_http_add_variable(cf, &value[1], NGX_HTTP_VAR_CHANGEABLE);
    if (v == NULL) {
        return NGX_CONF_ERROR;
    }

    pv = ngx_palloc(cf->pool, sizeof(ngx_http_perl_variable_t));
    if (pv == NULL) {
        return NGX_CONF_ERROR;
    }

    index = ngx_http_get_variable_index(cf, &value[1]);
    if (index == NGX_ERROR) {
        return NGX_CONF_ERROR;
    }

    pmcf = ngx_http_conf_get_module_main_conf(cf, ngx_http_perl_module);

    if (pmcf->perl == NULL) {
        if (ngx_http_perl_init_interpreter(cf, pmcf) != NGX_CONF_OK) {
            return NGX_CONF_ERROR;
        }
    }

    pv->handler = value[2];

    {

    dTHXa(pmcf->perl);
    PERL_SET_CONTEXT(pmcf->perl);
    PERL_SET_INTERP(pmcf->perl);

    ngx_http_perl_eval_anon_sub(aTHX_ &value[2], &pv->sub);

    if (pv->sub == &PL_sv_undef) {
        ngx_conf_log_error(NGX_LOG_ERR, cf, 0,
                           "eval_pv(\"%V\") failed", &value[2]);
        return NGX_CONF_ERROR;
    }

    if (pv->sub == NULL) {
        pv->sub = newSVpvn((char *) value[2].data, value[2].len);
    }

    }

    v->get_handler = ngx_http_perl_variable;
    v->data = (uintptr_t) pv;

    return NGX_CONF_OK;
}


static ngx_int_t
ngx_http_perl_init_worker(ngx_cycle_t *cycle)
{
    ngx_http_perl_main_conf_t  *pmcf;

    pmcf = ngx_http_cycle_get_module_main_conf(cycle, ngx_http_perl_module);

    if (pmcf) {
        dTHXa(pmcf->perl);
        PERL_SET_CONTEXT(pmcf->perl);
        PERL_SET_INTERP(pmcf->perl);

        /* set worker's $$ */

        sv_setiv(GvSV(gv_fetchpv("$", TRUE, SVt_PV)), (I32) ngx_pid);
    }

    return NGX_OK;
}


static void
ngx_http_perl_exit(ngx_cycle_t *cycle)
{
#if (NGX_HAVE_PERL_MULTIPLICITY)

    /*
     * the master exit hook is run before global pool cleanup,
     * therefore just set flag here
     */

    ngx_perl_term = 1;

#else

    if (nginx_stash) {
        ngx_log_debug0(NGX_LOG_DEBUG_HTTP, cycle->log, 0, "perl term");

        (void) perl_destruct(perl);

        perl_free(perl);

        PERL_SYS_TERM();
    }

#endif
}
