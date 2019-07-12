
/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) Nginx, Inc.
 */


#define PERL_NO_GET_CONTEXT

#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>
#include <ngx_http_perl_module.h>

#include "XSUB.h"


#define ngx_http_perl_set_request(r, ctx)                                     \
                                                                              \
    ctx = INT2PTR(ngx_http_perl_ctx_t *, SvIV((SV *) SvRV(ST(0))));           \
    r = ctx->request


#define ngx_http_perl_set_targ(p, len)                                        \
                                                                              \
    SvUPGRADE(TARG, SVt_PV);                                                  \
    SvPOK_on(TARG);                                                           \
    sv_setpvn(TARG, (char *) p, len)


static ngx_int_t
ngx_http_perl_sv2str(pTHX_ ngx_http_request_t *r, ngx_str_t *s, SV *sv)
{
    u_char  *p;
    STRLEN   len;

    if (SvROK(sv) && SvTYPE(SvRV(sv)) == SVt_PV) {
        sv = SvRV(sv);
    }

    p = (u_char *) SvPV(sv, len);

    s->len = len;

    if (SvREADONLY(sv) && SvPOK(sv)) {
        s->data = p;

        ngx_log_debug2(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                       "perl sv2str: %08XD \"%V\"", sv->sv_flags, s);

        return NGX_OK;
    }

    s->data = ngx_pnalloc(r->pool, len);
    if (s->data == NULL) {
        return NGX_ERROR;
    }

    ngx_memcpy(s->data, p, len);

    ngx_log_debug2(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "perl sv2str: %08XD \"%V\"", sv->sv_flags, s);

    return NGX_OK;
}


static ngx_int_t
ngx_http_perl_output(ngx_http_request_t *r, ngx_http_perl_ctx_t *ctx,
    ngx_buf_t *b)
{
    ngx_chain_t   out;
#if (NGX_HTTP_SSI)
    ngx_chain_t  *cl;

    if (ctx->ssi) {
        cl = ngx_alloc_chain_link(r->pool);
        if (cl == NULL) {
            return NGX_ERROR;
        }

        cl->buf = b;
        cl->next = NULL;
        *ctx->ssi->last_out = cl;
        ctx->ssi->last_out = &cl->next;

        return NGX_OK;
    }
#endif

    out.buf = b;
    out.next = NULL;

    return ngx_http_output_filter(r, &out);
}


MODULE = nginx    PACKAGE = nginx


PROTOTYPES: DISABLE


void
status(r, code)
    CODE:

    ngx_http_request_t   *r;
    ngx_http_perl_ctx_t  *ctx;

    ngx_http_perl_set_request(r, ctx);

    r->headers_out.status = SvIV(ST(1));

    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "perl status: %d", r->headers_out.status);

    XSRETURN_UNDEF;


void
send_http_header(r, ...)
    CODE:

    ngx_http_request_t   *r;
    ngx_http_perl_ctx_t  *ctx;
    SV                   *sv;
    ngx_int_t             rc;

    ngx_http_perl_set_request(r, ctx);

    if (ctx->error) {
        croak("send_http_header(): called after error");
    }

    if (r->headers_out.status == 0) {
        r->headers_out.status = NGX_HTTP_OK;
    }

    if (items != 1) {
        sv = ST(1);

        if (ngx_http_perl_sv2str(aTHX_ r, &r->headers_out.content_type, sv)
            != NGX_OK)
        {
            ctx->error = 1;
            croak("ngx_http_perl_sv2str() failed");
        }

        r->headers_out.content_type_len = r->headers_out.content_type.len;

    } else {
        if (ngx_http_set_content_type(r) != NGX_OK) {
            ctx->error = 1;
            croak("ngx_http_set_content_type() failed");
        }
    }

    r->disable_not_modified = 1;

    rc = ngx_http_send_header(r);

    if (rc == NGX_ERROR || rc > NGX_OK) {
        ctx->error = 1;
        ctx->status = rc;
        croak("ngx_http_send_header() failed");
    }


void
header_only(r)
    CODE:

    dXSTARG;
    ngx_http_request_t   *r;
    ngx_http_perl_ctx_t  *ctx;

    ngx_http_perl_set_request(r, ctx);

    sv_upgrade(TARG, SVt_IV);
    sv_setiv(TARG, r->header_only);

    ST(0) = TARG;


void
uri(r)
    CODE:

    dXSTARG;
    ngx_http_request_t   *r;
    ngx_http_perl_ctx_t  *ctx;

    ngx_http_perl_set_request(r, ctx);
    ngx_http_perl_set_targ(r->uri.data, r->uri.len);

    ST(0) = TARG;


void
args(r)
    CODE:

    dXSTARG;
    ngx_http_request_t   *r;
    ngx_http_perl_ctx_t  *ctx;

    ngx_http_perl_set_request(r, ctx);
    ngx_http_perl_set_targ(r->args.data, r->args.len);

    ST(0) = TARG;


void
request_method(r)
    CODE:

    dXSTARG;
    ngx_http_request_t   *r;
    ngx_http_perl_ctx_t  *ctx;

    ngx_http_perl_set_request(r, ctx);
    ngx_http_perl_set_targ(r->method_name.data, r->method_name.len);

    ST(0) = TARG;


void
remote_addr(r)
    CODE:

    dXSTARG;
    ngx_http_request_t   *r;
    ngx_http_perl_ctx_t  *ctx;

    ngx_http_perl_set_request(r, ctx);
    ngx_http_perl_set_targ(r->connection->addr_text.data,
                           r->connection->addr_text.len);

    ST(0) = TARG;


void
header_in(r, key)
    CODE:

    dXSTARG;
    ngx_http_request_t         *r;
    ngx_http_perl_ctx_t        *ctx;
    SV                         *key;
    u_char                     *p, *lowcase_key, *value, sep;
    STRLEN                      len;
    ssize_t                     size;
    ngx_uint_t                  i, n, hash;
    ngx_array_t                *a;
    ngx_list_part_t            *part;
    ngx_table_elt_t            *h, **ph;
    ngx_http_header_t          *hh;
    ngx_http_core_main_conf_t  *cmcf;

    ngx_http_perl_set_request(r, ctx);

    key = ST(1);

    if (SvROK(key) && SvTYPE(SvRV(key)) == SVt_PV) {
        key = SvRV(key);
    }

    p = (u_char *) SvPV(key, len);

    /* look up hashed headers */

    lowcase_key = ngx_pnalloc(r->pool, len);
    if (lowcase_key == NULL) {
        ctx->error = 1;
        croak("ngx_pnalloc() failed");
    }

    hash = ngx_hash_strlow(lowcase_key, p, len);

    cmcf = ngx_http_get_module_main_conf(r, ngx_http_core_module);

    hh = ngx_hash_find(&cmcf->headers_in_hash, hash, lowcase_key, len);

    if (hh) {

        if (hh->offset == offsetof(ngx_http_headers_in_t, cookies)) {
            sep = ';';
            goto multi;
        }
#if (NGX_HTTP_X_FORWARDED_FOR)
        if (hh->offset == offsetof(ngx_http_headers_in_t, x_forwarded_for)) {
            sep = ',';
            goto multi;
        }
#endif

        ph = (ngx_table_elt_t **) ((char *) &r->headers_in + hh->offset);

        if (*ph) {
            ngx_http_perl_set_targ((*ph)->value.data, (*ph)->value.len);

            goto done;
        }

        XSRETURN_UNDEF;

    multi:

        /* Cookie, X-Forwarded-For */

        a = (ngx_array_t *) ((char *) &r->headers_in + hh->offset);

        n = a->nelts;

        if (n == 0) {
            XSRETURN_UNDEF;
        }

        ph = a->elts;

        if (n == 1) {
            ngx_http_perl_set_targ((*ph)->value.data, (*ph)->value.len);

            goto done;
        }

        size = - (ssize_t) (sizeof("; ") - 1);

        for (i = 0; i < n; i++) {
            size += ph[i]->value.len + sizeof("; ") - 1;
        }

        value = ngx_pnalloc(r->pool, size);
        if (value == NULL) {
            ctx->error = 1;
            croak("ngx_pnalloc() failed");
        }

        p = value;

        for (i = 0; /* void */ ; i++) {
            p = ngx_copy(p, ph[i]->value.data, ph[i]->value.len);

            if (i == n - 1) {
                break;
            }

            *p++ = sep; *p++ = ' ';
        }

        ngx_http_perl_set_targ(value, size);

        goto done;
    }

    /* iterate over all headers */

    part = &r->headers_in.headers.part;
    h = part->elts;

    for (i = 0; /* void */ ; i++) {

        if (i >= part->nelts) {
            if (part->next == NULL) {
                break;
            }

            part = part->next;
            h = part->elts;
            i = 0;
        }

        if (len != h[i].key.len
            || ngx_strcasecmp(p, h[i].key.data) != 0)
        {
            continue;
        }

        ngx_http_perl_set_targ(h[i].value.data, h[i].value.len);

        goto done;
    }

    XSRETURN_UNDEF;

    done:

    ST(0) = TARG;


void
has_request_body(r, next)
    CODE:

    dXSTARG;
    ngx_http_request_t   *r;
    ngx_http_perl_ctx_t  *ctx;
    ngx_int_t             rc;

    ngx_http_perl_set_request(r, ctx);

    if (ctx->next) {
        croak("has_request_body(): another handler active");
    }

    if (r->headers_in.content_length_n <= 0 && !r->headers_in.chunked) {
        XSRETURN_UNDEF;
    }

    ctx->next = SvRV(ST(1));

    r->request_body_in_single_buf = 1;
    r->request_body_in_persistent_file = 1;
    r->request_body_in_clean_file = 1;

    if (r->request_body_in_file_only) {
        r->request_body_file_log_level = 0;
    }

    rc = ngx_http_read_client_request_body(r, ngx_http_perl_handle_request);

    if (rc >= NGX_HTTP_SPECIAL_RESPONSE) {
        ctx->error = 1;
        ctx->status = rc;
        ctx->next = NULL;
        croak("ngx_http_read_client_request_body() failed");
    }

    sv_upgrade(TARG, SVt_IV);
    sv_setiv(TARG, 1);

    ST(0) = TARG;


void
request_body(r)
    CODE:

    dXSTARG;
    ngx_http_request_t   *r;
    ngx_http_perl_ctx_t  *ctx;
    u_char               *p, *data;
    size_t                len;
    ngx_buf_t            *buf;
    ngx_chain_t          *cl;

    ngx_http_perl_set_request(r, ctx);

    if (r->request_body == NULL
        || r->request_body->temp_file
        || r->request_body->bufs == NULL)
    {
        XSRETURN_UNDEF;
    }

    cl = r->request_body->bufs;
    buf = cl->buf;

    if (cl->next == NULL) {
        len = buf->last - buf->pos;
        data = buf->pos;
        goto done;
    }

    len = buf->last - buf->pos;
    cl = cl->next;

    for ( /* void */ ; cl; cl = cl->next) {
        buf = cl->buf;
        len += buf->last - buf->pos;
    }

    p = ngx_pnalloc(r->pool, len);
    if (p == NULL) {
        ctx->error = 1;
        croak("ngx_pnalloc() failed");
    }

    data = p;
    cl = r->request_body->bufs;

    for ( /* void */ ; cl; cl = cl->next) {
        buf = cl->buf;
        p = ngx_cpymem(p, buf->pos, buf->last - buf->pos);
    }

    done:

    if (len == 0) {
        XSRETURN_UNDEF;
    }

    ngx_http_perl_set_targ(data, len);

    ST(0) = TARG;


void
request_body_file(r)
    CODE:

    dXSTARG;
    ngx_http_request_t   *r;
    ngx_http_perl_ctx_t  *ctx;

    ngx_http_perl_set_request(r, ctx);

    if (r->request_body == NULL || r->request_body->temp_file == NULL) {
        XSRETURN_UNDEF;
    }

    ngx_http_perl_set_targ(r->request_body->temp_file->file.name.data,
                           r->request_body->temp_file->file.name.len);

    ST(0) = TARG;


void
discard_request_body(r)
    CODE:

    ngx_http_request_t   *r;
    ngx_http_perl_ctx_t  *ctx;
    ngx_int_t             rc;

    ngx_http_perl_set_request(r, ctx);

    rc = ngx_http_discard_request_body(r);

    if (rc != NGX_OK) {
        ctx->error = 1;
        ctx->status = rc;
        croak("ngx_http_discard_request_body() failed");
    }


void
header_out(r, key, value)
    CODE:

    ngx_http_request_t   *r;
    ngx_http_perl_ctx_t  *ctx;
    SV                   *key;
    SV                   *value;
    ngx_table_elt_t      *header;

    ngx_http_perl_set_request(r, ctx);

    if (ctx->error) {
        croak("header_out(): called after error");
    }

    key = ST(1);
    value = ST(2);

    header = ngx_list_push(&r->headers_out.headers);
    if (header == NULL) {
        ctx->error = 1;
        croak("ngx_list_push() failed");
    }

    header->hash = 1;

    if (ngx_http_perl_sv2str(aTHX_ r, &header->key, key) != NGX_OK) {
        header->hash = 0;
        ctx->error = 1;
        croak("ngx_http_perl_sv2str() failed");
    }

    if (ngx_http_perl_sv2str(aTHX_ r, &header->value, value) != NGX_OK) {
        header->hash = 0;
        ctx->error = 1;
        croak("ngx_http_perl_sv2str() failed");
    }

    if (header->key.len == sizeof("Content-Length") - 1
        && ngx_strncasecmp(header->key.data, (u_char *) "Content-Length",
                           sizeof("Content-Length") - 1) == 0)
    {
        r->headers_out.content_length_n = (off_t) SvIV(value);
        r->headers_out.content_length = header;
    }

    if (header->key.len == sizeof("Content-Encoding") - 1
        && ngx_strncasecmp(header->key.data, (u_char *) "Content-Encoding",
                           sizeof("Content-Encoding") - 1) == 0)
    {
        r->headers_out.content_encoding = header;
    }


void
filename(r)
    CODE:

    dXSTARG;
    ngx_http_request_t   *r;
    ngx_http_perl_ctx_t  *ctx;
    size_t                root;

    ngx_http_perl_set_request(r, ctx);

    if (ctx->filename.data) {
        goto done;
    }

    if (ngx_http_map_uri_to_path(r, &ctx->filename, &root, 0) == NULL) {
        ctx->error = 1;
        croak("ngx_http_map_uri_to_path() failed");
    }

    ctx->filename.len--;
    sv_setpv(PL_statname, (char *) ctx->filename.data);

    done:

    ngx_http_perl_set_targ(ctx->filename.data, ctx->filename.len);

    ST(0) = TARG;


void
print(r, ...)
    CODE:

    ngx_http_request_t   *r;
    ngx_http_perl_ctx_t  *ctx;
    SV                   *sv;
    int                   i;
    u_char               *p;
    size_t                size;
    STRLEN                len;
    ngx_int_t             rc;
    ngx_buf_t            *b;

    ngx_http_perl_set_request(r, ctx);

    if (ctx->error) {
        croak("print(): called after error");
    }

    if (items == 2) {

        /*
         * do zero copy for prolate single read-only SV:
         *     $r->print("some text\n");
         */

        sv = ST(1);

        if (SvROK(sv) && SvTYPE(SvRV(sv)) == SVt_PV) {
            sv = SvRV(sv);
        }

        if (SvREADONLY(sv) && SvPOK(sv)) {

            p = (u_char *) SvPV(sv, len);

            if (len == 0) {
                XSRETURN_EMPTY;
            }

            b = ngx_calloc_buf(r->pool);
            if (b == NULL) {
                ctx->error = 1;
                croak("ngx_calloc_buf() failed");
            }

            b->memory = 1;
            b->pos = p;
            b->last = p + len;
            b->start = p;
            b->end = b->last;

            ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                           "$r->print: read-only SV: %z", len);

            goto out;
        }
    }

    size = 0;

    for (i = 1; i < items; i++) {

        sv = ST(i);

        if (SvROK(sv) && SvTYPE(SvRV(sv)) == SVt_PV) {
            sv = SvRV(sv);
        }

        (void) SvPV(sv, len);

        ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                       "$r->print: copy SV: %z", len);

        size += len;
    }

    if (size == 0) {
        XSRETURN_EMPTY;
    }

    b = ngx_create_temp_buf(r->pool, size);
    if (b == NULL) {
        ctx->error = 1;
        croak("ngx_create_temp_buf() failed");
    }

    for (i = 1; i < items; i++) {
        sv = ST(i);

        if (SvROK(sv) && SvTYPE(SvRV(sv)) == SVt_PV) {
            sv = SvRV(sv);
        }

        p = (u_char *) SvPV(sv, len);
        b->last = ngx_cpymem(b->last, p, len);
    }

    out:

    rc = ngx_http_perl_output(r, ctx, b);

    if (rc == NGX_ERROR) {
        ctx->error = 1;
        croak("ngx_http_perl_output() failed");
    }


void
sendfile(r, filename, offset = -1, bytes = 0)
    CODE:

    ngx_http_request_t        *r;
    ngx_http_perl_ctx_t       *ctx;
    char                      *filename;
    off_t                      offset;
    size_t                     bytes;
    ngx_int_t                  rc;
    ngx_str_t                  path;
    ngx_buf_t                 *b;
    ngx_open_file_info_t       of;
    ngx_http_core_loc_conf_t  *clcf;

    ngx_http_perl_set_request(r, ctx);

    if (ctx->error) {
        croak("sendfile(): called after error");
    }

    filename = SvPV_nolen(ST(1));

    if (filename == NULL) {
        croak("sendfile(): NULL filename");
    }

    offset = items < 3 ? -1 : SvIV(ST(2));
    bytes = items < 4 ? 0 : SvIV(ST(3));

    b = ngx_calloc_buf(r->pool);
    if (b == NULL) {
        ctx->error = 1;
        croak("ngx_calloc_buf() failed");
    }

    b->file = ngx_pcalloc(r->pool, sizeof(ngx_file_t));
    if (b->file == NULL) {
        ctx->error = 1;
        croak("ngx_pcalloc() failed");
    }

    path.len = ngx_strlen(filename);

    path.data = ngx_pnalloc(r->pool, path.len + 1);
    if (path.data == NULL) {
        ctx->error = 1;
        croak("ngx_pnalloc() failed");
    }

    (void) ngx_cpystrn(path.data, (u_char *) filename, path.len + 1);

    clcf = ngx_http_get_module_loc_conf(r, ngx_http_core_module);

    ngx_memzero(&of, sizeof(ngx_open_file_info_t));

    of.read_ahead = clcf->read_ahead;
    of.directio = clcf->directio;
    of.valid = clcf->open_file_cache_valid;
    of.min_uses = clcf->open_file_cache_min_uses;
    of.errors = clcf->open_file_cache_errors;
    of.events = clcf->open_file_cache_events;

    if (ngx_http_set_disable_symlinks(r, clcf, &path, &of) != NGX_OK) {
        ctx->error = 1;
        croak("ngx_http_set_disable_symlinks() failed");
    }

    if (ngx_open_cached_file(clcf->open_file_cache, &path, &of, r->pool)
        != NGX_OK)
    {
        if (of.err == 0) {
            ctx->error = 1;
            croak("ngx_open_cached_file() failed");
        }

        ngx_log_error(NGX_LOG_CRIT, r->connection->log, ngx_errno,
                      "%s \"%s\" failed", of.failed, filename);

        ctx->error = 1;
        croak("ngx_open_cached_file() failed");
    }

    if (offset == -1) {
        offset = 0;
    }

    if (bytes == 0) {
        bytes = of.size - offset;
    }

    b->in_file = 1;

    b->file_pos = offset;
    b->file_last = offset + bytes;

    b->file->fd = of.fd;
    b->file->log = r->connection->log;
    b->file->directio = of.is_directio;

    rc = ngx_http_perl_output(r, ctx, b);

    if (rc == NGX_ERROR) {
        ctx->error = 1;
        croak("ngx_http_perl_output() failed");
    }


void
flush(r)
    CODE:

    ngx_http_request_t   *r;
    ngx_http_perl_ctx_t  *ctx;
    ngx_int_t             rc;
    ngx_buf_t            *b;

    ngx_http_perl_set_request(r, ctx);

    if (ctx->error) {
        croak("flush(): called after error");
    }

    b = ngx_calloc_buf(r->pool);
    if (b == NULL) {
        ctx->error = 1;
        croak("ngx_calloc_buf() failed");
    }

    b->flush = 1;

    ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "$r->flush");

    rc = ngx_http_perl_output(r, ctx, b);

    if (rc == NGX_ERROR) {
        ctx->error = 1;
        croak("ngx_http_perl_output() failed");
    }

    XSRETURN_EMPTY;


void
internal_redirect(r, uri)
    CODE:

    ngx_http_request_t   *r;
    ngx_http_perl_ctx_t  *ctx;
    SV                   *uri;
    ngx_uint_t            i;

    ngx_http_perl_set_request(r, ctx);

    uri = ST(1);

    if (ngx_http_perl_sv2str(aTHX_ r, &ctx->redirect_uri, uri) != NGX_OK) {
        ctx->error = 1;
        croak("ngx_http_perl_sv2str() failed");
    }

    for (i = 0; i < ctx->redirect_uri.len; i++) {
        if (ctx->redirect_uri.data[i] == '?') {

            ctx->redirect_args.len = ctx->redirect_uri.len - (i + 1);
            ctx->redirect_args.data = &ctx->redirect_uri.data[i + 1];
            ctx->redirect_uri.len = i;

            XSRETURN_EMPTY;
        }
    }


void
allow_ranges(r)
    CODE:

    ngx_http_request_t   *r;
    ngx_http_perl_ctx_t  *ctx;

    ngx_http_perl_set_request(r, ctx);

    r->allow_ranges = 1;


void
unescape(r, text, type = 0)
    CODE:

    dXSTARG;
    ngx_http_request_t   *r;
    ngx_http_perl_ctx_t  *ctx;
    SV                   *text;
    int                   type;
    u_char               *p, *dst, *src;
    STRLEN                len;

    ngx_http_perl_set_request(r, ctx);

    text = ST(1);

    src = (u_char *) SvPV(text, len);

    p = ngx_pnalloc(r->pool, len + 1);
    if (p == NULL) {
        ctx->error = 1;
        croak("ngx_pnalloc() failed");
    }

    dst = p;

    type = items < 3 ? 0 : SvIV(ST(2));

    ngx_unescape_uri(&dst, &src, len, (ngx_uint_t) type);
    *dst = '\0';

    ngx_http_perl_set_targ(p, dst - p);

    ST(0) = TARG;


void
variable(r, name, value = NULL)
    CODE:

    dXSTARG;
    ngx_http_request_t         *r;
    ngx_http_perl_ctx_t        *ctx;
    SV                         *name, *value;
    u_char                     *p, *lowcase;
    STRLEN                      len;
    ngx_str_t                   var, val;
    ngx_uint_t                  i, hash;
    ngx_http_perl_var_t        *v;
    ngx_http_variable_value_t  *vv;

    ngx_http_perl_set_request(r, ctx);

    name = ST(1);

    if (SvROK(name) && SvTYPE(SvRV(name)) == SVt_PV) {
        name = SvRV(name);
    }

    if (items == 2) {
        value = NULL;

    } else {
        value = ST(2);

        if (SvROK(value) && SvTYPE(SvRV(value)) == SVt_PV) {
            value = SvRV(value);
        }

        if (ngx_http_perl_sv2str(aTHX_ r, &val, value) != NGX_OK) {
            ctx->error = 1;
            croak("ngx_http_perl_sv2str() failed");
        }
    }

    p = (u_char *) SvPV(name, len);

    lowcase = ngx_pnalloc(r->pool, len);
    if (lowcase == NULL) {
        ctx->error = 1;
        croak("ngx_pnalloc() failed");
    }

    hash = ngx_hash_strlow(lowcase, p, len);

    var.len = len;
    var.data = lowcase;
#if (NGX_DEBUG)

    if (value) {
        ngx_log_debug2(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                       "perl variable: \"%V\"=\"%V\"", &var, &val);
    } else {
        ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                       "perl variable: \"%V\"", &var);
    }
#endif

    vv = ngx_http_get_variable(r, &var, hash);
    if (vv == NULL) {
        ctx->error = 1;
        croak("ngx_http_get_variable() failed");
    }

    if (vv->not_found) {

        if (ctx->variables) {

            v = ctx->variables->elts;
            for (i = 0; i < ctx->variables->nelts; i++) {

                if (hash != v[i].hash
                    || len != v[i].name.len
                    || ngx_strncmp(lowcase, v[i].name.data, len) != 0)
                {
                    continue;
                }

                if (value) {
                    v[i].value = val;
                    XSRETURN_UNDEF;
                }

                ngx_http_perl_set_targ(v[i].value.data, v[i].value.len);

                goto done;
            }
        }

        if (value) {
            if (ctx->variables == NULL) {
                ctx->variables = ngx_array_create(r->pool, 1,
                                                  sizeof(ngx_http_perl_var_t));
                if (ctx->variables == NULL) {
                    ctx->error = 1;
                    croak("ngx_array_create() failed");
                }
            }

            v = ngx_array_push(ctx->variables);
            if (v == NULL) {
                ctx->error = 1;
                croak("ngx_array_push() failed");
            }

            v->hash = hash;
            v->name.len = len;
            v->name.data = lowcase;
            v->value = val;

            XSRETURN_UNDEF;
        }

        XSRETURN_UNDEF;
    }

    if (value) {
        vv->len = val.len;
        vv->valid = 1;
        vv->no_cacheable = 0;
        vv->not_found = 0;
        vv->data = val.data;

        XSRETURN_UNDEF;
    }

    ngx_http_perl_set_targ(vv->data, vv->len);

    done:

    ST(0) = TARG;


void
sleep(r, sleep, next)
    CODE:

    ngx_http_request_t   *r;
    ngx_http_perl_ctx_t  *ctx;
    ngx_msec_t            sleep;

    ngx_http_perl_set_request(r, ctx);

    if (ctx->next) {
        croak("sleep(): another handler active");
    }

    sleep = (ngx_msec_t) SvIV(ST(1));

    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "perl sleep: %M", sleep);

    ctx->next = SvRV(ST(2));

    r->connection->write->delayed = 1;
    ngx_add_timer(r->connection->write, sleep);

    r->write_event_handler = ngx_http_perl_sleep_handler;
    r->main->count++;


void
log_error(r, err, msg)
    CODE:

    ngx_http_request_t   *r;
    ngx_http_perl_ctx_t  *ctx;
    SV                   *err, *msg;
    u_char               *p;
    STRLEN                len;
    ngx_err_t             e;

    ngx_http_perl_set_request(r, ctx);

    err = ST(1);

    if (SvROK(err) && SvTYPE(SvRV(err)) == SVt_PV) {
        err = SvRV(err);
    }

    e = SvIV(err);

    msg = ST(2);

    if (SvROK(msg) && SvTYPE(SvRV(msg)) == SVt_PV) {
        msg = SvRV(msg);
    }

    p = (u_char *) SvPV(msg, len);

    ngx_log_error(NGX_LOG_ERR, r->connection->log, e, "perl: %s", p);
