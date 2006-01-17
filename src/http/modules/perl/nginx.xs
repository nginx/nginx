
/*
 * Copyright (C) Igor Sysoev
 */


#define PERL_NO_GET_CONTEXT

#include "EXTERN.h"
#include "perl.h"
#include "XSUB.h"

#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>
#include <ngx_http_perl_module.h>


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

    if (SvREADONLY(sv)) {
        s->data = p;
        return NGX_OK;
    }

    s->data = ngx_palloc(r->pool, len);
    if (s->data == NULL) {
        return NGX_ERROR;
    }

    ngx_memcpy(s->data, p, len);

    return NGX_OK;
}


static ngx_int_t
ngx_http_perl_output(ngx_http_request_t *r, ngx_buf_t *b)
{
    ngx_chain_t          *cl, out;
    ngx_http_perl_ctx_t  *ctx;

    ctx = ngx_http_get_module_ctx(r, ngx_http_perl_module);

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

    out.buf = b;
    out.next = NULL;

    return ngx_http_output_filter(r, &out);
}


MODULE = nginx    PACKAGE = nginx


int
send_http_header(r, ...)
    nginx   r

    PREINIT:

    SV     *sv;

    CODE:

    if (r->headers_out.status == 0) {
        r->headers_out.status = NGX_HTTP_OK;
    }

    if (items != 1) {
        sv = ST(1);

        if (ngx_http_perl_sv2str(aTHX_ r, &r->headers_out.content_type, sv)
            != NGX_OK)
        {
            RETVAL = NGX_ERROR;
            goto done;
        }

    } else {
        if (r->headers_out.content_type.len == 0) {
            if (ngx_http_set_content_type(r) != NGX_OK) {
                RETVAL = NGX_ERROR;
                goto done;
            }
        }
    }

    RETVAL = ngx_http_send_header(r);

    done:

    OUTPUT:
    RETVAL


int
header_only(r)
    nginx  r

    CODE:
    RETVAL = r->header_only;

    OUTPUT:
    RETVAL


# The returning "char *" is more quickly than creating SV, because SV returned
# from XS is never used as permanent storage. Even in simple case:
# "$uri = $r->uri" the SV returned by $r->uri is copied to $uri's SV.

char *
uri(r, ...)
    nginx  r

    CODE:

    if (items != 1) {
        croak("$r->uri(text) is not implemented");
    }

    RETVAL = ngx_palloc(r->pool, r->uri.len + 1);
    if (RETVAL == NULL) {
        XSRETURN_UNDEF;
    }

    ngx_cpystrn((u_char *) RETVAL, r->uri.data, r->uri.len + 1);

    OUTPUT:
    RETVAL


char *
args(r, ...)
    nginx  r

    CODE:

    if (items != 1) {
        croak("$r->args(text) is not implemented");
    }

    RETVAL = ngx_palloc(r->pool, r->args.len + 1);
    if (RETVAL == NULL) {
        XSRETURN_UNDEF;
    }

    ngx_cpystrn((u_char *) RETVAL, r->args.data, r->args.len + 1);

    OUTPUT:
    RETVAL


char *
header_in(r, key)
    nginx             r
    SV               *key

    PREINIT:

    u_char           *p;
    STRLEN            len;
    ngx_uint_t        i;
    ngx_list_part_t  *part;
    ngx_table_elt_t  *header;

    CODE:

    if (SvROK(key) && SvTYPE(SvRV(key)) == SVt_PV) {
        key = SvRV(key);
    }

    p = (u_char *) SvPV(key, len);

    part = &r->headers_in.headers.part;
    header = part->elts;

    for (i = 0; /* void */ ; i++) {

        if (i >= part->nelts) {
            if (part->next == NULL) {
                break;
            }

            part = part->next;
            header = part->elts;
            i = 0;
        }

        if (len != header[i].key.len
            || ngx_strcasecmp(p, header[i].key.data) != 0)
        {
            continue;
        }

        RETVAL = (char *) header[i].value.data;

        goto done;
    }

    XSRETURN_UNDEF;

    done:

    OUTPUT:
    RETVAL


int
header_out(r, key, value)
    nginx             r
    SV               *key
    SV               *value

    PREINIT:

    ngx_table_elt_t  *header;

    CODE:

    header = ngx_list_push(&r->headers_out.headers);
    if (header == NULL) {
        RETVAL = NGX_ERROR;
        goto done;
    }

    header->hash = 1;

    if (ngx_http_perl_sv2str(aTHX_ r, &header->key, key) != NGX_OK) {
        RETVAL = NGX_ERROR;
        goto done;
    }

    if (ngx_http_perl_sv2str(aTHX_ r, &header->value, value) != NGX_OK) {
        RETVAL = NGX_ERROR;
        goto done;
    }

    if (header->key.len == sizeof("Content-Length") - 1
        && ngx_strncasecmp(header->key.data, "Content-Length",
                           sizeof("Content-Length") - 1) == 0
        && SvIOK(value))
    {
        r->headers_out.content_length_n = (ssize_t) SvIV(value);;
        r->headers_out.content_length = header;
    }

    RETVAL = NGX_OK;

    done:

    OUTPUT:
    RETVAL


char *
filename(r)
    nginx                 r

    PREINIT:

    ngx_str_t             path;
    ngx_http_perl_ctx_t  *ctx;

    CODE:

    ctx = ngx_http_get_module_ctx(r, ngx_http_perl_module);
    if (ctx->filename) {
        goto done;
    }

    if (ngx_http_map_uri_to_path(r, &path, 0) == NULL) {
        XSRETURN_UNDEF;
    }

    ctx->filename = (char *) path.data;

    sv_setpv(PL_statname, ctx->filename);

    done:

    RETVAL = ctx->filename;

    OUTPUT:
    RETVAL


int
print(r, ...)
    nginx       r

    PREINIT:

    SV         *sv;
    int         i;
    u_char     *p;
    size_t      size;
    STRLEN      len;
    ngx_buf_t  *b;

    CODE:

    RETVAL = NGX_OK;

    if (items == 2) {

        /*
         * do zero copy for prolate single read-only SV:
         *     $r->print("some text\n");
         */

        sv = ST(1);

        if (SvROK(sv) && SvTYPE(SvRV(sv)) == SVt_PV) {
            sv = SvRV(sv);
        }

        if (SvREADONLY(sv)) {

            p = (u_char *) SvPV(sv, len);

            if (len == 0) {
                goto done;
            }

            b = ngx_calloc_buf(r->pool);
            if (b == NULL) {
                RETVAL = NGX_ERROR;
                goto done;
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
        goto done;
    }

    b = ngx_create_temp_buf(r->pool, size);
    if (b == NULL) {
        RETVAL = NGX_ERROR;
        goto done;
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

    RETVAL = ngx_http_perl_output(r, b);

    done:

    OUTPUT:
    RETVAL


int
sendfile(r, filename)
    nginx                     r
    char                     *filename

    PREINIT:

    ngx_fd_t                  fd;
    ngx_buf_t                *b;
    ngx_file_info_t           fi;
    ngx_pool_cleanup_t       *cln;
    ngx_pool_cleanup_file_t  *clnf;

    CODE:

    if (filename == NULL) {
        croak("sendfile(): NULL filename");
    }

    b = ngx_calloc_buf(r->pool);
    if (b == NULL) {
        RETVAL = NGX_ERROR;
        goto done;
    }

    b->file = ngx_pcalloc(r->pool, sizeof(ngx_file_t));
    if (b->file == NULL) {
        RETVAL = NGX_ERROR;
        goto done;
    }

    cln = ngx_pool_cleanup_add(r->pool, sizeof(ngx_pool_cleanup_file_t));
    if (cln == NULL) {
        RETVAL = NGX_ERROR;
        goto done;
    }

    fd = ngx_open_file((u_char *) filename, NGX_FILE_RDONLY, NGX_FILE_OPEN);

    if (fd == NGX_INVALID_FILE) {
        ngx_log_error(NGX_LOG_CRIT, r->connection->log, ngx_errno,
                      ngx_open_file_n " \"%s\" failed", filename);
        RETVAL = NGX_ERROR;
        goto done;
    }

    if (ngx_fd_info(fd, &fi) == NGX_FILE_ERROR) {
        ngx_log_error(NGX_LOG_CRIT, r->connection->log, ngx_errno,
                      ngx_fd_info_n " \"%s\" failed", filename);

        if (ngx_close_file(fd) == NGX_FILE_ERROR) {
            ngx_log_error(NGX_LOG_ALERT, r->connection->log, ngx_errno,
                          ngx_close_file_n " \"%s\" failed", filename);
        }

        RETVAL = NGX_ERROR;
        goto done;
    }

    cln->handler = ngx_pool_cleanup_file;
    clnf = cln->data;

    clnf->fd = fd;
    clnf->name = (u_char *) "";
    clnf->log = r->pool->log;

    b->in_file = 1;
    b->file_pos = 0;
    b->file_last = ngx_file_size(&fi);

    b->file->fd = fd;
    b->file->log = r->connection->log;

    RETVAL = ngx_http_perl_output(r, b);

    done:

    OUTPUT:
    RETVAL


int
rflush(r)
    nginx       r

    PREINIT:

    ngx_buf_t  *b;

    CODE:

    b = ngx_calloc_buf(r->pool);
    if (b == NULL) {
        RETVAL = NGX_ERROR;
        goto done;
    }

    b->flush = 1;

    ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "$r->rflush");

    RETVAL = ngx_http_perl_output(r, b);

    done:

    OUTPUT:
    RETVAL


void
internal_redirect(r, uri)
    nginx                 r
    SV                   *uri

    PREINIT:

    ngx_uint_t            i;
    ngx_http_perl_ctx_t  *ctx;

    CODE:

    ctx = ngx_http_get_module_ctx(r, ngx_http_perl_module);

    if (ngx_http_perl_sv2str(aTHX_ r, &ctx->redirect_uri, uri) != NGX_OK) {
        XSRETURN_EMPTY;
    }

    for (i = 0; i < ctx->redirect_uri.len; i++) {
        if (ctx->redirect_uri.data[i] == '?') {

            ctx->redirect_args.len = ctx->redirect_uri.len - (i + 1);
            ctx->redirect_args.data = &ctx->redirect_uri.data[i + 1];
            ctx->redirect_uri.len = i;

            XSRETURN_EMPTY;
        }
    }


char *
unescape(r, text, type = 0)
    nginx    r
    SV      *text
    int      type

    PREINIT:

    u_char  *p, *dst, *src;
    STRLEN   n;

    CODE:

    src = (u_char *) SvPV(text, n);

    p = ngx_palloc(r->pool, n + 1);
    if (p == NULL) {
        XSRETURN_UNDEF;
    }

    dst = p;

    ngx_unescape_uri(&dst, &src, n, (ngx_uint_t) type);
    *dst = '\0';

    RETVAL = (char *) p;

    OUTPUT:
    RETVAL
