
/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) Nginx, Inc.
 */


#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>

#include <libxml/parser.h>
#include <libxml/tree.h>
#include <libxslt/xslt.h>
#include <libxslt/xsltInternals.h>
#include <libxslt/transform.h>
#include <libxslt/variables.h>
#include <libxslt/xsltutils.h>

#if (NGX_HAVE_EXSLT)
#include <libexslt/exslt.h>
#endif


#ifndef NGX_HTTP_XSLT_REUSE_DTD
#define NGX_HTTP_XSLT_REUSE_DTD  1
#endif


typedef struct {
    u_char                    *name;
    void                      *data;
} ngx_http_xslt_file_t;


typedef struct {
    ngx_array_t                dtd_files;    /* ngx_http_xslt_file_t */
    ngx_array_t                sheet_files;  /* ngx_http_xslt_file_t */
} ngx_http_xslt_filter_main_conf_t;


typedef struct {
    u_char                    *name;
    ngx_http_complex_value_t   value;
    ngx_uint_t                 quote;        /* unsigned  quote:1; */
} ngx_http_xslt_param_t;


typedef struct {
    xsltStylesheetPtr          stylesheet;
    ngx_array_t                params;       /* ngx_http_xslt_param_t */
} ngx_http_xslt_sheet_t;


typedef struct {
    xmlDtdPtr                  dtd;
    ngx_array_t                sheets;       /* ngx_http_xslt_sheet_t */
    ngx_hash_t                 types;
    ngx_array_t               *types_keys;
    ngx_array_t               *params;       /* ngx_http_xslt_param_t */
    ngx_flag_t                 last_modified;
} ngx_http_xslt_filter_loc_conf_t;


typedef struct {
    xmlDocPtr                  doc;
    xmlParserCtxtPtr           ctxt;
    xsltTransformContextPtr    transform;
    ngx_http_request_t        *request;
    ngx_array_t                params;

    ngx_uint_t                 done;         /* unsigned  done:1; */
} ngx_http_xslt_filter_ctx_t;


static ngx_int_t ngx_http_xslt_send(ngx_http_request_t *r,
    ngx_http_xslt_filter_ctx_t *ctx, ngx_buf_t *b);
static ngx_int_t ngx_http_xslt_add_chunk(ngx_http_request_t *r,
    ngx_http_xslt_filter_ctx_t *ctx, ngx_buf_t *b);


static void ngx_http_xslt_sax_external_subset(void *data, const xmlChar *name,
    const xmlChar *externalId, const xmlChar *systemId);
static void ngx_cdecl ngx_http_xslt_sax_error(void *data, const char *msg, ...);


static ngx_buf_t *ngx_http_xslt_apply_stylesheet(ngx_http_request_t *r,
    ngx_http_xslt_filter_ctx_t *ctx);
static ngx_int_t ngx_http_xslt_params(ngx_http_request_t *r,
    ngx_http_xslt_filter_ctx_t *ctx, ngx_array_t *params, ngx_uint_t final);
static u_char *ngx_http_xslt_content_type(xsltStylesheetPtr s);
static u_char *ngx_http_xslt_encoding(xsltStylesheetPtr s);
static void ngx_http_xslt_cleanup(void *data);

static char *ngx_http_xslt_entities(ngx_conf_t *cf, ngx_command_t *cmd,
    void *conf);
static char *ngx_http_xslt_stylesheet(ngx_conf_t *cf, ngx_command_t *cmd,
    void *conf);
static char *ngx_http_xslt_param(ngx_conf_t *cf, ngx_command_t *cmd,
    void *conf);
static void ngx_http_xslt_cleanup_dtd(void *data);
static void ngx_http_xslt_cleanup_stylesheet(void *data);
static void *ngx_http_xslt_filter_create_main_conf(ngx_conf_t *cf);
static void *ngx_http_xslt_filter_create_conf(ngx_conf_t *cf);
static char *ngx_http_xslt_filter_merge_conf(ngx_conf_t *cf, void *parent,
    void *child);
static ngx_int_t ngx_http_xslt_filter_preconfiguration(ngx_conf_t *cf);
static ngx_int_t ngx_http_xslt_filter_init(ngx_conf_t *cf);
static void ngx_http_xslt_filter_exit(ngx_cycle_t *cycle);


static ngx_str_t  ngx_http_xslt_default_types[] = {
    ngx_string("text/xml"),
    ngx_null_string
};


static ngx_command_t  ngx_http_xslt_filter_commands[] = {

    { ngx_string("xml_entities"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
      ngx_http_xslt_entities,
      NGX_HTTP_LOC_CONF_OFFSET,
      0,
      NULL },

    { ngx_string("xslt_stylesheet"),
      NGX_HTTP_LOC_CONF|NGX_CONF_1MORE,
      ngx_http_xslt_stylesheet,
      NGX_HTTP_LOC_CONF_OFFSET,
      0,
      NULL },

    { ngx_string("xslt_param"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE2,
      ngx_http_xslt_param,
      NGX_HTTP_LOC_CONF_OFFSET,
      0,
      NULL },

    { ngx_string("xslt_string_param"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE2,
      ngx_http_xslt_param,
      NGX_HTTP_LOC_CONF_OFFSET,
      0,
      (void *) 1 },

    { ngx_string("xslt_types"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_1MORE,
      ngx_http_types_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_xslt_filter_loc_conf_t, types_keys),
      &ngx_http_xslt_default_types[0] },

    { ngx_string("xslt_last_modified"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_FLAG,
      ngx_conf_set_flag_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_xslt_filter_loc_conf_t, last_modified),
      NULL },

      ngx_null_command
};


static ngx_http_module_t  ngx_http_xslt_filter_module_ctx = {
    ngx_http_xslt_filter_preconfiguration, /* preconfiguration */
    ngx_http_xslt_filter_init,             /* postconfiguration */

    ngx_http_xslt_filter_create_main_conf, /* create main configuration */
    NULL,                                  /* init main configuration */

    NULL,                                  /* create server configuration */
    NULL,                                  /* merge server configuration */

    ngx_http_xslt_filter_create_conf,      /* create location configuration */
    ngx_http_xslt_filter_merge_conf        /* merge location configuration */
};


ngx_module_t  ngx_http_xslt_filter_module = {
    NGX_MODULE_V1,
    &ngx_http_xslt_filter_module_ctx,      /* module context */
    ngx_http_xslt_filter_commands,         /* module directives */
    NGX_HTTP_MODULE,                       /* module type */
    NULL,                                  /* init master */
    NULL,                                  /* init module */
    NULL,                                  /* init process */
    NULL,                                  /* init thread */
    NULL,                                  /* exit thread */
    ngx_http_xslt_filter_exit,             /* exit process */
    ngx_http_xslt_filter_exit,             /* exit master */
    NGX_MODULE_V1_PADDING
};


static ngx_http_output_header_filter_pt  ngx_http_next_header_filter;
static ngx_http_output_body_filter_pt    ngx_http_next_body_filter;


static ngx_int_t
ngx_http_xslt_header_filter(ngx_http_request_t *r)
{
    ngx_http_xslt_filter_ctx_t       *ctx;
    ngx_http_xslt_filter_loc_conf_t  *conf;

    ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "xslt filter header");

    if (r->headers_out.status == NGX_HTTP_NOT_MODIFIED) {
        return ngx_http_next_header_filter(r);
    }

    conf = ngx_http_get_module_loc_conf(r, ngx_http_xslt_filter_module);

    if (conf->sheets.nelts == 0
        || ngx_http_test_content_type(r, &conf->types) == NULL)
    {
        return ngx_http_next_header_filter(r);
    }

    ctx = ngx_http_get_module_ctx(r, ngx_http_xslt_filter_module);

    if (ctx) {
        return ngx_http_next_header_filter(r);
    }

    ctx = ngx_pcalloc(r->pool, sizeof(ngx_http_xslt_filter_ctx_t));
    if (ctx == NULL) {
        return NGX_ERROR;
    }

    ngx_http_set_ctx(r, ctx, ngx_http_xslt_filter_module);

    r->main_filter_need_in_memory = 1;

    return NGX_OK;
}


static ngx_int_t
ngx_http_xslt_body_filter(ngx_http_request_t *r, ngx_chain_t *in)
{
    int                          wellFormed;
    ngx_chain_t                 *cl;
    ngx_http_xslt_filter_ctx_t  *ctx;

    ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "xslt filter body");

    if (in == NULL) {
        return ngx_http_next_body_filter(r, in);
    }

    ctx = ngx_http_get_module_ctx(r, ngx_http_xslt_filter_module);

    if (ctx == NULL || ctx->done) {
        return ngx_http_next_body_filter(r, in);
    }

    for (cl = in; cl; cl = cl->next) {

        if (ngx_http_xslt_add_chunk(r, ctx, cl->buf) != NGX_OK) {

            if (ctx->ctxt->myDoc) {

#if (NGX_HTTP_XSLT_REUSE_DTD)
                ctx->ctxt->myDoc->extSubset = NULL;
#endif
                xmlFreeDoc(ctx->ctxt->myDoc);
            }

            xmlFreeParserCtxt(ctx->ctxt);

            return ngx_http_xslt_send(r, ctx, NULL);
        }

        if (cl->buf->last_buf || cl->buf->last_in_chain) {

            ctx->doc = ctx->ctxt->myDoc;

#if (NGX_HTTP_XSLT_REUSE_DTD)
            ctx->doc->extSubset = NULL;
#endif

            wellFormed = ctx->ctxt->wellFormed;

            xmlFreeParserCtxt(ctx->ctxt);

            if (wellFormed) {
                return ngx_http_xslt_send(r, ctx,
                                       ngx_http_xslt_apply_stylesheet(r, ctx));
            }

            xmlFreeDoc(ctx->doc);

            ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                          "not well formed XML document");

            return ngx_http_xslt_send(r, ctx, NULL);
        }
    }

    return NGX_OK;
}


static ngx_int_t
ngx_http_xslt_send(ngx_http_request_t *r, ngx_http_xslt_filter_ctx_t *ctx,
    ngx_buf_t *b)
{
    ngx_int_t                         rc;
    ngx_chain_t                       out;
    ngx_pool_cleanup_t               *cln;
    ngx_http_xslt_filter_loc_conf_t  *conf;

    ctx->done = 1;

    if (b == NULL) {
        return ngx_http_filter_finalize_request(r, &ngx_http_xslt_filter_module,
                                               NGX_HTTP_INTERNAL_SERVER_ERROR);
    }

    cln = ngx_pool_cleanup_add(r->pool, 0);

    if (cln == NULL) {
        ngx_free(b->pos);
        return ngx_http_filter_finalize_request(r, &ngx_http_xslt_filter_module,
                                               NGX_HTTP_INTERNAL_SERVER_ERROR);
    }

    if (r == r->main) {
        r->headers_out.content_length_n = b->last - b->pos;

        if (r->headers_out.content_length) {
            r->headers_out.content_length->hash = 0;
            r->headers_out.content_length = NULL;
        }

        conf = ngx_http_get_module_loc_conf(r, ngx_http_xslt_filter_module);

        if (!conf->last_modified) {
            ngx_http_clear_last_modified(r);
            ngx_http_clear_etag(r);

        } else {
            ngx_http_weak_etag(r);
        }
    }

    rc = ngx_http_next_header_filter(r);

    if (rc == NGX_ERROR || rc > NGX_OK || r->header_only) {
        ngx_free(b->pos);
        return rc;
    }

    cln->handler = ngx_http_xslt_cleanup;
    cln->data = b->pos;

    out.buf = b;
    out.next = NULL;

    return ngx_http_next_body_filter(r, &out);
}


static ngx_int_t
ngx_http_xslt_add_chunk(ngx_http_request_t *r, ngx_http_xslt_filter_ctx_t *ctx,
    ngx_buf_t *b)
{
    int               err;
    xmlParserCtxtPtr  ctxt;

    if (ctx->ctxt == NULL) {

        ctxt = xmlCreatePushParserCtxt(NULL, NULL, NULL, 0, NULL);
        if (ctxt == NULL) {
            ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                          "xmlCreatePushParserCtxt() failed");
            return NGX_ERROR;
        }
        xmlCtxtUseOptions(ctxt, XML_PARSE_NOENT|XML_PARSE_DTDLOAD
                                               |XML_PARSE_NOWARNING);

        ctxt->sax->externalSubset = ngx_http_xslt_sax_external_subset;
        ctxt->sax->setDocumentLocator = NULL;
        ctxt->sax->error = ngx_http_xslt_sax_error;
        ctxt->sax->fatalError = ngx_http_xslt_sax_error;
        ctxt->sax->_private = ctx;

        ctx->ctxt = ctxt;
        ctx->request = r;
    }

    err = xmlParseChunk(ctx->ctxt, (char *) b->pos, (int) (b->last - b->pos),
                        (b->last_buf) || (b->last_in_chain));

    if (err == 0) {
        b->pos = b->last;
        return NGX_OK;
    }

    ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                  "xmlParseChunk() failed, error:%d", err);

    return NGX_ERROR;
}


static void
ngx_http_xslt_sax_external_subset(void *data, const xmlChar *name,
    const xmlChar *externalId, const xmlChar *systemId)
{
    xmlParserCtxtPtr ctxt = data;

    xmlDocPtr                         doc;
    xmlDtdPtr                         dtd;
    ngx_http_request_t               *r;
    ngx_http_xslt_filter_ctx_t       *ctx;
    ngx_http_xslt_filter_loc_conf_t  *conf;

    ctx = ctxt->sax->_private;
    r = ctx->request;

    conf = ngx_http_get_module_loc_conf(r, ngx_http_xslt_filter_module);

    ngx_log_debug3(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "xslt filter extSubset: \"%s\" \"%s\" \"%s\"",
                   name ? name : (xmlChar *) "",
                   externalId ? externalId : (xmlChar *) "",
                   systemId ? systemId : (xmlChar *) "");

    doc = ctxt->myDoc;

#if (NGX_HTTP_XSLT_REUSE_DTD)

    dtd = conf->dtd;

#else

    dtd = xmlCopyDtd(conf->dtd);
    if (dtd == NULL) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                      "xmlCopyDtd() failed");
        return;
    }

    if (doc->children == NULL) {
        xmlAddChild((xmlNodePtr) doc, (xmlNodePtr) dtd);

    } else {
        xmlAddPrevSibling(doc->children, (xmlNodePtr) dtd);
    }

#endif

    doc->extSubset = dtd;
}


static void ngx_cdecl
ngx_http_xslt_sax_error(void *data, const char *msg, ...)
{
    xmlParserCtxtPtr ctxt = data;

    size_t                       n;
    va_list                      args;
    ngx_http_xslt_filter_ctx_t  *ctx;
    u_char                       buf[NGX_MAX_ERROR_STR];

    ctx = ctxt->sax->_private;

    buf[0] = '\0';

    va_start(args, msg);
    n = (size_t) vsnprintf((char *) buf, NGX_MAX_ERROR_STR, msg, args);
    va_end(args);

    while (--n && (buf[n] == CR || buf[n] == LF)) { /* void */ }

    ngx_log_error(NGX_LOG_ERR, ctx->request->connection->log, 0,
                  "libxml2 error: \"%*s\"", n + 1, buf);
}


static ngx_buf_t *
ngx_http_xslt_apply_stylesheet(ngx_http_request_t *r,
    ngx_http_xslt_filter_ctx_t *ctx)
{
    int                               len, rc, doc_type;
    u_char                           *type, *encoding;
    ngx_buf_t                        *b;
    ngx_uint_t                        i;
    xmlChar                          *buf;
    xmlDocPtr                         doc, res;
    ngx_http_xslt_sheet_t            *sheet;
    ngx_http_xslt_filter_loc_conf_t  *conf;

    conf = ngx_http_get_module_loc_conf(r, ngx_http_xslt_filter_module);
    sheet = conf->sheets.elts;
    doc = ctx->doc;

    /* preallocate array for 4 params */

    if (ngx_array_init(&ctx->params, r->pool, 4 * 2 + 1, sizeof(char *))
        != NGX_OK)
    {
        xmlFreeDoc(doc);
        return NULL;
    }

    for (i = 0; i < conf->sheets.nelts; i++) {

        ctx->transform = xsltNewTransformContext(sheet[i].stylesheet, doc);
        if (ctx->transform == NULL) {
            xmlFreeDoc(doc);
            return NULL;
        }

        if (conf->params
            && ngx_http_xslt_params(r, ctx, conf->params, 0) != NGX_OK)
        {
            xsltFreeTransformContext(ctx->transform);
            xmlFreeDoc(doc);
            return NULL;
        }

        if (ngx_http_xslt_params(r, ctx, &sheet[i].params, 1) != NGX_OK) {
            xsltFreeTransformContext(ctx->transform);
            xmlFreeDoc(doc);
            return NULL;
        }

        res = xsltApplyStylesheetUser(sheet[i].stylesheet, doc,
                                      ctx->params.elts, NULL, NULL,
                                      ctx->transform);

        xsltFreeTransformContext(ctx->transform);
        xmlFreeDoc(doc);

        if (res == NULL) {
            ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                          "xsltApplyStylesheet() failed");
            return NULL;
        }

        doc = res;

        /* reset array elements */
        ctx->params.nelts = 0;
    }

    /* there must be at least one stylesheet */

    if (r == r->main) {
        type = ngx_http_xslt_content_type(sheet[i - 1].stylesheet);

    } else {
        type = NULL;
    }

    encoding = ngx_http_xslt_encoding(sheet[i - 1].stylesheet);
    doc_type = doc->type;

    ngx_log_debug3(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "xslt filter type: %d t:%s e:%s",
                   doc_type, type ? type : (u_char *) "(null)",
                   encoding ? encoding : (u_char *) "(null)");

    rc = xsltSaveResultToString(&buf, &len, doc, sheet[i - 1].stylesheet);

    xmlFreeDoc(doc);

    if (rc != 0) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                      "xsltSaveResultToString() failed");
        return NULL;
    }

    if (len == 0) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                      "xsltSaveResultToString() returned zero-length result");
        return NULL;
    }

    b = ngx_calloc_buf(r->pool);
    if (b == NULL) {
        ngx_free(buf);
        return NULL;
    }

    b->pos = buf;
    b->last = buf + len;
    b->memory = 1;

    if (encoding) {
        r->headers_out.charset.len = ngx_strlen(encoding);
        r->headers_out.charset.data = encoding;
    }

    if (r != r->main) {
        return b;
    }

    b->last_buf = 1;

    if (type) {
        len = ngx_strlen(type);

        r->headers_out.content_type_len = len;
        r->headers_out.content_type.len = len;
        r->headers_out.content_type.data = type;

    } else if (doc_type == XML_HTML_DOCUMENT_NODE) {

        r->headers_out.content_type_len = sizeof("text/html") - 1;
        ngx_str_set(&r->headers_out.content_type, "text/html");
    }

    r->headers_out.content_type_lowcase = NULL;

    return b;
}


static ngx_int_t
ngx_http_xslt_params(ngx_http_request_t *r, ngx_http_xslt_filter_ctx_t *ctx,
    ngx_array_t *params, ngx_uint_t final)
{
    u_char                 *p, *last, *value, *dst, *src, **s;
    size_t                  len;
    ngx_uint_t              i;
    ngx_str_t               string;
    ngx_http_xslt_param_t  *param;

    param = params->elts;

    for (i = 0; i < params->nelts; i++) {

        if (ngx_http_complex_value(r, &param[i].value, &string) != NGX_OK) {
            return NGX_ERROR;
        }

        ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                       "xslt filter param: \"%s\"", string.data);

        if (param[i].name) {

            ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                           "xslt filter param name: \"%s\"", param[i].name);

            if (param[i].quote) {
                if (xsltQuoteOneUserParam(ctx->transform, param[i].name,
                                          string.data)
                    != 0)
                {
                    ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                                "xsltQuoteOneUserParam(\"%s\", \"%s\") failed",
                                param[i].name, string.data);
                    return NGX_ERROR;
                }

                continue;
            }

            s = ngx_array_push(&ctx->params);
            if (s == NULL) {
                return NGX_ERROR;
            }

            *s = param[i].name;

            s = ngx_array_push(&ctx->params);
            if (s == NULL) {
                return NGX_ERROR;
            }

            *s = string.data;

            continue;
        }

        /*
         * parse param1=value1:param2=value2 syntax as used by parameters
         * specified in xslt_stylesheet directives
         */

        if (param[i].value.lengths) {
            p = string.data;

        } else {
            p = ngx_pnalloc(r->pool, string.len + 1);
            if (p == NULL) {
                return NGX_ERROR;
            }

            ngx_memcpy(p, string.data, string.len + 1);
        }

        last = p + string.len;

        while (p && *p) {

            value = p;
            p = (u_char *) ngx_strchr(p, '=');
            if (p == NULL) {
                ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                                "invalid libxslt parameter \"%s\"", value);
                return NGX_ERROR;
            }
            *p++ = '\0';

            ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                           "xslt filter param name: \"%s\"", value);

            s = ngx_array_push(&ctx->params);
            if (s == NULL) {
                return NGX_ERROR;
            }

            *s = value;

            value = p;
            p = (u_char *) ngx_strchr(p, ':');

            if (p) {
                len = p - value;
                *p++ = '\0';

            } else {
                len = last - value;
            }

            ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                           "xslt filter param value: \"%s\"", value);

            dst = value;
            src = value;

            ngx_unescape_uri(&dst, &src, len, 0);

            *dst = '\0';

            ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                           "xslt filter param unescaped: \"%s\"", value);

            s = ngx_array_push(&ctx->params);
            if (s == NULL) {
                return NGX_ERROR;
            }

            *s = value;
        }
    }

    if (final) {
        s = ngx_array_push(&ctx->params);
        if (s == NULL) {
            return NGX_ERROR;
        }

        *s = NULL;
    }

    return NGX_OK;
}


static u_char *
ngx_http_xslt_content_type(xsltStylesheetPtr s)
{
    u_char  *type;

    if (s->mediaType) {
        return s->mediaType;
    }

    for (s = s->imports; s; s = s->next) {

        type = ngx_http_xslt_content_type(s);

        if (type) {
            return type;
        }
    }

    return NULL;
}


static u_char *
ngx_http_xslt_encoding(xsltStylesheetPtr s)
{
    u_char  *encoding;

    if (s->encoding) {
        return s->encoding;
    }

    for (s = s->imports; s; s = s->next) {

        encoding = ngx_http_xslt_encoding(s);

        if (encoding) {
            return encoding;
        }
    }

    return NULL;
}


static void
ngx_http_xslt_cleanup(void *data)
{
    ngx_free(data);
}


static char *
ngx_http_xslt_entities(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    ngx_http_xslt_filter_loc_conf_t *xlcf = conf;

    ngx_str_t                         *value;
    ngx_uint_t                         i;
    ngx_pool_cleanup_t                *cln;
    ngx_http_xslt_file_t              *file;
    ngx_http_xslt_filter_main_conf_t  *xmcf;

    if (xlcf->dtd) {
        return "is duplicate";
    }

    value = cf->args->elts;

    xmcf = ngx_http_conf_get_module_main_conf(cf, ngx_http_xslt_filter_module);

    file = xmcf->dtd_files.elts;
    for (i = 0; i < xmcf->dtd_files.nelts; i++) {
        if (ngx_strcmp(file[i].name, value[1].data) == 0) {
            xlcf->dtd = file[i].data;
            return NGX_CONF_OK;
        }
    }

    cln = ngx_pool_cleanup_add(cf->pool, 0);
    if (cln == NULL) {
        return NGX_CONF_ERROR;
    }

    xlcf->dtd = xmlParseDTD(NULL, (xmlChar *) value[1].data);

    if (xlcf->dtd == NULL) {
        ngx_conf_log_error(NGX_LOG_ERR, cf, 0, "xmlParseDTD() failed");
        return NGX_CONF_ERROR;
    }

    cln->handler = ngx_http_xslt_cleanup_dtd;
    cln->data = xlcf->dtd;

    file = ngx_array_push(&xmcf->dtd_files);
    if (file == NULL) {
        return NGX_CONF_ERROR;
    }

    file->name = value[1].data;
    file->data = xlcf->dtd;

    return NGX_CONF_OK;
}



static char *
ngx_http_xslt_stylesheet(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    ngx_http_xslt_filter_loc_conf_t *xlcf = conf;

    ngx_str_t                         *value;
    ngx_uint_t                         i, n;
    ngx_pool_cleanup_t                *cln;
    ngx_http_xslt_file_t              *file;
    ngx_http_xslt_sheet_t             *sheet;
    ngx_http_xslt_param_t             *param;
    ngx_http_compile_complex_value_t   ccv;
    ngx_http_xslt_filter_main_conf_t  *xmcf;

    value = cf->args->elts;

    if (xlcf->sheets.elts == NULL) {
        if (ngx_array_init(&xlcf->sheets, cf->pool, 1,
                           sizeof(ngx_http_xslt_sheet_t))
            != NGX_OK)
        {
            return NGX_CONF_ERROR;
        }
    }

    sheet = ngx_array_push(&xlcf->sheets);
    if (sheet == NULL) {
        return NGX_CONF_ERROR;
    }

    ngx_memzero(sheet, sizeof(ngx_http_xslt_sheet_t));

    if (ngx_conf_full_name(cf->cycle, &value[1], 0) != NGX_OK) {
        return NGX_CONF_ERROR;
    }

    xmcf = ngx_http_conf_get_module_main_conf(cf, ngx_http_xslt_filter_module);

    file = xmcf->sheet_files.elts;
    for (i = 0; i < xmcf->sheet_files.nelts; i++) {
        if (ngx_strcmp(file[i].name, value[1].data) == 0) {
            sheet->stylesheet = file[i].data;
            goto found;
        }
    }

    cln = ngx_pool_cleanup_add(cf->pool, 0);
    if (cln == NULL) {
        return NGX_CONF_ERROR;
    }

    sheet->stylesheet = xsltParseStylesheetFile(value[1].data);
    if (sheet->stylesheet == NULL) {
        ngx_conf_log_error(NGX_LOG_ERR, cf, 0,
                           "xsltParseStylesheetFile(\"%s\") failed",
                           value[1].data);
        return NGX_CONF_ERROR;
    }

    cln->handler = ngx_http_xslt_cleanup_stylesheet;
    cln->data = sheet->stylesheet;

    file = ngx_array_push(&xmcf->sheet_files);
    if (file == NULL) {
        return NGX_CONF_ERROR;
    }

    file->name = value[1].data;
    file->data = sheet->stylesheet;

found:

    n = cf->args->nelts;

    if (n == 2) {
        return NGX_CONF_OK;
    }

    if (ngx_array_init(&sheet->params, cf->pool, n - 2,
                       sizeof(ngx_http_xslt_param_t))
        != NGX_OK)
    {
        return NGX_CONF_ERROR;
    }

    for (i = 2; i < n; i++) {

        param = ngx_array_push(&sheet->params);
        if (param == NULL) {
            return NGX_CONF_ERROR;
        }

        ngx_memzero(param, sizeof(ngx_http_xslt_param_t));
        ngx_memzero(&ccv, sizeof(ngx_http_compile_complex_value_t));

        ccv.cf = cf;
        ccv.value = &value[i];
        ccv.complex_value = &param->value;
        ccv.zero = 1;

        if (ngx_http_compile_complex_value(&ccv) != NGX_OK) {
            return NGX_CONF_ERROR;
        }
    }

    return NGX_CONF_OK;
}


static char *
ngx_http_xslt_param(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    ngx_http_xslt_filter_loc_conf_t  *xlcf = conf;

    ngx_http_xslt_param_t            *param;
    ngx_http_compile_complex_value_t  ccv;
    ngx_str_t                        *value;

    value = cf->args->elts;

    if (xlcf->params == NULL) {
        xlcf->params = ngx_array_create(cf->pool, 2,
                                        sizeof(ngx_http_xslt_param_t));
        if (xlcf->params == NULL) {
            return NGX_CONF_ERROR;
        }
    }

    param = ngx_array_push(xlcf->params);
    if (param == NULL) {
        return NGX_CONF_ERROR;
    }

    param->name = value[1].data;
    param->quote = (cmd->post == NULL) ? 0 : 1;

    ngx_memzero(&ccv, sizeof(ngx_http_compile_complex_value_t));

    ccv.cf = cf;
    ccv.value = &value[2];
    ccv.complex_value = &param->value;
    ccv.zero = 1;

    if (ngx_http_compile_complex_value(&ccv) != NGX_OK) {
        return NGX_CONF_ERROR;
    }

    return NGX_CONF_OK;
}


static void
ngx_http_xslt_cleanup_dtd(void *data)
{
    xmlFreeDtd(data);
}


static void
ngx_http_xslt_cleanup_stylesheet(void *data)
{
    xsltFreeStylesheet(data);
}


static void *
ngx_http_xslt_filter_create_main_conf(ngx_conf_t *cf)
{
    ngx_http_xslt_filter_main_conf_t  *conf;

    conf = ngx_palloc(cf->pool, sizeof(ngx_http_xslt_filter_main_conf_t));
    if (conf == NULL) {
        return NULL;
    }

    if (ngx_array_init(&conf->dtd_files, cf->pool, 1,
                       sizeof(ngx_http_xslt_file_t))
        != NGX_OK)
    {
        return NULL;
    }

    if (ngx_array_init(&conf->sheet_files, cf->pool, 1,
                       sizeof(ngx_http_xslt_file_t))
        != NGX_OK)
    {
        return NULL;
    }

    return conf;
}


static void *
ngx_http_xslt_filter_create_conf(ngx_conf_t *cf)
{
    ngx_http_xslt_filter_loc_conf_t  *conf;

    conf = ngx_pcalloc(cf->pool, sizeof(ngx_http_xslt_filter_loc_conf_t));
    if (conf == NULL) {
        return NULL;
    }

    /*
     * set by ngx_pcalloc():
     *
     *     conf->dtd = NULL;
     *     conf->sheets = { NULL };
     *     conf->types = { NULL };
     *     conf->types_keys = NULL;
     *     conf->params = NULL;
     */

    conf->last_modified = NGX_CONF_UNSET;

    return conf;
}


static char *
ngx_http_xslt_filter_merge_conf(ngx_conf_t *cf, void *parent, void *child)
{
    ngx_http_xslt_filter_loc_conf_t *prev = parent;
    ngx_http_xslt_filter_loc_conf_t *conf = child;

    if (conf->dtd == NULL) {
        conf->dtd = prev->dtd;
    }

    if (conf->sheets.nelts == 0) {
        conf->sheets = prev->sheets;
    }

    if (conf->params == NULL) {
        conf->params = prev->params;
    }

    if (ngx_http_merge_types(cf, &conf->types_keys, &conf->types,
                             &prev->types_keys, &prev->types,
                             ngx_http_xslt_default_types)
        != NGX_OK)
    {
        return NGX_CONF_ERROR;
    }

    ngx_conf_merge_value(conf->last_modified, prev->last_modified, 0);

    return NGX_CONF_OK;
}


static ngx_int_t
ngx_http_xslt_filter_preconfiguration(ngx_conf_t *cf)
{
    xmlInitParser();

#if (NGX_HAVE_EXSLT)
    exsltRegisterAll();
#endif

    return NGX_OK;
}


static ngx_int_t
ngx_http_xslt_filter_init(ngx_conf_t *cf)
{
    ngx_http_next_header_filter = ngx_http_top_header_filter;
    ngx_http_top_header_filter = ngx_http_xslt_header_filter;

    ngx_http_next_body_filter = ngx_http_top_body_filter;
    ngx_http_top_body_filter = ngx_http_xslt_body_filter;

    return NGX_OK;
}


static void
ngx_http_xslt_filter_exit(ngx_cycle_t *cycle)
{
    xsltCleanupGlobals();
    xmlCleanupParser();
}
