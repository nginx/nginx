
/*
 * Copyright (C) Unbit S.a.s. 2009-2010
 * Copyright (C) 2008 Manlio Perillo (manlio.perillo@gmail.com)
 * Copyright (C) Igor Sysoev
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY AUTHOR AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL AUTHOR OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */


#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>


#define NGX_HTTP_UWSGI_TEMP_PATH  "uwsgi_temp"


typedef struct {
    ngx_http_upstream_conf_t   upstream;

    ngx_array_t               *flushes;
    ngx_array_t               *params_len;
    ngx_array_t               *params;
    ngx_array_t               *params_source;

    ngx_array_t               *uwsgi_lengths;
    ngx_array_t               *uwsgi_values;

    ngx_str_t                  uwsgi_string ;

    u_char                     modifier1;
    u_char                     modifier2;
} ngx_http_uwsgi_loc_conf_t;

typedef struct {
    ngx_uint_t                 status;
    ngx_uint_t                 status_count;
    u_char                    *status_start;
    u_char                    *status_end;
} ngx_http_uwsgi_ctx_t;


#define NGX_HTTP_UWSGI_PARSE_NO_HEADER  20


#ifndef NGX_HAVE_LITTLE_ENDIAN
static uint16_t
uwsgi_swap16(uint16_t x)
{
    return (uint16_t) ((x & 0xff) << 8 | (x & 0xff00) >> 8);
}
#endif



static ngx_int_t ngx_http_uwsgi_eval(ngx_http_request_t *r,
    ngx_http_uwsgi_loc_conf_t *uwcf);
static ngx_int_t ngx_http_uwsgi_create_request(ngx_http_request_t *r);
static ngx_int_t ngx_http_uwsgi_reinit_request(ngx_http_request_t *r);
static ngx_int_t ngx_http_uwsgi_process_status_line(ngx_http_request_t *r);
static ngx_int_t ngx_http_uwsgi_parse_status_line(ngx_http_request_t *r,
    ngx_http_uwsgi_ctx_t *ctx);
static ngx_int_t ngx_http_uwsgi_process_header(ngx_http_request_t *r);
static ngx_int_t ngx_http_uwsgi_process_header(ngx_http_request_t *r);
static void ngx_http_uwsgi_abort_request(ngx_http_request_t *r);
static void ngx_http_uwsgi_finalize_request(ngx_http_request_t *r,
    ngx_int_t rc);

static char *ngx_http_uwsgi_modifier1(ngx_conf_t *cf, ngx_command_t *cmd,
    void *conf);

static char *ngx_http_uwsgi_modifier2(ngx_conf_t *cf, ngx_command_t *cmd,
    void *conf);

static ngx_int_t ngx_http_uwsgi_add_variables(ngx_conf_t *cf);
static void *ngx_http_uwsgi_create_loc_conf(ngx_conf_t *cf);
static char *ngx_http_uwsgi_merge_loc_conf(ngx_conf_t *cf, void *parent,
    void *child);

static char *ngx_http_uwsgi_pass(ngx_conf_t *cf, ngx_command_t *cmd,
    void *conf);


static ngx_conf_bitmask_t ngx_http_uwsgi_next_upstream_masks[] = {
    { ngx_string("error"), NGX_HTTP_UPSTREAM_FT_ERROR },
    { ngx_string("timeout"), NGX_HTTP_UPSTREAM_FT_TIMEOUT },
    { ngx_string("invalid_header"), NGX_HTTP_UPSTREAM_FT_INVALID_HEADER },
    { ngx_string("http_500"), NGX_HTTP_UPSTREAM_FT_HTTP_500 },
    { ngx_string("http_503"), NGX_HTTP_UPSTREAM_FT_HTTP_503 },
    { ngx_string("http_404"), NGX_HTTP_UPSTREAM_FT_HTTP_404 },
    { ngx_string("updating"), NGX_HTTP_UPSTREAM_FT_UPDATING },
    { ngx_string("off"), NGX_HTTP_UPSTREAM_FT_OFF },
    { ngx_null_string, 0 }
};


static ngx_conf_bitmask_t ngx_http_uwsgi_ignore_headers_masks[] = {
    { ngx_string("X-Accel-Redirect"), NGX_HTTP_UPSTREAM_IGN_XA_REDIRECT },
    { ngx_string("X-Accel-Expires"), NGX_HTTP_UPSTREAM_IGN_XA_EXPIRES },
    { ngx_string("Expires"), NGX_HTTP_UPSTREAM_IGN_EXPIRES },
    { ngx_string("Cache-Control"), NGX_HTTP_UPSTREAM_IGN_CACHE_CONTROL },
    { ngx_null_string, 0 }
};


ngx_module_t ngx_http_uwsgi_module;


static ngx_command_t ngx_http_uwsgi_commands[] = {

    { ngx_string("uwsgi_pass"),
      NGX_HTTP_LOC_CONF|NGX_HTTP_LIF_CONF|NGX_CONF_TAKE1,
      ngx_http_uwsgi_pass,
      NGX_HTTP_LOC_CONF_OFFSET,
      0,
      NULL },

    { ngx_string("uwsgi_modifier1"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
      ngx_http_uwsgi_modifier1,
      NGX_HTTP_LOC_CONF_OFFSET,
      0,
      NULL },

    { ngx_string("uwsgi_modifier2"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
      ngx_http_uwsgi_modifier2,
      NGX_HTTP_LOC_CONF_OFFSET,
      0,
      NULL },

    { ngx_string("uwsgi_ignore_client_abort"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_FLAG,
      ngx_conf_set_flag_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_uwsgi_loc_conf_t, upstream.ignore_client_abort),
      NULL },

    { ngx_string("uwsgi_connect_timeout"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_msec_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_uwsgi_loc_conf_t, upstream.connect_timeout),
      NULL },

    { ngx_string("uwsgi_send_timeout"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_msec_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_uwsgi_loc_conf_t, upstream.send_timeout),
      NULL },

    { ngx_string("uwsgi_buffer_size"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_size_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_uwsgi_loc_conf_t, upstream.buffer_size),
      NULL },

    { ngx_string("uwsgi_pass_request_headers"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_FLAG,
      ngx_conf_set_flag_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_uwsgi_loc_conf_t, upstream.pass_request_headers),
      NULL },

    { ngx_string("uwsgi_pass_request_body"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_FLAG,
      ngx_conf_set_flag_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_uwsgi_loc_conf_t, upstream.pass_request_body),
      NULL },

    { ngx_string("uwsgi_intercept_errors"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_FLAG,
      ngx_conf_set_flag_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_uwsgi_loc_conf_t, upstream.intercept_errors),
      NULL },

    { ngx_string("uwsgi_read_timeout"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_msec_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_uwsgi_loc_conf_t, upstream.read_timeout),
      NULL },

    { ngx_string("uwsgi_buffers"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE2,
      ngx_conf_set_bufs_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_uwsgi_loc_conf_t, upstream.bufs),
      NULL },

    { ngx_string("uwsgi_busy_buffers_size"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_size_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_uwsgi_loc_conf_t, upstream.busy_buffers_size_conf),
      NULL },

    { ngx_string("uwsgi_temp_path"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1234,
      ngx_conf_set_path_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_uwsgi_loc_conf_t, upstream.temp_path),
      NULL },

    { ngx_string("uwsgi_max_temp_file_size"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_size_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_uwsgi_loc_conf_t, upstream.max_temp_file_size_conf),
      NULL },

    { ngx_string("uwsgi_temp_file_write_size"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_size_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_uwsgi_loc_conf_t, upstream.temp_file_write_size_conf),
      NULL },

    { ngx_string("uwsgi_next_upstream"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_1MORE,
      ngx_conf_set_bitmask_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_uwsgi_loc_conf_t, upstream.next_upstream),
      &ngx_http_uwsgi_next_upstream_masks },

    { ngx_string("uwsgi_param"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE2,
      ngx_conf_set_keyval_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_uwsgi_loc_conf_t, params_source),
      NULL },

    { ngx_string("uwsgi_string"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_str_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_uwsgi_loc_conf_t, uwsgi_string),
      NULL },

    { ngx_string("uwsgi_pass_header"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_FLAG,
      ngx_conf_set_str_array_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_uwsgi_loc_conf_t, upstream.pass_headers),
      NULL },

    { ngx_string("uwsgi_hide_header"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_FLAG,
      ngx_conf_set_str_array_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_uwsgi_loc_conf_t, upstream.hide_headers),
      NULL },

    { ngx_string("uwsgi_ignore_headers"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_1MORE,
      ngx_conf_set_bitmask_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_uwsgi_loc_conf_t, upstream.ignore_headers),
      &ngx_http_uwsgi_ignore_headers_masks },

      ngx_null_command
};


static ngx_http_module_t ngx_http_uwsgi_module_ctx = {
    ngx_http_uwsgi_add_variables,          /* preconfiguration */
    NULL,                                  /* postconfiguration */

    NULL,                                  /* create main configuration */
    NULL,                                  /* init main configuration */

    NULL,                                  /* create server configuration */
    NULL,                                  /* merge server configuration */

    ngx_http_uwsgi_create_loc_conf,        /* create location configuration */
    ngx_http_uwsgi_merge_loc_conf          /* merge location configuration */
};


ngx_module_t ngx_http_uwsgi_module = {
    NGX_MODULE_V1,
    &ngx_http_uwsgi_module_ctx,            /* module context */
    ngx_http_uwsgi_commands,               /* module directives */
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


static ngx_http_variable_t ngx_http_uwsgi_vars[] = {

    { ngx_null_string, NULL, NULL, 0, 0, 0 }
};


static ngx_str_t ngx_http_uwsgi_hide_headers[] = {
    ngx_string("Status"),
    ngx_string("X-Accel-Expires"),
    ngx_string("X-Accel-Redirect"),
    ngx_string("X-Accel-Limit-Rate"),
    ngx_string("X-Accel-Buffering"),
    ngx_string("X-Accel-Charset"),
    ngx_null_string
};


static ngx_path_init_t ngx_http_uwsgi_temp_path = {
    ngx_string(NGX_HTTP_UWSGI_TEMP_PATH), { 1, 2, 0 }
};


static ngx_int_t
ngx_http_uwsgi_handler(ngx_http_request_t *r)
{
    ngx_int_t                   rc;
    ngx_http_upstream_t        *u;
    ngx_http_uwsgi_ctx_t       *ctx;
    ngx_http_uwsgi_loc_conf_t  *uwcf;

    if (r->subrequest_in_memory) {
        ngx_log_error(NGX_LOG_ALERT, r->connection->log, 0,
                      "ngx_http_uwsgi_module does not support "
                      "subrequests in memory");
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    if (ngx_http_upstream_create(r) != NGX_OK) {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    ctx = ngx_pcalloc(r->pool, sizeof(ngx_http_uwsgi_ctx_t));
    if (ctx == NULL) {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    ngx_http_set_ctx(r, ctx, ngx_http_uwsgi_module);

    uwcf = ngx_http_get_module_loc_conf(r, ngx_http_uwsgi_module);

    if (uwcf->uwsgi_lengths) {
        if (ngx_http_uwsgi_eval(r, uwcf) != NGX_OK) {
            return NGX_HTTP_INTERNAL_SERVER_ERROR;
        }
    }

    u = r->upstream;

    u->schema.len = sizeof ("uwsgi://") - 1;
    u->schema.data = (u_char *) "uwsgi://";

    u->output.tag = (ngx_buf_tag_t) &ngx_http_uwsgi_module;

    u->conf = &uwcf->upstream;

    u->create_request = ngx_http_uwsgi_create_request;
    u->reinit_request = ngx_http_uwsgi_reinit_request;
    u->process_header = ngx_http_uwsgi_process_status_line;
    u->abort_request = ngx_http_uwsgi_abort_request;
    u->finalize_request = ngx_http_uwsgi_finalize_request;

    u->buffering = 1;

    u->pipe = ngx_pcalloc(r->pool, sizeof(ngx_event_pipe_t));
    if (u->pipe == NULL) {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    u->pipe->input_filter = ngx_event_pipe_copy_input_filter;
    u->pipe->input_ctx = r;

    rc = ngx_http_read_client_request_body(r, ngx_http_upstream_init);

    if (rc >= NGX_HTTP_SPECIAL_RESPONSE) {
        return rc;
    }

    return NGX_DONE;
}


static ngx_int_t
ngx_http_uwsgi_eval(ngx_http_request_t *r, ngx_http_uwsgi_loc_conf_t * uwcf)
{
    ngx_url_t  u;

    ngx_memzero(&u, sizeof(ngx_url_t));

    if (ngx_http_script_run(r, &u.url, uwcf->uwsgi_lengths->elts, 0,
                            uwcf->uwsgi_values->elts)
        == NULL)
    {
        return NGX_ERROR;
    }

    u.no_resolve = 1;

    if (ngx_parse_url(r->pool, &u) != NGX_OK) {
        if (u.err) {
            ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                          "%s in upstream \"%V\"", u.err, &u.url);
        }

        return NGX_ERROR;
    }

    if (u.no_port) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                      "no port in upstream \"%V\"", &u.url);
        return NGX_ERROR;
    }

    r->upstream->resolved = ngx_pcalloc(r->pool,
                                        sizeof(ngx_http_upstream_resolved_t));
    if (r->upstream->resolved == NULL) {
        return NGX_ERROR;
    }

    if (u.addrs && u.addrs[0].sockaddr) {
        r->upstream->resolved->sockaddr = u.addrs[0].sockaddr;
        r->upstream->resolved->socklen = u.addrs[0].socklen;
        r->upstream->resolved->naddrs = 1;
        r->upstream->resolved->host = u.addrs[0].name;

    } else {
        r->upstream->resolved->host = u.host;
        r->upstream->resolved->port = u.port;
    }

    return NGX_OK;
}


static ngx_int_t
ngx_http_uwsgi_create_request(ngx_http_request_t *r)
{
    u_char                        ch, *pos, tmp[2];
    size_t                        key_len, val_len;
    uint16_t                      uwsgi_pkt_size, uwsgi_strlen;
    ngx_uint_t                    i, n;
    ngx_buf_t                    *b;
    ngx_chain_t                  *cl, *body;
    ngx_list_part_t              *part;
    ngx_table_elt_t              *header;
    ngx_http_script_code_pt       code;
    ngx_http_script_engine_t      e, le;
    ngx_http_uwsgi_loc_conf_t    *uwcf;
    ngx_http_script_len_code_pt   lcode;

    uwsgi_pkt_size = 0;

    uwcf = ngx_http_get_module_loc_conf(r, ngx_http_uwsgi_module);

    if (uwcf->params_len) {
        ngx_memzero(&le, sizeof(ngx_http_script_engine_t));

        ngx_http_script_flush_no_cacheable_variables(r, uwcf->flushes);
        le.flushed = 1;

        le.ip = uwcf->params_len->elts;
        le.request = r;

        while (*(uintptr_t *) le.ip) {

            lcode = *(ngx_http_script_len_code_pt *) le.ip;
            key_len = lcode(&le);

            for (val_len = 0; *(uintptr_t *) le.ip; val_len += lcode (&le)) {
                lcode = *(ngx_http_script_len_code_pt *) le.ip;
            }
            le.ip += sizeof(uintptr_t);

            uwsgi_pkt_size = (uint16_t)
                                  (uwsgi_pkt_size + 2 + key_len + 2 + val_len);
        }
    }

    if (uwcf->upstream.pass_request_headers) {

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

            uwsgi_pkt_size = (uint16_t) (uwsgi_pkt_size
                        + 2 + 5 + header[i].key.len + 2 + header[i].value.len);
        }
    }

    if (uwcf->uwsgi_string.data && uwcf->uwsgi_string.len) {
        uwsgi_pkt_size = (uint16_t) (uwsgi_pkt_size + uwcf->uwsgi_string.len);
    }

#if 0
    /* allow custom uwsgi packet */
    if (uwsgi_pkt_size > 0 && uwsgi_pkt_size < 2) {
        ngx_log_error (NGX_LOG_ALERT, r->connection->log, 0,
                       "uwsgi request is too little: %uz", uwsgi_pkt_size);
        return NGX_ERROR;
    }
#endif

    b = ngx_create_temp_buf(r->pool, uwsgi_pkt_size + 4);
    if (b == NULL) {
        return NGX_ERROR;
    }

    cl = ngx_alloc_chain_link(r->pool);
    if (cl == NULL) {
        return NGX_ERROR;
    }

    cl->buf = b;

    *b->pos = uwcf->modifier1;
#ifndef NGX_HAVE_LITTLE_ENDIAN
    uwsgi_pkt_size = uwsgi_swap16(uwsgi_pkt_size);
#endif
    b->last = ngx_cpymem(b->pos + 1, &uwsgi_pkt_size, 2);
    *(b->pos + 3) = uwcf->modifier2;
    b->last++;

    if (uwcf->params_len) {
        ngx_memzero(&e, sizeof(ngx_http_script_engine_t));

        e.ip = uwcf->params->elts;
        e.pos = b->last;
        e.request = r;
        e.flushed = 1;

        le.ip = uwcf->params_len->elts;

        while (*(uintptr_t *) le.ip) {

            lcode = *(ngx_http_script_len_code_pt *) le.ip;
            key_len = (u_char) lcode (&le);

            for (val_len = 0; *(uintptr_t *) le.ip; val_len += lcode(&le)) {
                lcode = *(ngx_http_script_len_code_pt *) le.ip;
            }
            le.ip += sizeof(uintptr_t);

#ifndef NGX_HAVE_LITTLE_ENDIAN
            uwsgi_strlen = uwsgi_swap16(key_len);
#else
            uwsgi_strlen = (uint16_t) key_len;
#endif
            e.pos = ngx_cpymem(e.pos, &uwsgi_strlen, 2);

            while (*(uintptr_t *) e.ip) {
                code = *(ngx_http_script_code_pt *) e.ip;
                code((ngx_http_script_engine_t *) & e);
            }

            pos = e.pos - val_len;
            /* move memory */
            for (i = 0; i < val_len; i += 2) {
                e.pos = ngx_cpymem(tmp, pos + i + 2, 2);
                e.pos = ngx_cpymem(pos + i + 2, pos, 2);
                e.pos = ngx_cpymem(pos, tmp, 2);
            }

            e.pos = pos;

#ifndef NGX_HAVE_LITTLE_ENDIAN
            uwsgi_strlen = uwsgi_swap16(val_len);
#else
            uwsgi_strlen = (uint16_t) val_len;
#endif
            e.pos = ngx_cpymem(e.pos, &uwsgi_strlen, 2);
            e.pos += val_len;

            e.ip += sizeof(uintptr_t);
        }

        b->last = e.pos;
    }

    if (uwcf->upstream.pass_request_headers) {

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

#ifndef NGX_HAVE_LITTLE_ENDIAN
            uwsgi_strlen = uwsgi_swap16(5 + header[i].key.len);
#else
            uwsgi_strlen = (uint16_t) (5 + header[i].key.len);
#endif
            b->last = ngx_cpymem(b->last, &uwsgi_strlen, 2);
            b->last = ngx_cpymem(b->last, "HTTP_", 5);
            for (n = 0; n < header[i].key.len; n++) {
                ch = header[i].key.data[n];

                if (ch >= 'a' && ch <= 'z') {
                    ch &= ~0x20;

                } else if (ch == '-') {
                    ch = '_';
                }

                *b->last++ = ch;
            }
#ifndef NGX_HAVE_LITTLE_ENDIAN
            uwsgi_strlen = uwsgi_swap16 (header[i].value.len);
#else
            uwsgi_strlen = (uint16_t) header[i].value.len;
#endif
            b->last = ngx_cpymem(b->last, &uwsgi_strlen, 2);
            b->last =
                ngx_copy(b->last, header[i].value.data, header[i].value.len);
        }
    }

    if (uwcf->uwsgi_string.data && uwcf->uwsgi_string.len) {
        b->last = ngx_copy(b->last, uwcf->uwsgi_string.data,
                           uwcf->uwsgi_string.len);
    }

    if (uwcf->upstream.pass_request_body) {
        body = r->upstream->request_bufs;
        r->upstream->request_bufs = cl;

        while (body) {
            b = ngx_alloc_buf(r->pool);
            if (b == NULL) {
                return NGX_ERROR;
            }

            ngx_memcpy(b, body->buf, sizeof(ngx_buf_t));

            cl->next = ngx_alloc_chain_link(r->pool);
            if (cl->next == NULL) {
                return NGX_ERROR;
            }

            cl = cl->next;
            cl->buf = b;

            body = body->next;
        }

        b->flush = 1;

    } else {
        r->upstream->request_bufs = cl;
    }

    cl->next = NULL;

    return NGX_OK;
}


static ngx_int_t
ngx_http_uwsgi_reinit_request(ngx_http_request_t *r)
{
    ngx_http_uwsgi_ctx_t  *ctx;

    ctx = ngx_http_get_module_ctx(r, ngx_http_uwsgi_module);

    if (ctx == NULL) {
        return NGX_OK;
    }

    ctx->status = 0;
    ctx->status_count = 0;
    ctx->status_start = NULL;
    ctx->status_end = NULL;

    r->upstream->process_header = ngx_http_uwsgi_process_status_line;

    return NGX_OK;
}

static ngx_int_t
ngx_http_uwsgi_parse_status_line(ngx_http_request_t *r,
    ngx_http_uwsgi_ctx_t *ctx)
{
    u_char                ch;
    u_char               *p;
    ngx_http_upstream_t  *u;
    enum {
        sw_start = 0,
        sw_H,
        sw_HT,
        sw_HTT,
        sw_HTTP,
        sw_first_major_digit,
        sw_major_digit,
        sw_first_minor_digit,
        sw_minor_digit,
        sw_status,
        sw_space_after_status,
        sw_status_text,
        sw_almost_done
    } state;

    u = r->upstream;

    state = r->state;

    for (p = u->buffer.pos; p < u->buffer.last; p++) {
        ch = *p;

        switch (state) {

        /* "HTTP/" */
        case sw_start:
            switch (ch) {
            case 'H':
                state = sw_H;
                break;
            default:
                return NGX_HTTP_UWSGI_PARSE_NO_HEADER;
            }
            break;

        case sw_H:
            switch (ch) {
            case 'T':
                state = sw_HT;
                break;
            default:
                return NGX_HTTP_UWSGI_PARSE_NO_HEADER;
            }
            break;

        case sw_HT:
            switch (ch) {
            case 'T':
                state = sw_HTT;
                break;
            default:
                return NGX_HTTP_UWSGI_PARSE_NO_HEADER;
            }
            break;

        case sw_HTT:
            switch (ch) {
            case 'P':
                state = sw_HTTP;
                break;
            default:
                return NGX_HTTP_UWSGI_PARSE_NO_HEADER;
            }
            break;

        case sw_HTTP:
            switch (ch) {
            case '/':
                state = sw_first_major_digit;
                break;
            default:
                return NGX_HTTP_UWSGI_PARSE_NO_HEADER;
            }
            break;

        /* the first digit of major HTTP version */
        case sw_first_major_digit:
            if (ch < '1' || ch > '9') {
                return NGX_HTTP_UWSGI_PARSE_NO_HEADER;
            }

            state = sw_major_digit;
            break;

        /* the major HTTP version or dot */
        case sw_major_digit:
            if (ch == '.') {
                state = sw_first_minor_digit;
                break;
            }

            if (ch < '0' || ch > '9') {
                return NGX_HTTP_UWSGI_PARSE_NO_HEADER;
            }

            break;

        /* the first digit of minor HTTP version */
        case sw_first_minor_digit:
            if (ch < '0' || ch > '9') {
                return NGX_HTTP_UWSGI_PARSE_NO_HEADER;
            }

            state = sw_minor_digit;
            break;

        /* the minor HTTP version or the end of the request line */
        case sw_minor_digit:
            if (ch == ' ') {
                state = sw_status;
                break;
            }

            if (ch < '0' || ch > '9') {
                return NGX_HTTP_UWSGI_PARSE_NO_HEADER;
            }

            break;

        /* HTTP status code */
        case sw_status:
            if (ch == ' ') {
                break;
            }

            if (ch < '0' || ch > '9') {
                return NGX_HTTP_UWSGI_PARSE_NO_HEADER;
            }

            ctx->status = ctx->status * 10 + ch - '0';

            if (++ctx->status_count == 3) {
                state = sw_space_after_status;
                ctx->status_start = p - 2;
            }

            break;

        /* space or end of line */
        case sw_space_after_status:
            switch (ch) {
            case ' ':
                state = sw_status_text;
                break;
            case '.':                /* IIS may send 403.1, 403.2, etc */
                state = sw_status_text;
                break;
            case CR:
                state = sw_almost_done;
                break;
            case LF:
                goto done;
            default:
                return NGX_HTTP_UWSGI_PARSE_NO_HEADER;
            }
            break;

        /* any text until end of line */
        case sw_status_text:
            switch (ch) {
            case CR:
                state = sw_almost_done;

                break;
            case LF:
                goto done;
            }
            break;

        /* end of status line */
        case sw_almost_done:
            ctx->status_end = p - 1;
            switch (ch) {
            case LF:
                goto done;
            default:
                return NGX_HTTP_UWSGI_PARSE_NO_HEADER;
            }
        }
    }

    u->buffer.pos = p;
    r->state = state;

    return NGX_AGAIN;

done:

    u->buffer.pos = p + 1;

    if (ctx->status_end == NULL) {
        ctx->status_end = p;
    }

    r->state = sw_start;

    return NGX_OK;
}


static ngx_int_t
ngx_http_uwsgi_process_status_line(ngx_http_request_t *r)
{
    ngx_int_t             rc;
    ngx_http_upstream_t   *u;
    ngx_http_uwsgi_ctx_t  *ctx;

    ctx = ngx_http_get_module_ctx(r, ngx_http_uwsgi_module);

    if (ctx == NULL) {
        return NGX_ERROR;
    }

    rc = ngx_http_uwsgi_parse_status_line(r, ctx);

    if (rc == NGX_AGAIN) {
        return rc;
    }

    u = r->upstream;

    if (rc == NGX_HTTP_UWSGI_PARSE_NO_HEADER) {

        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                      "upstream sent no valid HTTP/1.0 header");

        r->http_version = NGX_HTTP_VERSION_9;
        u->headers_in.status_n = NGX_HTTP_OK;
        u->state->status = NGX_HTTP_OK;

        return NGX_OK;
    }

    if (u->state) {
        u->state->status = ctx->status;
    }

    u->headers_in.status_n = ctx->status;

    u->headers_in.status_line.len = ctx->status_end - ctx->status_start;
    u->headers_in.status_line.data = ngx_pnalloc(r->pool,
                                                 u->headers_in.status_line.len);
    if (u->headers_in.status_line.data == NULL) {
        return NGX_ERROR;
    }

    ngx_memcpy(u->headers_in.status_line.data, ctx->status_start,
               u->headers_in.status_line.len);

    ngx_log_debug2(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "http uwsgi status %ui \"%V\"",
                   u->headers_in.status_n, &u->headers_in.status_line);

    u->process_header = ngx_http_uwsgi_process_header;

    return ngx_http_uwsgi_process_header(r);
}


static ngx_int_t
ngx_http_uwsgi_process_header(ngx_http_request_t *r)
{
    ngx_int_t                       rc;
    ngx_table_elt_t                *h;
    ngx_http_upstream_header_t     *hh;
    ngx_http_upstream_main_conf_t  *umcf;

    umcf = ngx_http_get_module_main_conf(r, ngx_http_upstream_module);

    for ( ;; ) {

        rc = ngx_http_parse_header_line(r, &r->upstream->buffer, 1);

        if (rc == NGX_OK) {

            /* a header line has been parsed successfully */

            h = ngx_list_push(&r->upstream->headers_in.headers);
            if (h == NULL) {
                return NGX_ERROR;
            }

            h->hash = r->header_hash;

            h->key.len = r->header_name_end - r->header_name_start;
            h->value.len = r->header_end - r->header_start;

            h->key.data = ngx_pnalloc(r->pool,
                                      h->key.len + 1 + h->value.len + 1
                                      + h->key.len);
            if (h->key.data == NULL) {
                return NGX_ERROR;
            }

            h->value.data = h->key.data + h->key.len + 1;
            h->lowcase_key = h->key.data + h->key.len + 1 + h->value.len + 1;

            ngx_cpystrn(h->key.data, r->header_name_start, h->key.len + 1);
            ngx_cpystrn(h->value.data, r->header_start, h->value.len + 1);

            if (h->key.len == r->lowcase_index) {
                ngx_memcpy(h->lowcase_key, r->lowcase_header, h->key.len);

            } else {
                ngx_strlow(h->lowcase_key, h->key.data, h->key.len);
            }

            hh = ngx_hash_find(&umcf->headers_in_hash, h->hash,
                               h->lowcase_key, h->key.len);

            if (hh && hh->handler(r, h, hh->offset) != NGX_OK) {
                return NGX_ERROR;
            }

            ngx_log_debug2(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                           "http uwsgi header: \"%V: %V\"", &h->key, &h->value);

            continue;
        }

        if (rc == NGX_HTTP_PARSE_HEADER_DONE) {

            /* a whole header has been parsed successfully */

            ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                           "http uwsgi header done");

            /*
             * if no "Server" and "Date" in header line,
             * then add the special empty headers
             */

            if (r->upstream->headers_in.server == NULL) {
                h = ngx_list_push(&r->upstream->headers_in.headers);
                if (h == NULL) {
                    return NGX_ERROR;
                }

                h->hash = ngx_hash(ngx_hash(ngx_hash(ngx_hash(
                                   ngx_hash ('s', 'e'), 'r'), 'v'), 'e'), 'r');

                h->key.len = sizeof("Server") - 1;
                h->key.data = (u_char *) "Server";
                h->value.len = 0;
                h->value.data = NULL;
                h->lowcase_key = (u_char *) "server";
            }

            if (r->upstream->headers_in.date == NULL) {
                h = ngx_list_push(&r->upstream->headers_in.headers);
                if (h == NULL) {
                    return NGX_ERROR;
                }

                h->hash = ngx_hash(ngx_hash(ngx_hash('d', 'a'), 't'), 'e');

                h->key.len = sizeof("Date") - 1;
                h->key.data = (u_char *) "Date";
                h->value.len = 0;
                h->value.data = NULL;
                h->lowcase_key = (u_char *) "date";
            }

            return NGX_OK;
        }

        if (rc == NGX_AGAIN) {
            return NGX_AGAIN;
        }

        /* there was error while a header line parsing */

        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                      "upstream sent invalid header");

        return NGX_HTTP_UPSTREAM_INVALID_HEADER;
    }
}


static void
ngx_http_uwsgi_abort_request(ngx_http_request_t *r)
{
    ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "abort http uwsgi request");

    return;
}


static void
ngx_http_uwsgi_finalize_request(ngx_http_request_t *r, ngx_int_t rc)
{
    ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "finalize http uwsgi request");

    return;
}


static ngx_int_t
ngx_http_uwsgi_add_variables(ngx_conf_t *cf)
{
    ngx_http_variable_t  *var, *v;

    for (v = ngx_http_uwsgi_vars; v->name.len; v++) {
        var = ngx_http_add_variable(cf, &v->name, v->flags);
        if (var == NULL) {
            return NGX_ERROR;
        }

        var->get_handler = v->get_handler;
        var->data = v->data;
    }

    return NGX_OK;
}


static void *
ngx_http_uwsgi_create_loc_conf(ngx_conf_t *cf)
{
    ngx_http_uwsgi_loc_conf_t  *conf;

    conf = ngx_pcalloc(cf->pool, sizeof(ngx_http_uwsgi_loc_conf_t));
    if (conf == NULL) {
        return NULL;
    }

    conf->upstream.store = NGX_CONF_UNSET;
    conf->upstream.store_access = NGX_CONF_UNSET_UINT;
    conf->upstream.buffering = NGX_CONF_UNSET;
    conf->upstream.ignore_client_abort = NGX_CONF_UNSET;

    conf->upstream.connect_timeout = NGX_CONF_UNSET_MSEC;
    conf->upstream.send_timeout = NGX_CONF_UNSET_MSEC;
    conf->upstream.read_timeout = NGX_CONF_UNSET_MSEC;

    conf->upstream.send_lowat = NGX_CONF_UNSET_SIZE;
    conf->upstream.buffer_size = NGX_CONF_UNSET_SIZE;

    conf->upstream.busy_buffers_size_conf = NGX_CONF_UNSET_SIZE;
    conf->upstream.max_temp_file_size_conf = NGX_CONF_UNSET_SIZE;
    conf->upstream.temp_file_write_size_conf = NGX_CONF_UNSET_SIZE;

    conf->upstream.pass_request_headers = NGX_CONF_UNSET;
    conf->upstream.pass_request_body = NGX_CONF_UNSET;

    conf->upstream.hide_headers = NGX_CONF_UNSET_PTR;
    conf->upstream.pass_headers = NGX_CONF_UNSET_PTR;

    conf->upstream.intercept_errors = NGX_CONF_UNSET;

    /* "uwsgi_cyclic_temp_file" is disabled */
    conf->upstream.cyclic_temp_file = 0;

    return conf;
}


static char *
ngx_http_uwsgi_merge_loc_conf(ngx_conf_t *cf, void *parent, void *child)
{
    ngx_http_uwsgi_loc_conf_t *prev = parent;
    ngx_http_uwsgi_loc_conf_t *conf = child;

    u_char                       *p;
    size_t                        size;
    uintptr_t                    *code;
    ngx_uint_t                    i;
    ngx_keyval_t                 *src;
    ngx_hash_init_t               hash;
    ngx_http_script_compile_t     sc;
    ngx_http_script_copy_code_t  *copy;

    if (conf->upstream.store != 0) {
        ngx_conf_merge_value(conf->upstream.store, prev->upstream.store, 0);

        if (conf->upstream.store_lengths == NULL) {
            conf->upstream.store_lengths = prev->upstream.store_lengths;
            conf->upstream.store_values = prev->upstream.store_values;
        }
    }

    ngx_conf_merge_uint_value(conf->upstream.store_access,
                              prev->upstream.store_access, 0600);

    ngx_conf_merge_value(conf->upstream.buffering,
                              prev->upstream.buffering, 1);

    ngx_conf_merge_value(conf->upstream.ignore_client_abort,
                              prev->upstream.ignore_client_abort, 0);

    ngx_conf_merge_msec_value(conf->upstream.connect_timeout,
                              prev->upstream.connect_timeout, 60000);

    ngx_conf_merge_msec_value(conf->upstream.send_timeout,
                              prev->upstream.send_timeout, 60000);

    ngx_conf_merge_msec_value(conf->upstream.read_timeout,
                              prev->upstream.read_timeout, 60000);

    ngx_conf_merge_size_value(conf->upstream.send_lowat,
                              prev->upstream.send_lowat, 0);

    ngx_conf_merge_size_value(conf->upstream.buffer_size,
                              prev->upstream.buffer_size,
                              (size_t) ngx_pagesize);


    ngx_conf_merge_bufs_value(conf->upstream.bufs, prev->upstream.bufs,
                              8, ngx_pagesize);

    if (conf->upstream.bufs.num < 2) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                           "there must be at least 2 \"uwsgi_buffers\"");
        return NGX_CONF_ERROR;
    }


    size = conf->upstream.buffer_size;
    if (size < conf->upstream.bufs.size) {
        size = conf->upstream.bufs.size;
    }


    ngx_conf_merge_size_value(conf->upstream.busy_buffers_size_conf,
                              prev->upstream.busy_buffers_size_conf,
                              NGX_CONF_UNSET_SIZE);

    if (conf->upstream.busy_buffers_size_conf == NGX_CONF_UNSET_SIZE) {
        conf->upstream.busy_buffers_size = 2 * size;
    } else {
        conf->upstream.busy_buffers_size =
            conf->upstream.busy_buffers_size_conf;
    }

    if (conf->upstream.busy_buffers_size < size) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
            "\"uwsgi_busy_buffers_size\" must be equal or bigger "
            "than maximum of the value of \"uwsgi_buffer_size\" and "
            "one of the \"uwsgi_buffers\"");

        return NGX_CONF_ERROR;
    }

    if (conf->upstream.busy_buffers_size
        > (conf->upstream.bufs.num - 1) * conf->upstream.bufs.size)
    {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
            "\"uwsgi_busy_buffers_size\" must be less than "
            "the size of all \"uwsgi_buffers\" minus one buffer");

        return NGX_CONF_ERROR;
    }


    ngx_conf_merge_size_value(conf->upstream.temp_file_write_size_conf,
                              prev->upstream.temp_file_write_size_conf,
                              NGX_CONF_UNSET_SIZE);

    if (conf->upstream.temp_file_write_size_conf == NGX_CONF_UNSET_SIZE) {
        conf->upstream.temp_file_write_size = 2 * size;
    } else {
        conf->upstream.temp_file_write_size =
            conf->upstream.temp_file_write_size_conf;
    }

    if (conf->upstream.temp_file_write_size < size) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
            "\"uwsgi_temp_file_write_size\" must be equal or bigger than "
            "maximum of the value of \"uwsgi_buffer_size\" and "
            "one of the \"uwsgi_buffers\"");

        return NGX_CONF_ERROR;
    }


    ngx_conf_merge_size_value(conf->upstream.max_temp_file_size_conf,
                              prev->upstream.max_temp_file_size_conf,
                              NGX_CONF_UNSET_SIZE);

    if (conf->upstream.max_temp_file_size_conf == NGX_CONF_UNSET_SIZE) {
        conf->upstream.max_temp_file_size = 1024 * 1024 * 1024;
    } else {
        conf->upstream.max_temp_file_size =
            conf->upstream.max_temp_file_size_conf;
    }

    if (conf->upstream.max_temp_file_size != 0
        && conf->upstream.max_temp_file_size < size) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
            "\"uwsgi_max_temp_file_size\" must be equal to zero to disable "
            "the temporary files usage or must be equal or bigger than "
            "maximum of the value of \"uwsgi_buffer_size\" and "
            "one of the \"uwsgi_buffers\"");

        return NGX_CONF_ERROR;
    }


    ngx_conf_merge_bitmask_value(conf->upstream.ignore_headers,
                                 prev->upstream.ignore_headers,
                                 NGX_CONF_BITMASK_SET);


    ngx_conf_merge_bitmask_value(conf->upstream.next_upstream,
                                 prev->upstream.next_upstream,
                                 (NGX_CONF_BITMASK_SET
                                  |NGX_HTTP_UPSTREAM_FT_ERROR
                                  |NGX_HTTP_UPSTREAM_FT_TIMEOUT));

    if (conf->upstream.next_upstream & NGX_HTTP_UPSTREAM_FT_OFF) {
        conf->upstream.next_upstream = NGX_CONF_BITMASK_SET
                                       |NGX_HTTP_UPSTREAM_FT_OFF;
    }

    if (ngx_conf_merge_path_value(cf, &conf->upstream.temp_path,
                                  prev->upstream.temp_path,
                                  &ngx_http_uwsgi_temp_path)
        != NGX_OK)
    {
        return NGX_CONF_ERROR;
    }

    ngx_conf_merge_value(conf->upstream.pass_request_headers,
                         prev->upstream.pass_request_headers, 1);
    ngx_conf_merge_value(conf->upstream.pass_request_body,
                         prev->upstream.pass_request_body, 1);

    ngx_conf_merge_value(conf->upstream.intercept_errors,
                         prev->upstream.intercept_errors, 0);

    ngx_conf_merge_str_value(conf->uwsgi_string, prev->uwsgi_string, "");

    hash.max_size = 512;
    hash.bucket_size = ngx_align(64, ngx_cacheline_size);
    hash.name = "uwsgi_hide_headers_hash";

    if (ngx_http_upstream_hide_headers_hash(cf, &conf->upstream,
                                            &prev->upstream,
                                            ngx_http_uwsgi_hide_headers, &hash)
        != NGX_OK)
    {
        return NGX_CONF_ERROR;
    }

    if (conf->upstream.upstream == NULL) {
        conf->upstream.upstream = prev->upstream.upstream;
    }

    if (conf->uwsgi_lengths == NULL) {
        conf->uwsgi_lengths = prev->uwsgi_lengths;
        conf->uwsgi_values = prev->uwsgi_values;
    }

    if (conf->modifier1 == 0) {
        conf->modifier1 = prev->modifier1;
    }

    if (conf->modifier2 == 0) {
        conf->modifier2 = prev->modifier2;
    }

    if (conf->params_source == NULL) {
        conf->flushes = prev->flushes;
        conf->params_len = prev->params_len;
        conf->params = prev->params;
        conf->params_source = prev->params_source;

        if (conf->params_source == NULL) {
            return NGX_CONF_OK;
        }
    }

    conf->params_len = ngx_array_create(cf->pool, 64, 1);
    if (conf->params_len == NULL) {
        return NGX_CONF_ERROR;
    }

    conf->params = ngx_array_create(cf->pool, 512, 1);
    if (conf->params == NULL) {
        return NGX_CONF_ERROR;
    }

    src = conf->params_source->elts;
    for (i = 0; i < conf->params_source->nelts; i++) {

        if (ngx_http_script_variables_count(&src[i].value) == 0) {
            copy = ngx_array_push_n(conf->params_len,
                                    sizeof(ngx_http_script_copy_code_t));
            if (copy == NULL) {
                return NGX_CONF_ERROR;
            }

            copy->code = (ngx_http_script_code_pt)
                              ngx_http_script_copy_len_code;
            copy->len = src[i].key.len;

            copy = ngx_array_push_n(conf->params_len,
                                    sizeof(ngx_http_script_copy_code_t));
            if (copy == NULL) {
                return NGX_CONF_ERROR;
            }

            copy->code = (ngx_http_script_code_pt)
                               ngx_http_script_copy_len_code;
            copy->len = src[i].value.len;


            size = (sizeof(ngx_http_script_copy_code_t)
                    + src[i].key.len + src[i].value.len
                    + sizeof(uintptr_t) - 1) & ~(sizeof(uintptr_t) - 1);

            copy = ngx_array_push_n(conf->params, size);
            if (copy == NULL) {
                return NGX_CONF_ERROR;
            }

            copy->code = ngx_http_script_copy_code;
            copy->len = src[i].key.len + src[i].value.len;

            p = (u_char *) copy + sizeof(ngx_http_script_copy_code_t);

            p = ngx_cpymem(p, src[i].key.data, src[i].key.len);
            ngx_memcpy(p, src[i].value.data, src[i].value.len);

        } else {
            copy = ngx_array_push_n(conf->params_len,
                                    sizeof(ngx_http_script_copy_code_t));
            if (copy == NULL) {
                return NGX_CONF_ERROR;
            }

            copy->code = (ngx_http_script_code_pt)
                              ngx_http_script_copy_len_code;
            copy->len = src[i].key.len;


            size = (sizeof(ngx_http_script_copy_code_t)
                    + src[i].key.len + sizeof(uintptr_t) - 1)
                   & ~(sizeof(uintptr_t) - 1);

            copy = ngx_array_push_n(conf->params, size);
            if (copy == NULL) {
                return NGX_CONF_ERROR;
            }

            copy->code = ngx_http_script_copy_code;
            copy->len = src[i].key.len;

            p = (u_char *) copy + sizeof(ngx_http_script_copy_code_t);
            ngx_memcpy(p, src[i].key.data, src[i].key.len);


            ngx_memzero(&sc, sizeof(ngx_http_script_compile_t));

            sc.cf = cf;
            sc.source = &src[i].value;
            sc.flushes = &conf->flushes;
            sc.lengths = &conf->params_len;
            sc.values = &conf->params;

            if (ngx_http_script_compile(&sc) != NGX_OK) {
                return NGX_CONF_ERROR;
            }
        }

        code = ngx_array_push_n(conf->params_len, sizeof(uintptr_t));
        if (code == NULL) {
            return NGX_CONF_ERROR;
        }

        *code = (uintptr_t) NULL;


        code = ngx_array_push_n(conf->params, sizeof(uintptr_t));
        if (code == NULL) {
            return NGX_CONF_ERROR;
        }

        *code = (uintptr_t) NULL;
    }

    code = ngx_array_push_n(conf->params_len, sizeof(uintptr_t));
    if (code == NULL) {
        return NGX_CONF_ERROR;
    }

    *code = (uintptr_t) NULL;

    return NGX_CONF_OK;
}


static char *
ngx_http_uwsgi_pass(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    ngx_http_uwsgi_loc_conf_t *uwcf = conf;

    ngx_url_t                   u;
    ngx_str_t                  *value, *url;
    ngx_uint_t                  n;
    ngx_http_core_loc_conf_t   *clcf;
    ngx_http_script_compile_t   sc;

    if (uwcf->upstream.upstream || uwcf->uwsgi_lengths) {
        return "is duplicate";
    }

    clcf = ngx_http_conf_get_module_loc_conf (cf, ngx_http_core_module);
    clcf->handler = ngx_http_uwsgi_handler;

    value = cf->args->elts;

    url = &value[1];

    n = ngx_http_script_variables_count(url);

    if (n) {

        ngx_memzero(&sc, sizeof(ngx_http_script_compile_t));

        sc.cf = cf;
        sc.source = url;
        sc.lengths = &uwcf->uwsgi_lengths;
        sc.values = &uwcf->uwsgi_values;
        sc.variables = n;
        sc.complete_lengths = 1;
        sc.complete_values = 1;

        if (ngx_http_script_compile(&sc) != NGX_OK) {
            return NGX_CONF_ERROR;
        }

        return NGX_CONF_OK;
    }

    ngx_memzero(&u, sizeof(ngx_url_t));

    u.url = value[1];
    u.no_resolve = 1;

    uwcf->upstream.upstream = ngx_http_upstream_add(cf, &u, 0);
    if (uwcf->upstream.upstream == NULL) {
        return NGX_CONF_ERROR;
    }

    if (clcf->name.data[clcf->name.len - 1] == '/') {
        clcf->auto_redirect = 1;
    }

    return NGX_CONF_OK;
}


static char *
ngx_http_uwsgi_modifier1(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    ngx_http_uwsgi_loc_conf_t *uwcf = conf;
    ngx_str_t  *value;

    value = cf->args->elts;

    uwcf->modifier1 = (u_char) ngx_atoi(value[1].data, value[1].len);

    return NGX_CONF_OK;
}


static char *
ngx_http_uwsgi_modifier2(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    ngx_http_uwsgi_loc_conf_t *uwcf = conf;

    ngx_str_t  *value;

    value = cf->args->elts;

    uwcf->modifier2 = (u_char) ngx_atoi(value[1].data, value[1].len);

    return NGX_CONF_OK;
}
