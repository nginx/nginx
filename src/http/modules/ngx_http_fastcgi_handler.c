
/*
 * Copyright (C) Igor Sysoev
 */


#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>
#include <nginx.h>


typedef struct {
    ngx_http_upstream_conf_t        upstream;

    ngx_peers_t                    *peers;

    ngx_uint_t                      params;

    ngx_str_t                       root;
    ngx_str_t                       index;

    ngx_str_t                      *location;
} ngx_http_fastcgi_loc_conf_t;


typedef struct {
    ngx_list_t                      headers;

    ngx_table_elt_t                *status;

    ngx_table_elt_t                *content_type;
    ngx_table_elt_t                *content_length;
    ngx_table_elt_t                *x_powered_by;

#if (NGX_HTTP_GZIP)
    ngx_table_elt_t                *content_encoding;
#endif
} ngx_http_fastcgi_headers_in_t;


typedef struct {
    ngx_http_fastcgi_headers_in_t   headers_in;
} ngx_http_fastcgi_upstream_t;


typedef enum {
    ngx_http_fastcgi_st_version = 0,
    ngx_http_fastcgi_st_type,
    ngx_http_fastcgi_st_request_id_hi,
    ngx_http_fastcgi_st_request_id_lo,
    ngx_http_fastcgi_st_content_length_hi,
    ngx_http_fastcgi_st_content_length_lo,
    ngx_http_fastcgi_st_padding_length,
    ngx_http_fastcgi_st_reserved,
    ngx_http_fastcgi_st_data,
    ngx_http_fastcgi_st_padding,
} ngx_http_fastcgi_state_e;


typedef struct {
    ngx_http_fastcgi_state_e      state;
    u_char                       *pos;
    u_char                       *last;
    ngx_uint_t                    type;
    size_t                        length;
    size_t                        padding;

    ngx_http_fastcgi_upstream_t  *upstream;
} ngx_http_fastcgi_ctx_t;


#define NGX_HTTP_FASTCGI_REMOTE_ADDR          0x0002
#define NGX_HTTP_FASTCGI_REMOTE_USER          0x0004
#define NGX_HTTP_FASTCGI_SERVER_NAME          0x0008
#define NGX_HTTP_FASTCGI_SERVER_ADDR          0x0010
#define NGX_HTTP_FASTCGI_SERVER_PORT          0x0020
#define NGX_HTTP_FASTCGI_SCRIPT_NAME          0x0040
#define NGX_HTTP_FASTCGI_AUTH_TYPE            0x0080
#define NGX_HTTP_FASTCGI_SERVER_PROTOCOL      0x0100
#define NGX_HTTP_FASTCGI_SERVER_SOFTWARE      0x0200
#define NGX_HTTP_FASTCGI_GATEWAY_INTERFACE    0x0400
#define NGX_HTTP_FASTCGI_REQUEST_URI          0x0800
#define NGX_HTTP_FASTCGI_REDIRECT_STATUS      0x1000


#define NGX_HTTP_FASTCGI_RESPONDER      1

#define NGX_HTTP_FASTCGI_BEGIN_REQUEST  1
#define NGX_HTTP_FASTCGI_ABORT_REQUEST  2
#define NGX_HTTP_FASTCGI_END_REQUEST    3
#define NGX_HTTP_FASTCGI_PARAMS         4
#define NGX_HTTP_FASTCGI_STDIN          5
#define NGX_HTTP_FASTCGI_STDOUT         6
#define NGX_HTTP_FASTCGI_STDERR         7
#define NGX_HTTP_FASTCGI_DATA           8


typedef struct {
    u_char  version;
    u_char  type;
    u_char  request_id_hi;
    u_char  request_id_lo;
    u_char  content_length_hi;
    u_char  content_length_lo;
    u_char  padding_length;
    u_char  reserved;
} ngx_http_fastcgi_header_t;


typedef struct {
    u_char  role_hi;
    u_char  role_lo;
    u_char  flags;
    u_char  reserved[5];
} ngx_http_fastcgi_begin_request_t;


static ngx_int_t ngx_http_fastcgi_create_request(ngx_http_request_t *r);
static ngx_int_t ngx_http_fastcgi_reinit_request(ngx_http_request_t *r);
static ngx_int_t ngx_http_fastcgi_process_header(ngx_http_request_t *r);
static ngx_int_t ngx_http_fastcgi_send_header(ngx_http_request_t *r);
static ngx_int_t ngx_http_fastcgi_input_filter(ngx_event_pipe_t *p,
                                               ngx_buf_t *buf);
static ngx_int_t ngx_http_fastcgi_process_record(ngx_http_request_t *r,
                                                 ngx_http_fastcgi_ctx_t *f);
static void ngx_http_fastcgi_abort_request(ngx_http_request_t *r);
static void ngx_http_fastcgi_finalize_request(ngx_http_request_t *r,
                                              ngx_int_t rc);

static char *ngx_http_fastcgi_pass(ngx_conf_t *cf, ngx_command_t *cmd,
                                   void *conf);
static char *ngx_http_fastcgi_lowat_check(ngx_conf_t *cf, void *post,
                                          void *data);
static void *ngx_http_fastcgi_create_loc_conf(ngx_conf_t *cf);
static char *ngx_http_fastcgi_merge_loc_conf(ngx_conf_t *cf,
                                             void *parent, void *child);


static ngx_str_t ngx_http_fastcgi_methods[] = {
    ngx_string("GET"),
    ngx_string("HEAD"),
    ngx_string("POST")
};


static ngx_str_t ngx_http_fastcgi_uri = ngx_string("/");


static ngx_http_header_t ngx_http_fastcgi_headers_in[] = {
    { ngx_string("Status"), offsetof(ngx_http_fastcgi_headers_in_t, status) },

    { ngx_string("Content-Type"),
                       offsetof(ngx_http_fastcgi_headers_in_t, content_type) },

    { ngx_string("Content-Length"),
                     offsetof(ngx_http_fastcgi_headers_in_t, content_length) },

    { ngx_string("X-Powered-By"),
                       offsetof(ngx_http_fastcgi_headers_in_t, x_powered_by) },

#if (NGX_HTTP_GZIP)
    { ngx_string("Content-Encoding"),
                   offsetof(ngx_http_fastcgi_headers_in_t, content_encoding) },
#endif

    { ngx_null_string, 0 }
};


static ngx_conf_post_t  ngx_http_fastcgi_lowat_post =
                                             { ngx_http_fastcgi_lowat_check } ;

static ngx_conf_bitmask_t  ngx_http_fastcgi_next_upstream_masks[] = {
    { ngx_string("error"), NGX_HTTP_UPSTREAM_FT_ERROR },
    { ngx_string("timeout"), NGX_HTTP_UPSTREAM_FT_TIMEOUT },
    { ngx_string("invalid_header"), NGX_HTTP_UPSTREAM_FT_INVALID_HEADER },
    { ngx_string("http_500"), NGX_HTTP_UPSTREAM_FT_HTTP_500 },
    { ngx_string("http_404"), NGX_HTTP_UPSTREAM_FT_HTTP_404 },
    { ngx_null_string, 0 }
};


static ngx_conf_bitmask_t  ngx_http_fastcgi_params_masks[] = {
    { ngx_string("remote_addr"), NGX_HTTP_FASTCGI_REMOTE_ADDR },
    { ngx_string("server_port"), NGX_HTTP_FASTCGI_SERVER_PORT },
    { ngx_string("server_addr"), NGX_HTTP_FASTCGI_SERVER_ADDR },
    { ngx_string("server_name"), NGX_HTTP_FASTCGI_SERVER_NAME },
    { ngx_string("script_name"), NGX_HTTP_FASTCGI_SCRIPT_NAME },

    { ngx_string("server_protocol"), NGX_HTTP_FASTCGI_SERVER_PROTOCOL },
    { ngx_string("server_software"), NGX_HTTP_FASTCGI_SERVER_SOFTWARE },
    { ngx_string("gateway_interface"), NGX_HTTP_FASTCGI_GATEWAY_INTERFACE },

    { ngx_string("redirect_status"), NGX_HTTP_FASTCGI_REDIRECT_STATUS },
    { ngx_string("request_uri"), NGX_HTTP_FASTCGI_REQUEST_URI },

    { ngx_null_string, 0 }
};


static ngx_command_t  ngx_http_fastcgi_commands[] = {

    { ngx_string("fastcgi_pass"),
      NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
      ngx_http_fastcgi_pass,
      NGX_HTTP_LOC_CONF_OFFSET,
      0,
      NULL },

    { ngx_string("fastcgi_root"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_str_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_fastcgi_loc_conf_t, root),
      NULL },

    { ngx_string("fastcgi_index"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_str_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_fastcgi_loc_conf_t, index),
      NULL },

    { ngx_string("fastcgi_connect_timeout"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_msec_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_fastcgi_loc_conf_t, upstream.connect_timeout),
      NULL },

    { ngx_string("fastcgi_send_timeout"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_msec_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_fastcgi_loc_conf_t, upstream.send_timeout),
      NULL },

    { ngx_string("fastcgi_send_lowat"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_size_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_fastcgi_loc_conf_t, upstream.send_lowat),
      &ngx_http_fastcgi_lowat_post },

    { ngx_string("fastcgi_header_buffer_size"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_size_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_fastcgi_loc_conf_t, upstream.header_buffer_size),
      NULL },

    { ngx_string("fastcgi_x_powered_by"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_FLAG,
      ngx_conf_set_flag_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_fastcgi_loc_conf_t, upstream.x_powered_by),
      NULL },

    { ngx_string("fastcgi_read_timeout"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_msec_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_fastcgi_loc_conf_t, upstream.read_timeout),
      NULL },

    { ngx_string("fastcgi_buffers"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE2,
      ngx_conf_set_bufs_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_fastcgi_loc_conf_t, upstream.bufs),
      NULL },

    { ngx_string("fastcgi_busy_buffers_size"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_size_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_fastcgi_loc_conf_t, upstream.busy_buffers_size),
      NULL },

    { ngx_string("fastcgi_temp_path"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1234,
      ngx_conf_set_path_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_fastcgi_loc_conf_t, upstream.temp_path),
      (void *) ngx_garbage_collector_temp_handler },

    { ngx_string("fastcgi_max_temp_file_size"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_size_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_fastcgi_loc_conf_t, upstream.max_temp_file_size),
      NULL },

    { ngx_string("fastcgi_temp_file_write_size"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_size_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_fastcgi_loc_conf_t, upstream.temp_file_write_size),
      NULL },

    { ngx_string("fastcgi_next_upstream"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_ANY,
      ngx_conf_set_bitmask_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_fastcgi_loc_conf_t, upstream.next_upstream),
      &ngx_http_fastcgi_next_upstream_masks },

    { ngx_string("fastcgi_params"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_ANY,
      ngx_conf_set_bitmask_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_fastcgi_loc_conf_t, params),
      &ngx_http_fastcgi_params_masks },

      ngx_null_command
};


ngx_http_module_t  ngx_http_fastcgi_module_ctx = {
    NULL,                                  /* pre conf */

    NULL,                                  /* create main configuration */
    NULL,                                  /* init main configuration */

    NULL,                                  /* create server configuration */
    NULL,                                  /* merge server configuration */

    ngx_http_fastcgi_create_loc_conf,      /* create location configuration */
    ngx_http_fastcgi_merge_loc_conf        /* merge location configuration */
};


ngx_module_t  ngx_http_fastcgi_module = {
    NGX_MODULE,
    &ngx_http_fastcgi_module_ctx,          /* module context */
    ngx_http_fastcgi_commands,             /* module directives */
    NGX_HTTP_MODULE,                       /* module type */
    NULL,                                  /* init module */
    NULL                                   /* init process */
};


static ngx_int_t ngx_http_fastcgi_handler(ngx_http_request_t *r)
{
    ngx_int_t                     rc;
    ngx_http_upstream_t          *u;
    ngx_http_fastcgi_loc_conf_t  *flcf;

    flcf = ngx_http_get_module_loc_conf(r, ngx_http_fastcgi_module);

    if (!(u = ngx_pcalloc(r->pool, sizeof(ngx_http_upstream_t)))) {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    u->peer.log = r->connection->log;
    u->peer.log_error = NGX_ERROR_ERR;
    u->peer.peers = flcf->peers;
    u->peer.tries = flcf->peers->number;
#if (NGX_THREADS)
    u->peer.lock = &r->connection->lock;
#endif

    u->output.tag = (ngx_buf_tag_t) &ngx_http_fastcgi_module;

    u->conf = &flcf->upstream;

    u->location = flcf->location;

    u->create_request = ngx_http_fastcgi_create_request;
    u->reinit_request = ngx_http_fastcgi_reinit_request;
    u->process_header = ngx_http_fastcgi_process_header;
    u->send_header = ngx_http_fastcgi_send_header;
    u->abort_request = ngx_http_fastcgi_abort_request;
    u->finalize_request = ngx_http_fastcgi_finalize_request;

    u->pipe.input_filter = ngx_http_fastcgi_input_filter;
    u->pipe.input_ctx = r;

    u->log_ctx = r->connection->log->data;
    u->log_handler = ngx_http_upstream_log_error;

    u->schema.len = sizeof("fastcgi://") - 1;
    u->schema.data = (u_char *) "fastcgi://";
    u->uri.len = sizeof("/") - 1;
    u->uri.data = (u_char *) "/";

    r->upstream = u;

    rc = ngx_http_read_client_request_body(r, ngx_http_upstream_init);

    if (rc >= NGX_HTTP_SPECIAL_RESPONSE) {
        return rc;
    }

    return NGX_DONE;
}


static ngx_int_t ngx_http_fastcgi_create_request(ngx_http_request_t *r)
{
    u_char                             ch, *pos, addr_text[INET_ADDRSTRLEN];
    size_t                             size, len, index, padding, addr_len;
    off_t                              file_pos;
    ngx_buf_t                         *b;
    socklen_t                          slen;
    ngx_chain_t                       *cl, *body;
    ngx_uint_t                         i, n, next;
    ngx_list_part_t                   *part;
    ngx_table_elt_t                   *header;
    struct sockaddr_in                 sin;
    ngx_http_fastcgi_header_t         *h;
    ngx_http_fastcgi_loc_conf_t       *flcf;
    ngx_http_fastcgi_begin_request_t  *br;

    flcf = ngx_http_get_module_loc_conf(r, ngx_http_fastcgi_module);

    if ((flcf->params & NGX_HTTP_FASTCGI_SERVER_ADDR) && r->in_addr == 0) {

        slen = sizeof(struct sockaddr_in);
        if (getsockname(r->connection->fd,
                        (struct sockaddr *) &sin, &slen) == -1)
        {
            ngx_log_error(NGX_LOG_CRIT, r->connection->log,
                          ngx_socket_errno, "getsockname() failed");
            return NGX_ERROR;
        }

        r->in_addr = sin.sin_addr.s_addr;
    }

    addr_len = ngx_inet_ntop(r->connection->listening->family, &r->in_addr,
                             addr_text, INET_ADDRSTRLEN);
    if (addr_len == 0) {
        return NGX_ERROR;
    }


    if (r->upstream->method) {
        len = 1 + 1 + sizeof("REQUEST_METHOD") - 1
                + ngx_http_fastcgi_methods[r->upstream->method - 1].len;
    
    } else {
        len = 1 + ((r->method_name.len - 1 > 127) ? 4 : 1)
                                            + sizeof("REQUEST_METHOD") - 1
                                            + r->method_name.len - 1;
    }


    index = (r->uri.data[r->uri.len - 1] == '/') ? flcf->index.len : 0;

    len += 1 + ((flcf->root.len + r->uri.len + index > 127) ? 4 : 1)
             + sizeof("PATH_TRANSLATED") - 1
             + flcf->root.len + r->uri.len + index;

    if (r->args.len) {
        len += 1 + ((r->args.len > 127) ? 4 : 1) + sizeof("QUERY_STRING") - 1
                                                 + r->args.len;
    }

    if (r->headers_in.content_length_n > 0) {
        len += 1 + ((r->headers_in.content_length->value.len > 127) ? 4 : 1)
                 + sizeof("CONTENT_LENGTH") - 1
                 + r->headers_in.content_length->value.len;
    }


    if (r->headers_in.content_type) {
        len += 1 + ((r->headers_in.content_type->value.len > 127) ? 4 : 1)
                 + sizeof("CONTENT_TYPE") - 1
                 + r->headers_in.content_type->value.len;
    }


    if (flcf->params & NGX_HTTP_FASTCGI_REDIRECT_STATUS) {
        len += 1 + 1 + sizeof("REDIRECT_STATUS200") - 1;
    }

    if (flcf->params & NGX_HTTP_FASTCGI_REQUEST_URI) {
        len += 1 + ((r->unparsed_uri.len > 127) ? 4 : 1)
                 + sizeof("REQUEST_URI") - 1 + r->unparsed_uri.len;
    }

    if (flcf->params & NGX_HTTP_FASTCGI_SCRIPT_NAME) {
        len += 1 + ((r->uri.len + index > 127) ? 4 : 1)
                 + sizeof("SCRIPT_NAME") - 1 + r->uri.len + index ;
    }

    if (flcf->params & NGX_HTTP_FASTCGI_REMOTE_ADDR) {
        len += 1 + 1 + sizeof("REMOTE_ADDR") - 1 + r->connection->addr_text.len;
    }

    if (flcf->params & NGX_HTTP_FASTCGI_SERVER_NAME) {
        len += 1 + 1 + sizeof("SERVER_NAME") - 1 + r->server_name.len;
    }

    if (flcf->params & NGX_HTTP_FASTCGI_SERVER_PORT) {
        len += 1 + 1 + sizeof("SERVER_PORT") - 1 + r->port_text->len - 1;
    }

    if (flcf->params & NGX_HTTP_FASTCGI_SERVER_ADDR) {
        len += 1 + 1 + sizeof("SERVER_ADDR") - 1 + addr_len;
    }

    if (flcf->params & NGX_HTTP_FASTCGI_SERVER_PROTOCOL
        && r->http_protocol.len)
    {
        len += 1 + ((r->http_protocol.len > 127) ? 4 : 1)
                 + sizeof("SERVER_PROTOCOL") - 1 + r->http_protocol.len;
    }

    if (flcf->params & NGX_HTTP_FASTCGI_SERVER_SOFTWARE) {
        len += 1 + 1 + sizeof("SERVER_SOFTWARE") - 1 + sizeof(NGINX_VER) - 1;
    }

    if (flcf->params & NGX_HTTP_FASTCGI_GATEWAY_INTERFACE) {
        len += 1 + 1 + sizeof("GATEWAY_INTERFACE") - 1 + sizeof("CGI/1.1") - 1;
    }


    part = &r->headers_in.headers.part;
    header = part->elts;

    for (i = 0; /* void */; i++) {

        if (i >= part->nelts) {
            if (part->next == NULL) {
                break;
            }

            part = part->next;
            header = part->elts;
            i = 0;
        }

        len += ((header[i].key.len > 127) ? 4 : 1)
               + ((header[i].value.len > 127) ? 4 : 1)
               + 5 + header[i].key.len + header[i].value.len;
    }


    if (len > 65535) {
        ngx_log_error(NGX_LOG_ALERT, r->connection->log, 0,
                      "fastcgi: the request record is too big");
        return NGX_ERROR;
    }


    padding = 8 - len % 8;
    padding = (padding == 8) ? 0 : padding;


    size = sizeof(ngx_http_fastcgi_header_t)
           + sizeof(ngx_http_fastcgi_begin_request_t)

           + sizeof(ngx_http_fastcgi_header_t)  /* NGX_HTTP_FASTCGI_PARAMS */
           + len + padding
           + sizeof(ngx_http_fastcgi_header_t)  /* NGX_HTTP_FASTCGI_PARAMS */

           + sizeof(ngx_http_fastcgi_header_t); /* NGX_HTTP_FASTCGI_STDIN */


    if (!(b = ngx_create_temp_buf(r->pool, size))) {
        return NGX_ERROR;
    }

    if (!(cl = ngx_alloc_chain_link(r->pool))) {
        return NGX_ERROR;
    }

    cl->buf = b;

    h = (ngx_http_fastcgi_header_t *) b->pos;

    h->version = 1;
    h->type = NGX_HTTP_FASTCGI_BEGIN_REQUEST;
    h->request_id_hi = 0;
    h->request_id_lo = 1;
    h->content_length_hi = 0;
    h->content_length_lo = sizeof(ngx_http_fastcgi_begin_request_t);
    h->padding_length = 0;
    h->reserved = 0;

    br = (ngx_http_fastcgi_begin_request_t *)
                                  (b->pos + sizeof(ngx_http_fastcgi_header_t));
    br->role_hi = 0;
    br->role_lo = NGX_HTTP_FASTCGI_RESPONDER;
    br->flags = 0; /* NGX_HTTP_FASTCGI_KEEP_CONN */
    br->reserved[0] = 0;
    br->reserved[1] = 0;
    br->reserved[2] = 0;
    br->reserved[3] = 0;
    br->reserved[4] = 0;

    h = (ngx_http_fastcgi_header_t *)
             (b->pos + sizeof(ngx_http_fastcgi_header_t)
                     + sizeof(ngx_http_fastcgi_begin_request_t));

    h->version = 1;
    h->type = NGX_HTTP_FASTCGI_PARAMS;
    h->request_id_hi = 0;
    h->request_id_lo = 1;
    h->content_length_hi = (u_char) ((len >> 8) & 0xff);
    h->content_length_lo = (u_char) (len & 0xff);
    h->padding_length = (u_char) padding;
    h->reserved = 0;

    b->last = b->pos + sizeof(ngx_http_fastcgi_header_t)
                     + sizeof(ngx_http_fastcgi_begin_request_t)
                     + sizeof(ngx_http_fastcgi_header_t);


    *b->last++ = sizeof("PATH_TRANSLATED") - 1;

    len = flcf->root.len + r->uri.len + index;
    if (len > 127) {
        *b->last++ = (u_char) (((len >> 24) & 0x7f) | 0x80);
        *b->last++ = (u_char) ((len >> 16) & 0xff);
        *b->last++ = (u_char) ((len >> 8) & 0xff);
        *b->last++ = (u_char) (len & 0xff);

    } else {
        *b->last++ = (u_char) len;
    }

    b->last = ngx_cpymem(b->last, "PATH_TRANSLATED",
                         sizeof("PATH_TRANSLATED") - 1);
    b->last = ngx_cpymem(b->last, flcf->root.data, flcf->root.len);
    b->last = ngx_cpymem(b->last, r->uri.data, r->uri.len);

    if (index) {
        b->last = ngx_cpymem(b->last, flcf->index.data, index);
    }


    *b->last++ = sizeof("REQUEST_METHOD") - 1;

    if (r->upstream->method) {
        *b->last++ = (u_char)
                         ngx_http_fastcgi_methods[r->upstream->method - 1].len;

        b->last = ngx_cpymem(b->last, "REQUEST_METHOD",
                             sizeof("REQUEST_METHOD") - 1);

        b->last = ngx_cpymem(b->last,
                        ngx_http_fastcgi_methods[r->upstream->method - 1].data,
                        ngx_http_fastcgi_methods[r->upstream->method - 1].len);

    } else {
        len = r->method_name.len - 1;
        if (len > 127) {
            *b->last++ = (u_char) (((len >> 24) & 0x7f) | 0x80);
            *b->last++ = (u_char) ((len >> 16) & 0xff);
            *b->last++ = (u_char) ((len >> 8) & 0xff);
            *b->last++ = (u_char) (len & 0xff);

        } else {
            *b->last++ = (u_char) len;
        }

        b->last = ngx_cpymem(b->last, "REQUEST_METHOD",
                             sizeof("REQUEST_METHOD") - 1);
        b->last = ngx_cpymem(b->last, r->method_name.data, len);
    }


    if (r->args.len) {
        *b->last++ = sizeof("QUERY_STRING") - 1;

        len = r->args.len;
        if (len > 127) {
            *b->last++ = (u_char) (((len >> 24) & 0x7f) | 0x80);
            *b->last++ = (u_char) ((len >> 16) & 0xff);
            *b->last++ = (u_char) ((len >> 8) & 0xff);
            *b->last++ = (u_char) (len & 0xff);

        } else {
            *b->last++ = (u_char) len;
        }

        b->last = ngx_cpymem(b->last, "QUERY_STRING",
                             sizeof("QUERY_STRING") - 1);
        b->last = ngx_cpymem(b->last, r->args.data, len);
    }


    if (r->headers_in.content_length_n > 0) {
        *b->last++ = sizeof("CONTENT_LENGTH") - 1;

        len = r->headers_in.content_length->value.len;
        if (len > 127) {
            *b->last++ = (u_char) (((len >> 24) & 0x7f) | 0x80);
            *b->last++ = (u_char) ((len >> 16) & 0xff);
            *b->last++ = (u_char) ((len >> 8) & 0xff);
            *b->last++ = (u_char) (len & 0xff);

        } else {
            *b->last++ = (u_char) len;
        }

        b->last = ngx_cpymem(b->last, "CONTENT_LENGTH",
                             sizeof("CONTENT_LENGTH") - 1);
        b->last = ngx_cpymem(b->last, r->headers_in.content_length->value.data,
                             len);
    }


    if (r->headers_in.content_type) {
        *b->last++ = sizeof("CONTENT_TYPE") - 1;

        len = r->headers_in.content_type->value.len;
        if (len > 127) {
            *b->last++ = (u_char) (((len >> 24) & 0x7f) | 0x80);
            *b->last++ = (u_char) ((len >> 16) & 0xff);
            *b->last++ = (u_char) ((len >> 8) & 0xff);
            *b->last++ = (u_char) (len & 0xff);

        } else {
            *b->last++ = (u_char) len;
        }

        b->last = ngx_cpymem(b->last, "CONTENT_TYPE",
                             sizeof("CONTENT_TYPE") - 1);
        b->last = ngx_cpymem(b->last, r->headers_in.content_type->value.data,
                             len);
    }


    if (flcf->params & NGX_HTTP_FASTCGI_REDIRECT_STATUS) {
        *b->last++ = sizeof("REDIRECT_STATUS") - 1;
        *b->last++ = sizeof("200") - 1;
        b->last = ngx_cpymem(b->last, "REDIRECT_STATUS200",
                             sizeof("REDIRECT_STATUS200") - 1);
    }


    if (flcf->params & NGX_HTTP_FASTCGI_REQUEST_URI) {
        *b->last++ = sizeof("REQUEST_URI") - 1;

        len = r->unparsed_uri.len;
        if (len > 127) {
            *b->last++ = (u_char) (((len >> 24) & 0x7f) | 0x80);
            *b->last++ = (u_char) ((len >> 16) & 0xff);
            *b->last++ = (u_char) ((len >> 8) & 0xff);
            *b->last++ = (u_char) (len & 0xff);

        } else {
            *b->last++ = (u_char) len;
        }

        b->last = ngx_cpymem(b->last, "REQUEST_URI", sizeof("REQUEST_URI") - 1);
        b->last = ngx_cpymem(b->last, r->unparsed_uri.data, len);
    }


    if (flcf->params & NGX_HTTP_FASTCGI_SCRIPT_NAME) {
        *b->last++ = sizeof("SCRIPT_NAME") - 1;

        len = r->uri.len + index;
        if (len > 127) {
            *b->last++ = (u_char) (((len >> 24) & 0x7f) | 0x80);
            *b->last++ = (u_char) ((len >> 16) & 0xff);
            *b->last++ = (u_char) ((len >> 8) & 0xff);
            *b->last++ = (u_char) (len & 0xff);

        } else {
            *b->last++ = (u_char) len;
        }

        b->last = ngx_cpymem(b->last, "SCRIPT_NAME", sizeof("SCRIPT_NAME") - 1);
        b->last = ngx_cpymem(b->last, r->uri.data, r->uri.len);

        if (index) {
            b->last = ngx_cpymem(b->last, flcf->index.data, index);
        }
    }


    if (flcf->params & NGX_HTTP_FASTCGI_REMOTE_ADDR) {
        *b->last++ = sizeof("REMOTE_ADDR") - 1;
        *b->last++ = (u_char) (r->connection->addr_text.len);
        b->last = ngx_cpymem(b->last, "REMOTE_ADDR", sizeof("REMOTE_ADDR") - 1);
        b->last = ngx_cpymem(b->last, r->connection->addr_text.data,
                             r->connection->addr_text.len);
    }


    if (flcf->params & NGX_HTTP_FASTCGI_SERVER_NAME) {
        *b->last++ = sizeof("SERVER_NAME") - 1;
        *b->last++ = (u_char) r->server_name.len;
        b->last = ngx_cpymem(b->last, "SERVER_NAME", sizeof("SERVER_NAME") - 1);
        b->last = ngx_cpymem(b->last, r->server_name.data, r->server_name.len);
    }


    if (flcf->params & NGX_HTTP_FASTCGI_SERVER_PORT) {
        *b->last++ = sizeof("SERVER_PORT") - 1;
        *b->last++ = (u_char) (r->port_text->len - 1);
        b->last = ngx_cpymem(b->last, "SERVER_PORT", sizeof("SERVER_PORT") - 1);
        b->last = ngx_cpymem(b->last, r->port_text->data + 1,
                             r->port_text->len - 1);
    }


    if (flcf->params & NGX_HTTP_FASTCGI_SERVER_ADDR) {
        *b->last++ = sizeof("SERVER_ADDR") - 1;
        *b->last++ = (u_char) addr_len;
        b->last = ngx_cpymem(b->last, "SERVER_ADDR", sizeof("SERVER_ADDR") - 1);
        b->last = ngx_cpymem(b->last, addr_text, addr_len);
    }


    if (flcf->params & NGX_HTTP_FASTCGI_SERVER_PROTOCOL
        && r->http_protocol.len)
    {
        *b->last++ = sizeof("SERVER_PROTOCOL") - 1;

        len = r->http_protocol.len;
        if (len > 127) {
            *b->last++ = (u_char) (((len >> 24) & 0x7f) | 0x80);
            *b->last++ = (u_char) ((len >> 16) & 0xff);
            *b->last++ = (u_char) ((len >> 8) & 0xff);
            *b->last++ = (u_char) (len & 0xff);

        } else {
            *b->last++ = (u_char) len;
        }

        b->last = ngx_cpymem(b->last, "SERVER_PROTOCOL",
                             sizeof("SERVER_PROTOCOL") - 1);
        b->last = ngx_cpymem(b->last, r->http_protocol.data, len);
    }


    if (flcf->params & NGX_HTTP_FASTCGI_SERVER_SOFTWARE) {
        *b->last++ = sizeof("SERVER_SOFTWARE") - 1;
        *b->last++ = (u_char) (sizeof(NGINX_VER) - 1);
        b->last = ngx_cpymem(b->last, "SERVER_SOFTWARE",
                             sizeof("SERVER_SOFTWARE") - 1);
        b->last = ngx_cpymem(b->last, NGINX_VER, sizeof(NGINX_VER) - 1);
    }


    if (flcf->params & NGX_HTTP_FASTCGI_GATEWAY_INTERFACE) {
        *b->last++ = sizeof("GATEWAY_INTERFACE") - 1;
        *b->last++ = (u_char) (sizeof("CGI/1.1") - 1);
        b->last = ngx_cpymem(b->last, "GATEWAY_INTERFACE",
                             sizeof("GATEWAY_INTERFACE") - 1);
        b->last = ngx_cpymem(b->last, "CGI/1.1", sizeof("CGI/1.1") - 1);
    }


    part = &r->headers_in.headers.part;
    header = part->elts;

    for (i = 0; /* void */; i++) {

        if (i >= part->nelts) {
            if (part->next == NULL) {
                break;
            }

            part = part->next;
            header = part->elts;
            i = 0;
        }

        len = 5 + header[i].key.len;
        if (len > 127) {
            *b->last++ = (u_char) (((len >> 24) & 0x7f) | 0x80);
            *b->last++ = (u_char) ((len >> 16) & 0xff);
            *b->last++ = (u_char) ((len >> 8) & 0xff);
            *b->last++ = (u_char) (len & 0xff);

        } else {
            *b->last++ = (u_char) len;
        }

        len = header[i].value.len;
        if (len > 127) {
            *b->last++ = (u_char) (((len >> 24) & 0x7f) | 0x80);
            *b->last++ = (u_char) ((len >> 16) & 0xff);
            *b->last++ = (u_char) ((len >> 8) & 0xff);
            *b->last++ = (u_char) (len & 0xff);

        } else {
            *b->last++ = (u_char) len;
        }

        b->last = ngx_cpymem(b->last, "HTTP_", sizeof("HTTP_") - 1);

        for (n = 0; n < header[i].key.len; n++) {
            ch = header[i].key.data[n];

            if (ch >= 'a' && ch <= 'z') {
                ch &= ~0x20;

            } else if (ch == '-') {
                ch = '_';
            }

            *b->last++ = ch;
        }

        b->last = ngx_cpymem(b->last, header[i].value.data,
                             header[i].value.len);
    }


    if (padding) {
        ngx_memzero(b->last, padding);
        b->last += padding;
    }


    h = (ngx_http_fastcgi_header_t *) b->last;
    b->last += sizeof(ngx_http_fastcgi_header_t);

    h->version = 1;
    h->type = NGX_HTTP_FASTCGI_PARAMS;
    h->request_id_hi = 0;
    h->request_id_lo = 1;
    h->content_length_hi = 0;
    h->content_length_lo = 0;
    h->padding_length = 0;
    h->reserved = 0;

    h = (ngx_http_fastcgi_header_t *) b->last;
    b->last += sizeof(ngx_http_fastcgi_header_t);

    body = r->request_body->bufs;
    r->request_body->bufs = cl;

#if (NGX_SUPPRESS_WARN)
    file_pos = 0;
    pos = NULL;
#endif

    while (body) {

        if (body->buf->in_file) {
            file_pos = body->buf->file_pos;

        } else {
            pos = body->buf->pos;
        }

        next = 0;

        do {
            if (!(b = ngx_alloc_buf(r->pool))) {
                return NGX_ERROR;
            }

            ngx_memcpy(b, body->buf, sizeof(ngx_buf_t));

            if (body->buf->in_file) {
                b->file_pos = file_pos;
                file_pos += 32 * 1024;

                if (file_pos > body->buf->file_last) {
                    file_pos = body->buf->file_last;
                    next = 1;
                }

                b->file_last = file_pos;
                len = (ngx_uint_t) (file_pos - b->file_pos);

            } else {
                b->pos = pos;
                pos += 32 * 1024;

                if (pos > body->buf->last) {
                    pos = body->buf->last;
                    next = 1;
                }

                b->last = pos;
                len = (ngx_uint_t) (pos - b->pos);
            }

            padding = 8 - len % 8;
            padding = (padding == 8) ? 0 : padding;

            h->version = 1;
            h->type = NGX_HTTP_FASTCGI_STDIN;
            h->request_id_hi = 0;
            h->request_id_lo = 1;
            h->content_length_hi = (u_char) ((len >> 8) & 0xff);
            h->content_length_lo = (u_char) (len & 0xff);
            h->padding_length = (u_char) padding;
            h->reserved = 0;

            if (!(cl->next = ngx_alloc_chain_link(r->pool))) {
                return NGX_ERROR;
            }

            cl = cl->next;
            cl->buf = b;

            b = ngx_create_temp_buf(r->pool, sizeof(ngx_http_fastcgi_header_t)
                                             + padding);
            if (b == NULL) {
                return NGX_ERROR;
            }

            if (padding) {
                ngx_memzero(b->last, padding);
                b->last += padding;
            }

            h = (ngx_http_fastcgi_header_t *) b->last;
            b->last += sizeof(ngx_http_fastcgi_header_t);

            if (!(cl->next = ngx_alloc_chain_link(r->pool))) {
                return NGX_ERROR;
            }

            cl = cl->next;
            cl->buf = b;

        } while (!next);

        body = body->next;
    }

    h->version = 1;
    h->type = NGX_HTTP_FASTCGI_STDIN;
    h->request_id_hi = 0;
    h->request_id_lo = 1;
    h->content_length_hi = 0;
    h->content_length_lo = 0;
    h->padding_length = 0;
    h->reserved = 0;

    cl->next = NULL;

    return NGX_OK;
}


static ngx_int_t ngx_http_fastcgi_reinit_request(ngx_http_request_t *r)
{
    ngx_http_fastcgi_ctx_t  *f;

    f = ngx_http_get_module_ctx(r, ngx_http_fastcgi_module);

    if (f == NULL) {
        return NGX_OK;
    }

    f->state = ngx_http_fastcgi_st_version;

    ngx_memzero(&f->upstream->headers_in,
                sizeof(ngx_http_fastcgi_headers_in_t));

    if (f->upstream->headers_in.headers.part.elts) {
        if (ngx_list_init(&f->upstream->headers_in.headers, r->pool, 5,
                                         sizeof(ngx_table_elt_t)) == NGX_ERROR)
        {
            return NGX_ERROR;
        }
    }

    return NGX_OK;
}


static ngx_int_t ngx_http_fastcgi_process_header(ngx_http_request_t *r)
{
    u_char                  *start, *last;
    ngx_str_t               *status_line;
    ngx_int_t                rc, status;
    ngx_uint_t               i;
    ngx_table_elt_t         *h;
    ngx_http_upstream_t     *u;
    ngx_http_fastcgi_ctx_t  *f;

    f = ngx_http_get_module_ctx(r, ngx_http_fastcgi_module);

    if (f == NULL) {
        if (!(f = ngx_pcalloc(r->pool, sizeof(ngx_http_fastcgi_ctx_t)))) {
            return NGX_HTTP_INTERNAL_SERVER_ERROR;
        }

        ngx_http_set_ctx(r, f, ngx_http_fastcgi_module);

        f->upstream = ngx_pcalloc(r->pool, sizeof(ngx_http_fastcgi_upstream_t));
        if (f->upstream == NULL) {
            return NGX_HTTP_INTERNAL_SERVER_ERROR;
        }

        if (ngx_list_init(&f->upstream->headers_in.headers, r->pool, 5,
                                         sizeof(ngx_table_elt_t)) == NGX_ERROR)
        {
            return NGX_HTTP_INTERNAL_SERVER_ERROR;
        }
    }

    u = r->upstream;

    for ( ;; ) {

        if (f->state < ngx_http_fastcgi_st_data) {

            f->pos = u->header_in.pos;
            f->last = u->header_in.last;

            rc = ngx_http_fastcgi_process_record(r, f);

            u->header_in.pos = f->pos;
            u->header_in.last = f->last;

            if (rc == NGX_AGAIN) {
                return NGX_AGAIN;
            }

            if (rc == NGX_ERROR) {
                return NGX_HTTP_UPSTREAM_INVALID_HEADER;
            }

            if (f->type != NGX_HTTP_FASTCGI_STDOUT) {
                ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                              "upstream sent unexpected FastCGI record: %d",
                              f->type);

                return NGX_HTTP_UPSTREAM_INVALID_HEADER;
            }

            if (f->length == 0) {
                ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                              "upstream closed prematurely FastCGI stdout");

                return NGX_HTTP_UPSTREAM_INVALID_HEADER;
            }
        }

        if (f->state == ngx_http_fastcgi_st_padding) {

            if (u->header_in.pos + f->padding < u->header_in.last) {
                f->state = ngx_http_fastcgi_st_version;
                u->header_in.pos += f->padding;

                continue;
            }

            if (u->header_in.pos + f->padding == u->header_in.last) {
                f->state = ngx_http_fastcgi_st_version;
                u->header_in.pos = u->header_in.last;

                return NGX_AGAIN;
            }

            f->padding -= u->header_in.last - u->header_in.pos;
            u->header_in.pos = u->header_in.last;

            return NGX_AGAIN;
        }

        /* f->state == ngx_http_fastcgi_st_data */

        start = u->header_in.pos;

        if (u->header_in.pos + f->length < u->header_in.last) {

            /*
             * set u->header_in.last to the end of the FastCGI record data
             * for ngx_http_parse_header_line()
             */

            last = u->header_in.last;
            u->header_in.last = u->header_in.pos + f->length;

        } else {
            last = NULL;
        }

        for ( ;; ) {

            rc = ngx_http_parse_header_line(r, &u->header_in);

            ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                           "http fastcgi parser: %d", rc);

            if (rc == NGX_AGAIN) {
                break;
            }

            if (rc == NGX_OK) {

                /* a header line has been parsed successfully */

                if (!(h = ngx_list_push(&f->upstream->headers_in.headers))) {
                    return NGX_HTTP_INTERNAL_SERVER_ERROR;
                }

                h->key.len = r->header_name_end - r->header_name_start;
                h->value.len = r->header_end - r->header_start;

                h->key.data = ngx_palloc(r->pool,
                                         h->key.len + 1 + h->value.len + 1);
                if (h->key.data == NULL) {
                    return NGX_HTTP_INTERNAL_SERVER_ERROR;
                }

                h->value.data = h->key.data + h->key.len + 1;

                ngx_cpystrn(h->key.data, r->header_name_start, h->key.len + 1);
                ngx_cpystrn(h->value.data, r->header_start, h->value.len + 1);

                for (i = 0; ngx_http_fastcgi_headers_in[i].name.len != 0; i++) {
                    if (ngx_http_fastcgi_headers_in[i].name.len != h->key.len) {
                        continue;
                    }

                    if (ngx_strcasecmp(ngx_http_fastcgi_headers_in[i].name.data,
                                                             h->key.data) == 0)
                    {
                        *((ngx_table_elt_t **)
                                 ((char *) &f->upstream->headers_in
                                 + ngx_http_fastcgi_headers_in[i].offset)) = h;
                        break;
                    }
                }

                ngx_log_debug2(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                               "http fastcgi header: \"%V: %V\"",
                               &h->key, &h->value);

                continue;
            }

            if (rc == NGX_HTTP_PARSE_HEADER_DONE) {

                /* a whole header has been parsed successfully */

                ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                               "http fastcgi header done");

                if (f->upstream->headers_in.status) {
                    status_line = &f->upstream->headers_in.status->value;

                    status = ngx_atoi(status_line->data, 3);

                    if (status == NGX_ERROR) {
                        return NGX_HTTP_INTERNAL_SERVER_ERROR;
                    }

                    r->headers_out.status = status;
                    r->headers_out.status_line = *status_line;

                } else {
                    r->headers_out.status = 200;
                    r->headers_out.status_line.len = sizeof("200 OK") - 1;
                    r->headers_out.status_line.data = (u_char *) "200 OK";
                }

                u->state->status = r->headers_out.status;
#if 0
                if (u->cachable) {
                    u->cachable = ngx_http_upstream_is_cachable(r);
                }
#endif

                break;
            }

            /* there was error while a header line parsing */

            ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                          ngx_http_upstream_header_errors[rc
                                                - NGX_HTTP_PARSE_HEADER_ERROR]);

            return NGX_HTTP_UPSTREAM_INVALID_HEADER;

        }

        if (last) {
            u->header_in.last = last;
        }

        f->length -= u->header_in.pos - start;

        if (rc == NGX_AGAIN) {
            if (u->header_in.pos == u->header_in.last) {
                return NGX_AGAIN;
            }

            ngx_log_error(NGX_LOG_ALERT, r->connection->log, 0,
                          "upstream split a header in FastCGI records");

            return NGX_HTTP_UPSTREAM_INVALID_HEADER;
        }

        if (f->length == 0) {
            if (f->padding) {
                f->state = ngx_http_fastcgi_st_padding;
            } else {
                f->state = ngx_http_fastcgi_st_version;
            }
        }

        return NGX_OK;
    }
}


static ngx_int_t ngx_http_fastcgi_send_header(ngx_http_request_t *r)
{
    ngx_uint_t                      i;
    ngx_list_part_t                *part;
    ngx_table_elt_t                *ho, *h;
    ngx_http_fastcgi_ctx_t         *f;
    ngx_http_fastcgi_headers_in_t  *headers_in;

    f = ngx_http_get_module_ctx(r, ngx_http_fastcgi_module);

    headers_in = &f->upstream->headers_in;
    part = &headers_in->headers.part;
    h = part->elts;

    for (i = 0; /* void */; i++) {

        if (i >= part->nelts) {
            if (part->next == NULL) {
                break;
            }

            part = part->next;
            h = part->elts;
            i = 0;
        }

        /* ignore some headers */

        if (&h[i] == headers_in->status) {
            continue;
        }


        if (&h[i] == headers_in->x_powered_by
            && !r->upstream->conf->x_powered_by)
        {
            continue;
        }


        /* "Content-Type" is handled specially */

        if (&h[i] == headers_in->content_type) {
            r->headers_out.content_type = &h[i];
            r->headers_out.content_type->key.len = 0;
            continue;
        }


        /* copy some header pointers and set up r->headers_out */

        if (!(ho = ngx_list_push(&r->headers_out.headers))) {
            return NGX_HTTP_INTERNAL_SERVER_ERROR;
        }

        *ho = h[i];

#if (NGX_HTTP_GZIP)
        if (&h[i] == headers_in->content_encoding) {
            r->headers_out.content_encoding = ho;
            continue;
        }
#endif

        if (&h[i] == headers_in->content_length) {
            r->headers_out.content_length = ho;
            r->headers_out.content_length_n = ngx_atoi(ho->value.data,
                                                       ho->value.len);
            continue;
        }
    }

    return ngx_http_send_header(r);
}


static ngx_int_t ngx_http_fastcgi_input_filter(ngx_event_pipe_t *p,
                                               ngx_buf_t *buf)
{
    ngx_int_t                rc;
    ngx_buf_t               *b, **prev;
    ngx_str_t                line;
    ngx_chain_t             *cl;
    ngx_http_request_t      *r;
    ngx_http_fastcgi_ctx_t  *f;

    if (buf->pos == buf->last) {
        return NGX_OK;
    }

    r = p->input_ctx;
    f = ngx_http_get_module_ctx(r, ngx_http_fastcgi_module);

    b = NULL;
    prev = &buf->shadow;

    f->pos = buf->pos;
    f->last = buf->last;

    for ( ;; ) {
        if (f->state < ngx_http_fastcgi_st_data) {

            rc = ngx_http_fastcgi_process_record(r, f);

            if (rc == NGX_AGAIN) {
                break;
            }

            if (rc == NGX_ERROR) {
                return NGX_ERROR;
            }

            if (f->type == NGX_HTTP_FASTCGI_STDOUT && f->length == 0) {
                f->state = ngx_http_fastcgi_st_version;
                p->upstream_done = 1;

                ngx_log_debug0(NGX_LOG_DEBUG_HTTP, p->log, 0,
                               "http fastcgi closed stdout");

                continue;
            }

            if (f->type == NGX_HTTP_FASTCGI_END_REQUEST) {
                f->state = ngx_http_fastcgi_st_version;
                p->upstream_done = 1;

                ngx_log_debug0(NGX_LOG_DEBUG_HTTP, p->log, 0,
                               "http fastcgi sent end request");

                break;
            }
        }


        if (f->state == ngx_http_fastcgi_st_padding) {

            if (f->pos + f->padding < f->last) {
                f->state = ngx_http_fastcgi_st_version;
                f->pos += f->padding;

                continue;
            }

            if (f->pos + f->padding == f->last) {
                f->state = ngx_http_fastcgi_st_version;

                break;
            }

            f->padding -= f->last - f->pos;

            break;
        }


        /* f->state == ngx_http_fastcgi_st_data */

        if (f->type == NGX_HTTP_FASTCGI_STDERR) {

            if (f->length) {
                line.data = f->pos;

                if (f->pos + f->length <= f->last) {
                    line.len = f->length;
                    f->pos += f->length;

                } else { 
                    line.len = f->last - f->pos;
                    f->length -= f->last - f->pos;
                    f->pos = f->last;
                }

                /*
                 * TODO: copy split stderr output into buffer,
                 *       clean it up
                 */

                ngx_log_error(NGX_LOG_ERR, p->log, 0,
                              "FastCGI stderr: %V", &line);

                if (f->pos == f->last) {
                    break;
                }
            }

            f->state = ngx_http_fastcgi_st_version;

            continue;
        }


        /* f->type == NGX_HTTP_FASTCGI_STDOUT */

        if (p->free) {
            b = p->free->buf;
            p->free = p->free->next;

        } else {
            if (!(b = ngx_alloc_buf(p->pool))) {
                return NGX_ERROR;
            }
        }

        ngx_memzero(b, sizeof(ngx_buf_t));

        b->pos = f->pos;
        b->start = buf->start;
        b->end = buf->end;
        b->tag = p->tag;
        b->temporary = 1;
        b->recycled = 1;

        *prev = b;
        prev = &b->shadow;

        if (!(cl = ngx_alloc_chain_link(p->pool))) {
            return NGX_ERROR;
        }

        cl->buf = b;
        cl->next = NULL;

        /* STUB */ b->num = buf->num;

        ngx_log_debug1(NGX_LOG_DEBUG_EVENT, p->log, 0, "input buf #%d", b->num);

        ngx_chain_add_link(p->in, p->last_in, cl);

        if (f->pos + f->length < f->last) {

            if (f->padding) {
                f->state = ngx_http_fastcgi_st_padding;
            } else {
                f->state = ngx_http_fastcgi_st_version;
            }

            f->pos += f->length;
            b->last = f->pos;

            continue;
        }

        if (f->pos + f->length == f->last) {

            if (f->padding) {
                f->state = ngx_http_fastcgi_st_padding;
            } else {
                f->state = ngx_http_fastcgi_st_version;
            }

            b->last = f->last;

            break;
        }

        f->length -= f->last - f->pos;

        b->last = f->last;

        break;

    }

    if (b) {
        b->shadow = buf;
        b->last_shadow = 1;

        return NGX_OK;
    }

    /* there is no data record in the buf, add it to free chain */

    if (ngx_event_pipe_add_free_buf(p, buf) != NGX_OK) {
        return NGX_ERROR;
    }

    return NGX_OK;
}


static ngx_int_t ngx_http_fastcgi_process_record(ngx_http_request_t *r,
                                                 ngx_http_fastcgi_ctx_t *f)
{
    u_char                     ch, *p;
    ngx_http_upstream_t       *u;
    ngx_http_fastcgi_state_e   state;

    u = r->upstream;

    state = f->state;

    for (p = f->pos; p < f->last; p++) {

        ch = *p;

        ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                       "http fastcgi record byte: %02Xd", ch);

        switch (state) {

        case ngx_http_fastcgi_st_version:
            if (ch != 1) {
                ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                              "upstream sent unsupported FastCGI "
                              "protocol version: %d", ch);
                return NGX_ERROR;
            }
            state = ngx_http_fastcgi_st_type;
            break;

        case ngx_http_fastcgi_st_type:
            switch (ch) {
            case NGX_HTTP_FASTCGI_STDOUT:
            case NGX_HTTP_FASTCGI_STDERR:
            case NGX_HTTP_FASTCGI_END_REQUEST:
                 f->type = (ngx_uint_t) ch;
                 break;
            default:
                ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                              "upstream sent invalid FastCGI "
                              "record type: %d", ch);
                return NGX_ERROR;

            }
            state = ngx_http_fastcgi_st_request_id_hi;
            break;

        /* we support the single request per connection */

        case ngx_http_fastcgi_st_request_id_hi:
            if (ch != 0) {
                ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                              "upstream sent unexpected FastCGI "
                              "request id high byte: %d", ch);
                return NGX_ERROR;
            }
            state = ngx_http_fastcgi_st_request_id_lo;
            break;

        case ngx_http_fastcgi_st_request_id_lo:
            if (ch != 1) {
                ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                              "upstream sent unexpected FastCGI "
                              "request id low byte: %d", ch);
                return NGX_ERROR;
            }
            state = ngx_http_fastcgi_st_content_length_hi;
            break;

        case ngx_http_fastcgi_st_content_length_hi:
            f->length = ch << 8;
            state = ngx_http_fastcgi_st_content_length_lo;
            break;

        case ngx_http_fastcgi_st_content_length_lo:
            f->length |= (size_t) ch;
            state = ngx_http_fastcgi_st_padding_length;
            break;

        case ngx_http_fastcgi_st_padding_length:
            f->padding = (size_t) ch;
            state = ngx_http_fastcgi_st_reserved;
            break;

        case ngx_http_fastcgi_st_reserved:
            state = ngx_http_fastcgi_st_data;

            ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                           "http fastcgi record length: %z", f->length);

            f->pos = p + 1;
            f->state = state;

            return NGX_OK;

        /* suppress warning */
        case ngx_http_fastcgi_st_data:
        case ngx_http_fastcgi_st_padding:
            break;
        }
    }

    f->pos = p + 1;
    f->state = state;

    return NGX_AGAIN;
}


static void ngx_http_fastcgi_abort_request(ngx_http_request_t *r)
{
    ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "abort http fastcgi request");

    return;
}


static void ngx_http_fastcgi_finalize_request(ngx_http_request_t *r,
                                              ngx_int_t rc)
{
    ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "finalize http fastcgi request");

    return;
}


static char *ngx_http_fastcgi_pass(ngx_conf_t *cf, ngx_command_t *cmd,
                                   void *conf)
{
    ngx_http_fastcgi_loc_conf_t *lcf = conf;

    ngx_str_t                   *value;
    ngx_inet_upstream_t          inet_upstream;
    ngx_http_core_loc_conf_t    *clcf;
#if (NGX_HAVE_UNIX_DOMAIN)
    ngx_unix_domain_upstream_t   unix_upstream;
#endif

    value = cf->args->elts;

    if (ngx_strncasecmp(value[1].data, "unix:", 5) == 0) {

#if (NGX_HAVE_UNIX_DOMAIN)

        ngx_memzero(&unix_upstream, sizeof(ngx_unix_domain_upstream_t));

        unix_upstream.name = value[1];
        unix_upstream.url = value[1];

        if (!(lcf->peers = ngx_unix_upstream_parse(cf, &unix_upstream))) {
            return NGX_CONF_ERROR;
        }

#else
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                           "the unix domain sockets are not supported "
                           "on this platform");
        return NGX_CONF_ERROR;

#endif

    } else {
        ngx_memzero(&inet_upstream, sizeof(ngx_inet_upstream_t));

        inet_upstream.name = value[1];
        inet_upstream.url = value[1];
    
        if (!(lcf->peers = ngx_inet_upstream_parse(cf, &inet_upstream))) {
            return NGX_CONF_ERROR;
        }
    }

    clcf = ngx_http_conf_get_module_loc_conf(cf, ngx_http_core_module);

    clcf->handler = ngx_http_fastcgi_handler;

    lcf->location = clcf->regex ? &ngx_http_fastcgi_uri: &clcf->name;

    if (clcf->name.data[clcf->name.len - 1] == '/') {
        clcf->auto_redirect = 1;
    }

    return NGX_CONF_OK;
}


static char *ngx_http_fastcgi_lowat_check(ngx_conf_t *cf, void *post,
                                          void *data)
{
#if (NGX_FREEBSD)
    ssize_t *np = data;

    if (*np >= ngx_freebsd_net_inet_tcp_sendspace) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                           "\"fastcgi_send_lowat\" must be less than %d "
                           "(sysctl net.inet.tcp.sendspace)",
                           ngx_freebsd_net_inet_tcp_sendspace);

        return NGX_CONF_ERROR;
    }

#elif !(NGX_HAVE_SO_SNDLOWAT)
    ssize_t *np = data;

    ngx_conf_log_error(NGX_LOG_WARN, cf, 0,
                       "\"fastcgi_send_lowat\" is not supported, ignored");

    *np = 0;

#endif

    return NGX_CONF_OK;
}


static void *ngx_http_fastcgi_create_loc_conf(ngx_conf_t *cf)
{
    ngx_http_fastcgi_loc_conf_t  *conf;

    if (!(conf = ngx_pcalloc(cf->pool, sizeof(ngx_http_fastcgi_loc_conf_t)))) {
        return NGX_CONF_ERROR;
    }

    /*
     * set by ngx_pcalloc():
     *
     *     conf->upstream.bufs.num = 0;
     *     conf->upstream.path = NULL;
     *     conf->upstream.next_upstream = 0;
     *     conf->upstream.temp_path = NULL;
     *     conf->params = 0;
     *     conf->root.len = 0;
     *     conf->root.data = NULL;
     *     conf->index.len = 0;
     *     conf->index.data = NULL;
     *     conf->location = NULL;
     */

    conf->upstream.connect_timeout = NGX_CONF_UNSET_MSEC;
    conf->upstream.send_timeout = NGX_CONF_UNSET_MSEC;
    conf->upstream.send_lowat = NGX_CONF_UNSET_SIZE;

    conf->upstream.header_buffer_size = NGX_CONF_UNSET_SIZE;
    conf->upstream.read_timeout = NGX_CONF_UNSET_MSEC;
    conf->upstream.busy_buffers_size = NGX_CONF_UNSET_SIZE;

    conf->upstream.max_temp_file_size = NGX_CONF_UNSET_SIZE; 
    conf->upstream.temp_file_write_size = NGX_CONF_UNSET_SIZE;
    
    conf->upstream.x_powered_by = NGX_CONF_UNSET;

    /* "fastcgi_cyclic_temp_file" is disabled */
    conf->upstream.cyclic_temp_file = 0;

    return conf;
}


static char *ngx_http_fastcgi_merge_loc_conf(ngx_conf_t *cf,
                                             void *parent, void *child)
{
    ngx_http_fastcgi_loc_conf_t *prev = parent;
    ngx_http_fastcgi_loc_conf_t *conf = child;

    size_t  size;

    ngx_conf_merge_msec_value(conf->upstream.connect_timeout,
                              prev->upstream.connect_timeout, 60000);
    ngx_conf_merge_msec_value(conf->upstream.send_timeout,
                              prev->upstream.send_timeout, 60000);
    ngx_conf_merge_size_value(conf->upstream.send_lowat,
                              prev->upstream.send_lowat, 0);

    ngx_conf_merge_msec_value(conf->upstream.read_timeout,
                              prev->upstream.read_timeout, 60000);

    ngx_conf_merge_msec_value(conf->upstream.x_powered_by,
                              prev->upstream.x_powered_by, 1);


    ngx_conf_merge_size_value(conf->upstream.header_buffer_size, 
                              prev->upstream.header_buffer_size,
                              (size_t) ngx_pagesize);

    ngx_conf_merge_bufs_value(conf->upstream.bufs, prev->upstream.bufs,
                              8, ngx_pagesize);

    if (conf->upstream.bufs.num < 2) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                           "there must be at least 2 \"fastcgi_buffers\"");
        return NGX_CONF_ERROR;
    }


    size = conf->upstream.header_buffer_size;
    if (size < conf->upstream.bufs.size) {
        size = conf->upstream.bufs.size;
    }


    ngx_conf_merge_size_value(conf->upstream.busy_buffers_size, 
                              prev->upstream.busy_buffers_size,
                              NGX_CONF_UNSET_SIZE);

    if (conf->upstream.busy_buffers_size == NGX_CONF_UNSET_SIZE) {
        conf->upstream.busy_buffers_size = 2 * size;

    } else if (conf->upstream.busy_buffers_size < size) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
             "\"fastcgi_busy_buffers_size\" must be equal or bigger than "
             "maximum of the value of \"fastcgi_header_buffer_size\" and "
             "one of the \"fastcgi_buffers\"");

        return NGX_CONF_ERROR;

    } else if (conf->upstream.busy_buffers_size
               > (conf->upstream.bufs.num - 1) * conf->upstream.bufs.size)
    {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
             "\"fastcgi_busy_buffers_size\" must be less than "
             "the size of all \"fastcgi_buffers\" minus one buffer");

        return NGX_CONF_ERROR;
    }


    ngx_conf_merge_size_value(conf->upstream.temp_file_write_size, 
                              prev->upstream.temp_file_write_size,
                              NGX_CONF_UNSET_SIZE);

    if (conf->upstream.temp_file_write_size == NGX_CONF_UNSET_SIZE) {
        conf->upstream.temp_file_write_size = 2 * size;

    } else if (conf->upstream.temp_file_write_size < size) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
             "\"fastcgi_temp_file_write_size\" must be equal or bigger than "
             "maximum of the value of \"fastcgi_header_buffer_size\" and "
             "one of the \"fastcgi_buffers\"");

        return NGX_CONF_ERROR;
    }


    ngx_conf_merge_size_value(conf->upstream.max_temp_file_size,
                              prev->upstream.max_temp_file_size,
                              NGX_CONF_UNSET_SIZE);

    if (conf->upstream.max_temp_file_size == NGX_CONF_UNSET_SIZE) {

        conf->upstream.max_temp_file_size = 1024 * 1024 * 1024;

    } else if (conf->upstream.max_temp_file_size != 0
               && conf->upstream.max_temp_file_size < size)
    {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
             "\"fastcgi_max_temp_file_size\" must be equal to zero to disable "
             "the temporary files usage or must be equal or bigger than "
             "maximum of the value of \"fastcgi_header_buffer_size\" and "
             "one of the \"fastcgi_buffers\"");

        return NGX_CONF_ERROR;
    }


    ngx_conf_merge_bitmask_value(conf->upstream.next_upstream,
                                 prev->upstream.next_upstream,
                                 (NGX_CONF_BITMASK_SET
                                  |NGX_HTTP_UPSTREAM_FT_ERROR
                                  |NGX_HTTP_UPSTREAM_FT_TIMEOUT));

    ngx_conf_merge_path_value(conf->upstream.temp_path,
                              prev->upstream.temp_path,
                              NGX_HTTP_FASTCGI_TEMP_PATH, 1, 2, 0,
                              ngx_garbage_collector_temp_handler, cf);


    ngx_conf_merge_bitmask_value(conf->params, prev->params,
                                 (NGX_CONF_BITMASK_SET
                                  |NGX_HTTP_FASTCGI_REMOTE_ADDR
                                  |NGX_HTTP_FASTCGI_REMOTE_USER
                                  |NGX_HTTP_FASTCGI_SERVER_NAME
                                  |NGX_HTTP_FASTCGI_SERVER_PORT
                                  |NGX_HTTP_FASTCGI_SCRIPT_NAME
                                  |NGX_HTTP_FASTCGI_AUTH_TYPE
                                  |NGX_HTTP_FASTCGI_REQUEST_URI
                                  |NGX_HTTP_FASTCGI_REDIRECT_STATUS));

    ngx_conf_merge_str_value(conf->root, prev->root, "");

    if (conf->root.len && conf->root.data[conf->root.len - 1] == '/') {
        conf->root.len--;
    }

    ngx_conf_merge_str_value(conf->index, prev->index, "");

    return NGX_CONF_OK;
}
