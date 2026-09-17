
/*
 * Copyright (C) Roman Arutyunyan
 * Copyright (C) Nginx, Inc.
 */


#ifndef _NGX_HTTP_V3_PARSE_H_INCLUDED_
#define _NGX_HTTP_V3_PARSE_H_INCLUDED_


#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>


/*
 * Maximum buffered length of a PRIORITY_UPDATE Priority Field Value.  The
 * recognized RFC 9218 members ("u"/"i") need only ~10 bytes; the remainder
 * is headroom for unknown extension members a peer may legitimately send,
 * while keeping the per-stream buffer bounded.
 */
#define NGX_HTTP_V3_PRIORITY_VALUE_LEN  256


typedef struct {
    ngx_uint_t                      state;
    uint64_t                        value;
} ngx_http_v3_parse_varlen_int_t;


typedef struct {
    ngx_uint_t                      state;
    ngx_uint_t                      shift;
    uint64_t                        value;
} ngx_http_v3_parse_prefix_int_t;


typedef struct {
    ngx_uint_t                      state;
    uint64_t                        id;
    ngx_http_v3_parse_varlen_int_t  vlint;
} ngx_http_v3_parse_settings_t;


typedef struct {
    ngx_uint_t                      state;
    uint64_t                        element_id;
    ngx_http_v3_parse_varlen_int_t  vlint;

    /*
     * The Priority Field Value is a structured-field dictionary that is
     * parsed as a whole by the shared ngx_http_priority_parse(), exactly as
     * the HTTP/2 and upstream code paths do.  Parsing it in one pass (rather
     * than splitting on ',' ourselves) is what lets commas inside quoted
     * strings, structured-field parameters (e.g. u=0;ext="..."), and unknown
     * extension members all be handled correctly without dropping the
     * recognized "u"/"i" members.  Because the frame may be delivered across
     * several reads, the value bytes are buffered here until the frame
     * completes.
     *
     * A legitimate priority value is tiny: the only members RFC 9218 defines
     * are "u" (urgency, "u=0".."u=7") and "i" (incremental, "i" or "i=?1"),
     * so a fully-populated recognized value is at most "u=7, i=?1" (10 bytes
     * including optional whitespace).  RFC 9218 does, however, permit unknown
     * dictionary members, which a peer may legitimately include; the buffer
     * is therefore sized well beyond the recognized members
     * (NGX_HTTP_V3_PRIORITY_VALUE_LEN bytes) so that values carrying
     * reasonable unknown extensions are still accepted, while the amount of
     * unparsed data held per stream stays bounded.  A value that does not fit
     * the buffer is treated as excessive load rather than silently truncated
     * -- silent truncation could turn a well-formed value into a different,
     * valid-looking one and apply a priority the peer never signalled.
     */
    u_char                          value[NGX_HTTP_V3_PRIORITY_VALUE_LEN];
    ngx_uint_t                      value_len;
    unsigned                        value_overflow:1;
} ngx_http_v3_parse_priority_t;


typedef struct {
    ngx_uint_t                      state;
    ngx_uint_t                      insert_count;
    ngx_uint_t                      delta_base;
    ngx_uint_t                      sign;
    ngx_uint_t                      base;
    ngx_http_v3_parse_prefix_int_t  pint;
} ngx_http_v3_parse_field_section_prefix_t;


typedef struct {
    ngx_uint_t                      state;
    ngx_uint_t                      length;
    ngx_uint_t                      huffman;
    ngx_str_t                       value;
    u_char                         *last;
    u_char                          huffstate;
    ngx_buf_t                      *buf;
} ngx_http_v3_parse_literal_t;


typedef struct {
    ngx_uint_t                      state;
    ngx_uint_t                      index;
    ngx_uint_t                      base;
    ngx_uint_t                      dynamic;

    ngx_str_t                       name;
    ngx_str_t                       value;

    ngx_http_v3_parse_prefix_int_t  pint;
    ngx_http_v3_parse_literal_t     literal;
} ngx_http_v3_parse_field_t;


typedef struct {
    ngx_uint_t                      state;
    ngx_http_v3_parse_field_t       field;
} ngx_http_v3_parse_field_rep_t;


typedef struct {
    ngx_uint_t                      state;
    ngx_uint_t                      type;
    ngx_uint_t                      length;
    ngx_http_v3_parse_varlen_int_t  vlint;
    ngx_http_v3_parse_field_section_prefix_t  prefix;
    ngx_http_v3_parse_field_rep_t   field_rep;
} ngx_http_v3_parse_headers_t;


typedef struct {
    ngx_uint_t                      state;
    ngx_http_v3_parse_field_t       field;
    ngx_http_v3_parse_prefix_int_t  pint;
} ngx_http_v3_parse_encoder_t;


typedef struct {
    ngx_uint_t                      state;
    ngx_http_v3_parse_prefix_int_t  pint;
} ngx_http_v3_parse_decoder_t;


typedef struct {
    ngx_uint_t                      state;
    ngx_uint_t                      type;
    ngx_uint_t                      length;
    ngx_http_v3_parse_varlen_int_t  vlint;
    ngx_http_v3_parse_settings_t    settings;
    ngx_http_v3_parse_priority_t    priority;
} ngx_http_v3_parse_control_t;


typedef struct {
    ngx_uint_t                      state;
    ngx_http_v3_parse_varlen_int_t  vlint;
    union {
        ngx_http_v3_parse_encoder_t  encoder;
        ngx_http_v3_parse_decoder_t  decoder;
        ngx_http_v3_parse_control_t  control;
    } u;
} ngx_http_v3_parse_uni_t;


typedef struct {
    ngx_uint_t                      state;
    ngx_uint_t                      type;
    ngx_uint_t                      length;
    ngx_http_v3_parse_varlen_int_t  vlint;
} ngx_http_v3_parse_data_t;


/*
 * Parse functions return codes:
 *   NGX_DONE - parsing done
 *   NGX_OK - sub-element done
 *   NGX_AGAIN - more data expected
 *   NGX_BUSY - waiting for external event
 *   NGX_ERROR - internal error
 *   NGX_HTTP_V3_ERROR_XXX - HTTP/3 or QPACK error
 */

ngx_int_t ngx_http_v3_parse_headers(ngx_connection_t *c,
    ngx_http_v3_parse_headers_t *st, ngx_buf_t *b);
ngx_int_t ngx_http_v3_parse_data(ngx_connection_t *c,
    ngx_http_v3_parse_data_t *st, ngx_buf_t *b);
ngx_int_t ngx_http_v3_parse_uni(ngx_connection_t *c,
    ngx_http_v3_parse_uni_t *st, ngx_buf_t *b);


#endif /* _NGX_HTTP_V3_PARSE_H_INCLUDED_ */
