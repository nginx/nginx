
/*
 * Copyright (C) Nginx, Inc.
 */


#ifndef _NGX_JSON_UNESCAPE_H_INCLUDED_
#define _NGX_JSON_UNESCAPE_H_INCLUDED_


#include <ngx_config.h>
#include <ngx_core.h>


/*
 * Decode JSON escape sequences (RFC 8259, Section 7) in place.  The input
 * is an unquoted JSON string body (no surrounding double quotes); on success
 * str->len is updated to the decoded length.  Returns NGX_OK, or NGX_ERROR
 * on a malformed escape or invalid input.
 */
ngx_int_t ngx_json_unescape_string(ngx_str_t *str);
ngx_int_t ngx_json_hex_digit(u_char ch);


#endif /* _NGX_JSON_UNESCAPE_H_INCLUDED_ */
