/*
 * Copyright (C) 2026 Demi Marie Obenour
 */


#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>


static inline ngx_int_t
ngx_isspace(u_char ch);


ngx_int_t
ngx_http_v23_validate_header(ngx_http_request_t *r,
    ngx_str_t *name, ngx_str_t *value, ngx_int_t is_client)
{
    u_char                     ch;
    ngx_str_t                  tmp;
    ngx_uint_t                 i;
    ngx_http_core_srv_conf_t  *cscf;

    if (is_client) {
        r->invalid_header = 0;
    }

    cscf = ngx_http_get_module_srv_conf(r, ngx_http_core_module);

    if (name->len < 1) {
        ngx_log_error(NGX_LOG_INFO, r->connection->log, 0,
                      "%s sent empty header name",
                      is_client ? "client" : "upstream");

        return NGX_ERROR;
    }

    for (i = (name->data[0] == ':'); i != name->len; i++) {
        ch = name->data[i];

        if (is_client
            && ((ch >= 'a' && ch <= 'z')
                || (ch == '-')
                || (ch >= '0' && ch <= '9')
                || (ch == '_' && cscf->underscores_in_headers)))
        {
            continue;
        }

        if (ch <= 0x20 || ch == 0x7f || ch == ':'
            || (ch >= 'A' && ch <= 'Z'))
        {
            ngx_log_error(NGX_LOG_INFO, r->connection->log, 0,
                          "%s sent invalid header name",
                          is_client ? "client" : "upstream", name);

            return NGX_ERROR;
        }

        if (is_client) {
            r->invalid_header = 1;
        }
    }

    /* Keep subsequent code from having to special-case empty strings. */
    if (value->len == 0) {
        return NGX_OK;
    }

    for (i = 0; i != value->len; i++) {
        ch = value->data[i];

        if (ch == '\0' || ch == LF || ch == CR) {
            ngx_log_error(NGX_LOG_INFO, r->connection->log, 0,
                          "%s sent header \"%V\" with "
                          "invalid value",
                          is_client ? "client" : "upstream",
                          name, value);

            return NGX_ERROR;
        }
    }

    if (!ngx_isspace(value->data[0])
        && !ngx_isspace(value->data[value->len - 1])) {
        /* Fast path: nothing to strip. */
        return NGX_OK;
    }

    if (is_client ? cscf->reject_leading_trailing_whitespace_client
                  : cscf->reject_leading_trailing_whitespace_upstream) {
        ngx_log_error(NGX_LOG_INFO, r->connection->log, 0,
                      "%s sent header \"%V\" with "
                      "leading or trailing space",
                      is_client ? "client" : "upstream", name);

        return NGX_ERROR;
    }

    tmp = *value;

    /*
     * Strip trailing whitespace.  Do this first so that
     * if the string is all whitespace, tmp.data is not a
     * past-the-end pointer, which cannot be safely passed
     * to memmove().  After the loop, the string is either
     * empty or ends with a non-whitespace character.
     */
    while (tmp.len && ngx_isspace(tmp.data[tmp.len - 1])) {
        tmp.len--;
    }

    /* Strip leading whitespace */
    if (tmp.len && ngx_isspace(tmp.data[0])) {
        /*
         * Last loop guaranteed that 'tmp' does not end with whitespace, and
         * this check guarantees it is not empty and starts with whitespace.
         * Therefore, 'tmp' must end with a non-whitespace character, and must
         * be of length at least 2.  This means that it is safe to keep going
         * until a non-whitespace character is found.
         */
        do {
            tmp.len--;
            tmp.data++;
        } while (ngx_isspace(tmp.data[0]));

        /* Move remaining string to start of buffer. */
        memmove(value->data, tmp.data, tmp.len);
    }

    /*
     * NUL-pad the data, so that if it was NUL-terminated before, it stil is.
     * At least one byte will have been stripped, so value->data + tmp.len
     * is not a past-the-end pointer.
     */
    memset(value->data + tmp.len, '\0', value->len - tmp.len);

    /* Fix up length and return. */
    value->len = tmp.len;
    return NGX_OK;
}


static inline ngx_int_t
ngx_isspace(u_char ch)
{
    return ch == ' ' || ch == '\t';
}
