
/*
 * Copyright (C) Nginx, Inc.
 */


/*
 * JSON string unescape.  Decodes escape sequences defined by
 * RFC 8259, Section 7, including \uXXXX and UTF-16 surrogate pairs.
 */


#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_json_unescape.h>


static ngx_inline u_char *ngx_json_utf8_encode(u_char *dst,
    uint32_t codepoint);


ngx_int_t
ngx_json_unescape_string(ngx_str_t *str)
{
    size_t       size;
    u_char      *d, *s, *start, ch;
    uint32_t     codepoint, high_surrogate;
    ngx_int_t    n;
    ngx_uint_t   hex_left;

    enum {
        sw_usual = 0,
        sw_quoted,
        sw_hex,
        sw_surrogate_start,   /* expect '\' of \uDCxx after high surrogate */
        sw_surrogate_u        /* expect 'u' */
    } state;

    /*
     * RFC 8259, Section 7:
     *
     * string = quotation-mark *char quotation-mark
     *
     * char = unescaped /
     *        escape (
     *            %x22 /          ; "    quotation mark  U+0022
     *            %x5C /          ; \    reverse solidus U+005C
     *            %x2F /          ; /    solidus         U+002F
     *            %x62 /          ; b    backspace       U+0008
     *            %x66 /          ; f    form feed       U+000C
     *            %x6E /          ; n    line feed       U+000A
     *            %x72 /          ; r    carriage return U+000D
     *            %x74 /          ; t    tab             U+0009
     *            %x75 4HEXDIG )  ; uXXXX                U+XXXX
     *
     * Non-BMP code points are encoded as a UTF-16 surrogate pair:
     *   \uD800..\uDBFF  high surrogate
     *   \uDC00..\uDFFF  low  surrogate
     * The pair decodes to U+10000 + (high - 0xD800) * 0x400
     *                              + (low  - 0xDC00).
     * The input is an unquoted JSON string body (the bytes between the
     * surrounding double quotes); it is decoded in place.
     */

    if (str->len == 0) {
        return NGX_OK;
    }

    if (str->data == NULL) {
        return NGX_ERROR;
    }

    start = str->data;
    size = str->len;

    d = s = start;

    state = sw_usual;
    codepoint = 0;
    high_surrogate = 0;
    hex_left = 0;

    while (size--) {

        ch = *s++;

        switch (state) {
        case sw_usual:

            if (ch == '"') {
                return NGX_ERROR;
            }

            if (ch == '\\') {
                state = sw_quoted;
                break;
            }

            if (ch < 0x20) {
                /* RFC 8259: control characters must be escaped */
                return NGX_ERROR;
            }

            *d++ = ch;
            break;

        case sw_quoted:

            switch (ch) {

            case 'u':
                codepoint = 0;
                hex_left = 4;
                state = sw_hex;
                break;

            case '"':
            case '/':
            case '\\':
                *d++ = ch;
                state = sw_usual;
                break;

            case 'b':
                *d++ = '\b';
                state = sw_usual;
                break;

            case 'f':
                *d++ = '\f';
                state = sw_usual;
                break;

            case 'n':
                *d++ = '\n';
                state = sw_usual;
                break;

            case 'r':
                *d++ = '\r';
                state = sw_usual;
                break;

            case 't':
                *d++ = '\t';
                state = sw_usual;
                break;

            default:
                return NGX_ERROR;
            }

            break;

        case sw_hex:

            n = ngx_json_hex_digit(ch);
            if (n == NGX_ERROR) {
                return NGX_ERROR;
            }

            codepoint = (codepoint << 4) | (uint32_t) n;

            if (--hex_left > 0) {
                break;
            }

            if (high_surrogate) {
                if (codepoint < 0xDC00 || codepoint > 0xDFFF) {
                    return NGX_ERROR;
                }

                codepoint = 0x10000
                            + ((high_surrogate - 0xD800) << 10)
                            + (codepoint - 0xDC00);
                d = ngx_json_utf8_encode(d, codepoint);
                high_surrogate = 0;
                state = sw_usual;
                break;
            }

            if (codepoint >= 0xD800 && codepoint <= 0xDBFF) {
                /* high surrogate - wait for the low surrogate */
                high_surrogate = codepoint;
                state = sw_surrogate_start;
                break;
            }

            if (codepoint >= 0xDC00 && codepoint <= 0xDFFF) {
                /* lone low surrogate */
                return NGX_ERROR;
            }

            d = ngx_json_utf8_encode(d, codepoint);
            state = sw_usual;
            break;

        case sw_surrogate_start:
            /*
             * Expect '\' to begin the low-surrogate escape.
             * Lone surrogates are not valid Unicode scalar values
             * (RFC 8259, Section 8.2).
             */
            if (ch == '\\') {
                state = sw_surrogate_u;
                break;
            }

            /* lone high surrogate */
            return NGX_ERROR;

        case sw_surrogate_u:
            if (ch == 'u') {
                codepoint = 0;
                hex_left = 4;
                state = sw_hex;
                break;
            }

            /* lone high surrogate */
            return NGX_ERROR;
        }
    }

    if (state != sw_usual) {
        /* truncated escape sequence or unpaired high surrogate */
        return NGX_ERROR;
    }

    str->data = start;
    str->len = d - start;

    return NGX_OK;
}


static ngx_inline u_char *
ngx_json_utf8_encode(u_char *dst, uint32_t codepoint)
{
    if (codepoint <= 0x7F) {
        *dst++ = (u_char) codepoint;

    } else if (codepoint <= 0x7FF) {
        *dst++ = (u_char) (0xC0 | (codepoint >> 6));
        *dst++ = (u_char) (0x80 | (codepoint & 0x3F));

    } else if (codepoint <= 0xFFFF) {
        *dst++ = (u_char) (0xE0 | (codepoint >> 12));
        *dst++ = (u_char) (0x80 | ((codepoint >> 6) & 0x3F));
        *dst++ = (u_char) (0x80 | (codepoint & 0x3F));

    } else {
        *dst++ = (u_char) (0xF0 | (codepoint >> 18));
        *dst++ = (u_char) (0x80 | ((codepoint >> 12) & 0x3F));
        *dst++ = (u_char) (0x80 | ((codepoint >> 6) & 0x3F));
        *dst++ = (u_char) (0x80 | (codepoint & 0x3F));
    }

    return dst;
}


ngx_int_t
ngx_json_hex_digit(u_char ch)
{
    if (ch >= '0' && ch <= '9') {
        return ch - '0';
    }

    ch = (u_char) (ch | 0x20);

    if (ch >= 'a' && ch <= 'f') {
        return ch - 'a' + 10;
    }

    return NGX_ERROR;
}
