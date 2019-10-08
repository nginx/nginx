
/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) Nginx, Inc.
 */


#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>


static uint32_t  usual[] = {
    0xffffdbfe, /* 1111 1111 1111 1111  1101 1011 1111 1110 */

                /* ?>=< ;:98 7654 3210  /.-, +*)( '&%$ #"!  */
    0x7fff37d6, /* 0111 1111 1111 1111  0011 0111 1101 0110 */

                /* _^]\ [ZYX WVUT SRQP  ONML KJIH GFED CBA@ */
#if (NGX_WIN32)
    0xefffffff, /* 1110 1111 1111 1111  1111 1111 1111 1111 */
#else
    0xffffffff, /* 1111 1111 1111 1111  1111 1111 1111 1111 */
#endif

                /*  ~}| {zyx wvut srqp  onml kjih gfed cba` */
    0xffffffff, /* 1111 1111 1111 1111  1111 1111 1111 1111 */

    0xffffffff, /* 1111 1111 1111 1111  1111 1111 1111 1111 */
    0xffffffff, /* 1111 1111 1111 1111  1111 1111 1111 1111 */
    0xffffffff, /* 1111 1111 1111 1111  1111 1111 1111 1111 */
    0xffffffff  /* 1111 1111 1111 1111  1111 1111 1111 1111 */
};


#if (NGX_HAVE_LITTLE_ENDIAN && NGX_HAVE_NONALIGNED)

#define ngx_str3_cmp(m, c0, c1, c2, c3)                                       \
    *(uint32_t *) m == ((c3 << 24) | (c2 << 16) | (c1 << 8) | c0)

#define ngx_str3Ocmp(m, c0, c1, c2, c3)                                       \
    *(uint32_t *) m == ((c3 << 24) | (c2 << 16) | (c1 << 8) | c0)

#define ngx_str4cmp(m, c0, c1, c2, c3)                                        \
    *(uint32_t *) m == ((c3 << 24) | (c2 << 16) | (c1 << 8) | c0)

#define ngx_str5cmp(m, c0, c1, c2, c3, c4)                                    \
    *(uint32_t *) m == ((c3 << 24) | (c2 << 16) | (c1 << 8) | c0)             \
        && m[4] == c4

#define ngx_str6cmp(m, c0, c1, c2, c3, c4, c5)                                \
    *(uint32_t *) m == ((c3 << 24) | (c2 << 16) | (c1 << 8) | c0)             \
        && (((uint32_t *) m)[1] & 0xffff) == ((c5 << 8) | c4)

#define ngx_str7_cmp(m, c0, c1, c2, c3, c4, c5, c6, c7)                       \
    *(uint32_t *) m == ((c3 << 24) | (c2 << 16) | (c1 << 8) | c0)             \
        && ((uint32_t *) m)[1] == ((c7 << 24) | (c6 << 16) | (c5 << 8) | c4)

#define ngx_str8cmp(m, c0, c1, c2, c3, c4, c5, c6, c7)                        \
    *(uint32_t *) m == ((c3 << 24) | (c2 << 16) | (c1 << 8) | c0)             \
        && ((uint32_t *) m)[1] == ((c7 << 24) | (c6 << 16) | (c5 << 8) | c4)

#define ngx_str9cmp(m, c0, c1, c2, c3, c4, c5, c6, c7, c8)                    \
    *(uint32_t *) m == ((c3 << 24) | (c2 << 16) | (c1 << 8) | c0)             \
        && ((uint32_t *) m)[1] == ((c7 << 24) | (c6 << 16) | (c5 << 8) | c4)  \
        && m[8] == c8

#else /* !(NGX_HAVE_LITTLE_ENDIAN && NGX_HAVE_NONALIGNED) */

#define ngx_str3_cmp(m, c0, c1, c2, c3)                                       \
    m[0] == c0 && m[1] == c1 && m[2] == c2

#define ngx_str3Ocmp(m, c0, c1, c2, c3)                                       \
    m[0] == c0 && m[2] == c2 && m[3] == c3

#define ngx_str4cmp(m, c0, c1, c2, c3)                                        \
    m[0] == c0 && m[1] == c1 && m[2] == c2 && m[3] == c3

#define ngx_str5cmp(m, c0, c1, c2, c3, c4)                                    \
    m[0] == c0 && m[1] == c1 && m[2] == c2 && m[3] == c3 && m[4] == c4

#define ngx_str6cmp(m, c0, c1, c2, c3, c4, c5)                                \
    m[0] == c0 && m[1] == c1 && m[2] == c2 && m[3] == c3                      \
        && m[4] == c4 && m[5] == c5

#define ngx_str7_cmp(m, c0, c1, c2, c3, c4, c5, c6, c7)                       \
    m[0] == c0 && m[1] == c1 && m[2] == c2 && m[3] == c3                      \
        && m[4] == c4 && m[5] == c5 && m[6] == c6

#define ngx_str8cmp(m, c0, c1, c2, c3, c4, c5, c6, c7)                        \
    m[0] == c0 && m[1] == c1 && m[2] == c2 && m[3] == c3                      \
        && m[4] == c4 && m[5] == c5 && m[6] == c6 && m[7] == c7

#define ngx_str9cmp(m, c0, c1, c2, c3, c4, c5, c6, c7, c8)                    \
    m[0] == c0 && m[1] == c1 && m[2] == c2 && m[3] == c3                      \
        && m[4] == c4 && m[5] == c5 && m[6] == c6 && m[7] == c7 && m[8] == c8

#endif


/* gcc, icc, msvc and others compile these switches as an jump table */

ngx_int_t
ngx_http_parse_request_line(ngx_http_request_t *r, ngx_buf_t *b)
{
    u_char  c, ch, *p, *m;
    enum {
        sw_start = 0,
        sw_method,
        sw_spaces_before_uri,
        sw_schema,
        sw_schema_slash,
        sw_schema_slash_slash,
        sw_host_start,
        sw_host,
        sw_host_end,
        sw_host_ip_literal,
        sw_port,
        sw_host_http_09,
        sw_after_slash_in_uri,
        sw_check_uri,
        sw_check_uri_http_09,
        sw_uri,
        sw_http_09,
        sw_http_H,
        sw_http_HT,
        sw_http_HTT,
        sw_http_HTTP,
        sw_first_major_digit,
        sw_major_digit,
        sw_first_minor_digit,
        sw_minor_digit,
        sw_spaces_after_digit,
        sw_almost_done
    } state;

    state = r->state;

    for (p = b->pos; p < b->last; p++) {
        ch = *p;

        switch (state) {

        /* HTTP methods: GET, HEAD, POST */
        case sw_start:
            r->request_start = p;

            if (ch == CR || ch == LF) {
                break;
            }

            if ((ch < 'A' || ch > 'Z') && ch != '_' && ch != '-') {
                return NGX_HTTP_PARSE_INVALID_METHOD;
            }

            state = sw_method;
            break;

        case sw_method:
            if (ch == ' ') {
                r->method_end = p - 1;
                m = r->request_start;

                switch (p - m) {

                case 3:
                    if (ngx_str3_cmp(m, 'G', 'E', 'T', ' ')) {
                        r->method = NGX_HTTP_GET;
                        break;
                    }

                    if (ngx_str3_cmp(m, 'P', 'U', 'T', ' ')) {
                        r->method = NGX_HTTP_PUT;
                        break;
                    }

                    break;

                case 4:
                    if (m[1] == 'O') {

                        if (ngx_str3Ocmp(m, 'P', 'O', 'S', 'T')) {
                            r->method = NGX_HTTP_POST;
                            break;
                        }

                        if (ngx_str3Ocmp(m, 'C', 'O', 'P', 'Y')) {
                            r->method = NGX_HTTP_COPY;
                            break;
                        }

                        if (ngx_str3Ocmp(m, 'M', 'O', 'V', 'E')) {
                            r->method = NGX_HTTP_MOVE;
                            break;
                        }

                        if (ngx_str3Ocmp(m, 'L', 'O', 'C', 'K')) {
                            r->method = NGX_HTTP_LOCK;
                            break;
                        }

                    } else {

                        if (ngx_str4cmp(m, 'H', 'E', 'A', 'D')) {
                            r->method = NGX_HTTP_HEAD;
                            break;
                        }
                    }

                    break;

                case 5:
                    if (ngx_str5cmp(m, 'M', 'K', 'C', 'O', 'L')) {
                        r->method = NGX_HTTP_MKCOL;
                        break;
                    }

                    if (ngx_str5cmp(m, 'P', 'A', 'T', 'C', 'H')) {
                        r->method = NGX_HTTP_PATCH;
                        break;
                    }

                    if (ngx_str5cmp(m, 'T', 'R', 'A', 'C', 'E')) {
                        r->method = NGX_HTTP_TRACE;
                        break;
                    }

                    break;

                case 6:
                    if (ngx_str6cmp(m, 'D', 'E', 'L', 'E', 'T', 'E')) {
                        r->method = NGX_HTTP_DELETE;
                        break;
                    }

                    if (ngx_str6cmp(m, 'U', 'N', 'L', 'O', 'C', 'K')) {
                        r->method = NGX_HTTP_UNLOCK;
                        break;
                    }

                    break;

                case 7:
                    if (ngx_str7_cmp(m, 'O', 'P', 'T', 'I', 'O', 'N', 'S', ' '))
                    {
                        r->method = NGX_HTTP_OPTIONS;
                    }

                    break;

                case 8:
                    if (ngx_str8cmp(m, 'P', 'R', 'O', 'P', 'F', 'I', 'N', 'D'))
                    {
                        r->method = NGX_HTTP_PROPFIND;
                    }

                    break;

                case 9:
                    if (ngx_str9cmp(m,
                            'P', 'R', 'O', 'P', 'P', 'A', 'T', 'C', 'H'))
                    {
                        r->method = NGX_HTTP_PROPPATCH;
                    }

                    break;
                }

                state = sw_spaces_before_uri;
                break;
            }

            if ((ch < 'A' || ch > 'Z') && ch != '_' && ch != '-') {
                return NGX_HTTP_PARSE_INVALID_METHOD;
            }

            break;

        /* space* before URI */
        case sw_spaces_before_uri:

            if (ch == '/') {
                r->uri_start = p;
                state = sw_after_slash_in_uri;
                break;
            }

            c = (u_char) (ch | 0x20);
            if (c >= 'a' && c <= 'z') {
                r->schema_start = p;
                state = sw_schema;
                break;
            }

            switch (ch) {
            case ' ':
                break;
            default:
                return NGX_HTTP_PARSE_INVALID_REQUEST;
            }
            break;

        case sw_schema:

            c = (u_char) (ch | 0x20);
            if (c >= 'a' && c <= 'z') {
                break;
            }

            if ((ch >= '0' && ch <= '9') || ch == '+' || ch == '-' || ch == '.')
            {
                break;
            }

            switch (ch) {
            case ':':
                r->schema_end = p;
                state = sw_schema_slash;
                break;
            default:
                return NGX_HTTP_PARSE_INVALID_REQUEST;
            }
            break;

        case sw_schema_slash:
            switch (ch) {
            case '/':
                state = sw_schema_slash_slash;
                break;
            default:
                return NGX_HTTP_PARSE_INVALID_REQUEST;
            }
            break;

        case sw_schema_slash_slash:
            switch (ch) {
            case '/':
                state = sw_host_start;
                break;
            default:
                return NGX_HTTP_PARSE_INVALID_REQUEST;
            }
            break;

        case sw_host_start:

            r->host_start = p;

            if (ch == '[') {
                state = sw_host_ip_literal;
                break;
            }

            state = sw_host;

            /* fall through */

        case sw_host:

            c = (u_char) (ch | 0x20);
            if (c >= 'a' && c <= 'z') {
                break;
            }

            if ((ch >= '0' && ch <= '9') || ch == '.' || ch == '-') {
                break;
            }

            /* fall through */

        case sw_host_end:

            r->host_end = p;

            switch (ch) {
            case ':':
                state = sw_port;
                break;
            case '/':
                r->uri_start = p;
                state = sw_after_slash_in_uri;
                break;
            case ' ':
                /*
                 * use single "/" from request line to preserve pointers,
                 * if request line will be copied to large client buffer
                 */
                r->uri_start = r->schema_end + 1;
                r->uri_end = r->schema_end + 2;
                state = sw_host_http_09;
                break;
            default:
                return NGX_HTTP_PARSE_INVALID_REQUEST;
            }
            break;

        case sw_host_ip_literal:

            if (ch >= '0' && ch <= '9') {
                break;
            }

            c = (u_char) (ch | 0x20);
            if (c >= 'a' && c <= 'z') {
                break;
            }

            switch (ch) {
            case ':':
                break;
            case ']':
                state = sw_host_end;
                break;
            case '-':
            case '.':
            case '_':
            case '~':
                /* unreserved */
                break;
            case '!':
            case '$':
            case '&':
            case '\'':
            case '(':
            case ')':
            case '*':
            case '+':
            case ',':
            case ';':
            case '=':
                /* sub-delims */
                break;
            default:
                return NGX_HTTP_PARSE_INVALID_REQUEST;
            }
            break;

        case sw_port:
            if (ch >= '0' && ch <= '9') {
                break;
            }

            switch (ch) {
            case '/':
                r->port_end = p;
                r->uri_start = p;
                state = sw_after_slash_in_uri;
                break;
            case ' ':
                r->port_end = p;
                /*
                 * use single "/" from request line to preserve pointers,
                 * if request line will be copied to large client buffer
                 */
                r->uri_start = r->schema_end + 1;
                r->uri_end = r->schema_end + 2;
                state = sw_host_http_09;
                break;
            default:
                return NGX_HTTP_PARSE_INVALID_REQUEST;
            }
            break;

        /* space+ after "http://host[:port] " */
        case sw_host_http_09:
            switch (ch) {
            case ' ':
                break;
            case CR:
                r->http_minor = 9;
                state = sw_almost_done;
                break;
            case LF:
                r->http_minor = 9;
                goto done;
            case 'H':
                r->http_protocol.data = p;
                state = sw_http_H;
                break;
            default:
                return NGX_HTTP_PARSE_INVALID_REQUEST;
            }
            break;


        /* check "/.", "//", "%", and "\" (Win32) in URI */
        case sw_after_slash_in_uri:

            if (usual[ch >> 5] & (1U << (ch & 0x1f))) {
                state = sw_check_uri;
                break;
            }

            switch (ch) {
            case ' ':
                r->uri_end = p;
                state = sw_check_uri_http_09;
                break;
            case CR:
                r->uri_end = p;
                r->http_minor = 9;
                state = sw_almost_done;
                break;
            case LF:
                r->uri_end = p;
                r->http_minor = 9;
                goto done;
            case '.':
                r->complex_uri = 1;
                state = sw_uri;
                break;
            case '%':
                r->quoted_uri = 1;
                state = sw_uri;
                break;
            case '/':
                r->complex_uri = 1;
                state = sw_uri;
                break;
#if (NGX_WIN32)
            case '\\':
                r->complex_uri = 1;
                state = sw_uri;
                break;
#endif
            case '?':
                r->args_start = p + 1;
                state = sw_uri;
                break;
            case '#':
                r->complex_uri = 1;
                state = sw_uri;
                break;
            case '+':
                r->plus_in_uri = 1;
                break;
            case '\0':
                return NGX_HTTP_PARSE_INVALID_REQUEST;
            default:
                state = sw_check_uri;
                break;
            }
            break;

        /* check "/", "%" and "\" (Win32) in URI */
        case sw_check_uri:

            if (usual[ch >> 5] & (1U << (ch & 0x1f))) {
                break;
            }

            switch (ch) {
            case '/':
#if (NGX_WIN32)
                if (r->uri_ext == p) {
                    r->complex_uri = 1;
                    state = sw_uri;
                    break;
                }
#endif
                r->uri_ext = NULL;
                state = sw_after_slash_in_uri;
                break;
            case '.':
                r->uri_ext = p + 1;
                break;
            case ' ':
                r->uri_end = p;
                state = sw_check_uri_http_09;
                break;
            case CR:
                r->uri_end = p;
                r->http_minor = 9;
                state = sw_almost_done;
                break;
            case LF:
                r->uri_end = p;
                r->http_minor = 9;
                goto done;
#if (NGX_WIN32)
            case '\\':
                r->complex_uri = 1;
                state = sw_after_slash_in_uri;
                break;
#endif
            case '%':
                r->quoted_uri = 1;
                state = sw_uri;
                break;
            case '?':
                r->args_start = p + 1;
                state = sw_uri;
                break;
            case '#':
                r->complex_uri = 1;
                state = sw_uri;
                break;
            case '+':
                r->plus_in_uri = 1;
                break;
            case '\0':
                return NGX_HTTP_PARSE_INVALID_REQUEST;
            }
            break;

        /* space+ after URI */
        case sw_check_uri_http_09:
            switch (ch) {
            case ' ':
                break;
            case CR:
                r->http_minor = 9;
                state = sw_almost_done;
                break;
            case LF:
                r->http_minor = 9;
                goto done;
            case 'H':
                r->http_protocol.data = p;
                state = sw_http_H;
                break;
            default:
                r->space_in_uri = 1;
                state = sw_check_uri;
                p--;
                break;
            }
            break;


        /* URI */
        case sw_uri:

            if (usual[ch >> 5] & (1U << (ch & 0x1f))) {
                break;
            }

            switch (ch) {
            case ' ':
                r->uri_end = p;
                state = sw_http_09;
                break;
            case CR:
                r->uri_end = p;
                r->http_minor = 9;
                state = sw_almost_done;
                break;
            case LF:
                r->uri_end = p;
                r->http_minor = 9;
                goto done;
            case '#':
                r->complex_uri = 1;
                break;
            case '\0':
                return NGX_HTTP_PARSE_INVALID_REQUEST;
            }
            break;

        /* space+ after URI */
        case sw_http_09:
            switch (ch) {
            case ' ':
                break;
            case CR:
                r->http_minor = 9;
                state = sw_almost_done;
                break;
            case LF:
                r->http_minor = 9;
                goto done;
            case 'H':
                r->http_protocol.data = p;
                state = sw_http_H;
                break;
            default:
                r->space_in_uri = 1;
                state = sw_uri;
                p--;
                break;
            }
            break;

        case sw_http_H:
            switch (ch) {
            case 'T':
                state = sw_http_HT;
                break;
            default:
                return NGX_HTTP_PARSE_INVALID_REQUEST;
            }
            break;

        case sw_http_HT:
            switch (ch) {
            case 'T':
                state = sw_http_HTT;
                break;
            default:
                return NGX_HTTP_PARSE_INVALID_REQUEST;
            }
            break;

        case sw_http_HTT:
            switch (ch) {
            case 'P':
                state = sw_http_HTTP;
                break;
            default:
                return NGX_HTTP_PARSE_INVALID_REQUEST;
            }
            break;

        case sw_http_HTTP:
            switch (ch) {
            case '/':
                state = sw_first_major_digit;
                break;
            default:
                return NGX_HTTP_PARSE_INVALID_REQUEST;
            }
            break;

        /* first digit of major HTTP version */
        case sw_first_major_digit:
            if (ch < '1' || ch > '9') {
                return NGX_HTTP_PARSE_INVALID_REQUEST;
            }

            r->http_major = ch - '0';

            if (r->http_major > 1) {
                return NGX_HTTP_PARSE_INVALID_VERSION;
            }

            state = sw_major_digit;
            break;

        /* major HTTP version or dot */
        case sw_major_digit:
            if (ch == '.') {
                state = sw_first_minor_digit;
                break;
            }

            if (ch < '0' || ch > '9') {
                return NGX_HTTP_PARSE_INVALID_REQUEST;
            }

            r->http_major = r->http_major * 10 + (ch - '0');

            if (r->http_major > 1) {
                return NGX_HTTP_PARSE_INVALID_VERSION;
            }

            break;

        /* first digit of minor HTTP version */
        case sw_first_minor_digit:
            if (ch < '0' || ch > '9') {
                return NGX_HTTP_PARSE_INVALID_REQUEST;
            }

            r->http_minor = ch - '0';
            state = sw_minor_digit;
            break;

        /* minor HTTP version or end of request line */
        case sw_minor_digit:
            if (ch == CR) {
                state = sw_almost_done;
                break;
            }

            if (ch == LF) {
                goto done;
            }

            if (ch == ' ') {
                state = sw_spaces_after_digit;
                break;
            }

            if (ch < '0' || ch > '9') {
                return NGX_HTTP_PARSE_INVALID_REQUEST;
            }

            if (r->http_minor > 99) {
                return NGX_HTTP_PARSE_INVALID_REQUEST;
            }

            r->http_minor = r->http_minor * 10 + (ch - '0');
            break;

        case sw_spaces_after_digit:
            switch (ch) {
            case ' ':
                break;
            case CR:
                state = sw_almost_done;
                break;
            case LF:
                goto done;
            default:
                return NGX_HTTP_PARSE_INVALID_REQUEST;
            }
            break;

        /* end of request line */
        case sw_almost_done:
            r->request_end = p - 1;
            switch (ch) {
            case LF:
                goto done;
            default:
                return NGX_HTTP_PARSE_INVALID_REQUEST;
            }
        }
    }

    b->pos = p;
    r->state = state;

    return NGX_AGAIN;

done:

    b->pos = p + 1;

    if (r->request_end == NULL) {
        r->request_end = p;
    }

    r->http_version = r->http_major * 1000 + r->http_minor;
    r->state = sw_start;

    if (r->http_version == 9 && r->method != NGX_HTTP_GET) {
        return NGX_HTTP_PARSE_INVALID_09_METHOD;
    }

    return NGX_OK;
}


ngx_int_t
ngx_http_parse_header_line(ngx_http_request_t *r, ngx_buf_t *b,
    ngx_uint_t allow_underscores)
{
    u_char      c, ch, *p;
    ngx_uint_t  hash, i;
    enum {
        sw_start = 0,
        sw_name,
        sw_space_before_value,
        sw_value,
        sw_space_after_value,
        sw_ignore_line,
        sw_almost_done,
        sw_header_almost_done
    } state;

    /* the last '\0' is not needed because string is zero terminated */

    static u_char  lowcase[] =
        "\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0"
        "\0\0\0\0\0\0\0\0\0\0\0\0\0-\0\0" "0123456789\0\0\0\0\0\0"
        "\0abcdefghijklmnopqrstuvwxyz\0\0\0\0\0"
        "\0abcdefghijklmnopqrstuvwxyz\0\0\0\0\0"
        "\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0"
        "\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0"
        "\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0"
        "\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0";

    state = r->state;
    hash = r->header_hash;
    i = r->lowcase_index;

    for (p = b->pos; p < b->last; p++) {
        ch = *p;

        switch (state) {

        /* first char */
        case sw_start:
            r->header_name_start = p;
            r->invalid_header = 0;

            switch (ch) {
            case CR:
                r->header_end = p;
                state = sw_header_almost_done;
                break;
            case LF:
                r->header_end = p;
                goto header_done;
            default:
                state = sw_name;

                c = lowcase[ch];

                if (c) {
                    hash = ngx_hash(0, c);
                    r->lowcase_header[0] = c;
                    i = 1;
                    break;
                }

                if (ch == '_') {
                    if (allow_underscores) {
                        hash = ngx_hash(0, ch);
                        r->lowcase_header[0] = ch;
                        i = 1;

                    } else {
                        r->invalid_header = 1;
                    }

                    break;
                }

                if (ch == '\0') {
                    return NGX_HTTP_PARSE_INVALID_HEADER;
                }

                r->invalid_header = 1;

                break;

            }
            break;

        /* header name */
        case sw_name:
            c = lowcase[ch];

            if (c) {
                hash = ngx_hash(hash, c);
                r->lowcase_header[i++] = c;
                i &= (NGX_HTTP_LC_HEADER_LEN - 1);
                break;
            }

            if (ch == '_') {
                if (allow_underscores) {
                    hash = ngx_hash(hash, ch);
                    r->lowcase_header[i++] = ch;
                    i &= (NGX_HTTP_LC_HEADER_LEN - 1);

                } else {
                    r->invalid_header = 1;
                }

                break;
            }

            if (ch == ':') {
                r->header_name_end = p;
                state = sw_space_before_value;
                break;
            }

            if (ch == CR) {
                r->header_name_end = p;
                r->header_start = p;
                r->header_end = p;
                state = sw_almost_done;
                break;
            }

            if (ch == LF) {
                r->header_name_end = p;
                r->header_start = p;
                r->header_end = p;
                goto done;
            }

            /* IIS may send the duplicate "HTTP/1.1 ..." lines */
            if (ch == '/'
                && r->upstream
                && p - r->header_name_start == 4
                && ngx_strncmp(r->header_name_start, "HTTP", 4) == 0)
            {
                state = sw_ignore_line;
                break;
            }

            if (ch == '\0') {
                return NGX_HTTP_PARSE_INVALID_HEADER;
            }

            r->invalid_header = 1;

            break;

        /* space* before header value */
        case sw_space_before_value:
            switch (ch) {
            case ' ':
                break;
            case CR:
                r->header_start = p;
                r->header_end = p;
                state = sw_almost_done;
                break;
            case LF:
                r->header_start = p;
                r->header_end = p;
                goto done;
            case '\0':
                return NGX_HTTP_PARSE_INVALID_HEADER;
            default:
                r->header_start = p;
                state = sw_value;
                break;
            }
            break;

        /* header value */
        case sw_value:
            switch (ch) {
            case ' ':
                r->header_end = p;
                state = sw_space_after_value;
                break;
            case CR:
                r->header_end = p;
                state = sw_almost_done;
                break;
            case LF:
                r->header_end = p;
                goto done;
            case '\0':
                return NGX_HTTP_PARSE_INVALID_HEADER;
            }
            break;

        /* space* before end of header line */
        case sw_space_after_value:
            switch (ch) {
            case ' ':
                break;
            case CR:
                state = sw_almost_done;
                break;
            case LF:
                goto done;
            case '\0':
                return NGX_HTTP_PARSE_INVALID_HEADER;
            default:
                state = sw_value;
                break;
            }
            break;

        /* ignore header line */
        case sw_ignore_line:
            switch (ch) {
            case LF:
                state = sw_start;
                break;
            default:
                break;
            }
            break;

        /* end of header line */
        case sw_almost_done:
            switch (ch) {
            case LF:
                goto done;
            case CR:
                break;
            default:
                return NGX_HTTP_PARSE_INVALID_HEADER;
            }
            break;

        /* end of header */
        case sw_header_almost_done:
            switch (ch) {
            case LF:
                goto header_done;
            default:
                return NGX_HTTP_PARSE_INVALID_HEADER;
            }
        }
    }

    b->pos = p;
    r->state = state;
    r->header_hash = hash;
    r->lowcase_index = i;

    return NGX_AGAIN;

done:

    b->pos = p + 1;
    r->state = sw_start;
    r->header_hash = hash;
    r->lowcase_index = i;

    return NGX_OK;

header_done:

    b->pos = p + 1;
    r->state = sw_start;

    return NGX_HTTP_PARSE_HEADER_DONE;
}


ngx_int_t
ngx_http_parse_uri(ngx_http_request_t *r)
{
    u_char  *p, ch;
    enum {
        sw_start = 0,
        sw_after_slash_in_uri,
        sw_check_uri,
        sw_uri
    } state;

    state = sw_start;

    for (p = r->uri_start; p != r->uri_end; p++) {

        ch = *p;

        switch (state) {

        case sw_start:

            if (ch != '/') {
                return NGX_ERROR;
            }

            state = sw_after_slash_in_uri;
            break;

        /* check "/.", "//", "%", and "\" (Win32) in URI */
        case sw_after_slash_in_uri:

            if (usual[ch >> 5] & (1U << (ch & 0x1f))) {
                state = sw_check_uri;
                break;
            }

            switch (ch) {
            case ' ':
                r->space_in_uri = 1;
                state = sw_check_uri;
                break;
            case '.':
                r->complex_uri = 1;
                state = sw_uri;
                break;
            case '%':
                r->quoted_uri = 1;
                state = sw_uri;
                break;
            case '/':
                r->complex_uri = 1;
                state = sw_uri;
                break;
#if (NGX_WIN32)
            case '\\':
                r->complex_uri = 1;
                state = sw_uri;
                break;
#endif
            case '?':
                r->args_start = p + 1;
                state = sw_uri;
                break;
            case '#':
                r->complex_uri = 1;
                state = sw_uri;
                break;
            case '+':
                r->plus_in_uri = 1;
                break;
            default:
                state = sw_check_uri;
                break;
            }
            break;

        /* check "/", "%" and "\" (Win32) in URI */
        case sw_check_uri:

            if (usual[ch >> 5] & (1U << (ch & 0x1f))) {
                break;
            }

            switch (ch) {
            case '/':
#if (NGX_WIN32)
                if (r->uri_ext == p) {
                    r->complex_uri = 1;
                    state = sw_uri;
                    break;
                }
#endif
                r->uri_ext = NULL;
                state = sw_after_slash_in_uri;
                break;
            case '.':
                r->uri_ext = p + 1;
                break;
            case ' ':
                r->space_in_uri = 1;
                break;
#if (NGX_WIN32)
            case '\\':
                r->complex_uri = 1;
                state = sw_after_slash_in_uri;
                break;
#endif
            case '%':
                r->quoted_uri = 1;
                state = sw_uri;
                break;
            case '?':
                r->args_start = p + 1;
                state = sw_uri;
                break;
            case '#':
                r->complex_uri = 1;
                state = sw_uri;
                break;
            case '+':
                r->plus_in_uri = 1;
                break;
            }
            break;

        /* URI */
        case sw_uri:

            if (usual[ch >> 5] & (1U << (ch & 0x1f))) {
                break;
            }

            switch (ch) {
            case ' ':
                r->space_in_uri = 1;
                break;
            case '#':
                r->complex_uri = 1;
                break;
            }
            break;
        }
    }

    return NGX_OK;
}


ngx_int_t
ngx_http_parse_complex_uri(ngx_http_request_t *r, ngx_uint_t merge_slashes)
{
    u_char  c, ch, decoded, *p, *u;
    enum {
        sw_usual = 0,
        sw_slash,
        sw_dot,
        sw_dot_dot,
        sw_quoted,
        sw_quoted_second
    } state, quoted_state;

#if (NGX_SUPPRESS_WARN)
    decoded = '\0';
    quoted_state = sw_usual;
#endif

    state = sw_usual;
    p = r->uri_start;
    u = r->uri.data;
    r->uri_ext = NULL;
    r->args_start = NULL;

    ch = *p++;

    while (p <= r->uri_end) {

        /*
         * we use "ch = *p++" inside the cycle, but this operation is safe,
         * because after the URI there is always at least one character:
         * the line feed
         */

        ngx_log_debug3(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                       "s:%d in:'%Xd:%c'", state, ch, ch);

        switch (state) {

        case sw_usual:

            if (usual[ch >> 5] & (1U << (ch & 0x1f))) {
                *u++ = ch;
                ch = *p++;
                break;
            }

            switch (ch) {
#if (NGX_WIN32)
            case '\\':
                if (u - 2 >= r->uri.data
                    && *(u - 1) == '.' && *(u - 2) != '.')
                {
                    u--;
                }

                r->uri_ext = NULL;

                if (p == r->uri_start + r->uri.len) {

                    /*
                     * we omit the last "\" to cause redirect because
                     * the browsers do not treat "\" as "/" in relative URL path
                     */

                    break;
                }

                state = sw_slash;
                *u++ = '/';
                break;
#endif
            case '/':
#if (NGX_WIN32)
                if (u - 2 >= r->uri.data
                    && *(u - 1) == '.' && *(u - 2) != '.')
                {
                    u--;
                }
#endif
                r->uri_ext = NULL;
                state = sw_slash;
                *u++ = ch;
                break;
            case '%':
                quoted_state = state;
                state = sw_quoted;
                break;
            case '?':
                r->args_start = p;
                goto args;
            case '#':
                goto done;
            case '.':
                r->uri_ext = u + 1;
                *u++ = ch;
                break;
            case '+':
                r->plus_in_uri = 1;
                /* fall through */
            default:
                *u++ = ch;
                break;
            }

            ch = *p++;
            break;

        case sw_slash:

            if (usual[ch >> 5] & (1U << (ch & 0x1f))) {
                state = sw_usual;
                *u++ = ch;
                ch = *p++;
                break;
            }

            switch (ch) {
#if (NGX_WIN32)
            case '\\':
                break;
#endif
            case '/':
                if (!merge_slashes) {
                    *u++ = ch;
                }
                break;
            case '.':
                state = sw_dot;
                *u++ = ch;
                break;
            case '%':
                quoted_state = state;
                state = sw_quoted;
                break;
            case '?':
                r->args_start = p;
                goto args;
            case '#':
                goto done;
            case '+':
                r->plus_in_uri = 1;
                /* fall through */
            default:
                state = sw_usual;
                *u++ = ch;
                break;
            }

            ch = *p++;
            break;

        case sw_dot:

            if (usual[ch >> 5] & (1U << (ch & 0x1f))) {
                state = sw_usual;
                *u++ = ch;
                ch = *p++;
                break;
            }

            switch (ch) {
#if (NGX_WIN32)
            case '\\':
#endif
            case '/':
                state = sw_slash;
                u--;
                break;
            case '.':
                state = sw_dot_dot;
                *u++ = ch;
                break;
            case '%':
                quoted_state = state;
                state = sw_quoted;
                break;
            case '?':
                u--;
                r->args_start = p;
                goto args;
            case '#':
                u--;
                goto done;
            case '+':
                r->plus_in_uri = 1;
                /* fall through */
            default:
                state = sw_usual;
                *u++ = ch;
                break;
            }

            ch = *p++;
            break;

        case sw_dot_dot:

            if (usual[ch >> 5] & (1U << (ch & 0x1f))) {
                state = sw_usual;
                *u++ = ch;
                ch = *p++;
                break;
            }

            switch (ch) {
#if (NGX_WIN32)
            case '\\':
#endif
            case '/':
            case '?':
            case '#':
                u -= 4;
                for ( ;; ) {
                    if (u < r->uri.data) {
                        return NGX_HTTP_PARSE_INVALID_REQUEST;
                    }
                    if (*u == '/') {
                        u++;
                        break;
                    }
                    u--;
                }
                if (ch == '?') {
                    r->args_start = p;
                    goto args;
                }
                if (ch == '#') {
                    goto done;
                }
                state = sw_slash;
                break;
            case '%':
                quoted_state = state;
                state = sw_quoted;
                break;
            case '+':
                r->plus_in_uri = 1;
                /* fall through */
            default:
                state = sw_usual;
                *u++ = ch;
                break;
            }

            ch = *p++;
            break;

        case sw_quoted:
            r->quoted_uri = 1;

            if (ch >= '0' && ch <= '9') {
                decoded = (u_char) (ch - '0');
                state = sw_quoted_second;
                ch = *p++;
                break;
            }

            c = (u_char) (ch | 0x20);
            if (c >= 'a' && c <= 'f') {
                decoded = (u_char) (c - 'a' + 10);
                state = sw_quoted_second;
                ch = *p++;
                break;
            }

            return NGX_HTTP_PARSE_INVALID_REQUEST;

        case sw_quoted_second:
            if (ch >= '0' && ch <= '9') {
                ch = (u_char) ((decoded << 4) + (ch - '0'));

                if (ch == '%' || ch == '#') {
                    state = sw_usual;
                    *u++ = ch;
                    ch = *p++;
                    break;

                } else if (ch == '\0') {
                    return NGX_HTTP_PARSE_INVALID_REQUEST;
                }

                state = quoted_state;
                break;
            }

            c = (u_char) (ch | 0x20);
            if (c >= 'a' && c <= 'f') {
                ch = (u_char) ((decoded << 4) + (c - 'a') + 10);

                if (ch == '?') {
                    state = sw_usual;
                    *u++ = ch;
                    ch = *p++;
                    break;

                } else if (ch == '+') {
                    r->plus_in_uri = 1;
                }

                state = quoted_state;
                break;
            }

            return NGX_HTTP_PARSE_INVALID_REQUEST;
        }
    }

    if (state == sw_quoted || state == sw_quoted_second) {
        return NGX_HTTP_PARSE_INVALID_REQUEST;
    }

    if (state == sw_dot) {
        u--;

    } else if (state == sw_dot_dot) {
        u -= 4;

        for ( ;; ) {
            if (u < r->uri.data) {
                return NGX_HTTP_PARSE_INVALID_REQUEST;
            }

            if (*u == '/') {
                u++;
                break;
            }

            u--;
        }
    }

done:

    r->uri.len = u - r->uri.data;

    if (r->uri_ext) {
        r->exten.len = u - r->uri_ext;
        r->exten.data = r->uri_ext;
    }

    r->uri_ext = NULL;

    return NGX_OK;

args:

    while (p < r->uri_end) {
        if (*p++ != '#') {
            continue;
        }

        r->args.len = p - 1 - r->args_start;
        r->args.data = r->args_start;
        r->args_start = NULL;

        break;
    }

    r->uri.len = u - r->uri.data;

    if (r->uri_ext) {
        r->exten.len = u - r->uri_ext;
        r->exten.data = r->uri_ext;
    }

    r->uri_ext = NULL;

    return NGX_OK;
}


ngx_int_t
ngx_http_parse_status_line(ngx_http_request_t *r, ngx_buf_t *b,
    ngx_http_status_t *status)
{
    u_char   ch;
    u_char  *p;
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

    state = r->state;

    for (p = b->pos; p < b->last; p++) {
        ch = *p;

        switch (state) {

        /* "HTTP/" */
        case sw_start:
            switch (ch) {
            case 'H':
                state = sw_H;
                break;
            default:
                return NGX_ERROR;
            }
            break;

        case sw_H:
            switch (ch) {
            case 'T':
                state = sw_HT;
                break;
            default:
                return NGX_ERROR;
            }
            break;

        case sw_HT:
            switch (ch) {
            case 'T':
                state = sw_HTT;
                break;
            default:
                return NGX_ERROR;
            }
            break;

        case sw_HTT:
            switch (ch) {
            case 'P':
                state = sw_HTTP;
                break;
            default:
                return NGX_ERROR;
            }
            break;

        case sw_HTTP:
            switch (ch) {
            case '/':
                state = sw_first_major_digit;
                break;
            default:
                return NGX_ERROR;
            }
            break;

        /* the first digit of major HTTP version */
        case sw_first_major_digit:
            if (ch < '1' || ch > '9') {
                return NGX_ERROR;
            }

            r->http_major = ch - '0';
            state = sw_major_digit;
            break;

        /* the major HTTP version or dot */
        case sw_major_digit:
            if (ch == '.') {
                state = sw_first_minor_digit;
                break;
            }

            if (ch < '0' || ch > '9') {
                return NGX_ERROR;
            }

            if (r->http_major > 99) {
                return NGX_ERROR;
            }

            r->http_major = r->http_major * 10 + (ch - '0');
            break;

        /* the first digit of minor HTTP version */
        case sw_first_minor_digit:
            if (ch < '0' || ch > '9') {
                return NGX_ERROR;
            }

            r->http_minor = ch - '0';
            state = sw_minor_digit;
            break;

        /* the minor HTTP version or the end of the request line */
        case sw_minor_digit:
            if (ch == ' ') {
                state = sw_status;
                break;
            }

            if (ch < '0' || ch > '9') {
                return NGX_ERROR;
            }

            if (r->http_minor > 99) {
                return NGX_ERROR;
            }

            r->http_minor = r->http_minor * 10 + (ch - '0');
            break;

        /* HTTP status code */
        case sw_status:
            if (ch == ' ') {
                break;
            }

            if (ch < '0' || ch > '9') {
                return NGX_ERROR;
            }

            status->code = status->code * 10 + (ch - '0');

            if (++status->count == 3) {
                state = sw_space_after_status;
                status->start = p - 2;
            }

            break;

        /* space or end of line */
        case sw_space_after_status:
            switch (ch) {
            case ' ':
                state = sw_status_text;
                break;
            case '.':                    /* IIS may send 403.1, 403.2, etc */
                state = sw_status_text;
                break;
            case CR:
                state = sw_almost_done;
                break;
            case LF:
                goto done;
            default:
                return NGX_ERROR;
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
            status->end = p - 1;
            switch (ch) {
            case LF:
                goto done;
            default:
                return NGX_ERROR;
            }
        }
    }

    b->pos = p;
    r->state = state;

    return NGX_AGAIN;

done:

    b->pos = p + 1;

    if (status->end == NULL) {
        status->end = p;
    }

    status->http_version = r->http_major * 1000 + r->http_minor;
    r->state = sw_start;

    return NGX_OK;
}


ngx_int_t
ngx_http_parse_unsafe_uri(ngx_http_request_t *r, ngx_str_t *uri,
    ngx_str_t *args, ngx_uint_t *flags)
{
    u_char      ch, *p, *src, *dst;
    size_t      len;
    ngx_uint_t  quoted;

    len = uri->len;
    p = uri->data;
    quoted = 0;

    if (len == 0 || p[0] == '?') {
        goto unsafe;
    }

    if (p[0] == '.' && len > 1 && p[1] == '.'
        && (len == 2 || ngx_path_separator(p[2])))
    {
        goto unsafe;
    }

    for ( /* void */ ; len; len--) {

        ch = *p++;

        if (ch == '%') {
            quoted = 1;
            continue;
        }

        if (usual[ch >> 5] & (1U << (ch & 0x1f))) {
            continue;
        }

        if (ch == '?') {
            args->len = len - 1;
            args->data = p;
            uri->len -= len;

            break;
        }

        if (ch == '\0') {
            goto unsafe;
        }

        if (ngx_path_separator(ch) && len > 2) {

            /* detect "/../" and "/.." */

            if (p[0] == '.' && p[1] == '.'
                && (len == 3 || ngx_path_separator(p[2])))
            {
                goto unsafe;
            }
        }
    }

    if (quoted) {
        ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                       "escaped URI: \"%V\"", uri);

        src = uri->data;

        dst = ngx_pnalloc(r->pool, uri->len);
        if (dst == NULL) {
            return NGX_ERROR;
        }

        uri->data = dst;

        ngx_unescape_uri(&dst, &src, uri->len, 0);

        uri->len = dst - uri->data;

        ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                       "unescaped URI: \"%V\"", uri);

        len = uri->len;
        p = uri->data;

        if (p[0] == '.' && len > 1 && p[1] == '.'
            && (len == 2 || ngx_path_separator(p[2])))
        {
            goto unsafe;
        }

        for ( /* void */ ; len; len--) {

            ch = *p++;

            if (ch == '\0') {
                goto unsafe;
            }

            if (ngx_path_separator(ch) && len > 2) {

                /* detect "/../" and "/.." */

                if (p[0] == '.' && p[1] == '.'
                    && (len == 3 || ngx_path_separator(p[2])))
                {
                    goto unsafe;
                }
            }
        }
    }

    return NGX_OK;

unsafe:

    if (*flags & NGX_HTTP_LOG_UNSAFE) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                      "unsafe URI \"%V\" was detected", uri);
    }

    return NGX_ERROR;
}


ngx_int_t
ngx_http_parse_multi_header_lines(ngx_array_t *headers, ngx_str_t *name,
    ngx_str_t *value)
{
    ngx_uint_t         i;
    u_char            *start, *last, *end, ch;
    ngx_table_elt_t  **h;

    h = headers->elts;

    for (i = 0; i < headers->nelts; i++) {

        ngx_log_debug2(NGX_LOG_DEBUG_HTTP, headers->pool->log, 0,
                       "parse header: \"%V: %V\"", &h[i]->key, &h[i]->value);

        if (name->len > h[i]->value.len) {
            continue;
        }

        start = h[i]->value.data;
        end = h[i]->value.data + h[i]->value.len;

        while (start < end) {

            if (ngx_strncasecmp(start, name->data, name->len) != 0) {
                goto skip;
            }

            for (start += name->len; start < end && *start == ' '; start++) {
                /* void */
            }

            if (value == NULL) {
                if (start == end || *start == ',') {
                    return i;
                }

                goto skip;
            }

            if (start == end || *start++ != '=') {
                /* the invalid header value */
                goto skip;
            }

            while (start < end && *start == ' ') { start++; }

            for (last = start; last < end && *last != ';'; last++) {
                /* void */
            }

            value->len = last - start;
            value->data = start;

            return i;

        skip:

            while (start < end) {
                ch = *start++;
                if (ch == ';' || ch == ',') {
                    break;
                }
            }

            while (start < end && *start == ' ') { start++; }
        }
    }

    return NGX_DECLINED;
}


ngx_int_t
ngx_http_parse_set_cookie_lines(ngx_array_t *headers, ngx_str_t *name,
    ngx_str_t *value)
{
    ngx_uint_t         i;
    u_char            *start, *last, *end;
    ngx_table_elt_t  **h;

    h = headers->elts;

    for (i = 0; i < headers->nelts; i++) {

        ngx_log_debug2(NGX_LOG_DEBUG_HTTP, headers->pool->log, 0,
                       "parse header: \"%V: %V\"", &h[i]->key, &h[i]->value);

        if (name->len >= h[i]->value.len) {
            continue;
        }

        start = h[i]->value.data;
        end = h[i]->value.data + h[i]->value.len;

        if (ngx_strncasecmp(start, name->data, name->len) != 0) {
            continue;
        }

        for (start += name->len; start < end && *start == ' '; start++) {
            /* void */
        }

        if (start == end || *start++ != '=') {
            /* the invalid header value */
            continue;
        }

        while (start < end && *start == ' ') { start++; }

        for (last = start; last < end && *last != ';'; last++) {
            /* void */
        }

        value->len = last - start;
        value->data = start;

        return i;
    }

    return NGX_DECLINED;
}


ngx_int_t
ngx_http_arg(ngx_http_request_t *r, u_char *name, size_t len, ngx_str_t *value)
{
    u_char  *p, *last;

    if (r->args.len == 0) {
        return NGX_DECLINED;
    }

    p = r->args.data;
    last = p + r->args.len;

    for ( /* void */ ; p < last; p++) {

        /* we need '=' after name, so drop one char from last */

        p = ngx_strlcasestrn(p, last - 1, name, len - 1);

        if (p == NULL) {
            return NGX_DECLINED;
        }

        if ((p == r->args.data || *(p - 1) == '&') && *(p + len) == '=') {

            value->data = p + len + 1;

            p = ngx_strlchr(p, last, '&');

            if (p == NULL) {
                p = r->args.data + r->args.len;
            }

            value->len = p - value->data;

            return NGX_OK;
        }
    }

    return NGX_DECLINED;
}


void
ngx_http_split_args(ngx_http_request_t *r, ngx_str_t *uri, ngx_str_t *args)
{
    u_char  *p, *last;

    last = uri->data + uri->len;

    p = ngx_strlchr(uri->data, last, '?');

    if (p) {
        uri->len = p - uri->data;
        p++;
        args->len = last - p;
        args->data = p;

    } else {
        args->len = 0;
    }
}


ngx_int_t
ngx_http_parse_chunked(ngx_http_request_t *r, ngx_buf_t *b,
    ngx_http_chunked_t *ctx)
{
    u_char     *pos, ch, c;
    ngx_int_t   rc;
    enum {
        sw_chunk_start = 0,
        sw_chunk_size,
        sw_chunk_extension,
        sw_chunk_extension_almost_done,
        sw_chunk_data,
        sw_after_data,
        sw_after_data_almost_done,
        sw_last_chunk_extension,
        sw_last_chunk_extension_almost_done,
        sw_trailer,
        sw_trailer_almost_done,
        sw_trailer_header,
        sw_trailer_header_almost_done
    } state;

    state = ctx->state;

    if (state == sw_chunk_data && ctx->size == 0) {
        state = sw_after_data;
    }

    rc = NGX_AGAIN;

    for (pos = b->pos; pos < b->last; pos++) {

        ch = *pos;

        ngx_log_debug2(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                       "http chunked byte: %02Xd s:%d", ch, state);

        switch (state) {

        case sw_chunk_start:
            if (ch >= '0' && ch <= '9') {
                state = sw_chunk_size;
                ctx->size = ch - '0';
                break;
            }

            c = (u_char) (ch | 0x20);

            if (c >= 'a' && c <= 'f') {
                state = sw_chunk_size;
                ctx->size = c - 'a' + 10;
                break;
            }

            goto invalid;

        case sw_chunk_size:
            if (ctx->size > NGX_MAX_OFF_T_VALUE / 16) {
                goto invalid;
            }

            if (ch >= '0' && ch <= '9') {
                ctx->size = ctx->size * 16 + (ch - '0');
                break;
            }

            c = (u_char) (ch | 0x20);

            if (c >= 'a' && c <= 'f') {
                ctx->size = ctx->size * 16 + (c - 'a' + 10);
                break;
            }

            if (ctx->size == 0) {

                switch (ch) {
                case CR:
                    state = sw_last_chunk_extension_almost_done;
                    break;
                case LF:
                    state = sw_trailer;
                    break;
                case ';':
                case ' ':
                case '\t':
                    state = sw_last_chunk_extension;
                    break;
                default:
                    goto invalid;
                }

                break;
            }

            switch (ch) {
            case CR:
                state = sw_chunk_extension_almost_done;
                break;
            case LF:
                state = sw_chunk_data;
                break;
            case ';':
            case ' ':
            case '\t':
                state = sw_chunk_extension;
                break;
            default:
                goto invalid;
            }

            break;

        case sw_chunk_extension:
            switch (ch) {
            case CR:
                state = sw_chunk_extension_almost_done;
                break;
            case LF:
                state = sw_chunk_data;
            }
            break;

        case sw_chunk_extension_almost_done:
            if (ch == LF) {
                state = sw_chunk_data;
                break;
            }
            goto invalid;

        case sw_chunk_data:
            rc = NGX_OK;
            goto data;

        case sw_after_data:
            switch (ch) {
            case CR:
                state = sw_after_data_almost_done;
                break;
            case LF:
                state = sw_chunk_start;
                break;
            default:
                goto invalid;
            }
            break;

        case sw_after_data_almost_done:
            if (ch == LF) {
                state = sw_chunk_start;
                break;
            }
            goto invalid;

        case sw_last_chunk_extension:
            switch (ch) {
            case CR:
                state = sw_last_chunk_extension_almost_done;
                break;
            case LF:
                state = sw_trailer;
            }
            break;

        case sw_last_chunk_extension_almost_done:
            if (ch == LF) {
                state = sw_trailer;
                break;
            }
            goto invalid;

        case sw_trailer:
            switch (ch) {
            case CR:
                state = sw_trailer_almost_done;
                break;
            case LF:
                goto done;
            default:
                state = sw_trailer_header;
            }
            break;

        case sw_trailer_almost_done:
            if (ch == LF) {
                goto done;
            }
            goto invalid;

        case sw_trailer_header:
            switch (ch) {
            case CR:
                state = sw_trailer_header_almost_done;
                break;
            case LF:
                state = sw_trailer;
            }
            break;

        case sw_trailer_header_almost_done:
            if (ch == LF) {
                state = sw_trailer;
                break;
            }
            goto invalid;

        }
    }

data:

    ctx->state = state;
    b->pos = pos;

    if (ctx->size > NGX_MAX_OFF_T_VALUE - 5) {
        goto invalid;
    }

    switch (state) {

    case sw_chunk_start:
        ctx->length = 3 /* "0" LF LF */;
        break;
    case sw_chunk_size:
        ctx->length = 1 /* LF */
                      + (ctx->size ? ctx->size + 4 /* LF "0" LF LF */
                                   : 1 /* LF */);
        break;
    case sw_chunk_extension:
    case sw_chunk_extension_almost_done:
        ctx->length = 1 /* LF */ + ctx->size + 4 /* LF "0" LF LF */;
        break;
    case sw_chunk_data:
        ctx->length = ctx->size + 4 /* LF "0" LF LF */;
        break;
    case sw_after_data:
    case sw_after_data_almost_done:
        ctx->length = 4 /* LF "0" LF LF */;
        break;
    case sw_last_chunk_extension:
    case sw_last_chunk_extension_almost_done:
        ctx->length = 2 /* LF LF */;
        break;
    case sw_trailer:
    case sw_trailer_almost_done:
        ctx->length = 1 /* LF */;
        break;
    case sw_trailer_header:
    case sw_trailer_header_almost_done:
        ctx->length = 2 /* LF LF */;
        break;

    }

    return rc;

done:

    ctx->state = 0;
    b->pos = pos + 1;

    return NGX_DONE;

invalid:

    return NGX_ERROR;
}
