
#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>

int ngx_read_http_request_line(ngx_http_request_t *r)
{
    char  ch;
    char *p = r->header_in->pos.mem;
    enum {
        sw_start = 0,
        sw_space_after_method,
        sw_spaces_before_uri,
        sw_after_slash_in_uri,
        sw_check_uri,
        sw_uri,
        sw_http_09,
        sw_http_version,
        sw_first_major_digit,
        sw_major_digit,
        sw_first_minor_digit,
        sw_minor_digit,
        sw_almost_done,
        sw_done
    } state = r->state;

    while (p < r->header_in->last.mem && state < sw_done) {
        ch = *p++;

/*
printf("\nstate: %d, pos: %x, end: %x, char: '%c' buf: %s",
       state, p, r->header_in->last, ch, p);
*/

        /* GCC 2.95.2 and VC 6.0 compiles this switch as jump table */

        switch (state) {

        /* HTTP methods: GET, HEAD, POST */
        case sw_start:
            switch (ch) {
            case 'G':
                if (p + 1 >= r->header_in->last.mem)
                    return NGX_AGAIN;

                if (*p != 'E' || *(p + 1) != 'T')
                    return NGX_HTTP_PARSE_INVALID_METHOD;

                r->method = NGX_HTTP_GET;
                p += 2;
                break;

            case 'H':
                if (p + 2 >= r->header_in->last.mem)
                    return NGX_AGAIN;

                if (*p != 'E' || *(p + 1) != 'A' || *(p + 2) != 'D')
                    return NGX_HTTP_PARSE_INVALID_METHOD;

                r->method = NGX_HTTP_HEAD;
                p += 3;
                break;

            case 'P':
                if (p + 2 >= r->header_in->last.mem)
                    return NGX_AGAIN;

                if (*p != 'O' || *(p + 1) != 'S' || *(p + 2) != 'T')
                    return NGX_HTTP_PARSE_INVALID_METHOD;

                r->method = NGX_HTTP_POST;
                p += 3;
                break;

            default:
                return NGX_HTTP_PARSE_INVALID_METHOD;
            }

            state = sw_space_after_method;
            break;

        /* single space after method */
        case sw_space_after_method:
            switch (ch) {
            case ' ':
                state = sw_spaces_before_uri;
                break;
            default:
                return NGX_HTTP_PARSE_INVALID_METHOD;
            }
            break;

        /* space* before URI */
        case sw_spaces_before_uri:
            switch (ch) {
            case '/':
                r->uri_start = p - 1;
                state = sw_after_slash_in_uri;
                break;
            case ' ':
                break;
            default:
                r->unusual_uri = 1;
                r->uri_start = p - 1;
                state = sw_uri;
                break;
            }
            break;

        /* check dot after slash */
        case sw_after_slash_in_uri:
            switch (ch) {
            case CR:
                r->uri_end = p - 1;
                r->http_minor = 9;
                state = sw_almost_done;
                break;
            case LF:
                r->uri_end = p - 1;
                r->http_minor = 9;
                state = sw_done;
                break;
            case ' ':
                r->uri_end = p - 1;
                state = sw_http_09;
                break;
            case '.':
                r->complex_uri = 1;
                state = sw_uri;
                break;
            case '/':
                r->complex_uri = 1;
                state = sw_uri;
                break;
            case '?':
                r->args_start = p;
                state = sw_uri;
                break;
            default:
                state = sw_check_uri;
                break;
            }
            break;

        /* check slash in URI */
        case sw_check_uri:
            switch (ch) {
            case CR:
                r->uri_end = p - 1;
                r->http_minor = 9;
                state = sw_almost_done;
                break;
            case LF:
                r->uri_end = p - 1;
                r->http_minor = 9;
                state = sw_done;
                break;
            case ' ':
                r->uri_end = p - 1;
                state = sw_http_09;
                break;
            case '.':
                r->uri_ext = p;
                break;
            case '/':
                r->uri_ext = NULL;
                state = sw_after_slash_in_uri;
                break;
            case '?':
                r->args_start = p;
                state = sw_uri;
                break;
            }
            break;

        /* URI */
        case sw_uri:
            switch (ch) {
            case CR:
                r->uri_end = p - 1;
                r->http_minor = 9;
                state = sw_almost_done;
                break;
            case LF:
                r->uri_end = p - 1;
                r->http_minor = 9;
                state = sw_done;
                break;
            case ' ':
                r->uri_end = p - 1;
                state = sw_http_09;
                break;
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
                state = sw_done;
                break;
            case 'H':
                state = sw_http_version;
                break;
            default:
                return NGX_HTTP_PARSE_INVALID_REQUEST;
            }
            break;

        /* TTP/ */
        case sw_http_version:
            if (p + 2 >= r->header_in->last.mem) {
                r->state = sw_http_version;
                r->header_in->pos.mem = p - 1;
                return NGX_AGAIN;
            }

            if (ch != 'T' || *p != 'T' || *(p + 1) != 'P' || *(p + 2) != '/')
                return NGX_HTTP_PARSE_INVALID_REQUEST;

            p += 3;
            state = sw_first_major_digit;
            break;

        /* first digit of major HTTP version */
        case sw_first_major_digit:
            if (ch < '1' || ch > '9')
                return NGX_HTTP_PARSE_INVALID_REQUEST;

            r->http_major = ch - '0';
            state = sw_major_digit;
            break;

        /* major HTTP version or dot */
        case sw_major_digit:
            if (ch == '.') {
                state = sw_first_minor_digit;
                break;
            }

            if (ch < '0' || ch > '9')
                return NGX_HTTP_PARSE_INVALID_REQUEST;

            r->http_major = r->http_major * 10 + ch - '0';
            break;

        /* first digit of minor HTTP version */
        case sw_first_minor_digit:
            if (ch < '0' || ch > '9')
                return NGX_HTTP_PARSE_INVALID_REQUEST;

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
                state = sw_done;
                break;
            }

            if (ch < '0' || ch > '9')
                return NGX_HTTP_PARSE_INVALID_REQUEST;

            r->http_minor = r->http_minor * 10 + ch - '0';
            break;

        /* end of request line */
        case sw_almost_done:
            switch (ch) {
            case LF:
                state = sw_done;
                break;
            default:
                return NGX_HTTP_PARSE_INVALID_REQUEST;
            }
            break;
        }
    }

    r->header_in->pos.mem = p;

    if (state == sw_done) {
        r->http_version = r->http_major * 1000 + r->http_minor;
        r->state = sw_start;
        if (r->http_version == 9 && r->method == NGX_HTTP_HEAD)
            return NGX_HTTP_PARSE_INVALID_HEAD;
        else
            return NGX_OK;
    } else {
        r->state = state;
        return NGX_AGAIN;
    }
}

int ngx_read_http_header_line(ngx_http_request_t *r)
{
    char  c, ch;
    char *p = r->header_in->pos.mem;
    enum  {
        sw_start = 0,
        sw_name,
        sw_space_before_value,
        sw_value,
        sw_space_after_value,
        sw_almost_done,
        sw_header_almost_done,
        sw_done,
        sw_header_done
    } state = r->state;

    while (p < r->header_in->last.mem && state < sw_done) {
        ch = *p++;

/*
printf("\nstate: %d, pos: %x, end: %x, char: '%c' buf: %s",
       state, p, r->header_in->last.mem, ch, p);
*/

        switch (state) {

        /* first char */
        case sw_start:
            switch (ch) {
            case CR:
                r->header_end = p - 1;
                state = sw_header_almost_done;
                break;
            case LF:
                r->header_end = p - 1;
                state = sw_header_done;
                break;
            default:
                state = sw_name;
                r->header_name_start = p - 1;

                c = ch | 0x20;
                if (c >= 'a' && c <= 'z')
                    break;

                if (ch == '-')
                    break;

                if (ch >= '0' && ch <= '9')
                    break;

                return NGX_HTTP_PARSE_INVALID_HEADER;

            }
            break;

        /* header name */
        case sw_name:
            c = ch | 0x20;
            if (c >= 'a' && c <= 'z')
                break;

            if (ch == ':') {
                r->header_name_end = p - 1;
                state = sw_space_before_value;
                break;
            }

            if (ch == '-')
                break;

            if (ch >= '0' && ch <= '9')
                break;

            return NGX_HTTP_PARSE_INVALID_HEADER;

        /* space* before header value */
        case sw_space_before_value:
            switch (ch) {
            case ' ':
                break;
            case CR:
                r->header_start = r->header_end = p - 1;
                state = sw_almost_done;
                break;
            case LF:
                r->header_start = r->header_end = p - 1;
                state = sw_done;
                break;
            default:
                r->header_start = p - 1;
                state = sw_value;
                break;
            }
            break;

        /* header value */
        case sw_value:
            switch (ch) {
            case ' ':
                r->header_end = p - 1;
                state = sw_space_after_value;
                break;
            case CR:
                r->header_end = p - 1;
                state = sw_almost_done;
                break;
            case LF:
                r->header_end = p - 1;
                state = sw_done;
                break;
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
                state = sw_done;
                break;
            default:
                state = sw_value;
                break;
            }
            break;

        /* end of header line */
        case sw_almost_done:
            switch (ch) {
            case LF:
                state = sw_done;
                break;
            default:
                return NGX_HTTP_PARSE_INVALID_HEADER;
            }
            break;

        /* end of header */
        case sw_header_almost_done:
            switch (ch) {
            case LF:
                state = sw_header_done;
                break;
            default:
                return NGX_HTTP_PARSE_INVALID_HEADER;
            }
            break;
        }
    }

    r->header_in->pos.mem = p;

    if (state == sw_done) {
        r->state = sw_start;
        return NGX_OK;
    } else if (state == sw_header_done) {
        r->state = sw_start;
        return NGX_HTTP_PARSE_HEADER_DONE;
    } else {
        r->state = state;
        return NGX_AGAIN;
    }
}
