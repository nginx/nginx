
#include <ngx_config.h>
#include <ngx_http.h>

int ngx_read_http_request_line(ngx_http_request_t *r)
{
    char  ch;
    char *buff = r->buff->buff;
    char *p = r->buff->pos;
    enum {
        rl_start = 0,
        rl_space_after_method,
        rl_spaces_before_uri,
        rl_after_slash_in_uri,
        rl_check_uri,
        rl_uri,
        rl_http_09,
        rl_http_version,
        rl_first_major_digit,
        rl_major_digit,
        rl_first_minor_digit,
        rl_minor_digit,
        rl_almost_done,
        rl_done
    } state = r->state;

    while (p < r->buff->last && state < rl_done) {
        ch = *p++;

/*
printf("\nstate: %d, pos: %x, end: %x, char: '%c' buf: %s",
       state, p, r->buff->last, ch, p);
*/

        /* GCC complie it as jump table */

        switch (state) {

        /* HTTP methods: GET, HEAD, POST */
        case rl_start:
            switch (ch) {
            case 'G':
                if (p + 1 >= r->buff->last)
                    return 0;

                if (*p != 'E' || *(p + 1) != 'T')
                    return NGX_HTTP_INVALID_METHOD;

                r->method = NGX_HTTP_GET;
                p += 2;
                break;

            case 'H':
                if (p + 2 >= r->buff->last)
                    return 0;

                if (*p != 'E' || *(p + 1) != 'A' || *(p + 2) != 'D')
                    return NGX_HTTP_INVALID_METHOD;

                r->method = NGX_HTTP_HEAD;
                p += 3;
                break;

            case 'P':
                if (p + 2 >= r->buff->last)
                    return 0;

                if (*p != 'O' || *(p + 1) != 'S' || *(p + 2) != 'T')
                    return NGX_HTTP_INVALID_METHOD;

                r->method = NGX_HTTP_POST;
                p += 3;
                break;

            default:
                return NGX_HTTP_INVALID_METHOD;
            }

            state = rl_space_after_method;
            break;

        /* single space after method */
        case rl_space_after_method:
            switch (ch) {
            case ' ':
                state = rl_spaces_before_uri;
                break;
            default:
                return NGX_HTTP_INVALID_METHOD;
            }
            break;

        /* space* before URI */
        case rl_spaces_before_uri:
            switch (ch) {
            case '/':
                r->uri_start = p - 1;
                state = rl_after_slash_in_uri;
                break;
            case ' ':
                break;
            default:
                r->unusual_uri = 1;
                r->uri_start = p - 1;
                state = rl_uri;
                break;
            }
            break;

        /* check dot after slash */
        case rl_after_slash_in_uri:
            switch (ch) {
            case CR:
                r->uri_end = p - 1;
                r->http_minor = 9;
                state = rl_almost_done;
                break;
            case LF:
                r->uri_end = p - 1;
                r->http_minor = 9;
                state = rl_done;
                break;
            case ' ':
                r->uri_end = p - 1;
                state = rl_http_09;
                break;
            case '.':
                r->complex_uri = 1;
                state = rl_uri;
                break;
            case '/':
                r->complex_uri = 1;
                state = rl_uri;
                break;
            case '?':
                r->args_start = p;
                state = rl_uri;
                break;
            default:
                state = rl_check_uri;
                break;
            }
            break;

        /* check slash in URI */
        case rl_check_uri:
            switch (ch) {
            case CR:
                r->uri_end = p - 1;
                r->http_minor = 9;
                state = rl_almost_done;
                break;
            case LF:
                r->uri_end = p - 1;
                r->http_minor = 9;
                state = rl_done;
                break;
            case ' ':
                r->uri_end = p - 1;
                state = rl_http_09;
                break;
            case '.':
                r->uri_ext = p;
                break;
            case '/':
                r->uri_ext = NULL;
                state = rl_after_slash_in_uri;
                break;
            case '?':
                r->args_start = p;
                state = rl_uri;
                break;
            }
            break;

        /* URI */
        case rl_uri:
            switch (ch) {
            case CR:
                r->uri_end = p - 1;
                r->http_minor = 9;
                state = rl_almost_done;
                break;
            case LF:
                r->uri_end = p - 1;
                r->http_minor = 9;
                state = rl_done;
                break;
            case ' ':
                r->uri_end = p - 1;
                state = rl_http_09;
                break;
            }
            break;

        /* space+ after URI */
        case rl_http_09:
            switch (ch) {
            case ' ':
                break;
            case CR:
                r->http_minor = 9;
                state = rl_almost_done;
                break;
            case LF:
                r->http_minor = 9;
                state = rl_done;
                break;
            case 'H':
                state = rl_http_version;
                break;
            default:
                return NGX_HTTP_INVALID_REQUEST;
            }
            break;

        /* TTP/ */
        case rl_http_version:
            if (p + 2 >= r->buff->last) {
                r->state = rl_http_version;
                r->buff->pos = p - 1;
                return 0;
            }

            if (ch != 'T' || *p != 'T' || *(p + 1) != 'P' || *(p + 2) != '/')
                return NGX_HTTP_INVALID_REQUEST;

            p += 3;
            state = rl_first_major_digit;
            break;

        /* first digit of major HTTP version */
        case rl_first_major_digit:
            if (ch < '1' || ch > '9')
                return NGX_HTTP_INVALID_REQUEST;

            r->http_major = ch - '0';
            state = rl_major_digit;
            break;

        /* major HTTP version or dot */
        case rl_major_digit:
            if (ch == '.') {
                state = rl_first_minor_digit;
                break;
            }

            if (ch < '0' || ch > '9')
                return NGX_HTTP_INVALID_REQUEST;

            r->http_major = r->http_major * 10 + ch - '0';
            break;

        /* first digit of minor HTTP version */
        case rl_first_minor_digit:
            if (ch < '0' || ch > '9')
                return NGX_HTTP_INVALID_REQUEST;

            r->http_minor = ch - '0';

            state = rl_minor_digit;
            break;

        /* minor HTTP version or end of request line */
        case rl_minor_digit:
            if (ch == CR) {
                state = rl_almost_done;
                break;
            }

            if (ch == LF) {
                state = rl_done;
                break;
            }

            if (ch < '0' || ch > '9')
                return NGX_HTTP_INVALID_REQUEST;

            r->http_minor = r->http_minor * 10 + ch - '0';
            break;

        /* end of request line */
        case rl_almost_done:
            switch (ch) {
            case LF:
                state = rl_done;
                break;
            default:
                return NGX_HTTP_INVALID_METHOD;
            }
            break;
        }
    }

    r->buff->pos = p;

    if (state == rl_done) {
        r->http_version = r->http_major * 1000 + r->http_minor;
        r->state = rl_start;
        return 1;
    } else {
        r->state = state;
        return 0;
    }
}

int ngx_read_http_header_line(ngx_http_request_t *r)
{
    char  c, ch;
    char *buff = r->buff->buff;
    char *p = r->buff->pos;
    enum  {
        hl_start = 0,
        hl_name,
        hl_space_before_value,
        hl_value,
        hl_space_after_value,
        hl_almost_done,
        header_almost_done,
        hl_done,
        header_done
    } state = r->state;

    while (p < r->buff->last && state < hl_done) {
        ch = *p++;

/*
printf("\nstate: %d, pos: %x, end: %x, char: '%c' buf: %s",
       state, p, r->buff->last, ch, p);
*/

        switch (state) {

        /* first char */
        case hl_start:
            switch (ch) {
            case CR:
                r->header_end = p - 1;
                state = header_almost_done;
                break;
            case LF:
                r->header_end = p - 1;
                state = header_done;
                break;
            default:
                state = hl_name;
                r->header_name_start = p - 1;

                c = ch | 0x20;
                if (c >= 'a' && c <= 'z')
                    break;

                if (ch == '-')
                    break;

                if (ch >= '0' && ch <= '9')
                    break;

                return NGX_HTTP_INVALID_HEADER;

            }
            break;

        /* header name */
        case hl_name:
            c = ch | 0x20;
            if (c >= 'a' && c <= 'z')
                break;

            if (ch == ':') {
                r->header_name_end = p - 1;
                state = hl_space_before_value;
                break;
            }

            if (ch == '-')
                break;

            if (ch >= '0' && ch <= '9')
                break;

            return NGX_HTTP_INVALID_HEADER;

        /* space* before header value */
        case hl_space_before_value:
            switch (ch) {
            case ' ':
                break;
            case CR:
                r->header_start = r->header_end = p - 1;
                state = hl_almost_done;
                break;
            case LF:
                r->header_start = r->header_end = p - 1;
                state = hl_done;
                break;
            default:
                r->header_start = p - 1;
                state = hl_value;
                break;
            }
            break;

        /* header value */
        case hl_value:
            switch (ch) {
            case ' ':
                r->header_end = p - 1;
                state = hl_space_after_value;
                break;
            case CR:
                r->header_end = p - 1;
                state = hl_almost_done;
                break;
            case LF:
                r->header_end = p - 1;
                state = hl_done;
                break;
            }
            break;

        /* space* before end of header line */
        case hl_space_after_value:
            switch (ch) {
            case ' ':
                break;
            case CR:
                state = hl_almost_done;
                break;
            case LF:
                state = hl_done;
                break;
            default:
                state = hl_value;
                break;
            }
            break;

        /* end of header line */
        case hl_almost_done:
            switch (ch) {
            case LF:
                state = hl_done;
                break;
            default:
                return NGX_HTTP_INVALID_HEADER;
            }
            break;

        /* end of header */
        case header_almost_done:
            switch (ch) {
            case LF:
                state = header_done;
                break;
            default:
                return NGX_HTTP_INVALID_HEADER;
            }
            break;
        }
    }

    r->buff->pos = p;

    if (state == hl_done) {
        r->state = hl_start;
        return 1;
    } else if (state == header_done) {
        r->state = hl_start;
        return 2;
    } else {
        r->state = state;
        return 0;
    }
}
