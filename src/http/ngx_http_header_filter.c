
#include <nginx.h>

#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_string.h>
#include <ngx_hunk.h>
#include <ngx_http.h>


typedef struct {
    int    len;
    char  *line;
} line;


static line http_codes[] = {
    { 6, "200 OK" }
};



int ngx_http_header_filter(ngx_http_request_t *r)
{
    int  status;
    ngx_hunk_t   *h;
    ngx_chain_t  *ch;

    ngx_test_null(h, ngx_create_temp_hunk(r->pool, 1024, 0, 64),
                  NGX_ERROR);

    status = r->headers_out.status - NGX_HTTP_OK;

    ngx_memcpy(h->last.mem, "HTTP/1.1 ", 9);
    h->last.mem += 9;
    ngx_memcpy(h->last.mem, http_codes[status].line, http_codes[status].len);
    h->last.mem += http_codes[status].len;
    *(h->last.mem++) = CR; *(h->last.mem++) = LF;

#if 1
    r->keepalive = 1;
    ngx_memcpy(h->last.mem, "Connection: keep-alive" CRLF, 24);
    h->last.mem += 24;
#endif

    ngx_memcpy(h->last.mem, "Date: ", 6);
    h->last.mem += 6;
    h->last.mem += ngx_http_get_time(h->last.mem, time(NULL));
    *(h->last.mem++) = CR; *(h->last.mem++) = LF;

    /* 2^64 is 20 characters  */
    if (r->headers_out.content_length)
        h->last.mem += ngx_snprintf(h->last.mem, 49, "Content-Length: %d" CRLF,
                                    r->headers_out.content_length);

    /* check */

    if (r->headers_out.content_type)
        h->last.mem += ngx_snprintf(h->last.mem, 100, "Content-Type: %s" CRLF,
                                    r->headers_out.content_type);

    ngx_memcpy(h->last.mem, "Server: ", 8);
    h->last.mem += 8;
    if (r->headers_out.server) {
        h->last.mem = ngx_cpystrn(h->last.mem, r->headers_out.server,
                                  h->end - h->last.mem);
        /* check space */

    } else {
        ngx_memcpy(h->last.mem, NGINX_VER, sizeof(NGINX_VER) - 1);
        h->last.mem += sizeof(NGINX_VER) - 1;
    }
    *(h->last.mem++) = CR; *(h->last.mem++) = LF;

    /* end of HTTP header */
    *(h->last.mem++) = CR; *(h->last.mem++) = LF;

    ngx_test_null(ch, ngx_palloc(r->pool, sizeof(ngx_chain_t)),
                  /* STUB */
                  -1);
/*
                  NGX_HTTP_FILTER_ERROR);
*/

    ch->hunk = h;
    ch->next = NULL;

    return ngx_http_write_filter(r, ch);
}
