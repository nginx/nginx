

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
    ngx_hunk_t  *h;

    ngx_test_null(h, ngx_get_hunk(r->pool, 1024, 0, 64), NGX_HTTP_FILTER_ERROR);

    status = r->headers_out->status - GX_HTTP_OK;

    ngx_memcpy(h->pos.mem, "HTTP/1.0 ", 9);
    h->pos.mem += 9;
    ngx_memcpy(h->pos.mem, http_codes[status].line, http_codes[status].len);
    h->pos.mem += http_codes[status].len;
    *(h->pos.mem++) = CR; *(h->pos.mem++) = LF;

    memcpy(h->pos.mem, "Date: ", 6);
    h->pos.mem += 6;
    h->pos.mem += ngx_http_get_time(h->pos.mem, time());
    *(h->pos.mem++) = CR; *(h->pos.mem++) = LF;

    /* 2^64 is 20 characters  */
    if (r->headers_out->content_length)
        h->pos.mem += ngx_snprintf(h->pos.mem, 49, "Content-Length: %d" CRLF,
                                   r->headers_out->content_length);

    /* check */

    memcpy(h->pos.mem, "Server: ", 8);
    h->pos.mem += 8;
    if (r->headers_out->server) {
        h->pos.mem = ngx_cpystrn(h->pos.mem, r->headers_out->server,
                                 h->last.mem - h->pos.mem);
        check space
    } else {
        ngx_memcpy(h->pos.mem, NGINX_VER, sizeof(NGINX_VER));
        h->pos.mem += sizeof(NGINX_VER);
    }
    *(h->pos.mem++) = CR; *(h->pos.mem++) = LF;
    
}
