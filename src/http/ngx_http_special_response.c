

#include <ngx_config.h>
#if 0
#include <ngx_core.h>
#endif
#include <ngx_http.h>


int ngx_http_special_response(ngx_http_request_t *r, int error)
{
    switch (error) {

    default:
        r->headers_out.status = error;
        return ngx_http_header_filter(r);

    }

    return ngx_http_error(r, error);
}
