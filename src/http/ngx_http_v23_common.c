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
    ngx_uint_t                 i;
    ngx_http_core_srv_conf_t  *cscf;

    if (is_client) {
        r->invalid_header = 0;
    }

    cscf = ngx_http_get_module_srv_conf(r, ngx_http_core_module);

    if (name->len < 1) {
        ngx_log_error(NGX_LOG_INFO, r->connection->log, 0,
                      "%s sent empty header name",
                      is_client ? "client" : "server");

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
                          "%s sent invalid header name: \"%V\"",
                          is_client ? "client" : "server", name);

            return NGX_ERROR;
        }

        if (is_client) {
            r->invalid_header = 1;
        }
    }

    for (i = 0; i != value->len; i++) {
        ch = value->data[i];

        if (ch == '\0' || ch == LF || ch == CR) {
            ngx_log_error(NGX_LOG_INFO, r->connection->log, 0,
                          "%s sent header \"%V\" with "
                          "invalid value: \"%V\"",
                          is_client ? "client" : "upstream",
                          name, value);

            return NGX_ERROR;
        }
    }

    return NGX_OK;
}


static inline ngx_int_t
ngx_isspace(u_char ch)
{
    return ch == ' ' || ch == '\t';
}
