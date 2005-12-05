
/*
 * Copyright (C) Igor Sysoev
 */


#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_event.h>
#include <ngx_http.h>


static ngx_int_t ngx_http_variable_request(ngx_http_request_t *r,
    ngx_http_variable_value_t *v, uintptr_t data);
static ngx_int_t ngx_http_variable_header(ngx_http_request_t *r,
    ngx_http_variable_value_t *v, uintptr_t data);
static ngx_int_t ngx_http_variable_headers(ngx_http_request_t *r,
    ngx_http_variable_value_t *v, uintptr_t data);

static ngx_int_t ngx_http_variable_unknown_header_in(ngx_http_request_t *r,
    ngx_http_variable_value_t *v, uintptr_t data);
static ngx_int_t ngx_http_variable_unknown_header_out(ngx_http_request_t *r,
    ngx_http_variable_value_t *v, uintptr_t data);
static ngx_int_t ngx_http_variable_unknown_header(ngx_http_variable_value_t *v,
    ngx_str_t *var, ngx_list_part_t *part, size_t prefix);

static ngx_int_t ngx_http_variable_host(ngx_http_request_t *r,
    ngx_http_variable_value_t *v, uintptr_t data);
static ngx_int_t ngx_http_variable_remote_addr(ngx_http_request_t *r,
    ngx_http_variable_value_t *v, uintptr_t data);
static ngx_int_t ngx_http_variable_remote_port(ngx_http_request_t *r,
    ngx_http_variable_value_t *v, uintptr_t data);
static ngx_int_t ngx_http_variable_server_addr(ngx_http_request_t *r,
    ngx_http_variable_value_t *v, uintptr_t data);
static ngx_int_t ngx_http_variable_server_port(ngx_http_request_t *r,
    ngx_http_variable_value_t *v, uintptr_t data);
static ngx_int_t ngx_http_variable_document_root(ngx_http_request_t *r,
    ngx_http_variable_value_t *v, uintptr_t data);
static ngx_int_t ngx_http_variable_request_filename(ngx_http_request_t *r,
    ngx_http_variable_value_t *v, uintptr_t data);
static ngx_int_t ngx_http_variable_request_method(ngx_http_request_t *r,
    ngx_http_variable_value_t *v, uintptr_t data);
static ngx_int_t ngx_http_variable_remote_user(ngx_http_request_t *r,
    ngx_http_variable_value_t *v, uintptr_t data);


/*
 * TODO:
 *     Apache CGI: AUTH_TYPE, PATH_INFO (null), PATH_TRANSLATED
 *                 REMOTE_HOST (null), REMOTE_IDENT (null),
 *                 SERVER_SOFTWARE
 *
 *     Apache SSI: DOCUMENT_NAME, LAST_MODIFIED, USER_NAME (file owner)
 */

static ngx_http_variable_t  ngx_http_core_variables[] = {

    { ngx_string("http_host"), ngx_http_variable_header,
      offsetof(ngx_http_request_t, headers_in.host), 0, 0 },

    { ngx_string("http_user_agent"), ngx_http_variable_header,
      offsetof(ngx_http_request_t, headers_in.user_agent), 0, 0 },

    { ngx_string("http_referer"), ngx_http_variable_header,
      offsetof(ngx_http_request_t, headers_in.referer), 0, 0 },

#if (NGX_HTTP_GZIP)
    { ngx_string("http_via"), ngx_http_variable_header,
      offsetof(ngx_http_request_t, headers_in.via), 0, 0 },
#endif

#if (NGX_HTTP_PROXY)
    { ngx_string("http_x_forwarded_for"), ngx_http_variable_header,
      offsetof(ngx_http_request_t, headers_in.x_forwarded_for), 0, 0 },
#endif

    { ngx_string("http_cookie"), ngx_http_variable_headers,
      offsetof(ngx_http_request_t, headers_in.cookies), 0, 0 },

    { ngx_string("content_length"), ngx_http_variable_header,
      offsetof(ngx_http_request_t, headers_in.content_length), 0, 0 },

    { ngx_string("content_type"), ngx_http_variable_header,
      offsetof(ngx_http_request_t, headers_in.content_type), 0, 0 },

    { ngx_string("host"), ngx_http_variable_host, 0, 0, 0 },

    { ngx_string("remote_addr"), ngx_http_variable_remote_addr, 0, 0, 0 },

    { ngx_string("remote_port"), ngx_http_variable_remote_port, 0, 0, 0 },

    { ngx_string("server_addr"), ngx_http_variable_server_addr, 0, 0, 0 },

    { ngx_string("server_port"), ngx_http_variable_server_port, 0, 0, 0 },

    { ngx_string("server_protocol"), ngx_http_variable_request,
      offsetof(ngx_http_request_t, http_protocol), 0, 0 },

    { ngx_string("request_uri"), ngx_http_variable_request,
      offsetof(ngx_http_request_t, unparsed_uri), 0, 0 },

    { ngx_string("uri"), ngx_http_variable_request,
      offsetof(ngx_http_request_t, uri),
      NGX_HTTP_VAR_NOCACHABLE, 0 },

    { ngx_string("document_uri"), ngx_http_variable_request,
      offsetof(ngx_http_request_t, uri),
      NGX_HTTP_VAR_NOCACHABLE, 0 },

    { ngx_string("request"), ngx_http_variable_request,
      offsetof(ngx_http_request_t, request_line), 0, 0 },

    { ngx_string("document_root"), ngx_http_variable_document_root, 0, 0, 0 },

    { ngx_string("query_string"), ngx_http_variable_request,
      offsetof(ngx_http_request_t, args),
      NGX_HTTP_VAR_NOCACHABLE, 0 },

    { ngx_string("request_filename"), ngx_http_variable_request_filename, 0,
      NGX_HTTP_VAR_NOCACHABLE, 0 },

    { ngx_string("server_name"), ngx_http_variable_request,
      offsetof(ngx_http_request_t, server_name), 0, 0 },

    { ngx_string("request_method"), ngx_http_variable_request_method, 0, 0, 0 },

    { ngx_string("remote_user"), ngx_http_variable_remote_user, 0, 0, 0 },

    { ngx_null_string, NULL, 0, 0, 0 }
};


ngx_http_variable_value_t  ngx_http_variable_null_value =
    ngx_http_variable("");
ngx_http_variable_value_t  ngx_http_variable_true_value =
    ngx_http_variable("1");


ngx_http_variable_t *
ngx_http_add_variable(ngx_conf_t *cf, ngx_str_t *name, ngx_uint_t flags)
{
    ngx_uint_t                  i;
    ngx_http_variable_t        *v;
    ngx_http_core_main_conf_t  *cmcf;

    cmcf = ngx_http_conf_get_module_main_conf(cf, ngx_http_core_module);

    v = cmcf->all_variables.elts;
    for (i = 0; i < cmcf->all_variables.nelts; i++) {
        if (name->len != v[i].name.len
            || ngx_strncasecmp(name->data, v[i].name.data, name->len) != 0)
        {
            continue;
        }

        if (!(v[i].flags & NGX_HTTP_VAR_CHANGABLE)) {
            ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                               "the duplicate \"%V\" variable", name);
            return NULL;
        }

        return &v[i];
    }

    v = ngx_array_push(&cmcf->all_variables);
    if (v == NULL) {
        return NULL;
    }

    v->name.len = name->len;
    v->name.data = ngx_palloc(cf->pool, name->len);
    if (v->name.data == NULL) {
        return NULL;
    }

    for (i = 0; i < name->len; i++) {
        v->name.data[i] = ngx_tolower(name->data[i]);
    }

    v->handler = NULL;
    v->data = 0;
    v->flags = flags;
    v->index = 0;

    return v;
}


ngx_int_t
ngx_http_get_variable_index(ngx_conf_t *cf, ngx_str_t *name)
{
    ngx_uint_t                  i;
    ngx_http_variable_t        *v;
    ngx_http_core_main_conf_t  *cmcf;

    cmcf = ngx_http_conf_get_module_main_conf(cf, ngx_http_core_module);

    v = cmcf->variables.elts;

    if (v == NULL) {
        if (ngx_array_init(&cmcf->variables, cf->pool, 4,
                           sizeof(ngx_http_variable_t)) == NGX_ERROR)
        {
            return NGX_ERROR;
        }

    } else {
        for (i = 0; i < cmcf->variables.nelts; i++) {
            if (name->len != v[i].name.len
                || ngx_strncasecmp(name->data, v[i].name.data, name->len) != 0)
            {
                continue;
            }

            return i;
        }
    }

    v = ngx_array_push(&cmcf->variables);
    if (v == NULL) {
        return NGX_ERROR;
    }

    v->name.len = name->len;
    v->name.data = ngx_palloc(cf->pool, name->len);
    if (v->name.data == NULL) {
        return NGX_ERROR;
    }

    for (i = 0; i < name->len; i++) {
        v->name.data[i] = ngx_tolower(name->data[i]);
    }

    v->handler = NULL;
    v->data = 0;
    v->flags = 0;
    v->index = cmcf->variables.nelts - 1;

    return cmcf->variables.nelts - 1;
}


ngx_http_variable_value_t *
ngx_http_get_indexed_variable(ngx_http_request_t *r, ngx_uint_t index)
{
    ngx_http_variable_t        *v;
    ngx_http_core_main_conf_t  *cmcf;

    cmcf = ngx_http_get_module_main_conf(r, ngx_http_core_module);

    if (cmcf->variables.nelts <= index) {
        ngx_log_error(NGX_LOG_ALERT, r->connection->log, 0,
                      "unknown variable index: %d", index);
        return NULL;
    }

    if (r->variables[index].not_found || r->variables[index].valid) {
        return &r->variables[index];
    }

    v = cmcf->variables.elts;

    if (v[index].handler(r, &r->variables[index], v[index].data) == NGX_OK) {

        if (v[index].flags & NGX_HTTP_VAR_NOCACHABLE) {
            r->variables[index].no_cachable = 1;
        }

        return &r->variables[index];
    }

    return NULL;
}


ngx_http_variable_value_t *
ngx_http_get_flushed_variable(ngx_http_request_t *r, ngx_uint_t index)
{
    ngx_http_variable_value_t   *v;

    v = &r->variables[index];

    if (v->valid) {
        if (!v->no_cachable) {
            return v;
        }

        v->valid = 0;
        v->not_found = 0;
    }

    return ngx_http_get_indexed_variable(r, index);
}


ngx_http_variable_value_t *
ngx_http_get_variable(ngx_http_request_t *r, ngx_str_t *name)
{
    ngx_uint_t                  i, key;
    ngx_http_variable_t        *v;
    ngx_http_variable_value_t  *vv;
    ngx_http_core_main_conf_t  *cmcf;

    cmcf = ngx_http_get_module_main_conf(r, ngx_http_core_module);

    key = 0;
    for (i = 0; i < name->len; i++) {
        key += name->data[i];
    }

    key %= cmcf->variables_hash.hash_size;
    v = (ngx_http_variable_t *) cmcf->variables_hash.buckets;

    if (v[key].name.len == name->len
        && ngx_strncmp(v[key].name.data, name->data, name->len) == 0)
    {
        if (v[key].flags & NGX_HTTP_VAR_INDEXED) {
            return ngx_http_get_indexed_variable(r, v[key].index);

        } else {

            vv = ngx_palloc(r->pool, sizeof(ngx_http_variable_value_t));

            if (vv && v[key].handler(r, vv, v[key].data) == NGX_OK) {
                return vv;
            }

            return NULL;
        }
    }

    vv = ngx_palloc(r->pool, sizeof(ngx_http_variable_value_t));
    if (vv == NULL) {
        return NULL;
    }

    if (ngx_strncmp(name->data, "http_", 5) == 0) {

        if (ngx_http_variable_unknown_header_in(r, vv, (uintptr_t) name)
            == NGX_OK)
        {
            return vv;
        }

        return NULL;
    }

    if (ngx_strncmp(name->data, "sent_http_", 10) == 0) {

        if (ngx_http_variable_unknown_header_out(r, vv, (uintptr_t) name)
            == NGX_OK)
        {
            return vv;
        }

        return NULL;
    }

    ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                  "unknown \"%V\" variable", name);

    vv->not_found = 1;

    return vv;
}


static ngx_int_t
ngx_http_variable_request(ngx_http_request_t *r, ngx_http_variable_value_t *v,
    uintptr_t data)
{
    ngx_str_t  *s;

    s = (ngx_str_t *) ((char *) r + data);

    if (s->data) {
        v->len = s->len;
        v->valid = 1;
        v->no_cachable = 0;
        v->not_found = 0;
        v->data = s->data;

    } else {
        v->not_found = 1;
    }

    return NGX_OK;
}


static ngx_int_t
ngx_http_variable_header(ngx_http_request_t *r, ngx_http_variable_value_t *v,
    uintptr_t data)
{
    ngx_table_elt_t  *h;

    h = *(ngx_table_elt_t **) ((char *) r + data);

    if (h) {
        v->len = h->value.len;
        v->valid = 1;
        v->no_cachable = 0;
        v->not_found = 0;
        v->data = h->value.data;

    } else {
        v->not_found = 1;
    }

    return NGX_OK;
}


static ngx_int_t
ngx_http_variable_headers(ngx_http_request_t *r, ngx_http_variable_value_t *v,
    uintptr_t data)
{
    size_t             len;
    u_char            *p;
    ngx_uint_t         i;
    ngx_array_t       *a;
    ngx_table_elt_t  **h;

    a = (ngx_array_t *) ((char *) r + data);

    if (a->nelts == 0) {
        v->not_found = 1;
        return NGX_OK;
    }

    v->valid = 1;
    v->no_cachable = 0;
    v->not_found = 0;

    h = a->elts;

    if (a->nelts == 1) {
        v->len = (*h)->value.len;
        v->data = (*h)->value.data;

        return NGX_OK;
    }

    len = (size_t) - (ssize_t) (sizeof("; ") - 1);

    for (i = 0; i < a->nelts; i++) {
        len += h[i]->value.len + sizeof("; ") - 1;
    }

    p = ngx_palloc(r->pool, len);
    if (p == NULL) {
        return NGX_ERROR;
    }

    v->len = len;
    v->data = p;

    for (i = 0; /* void */ ; i++) {
        p = ngx_copy(p, h[i]->value.data, h[i]->value.len);

        if (i == a->nelts - 1) {
            break;
        }

        *p++ = ';'; *p++ = ' ';
    }

    return NGX_OK;
}


static ngx_int_t
ngx_http_variable_unknown_header_in(ngx_http_request_t *r,
    ngx_http_variable_value_t *v, uintptr_t data)
{
    return ngx_http_variable_unknown_header(v, (ngx_str_t *) data,
                                            &r->headers_in.headers.part,
                                            sizeof("http_") - 1);
}


static ngx_int_t
ngx_http_variable_unknown_header_out(ngx_http_request_t *r,
    ngx_http_variable_value_t *v, uintptr_t data)
{
    return ngx_http_variable_unknown_header(v, (ngx_str_t *) data,
                                            &r->headers_out.headers.part,
                                            sizeof("sent_http_") - 1);
}


static ngx_int_t
ngx_http_variable_unknown_header(ngx_http_variable_value_t *v, ngx_str_t *var,
    ngx_list_part_t *part, size_t prefix)
{
    u_char            ch;
    ngx_uint_t        i, n;
    ngx_table_elt_t  *header;

    header = part->elts;

    for (i = 0; /* void */ ; i++) {

        if (i >= part->nelts) {
            if (part->next == NULL) {
                break;
            }

            part = part->next;
            header = part->elts;
            i = 0;
        }

        for (n = 0; n + prefix < var->len && n < header[i].key.len; n++) {
            ch = header[i].key.data[n];

            if (ch >= 'A' && ch <= 'Z') {
                ch |= 0x20;

            } else if (ch == '-') {
                ch = '_';
            }

            if (var->data[n + prefix] != ch) {
                break;
            }
        }

        if (n + prefix == var->len) {
            v->len = header[i].value.len;
            v->valid = 1;
            v->no_cachable = 0;
            v->not_found = 0;
            v->data = header[i].value.data;

            return NGX_OK;
        }
    }

    v->not_found = 1;

    return NGX_OK;
}


static ngx_int_t
ngx_http_variable_host(ngx_http_request_t *r, ngx_http_variable_value_t *v,
    uintptr_t data)
{
    if (r->headers_in.host) {
        v->len = r->headers_in.host_name_len;
        v->data = r->headers_in.host->value.data;

    } else {
        v->len = r->server_name.len;
        v->data = r->server_name.data;
    }

    v->valid = 1;
    v->no_cachable = 0;
    v->not_found = 0;

    return NGX_OK;
}


static ngx_int_t
ngx_http_variable_remote_addr(ngx_http_request_t *r,
    ngx_http_variable_value_t *v, uintptr_t data)
{
    v->len = r->connection->addr_text.len;
    v->valid = 1;
    v->no_cachable = 0;
    v->not_found = 0;
    v->data = r->connection->addr_text.data;

    return NGX_OK;
}


static ngx_int_t
ngx_http_variable_remote_port(ngx_http_request_t *r,
    ngx_http_variable_value_t *v, uintptr_t data)
{
    ngx_uint_t           port;
    struct sockaddr_in  *sin;

    v->len = 0;
    v->valid = 1;
    v->no_cachable = 0;
    v->not_found = 0;

    v->data = ngx_palloc(r->pool, sizeof("65535") - 1);
    if (v->data == NULL) {
        return NGX_ERROR;
    }

    /* AF_INET only */

    if (r->connection->sockaddr->sa_family == AF_INET) {
        sin = (struct sockaddr_in *) r->connection->sockaddr;

        port = ntohs(sin->sin_port);

        if (port > 0 && port < 65536) {
            v->len = ngx_sprintf(v->data, "%ui", port) - v->data;
        }
    }

    return NGX_OK;
}


static ngx_int_t
ngx_http_variable_server_addr(ngx_http_request_t *r,
    ngx_http_variable_value_t *v, uintptr_t data)
{
    socklen_t            len;
    ngx_connection_t    *c;
    struct sockaddr_in   sin;

    v->data = ngx_palloc(r->pool, INET_ADDRSTRLEN);
    if (v->data == NULL) {
        return NGX_ERROR;
    }

    c = r->connection;

    if (r->in_addr == 0) {
        len = sizeof(struct sockaddr_in);
        if (getsockname(c->fd, (struct sockaddr *) &sin, &len) == -1) {
            ngx_log_error(NGX_LOG_CRIT, c->log,
                          ngx_socket_errno, "getsockname() failed");
            return NGX_ERROR;
        }

        r->in_addr = sin.sin_addr.s_addr;
    }

    v->len = ngx_inet_ntop(c->listening->family, &r->in_addr,
                           v->data, INET_ADDRSTRLEN);
    v->valid = 1;
    v->no_cachable = 0;
    v->not_found = 0;

    return NGX_OK;
}


static ngx_int_t
ngx_http_variable_server_port(ngx_http_request_t *r,
    ngx_http_variable_value_t *v, uintptr_t data)
{
    v->len = r->port_text->len - 1;
    v->valid = 1;
    v->no_cachable = 0;
    v->not_found = 0;
    v->data = r->port_text->data + 1;

    return NGX_OK;
}


static ngx_int_t
ngx_http_variable_document_root(ngx_http_request_t *r,
    ngx_http_variable_value_t *v, uintptr_t data)
{
    ngx_http_core_loc_conf_t  *clcf;

    clcf = ngx_http_get_module_loc_conf(r, ngx_http_core_module);

    v->len = clcf->root.len;
    v->valid = 1;
    v->no_cachable = 0;
    v->not_found = 0;
    v->data = clcf->root.data;

    return NGX_OK;
}


static ngx_int_t
ngx_http_variable_request_filename(ngx_http_request_t *r,
    ngx_http_variable_value_t *v, uintptr_t data)
{
    ngx_str_t  path;

    if (ngx_http_map_uri_to_path(r, &path, 0) == NULL) {
        return NGX_ERROR;
    }

    /* ngx_http_map_uri_to_path() allocates memory for terminating '\0' */

    v->len = path.len - 1;
    v->valid = 1;
    v->no_cachable = 0;
    v->not_found = 0;
    v->data = path.data;

    return NGX_OK;
}


static ngx_int_t
ngx_http_variable_request_method(ngx_http_request_t *r,
    ngx_http_variable_value_t *v, uintptr_t data)
{
    if (r->method_name.data) {
        if (r->upstream && r->upstream->method.len) {
            v->len = r->upstream->method.len;
            v->data = r->upstream->method.data;

        } else {
            v->len = r->method_name.len;
            v->data = r->method_name.data;
        }

        v->valid = 1;
        v->no_cachable = 0;
        v->not_found = 0;

    } else {
        v->not_found = 1;
    }

    return NGX_OK;
}


static ngx_int_t
ngx_http_variable_remote_user(ngx_http_request_t *r,
    ngx_http_variable_value_t *v, uintptr_t data)
{
    ngx_int_t  rc;

    rc = ngx_http_auth_basic_user(r);

    if (rc == NGX_DECLINED) {
        v->not_found = 1;
        return NGX_OK;
    }

    if (rc == NGX_ERROR) {
        return NGX_ERROR;
    }

    v->len = r->headers_in.user.len;
    v->valid = 1;
    v->no_cachable = 0;
    v->not_found = 0;
    v->data = r->headers_in.user.data;

    return NGX_OK;
}


ngx_int_t
ngx_http_variables_add_core_vars(ngx_conf_t *cf)
{
    ngx_http_variable_t        *v, *cv;
    ngx_http_core_main_conf_t  *cmcf;

    cmcf = ngx_http_conf_get_module_main_conf(cf, ngx_http_core_module);

    if (ngx_array_init(&cmcf->all_variables, cf->pool, 32,
                       sizeof(ngx_http_variable_t))
        == NGX_ERROR)
    {
        return NGX_ERROR;
    }

    for (cv = ngx_http_core_variables; cv->name.len; cv++) {
        v = ngx_array_push(&cmcf->all_variables);
        if (v == NULL) {
            return NGX_ERROR;
        }

        *v = *cv;
    }

    return NGX_OK;
}


ngx_int_t
ngx_http_variables_init_vars(ngx_conf_t *cf)
{
    ngx_uint_t                  i, n;
    ngx_http_variable_t        *v, *av;
    ngx_http_core_main_conf_t  *cmcf;

    /* set the handlers for the indexed http variables */

    cmcf = ngx_http_conf_get_module_main_conf(cf, ngx_http_core_module);

    v = cmcf->variables.elts;
    av = cmcf->all_variables.elts;

    for (i = 0; i < cmcf->variables.nelts; i++) {

        for (n = 0; n < cmcf->all_variables.nelts; n++) {

            if (v[i].name.len == av[n].name.len
                && ngx_strncmp(v[i].name.data, av[n].name.data, v[i].name.len)
                   == 0)
            {
                v[i].handler = av[n].handler;
                v[i].data = av[n].data;

                av[n].flags |= NGX_HTTP_VAR_INDEXED;
                v[i].flags = av[n].flags;

                av[n].index = i;

                goto next;
            }
        }

        if (ngx_strncmp(v[i].name.data, "http_", 5) == 0) {
            v[i].handler = ngx_http_variable_unknown_header_in;
            v[i].data = (uintptr_t) &v[i].name;

            continue;
        }

        if (ngx_strncmp(v[i].name.data, "sent_http_", 10) == 0) {
            v[i].handler = ngx_http_variable_unknown_header_out;
            v[i].data = (uintptr_t) &v[i].name;

            continue;
        }

        ngx_log_error(NGX_LOG_EMERG, cf->log, 0,
                      "unknown \"%V\" variable", &v[i].name);

        return NGX_ERROR;

    next:
        continue;
    }

    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, cf->log, 0,
                   "http variables: %ui", cmcf->variables.nelts);


    for (n = 0; n < cmcf->all_variables.nelts; n++) {
        if (av[n].flags & NGX_HTTP_VAR_NOHASH) {
            av[n].name.data = NULL;
        }
    }


    /* init the all http variables hash */

    cmcf->variables_hash.max_size = 500;
    cmcf->variables_hash.bucket_limit = 1;
    cmcf->variables_hash.bucket_size = sizeof(ngx_http_variable_t);
    cmcf->variables_hash.name = "http variables";

    if (ngx_hash_init(&cmcf->variables_hash, cf->pool,
                      cmcf->all_variables.elts, cmcf->all_variables.nelts)
        != NGX_OK)
    {
        return NGX_ERROR;
    }

    ngx_log_debug3(NGX_LOG_DEBUG_HTTP, cf->log, 0,
                   "http variables hash size: %ui for %ui values, "
                   "max buckets per entry: %ui",
                   cmcf->variables_hash.hash_size, cmcf->all_variables.nelts,
                   cmcf->variables_hash.min_buckets);

    return NGX_OK;
}
