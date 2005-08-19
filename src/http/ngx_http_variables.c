
/*
 * Copyright (C) Igor Sysoev
 */


#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_event.h>
#include <ngx_http.h>


static ngx_http_variable_value_t *
    ngx_http_variable_request(ngx_http_request_t *r, uintptr_t data);
static ngx_http_variable_value_t *
    ngx_http_variable_header(ngx_http_request_t *r, uintptr_t data);
static ngx_http_variable_value_t *
    ngx_http_variable_headers(ngx_http_request_t *r, uintptr_t data);
static ngx_http_variable_value_t *
    ngx_http_variable_unknown_header(ngx_http_request_t *r, uintptr_t data);
static ngx_http_variable_value_t *
    ngx_http_variable_host(ngx_http_request_t *r, uintptr_t data);
static ngx_http_variable_value_t *
    ngx_http_variable_remote_addr(ngx_http_request_t *r, uintptr_t data);
static ngx_http_variable_value_t *
    ngx_http_variable_remote_port(ngx_http_request_t *r, uintptr_t data);
static ngx_http_variable_value_t *
    ngx_http_variable_server_addr(ngx_http_request_t *r, uintptr_t data);
static ngx_http_variable_value_t *
    ngx_http_variable_server_port(ngx_http_request_t *r, uintptr_t data);
static ngx_http_variable_value_t *
    ngx_http_variable_document_root(ngx_http_request_t *r, uintptr_t data);
static ngx_http_variable_value_t *
    ngx_http_variable_request_filename(ngx_http_request_t *r, uintptr_t data);


/*
 * TODO:
 *     Apache CGI: AUTH_TYPE, PATH_INFO (null), PATH_TRANSLATED
 *                 REMOTE_HOST (null), REMOTE_IDENT (null),
 *                 SERVER_SOFTWARE
 *
 *     Apache SSI: DATE_GMT, DOCUMENT_NAME, LAST_MODIFIED,
 *                 USER_NAME (file owner)
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

    { ngx_string("document_uri"), ngx_http_variable_request,
      offsetof(ngx_http_request_t, uri), 0, 0 },

    { ngx_string("document_root"), ngx_http_variable_document_root, 0, 0, 0 },

    { ngx_string("query_string"), ngx_http_variable_request,
      offsetof(ngx_http_request_t, args),
      NGX_HTTP_VAR_NOCACHABLE, 0 },

    { ngx_string("request_filename"), ngx_http_variable_request_filename, 0,
      NGX_HTTP_VAR_NOCACHABLE, 0 },

    { ngx_string("server_name"), ngx_http_variable_request,
      offsetof(ngx_http_request_t, server_name), 0, 0 },

    { ngx_string("request_method"), ngx_http_variable_request,
      offsetof(ngx_http_request_t, method_name), 0, 0 },

    { ngx_string("remote_user"), ngx_http_variable_request,
      offsetof(ngx_http_request_t, headers_in.user), 0, 0 },

    { ngx_null_string, NULL, 0, 0, 0 }
};


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
    ngx_http_variable_value_t  *vv;
    ngx_http_core_main_conf_t  *cmcf;

    cmcf = ngx_http_get_module_main_conf(r, ngx_http_core_module);

    if (cmcf->variables.elts == NULL || cmcf->variables.nelts <= index) {
        ngx_log_error(NGX_LOG_ALERT, r->connection->log, 0,
                      "unknown variable index: %d", index);
        return NULL;
    }

    if (r->variables && r->variables[index]) {
        return r->variables[index];
    }

    v = cmcf->variables.elts;

    vv = v[index].handler(r, v[index].data);

    if (r->variables == NULL) {
        r->variables = ngx_pcalloc(r->pool, cmcf->variables.nelts
                                        * sizeof(ngx_http_variable_value_t *));
        if (r->variables == NULL) {
            return NULL;
        }
    }

    if (!(v[index].flags & NGX_HTTP_VAR_NOCACHABLE)) {
        r->variables[index] = vv;
    }

    return vv;
}


ngx_http_variable_value_t *
ngx_http_get_variable(ngx_http_request_t *r, ngx_str_t *name)
{
    ngx_uint_t                  i, key;
    ngx_http_variable_t        *v;
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
            return v[key].handler(r, v[key].data);
        }
    }

    if (ngx_strncmp(name->data, "http_", 5) == 0) {
        return ngx_http_variable_unknown_header(r, (uintptr_t) name);
    }

    ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                  "unknown \"%V\" variable", name);

    return NGX_HTTP_VAR_NOT_FOUND;
}


static ngx_http_variable_value_t *
ngx_http_variable_request(ngx_http_request_t *r, uintptr_t data)
{
    ngx_str_t                  *s;
    ngx_http_variable_value_t  *vv;

    s = (ngx_str_t *) ((char *) r + data);

    if (s->data == NULL) {
        return NGX_HTTP_VAR_NOT_FOUND;
    }

    vv = ngx_palloc(r->pool, sizeof(ngx_http_variable_value_t));
    if (vv == NULL) {
        return NULL;
    }

    vv->value = 0;
    vv->text = *s;

    return vv;
}


static ngx_http_variable_value_t *
ngx_http_variable_header(ngx_http_request_t *r, uintptr_t data)
{
    ngx_table_elt_t            *h;
    ngx_http_variable_value_t  *vv;

    h = *(ngx_table_elt_t **) ((char *) r + data);

    if (h == NULL) {
        return NGX_HTTP_VAR_NOT_FOUND;
    }

    vv = ngx_palloc(r->pool, sizeof(ngx_http_variable_value_t));
    if (vv == NULL) {
        return NULL;
    }

    vv->value = 0;
    vv->text = h->value;

    return vv;
}


static ngx_http_variable_value_t *
ngx_http_variable_headers(ngx_http_request_t *r, uintptr_t data)
{
    u_char                      *p;
    ngx_uint_t                   i;
    ngx_array_t                 *a;
    ngx_table_elt_t            **h;
    ngx_http_variable_value_t   *vv;

    a = (ngx_array_t *) ((char *) r + data);

    if (a->nelts == 0) {
        return NGX_HTTP_VAR_NOT_FOUND;
    }

    vv = ngx_palloc(r->pool, sizeof(ngx_http_variable_value_t));
    if (vv == NULL) {
        return NULL;
    }

    vv->value = 0;

    h = a->elts;

    if (a->nelts == 1) {
        vv->text = (*h)->value;
        return vv;
    }

    vv->text.len = (size_t) - (ssize_t) (sizeof("; ") - 1);

    for (i = 0; i < a->nelts; i++) {
        vv->text.len += h[i]->value.len + sizeof("; ") - 1;
    }

    vv->text.data = ngx_palloc(r->pool, vv->text.len);
    if (vv->text.data == NULL) {
        return NULL;
    }

    p = vv->text.data;

    for (i = 0; /* void */ ; i++) {
        p = ngx_cpymem(p, h[i]->value.data, h[i]->value.len);

        if (i == a->nelts - 1) {
            break;
        }

        *p++ = ';'; *p++ = ' ';
    }

    return vv;
}


static ngx_http_variable_value_t *
ngx_http_variable_unknown_header(ngx_http_request_t *r, uintptr_t data)
{
    ngx_str_t  *var = (ngx_str_t *) data;

    u_char                      ch;
    ngx_uint_t                  i, n;
    ngx_list_part_t            *part;
    ngx_table_elt_t            *header;
    ngx_http_variable_value_t  *vv;

    part = &r->headers_in.headers.part;
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

        for (n = 0; n + 5 < var->len && n < header[i].key.len; n++) {
            ch = header[i].key.data[n];

            if (ch >= 'A' && ch <= 'Z') {
                ch |= 0x20;

            } else if (ch == '-') {
                ch = '_';
            }

            if (var->data[n + 5] != ch) {
                break;
            }
        }

        if (n + 5 == var->len) {
            vv = ngx_palloc(r->pool, sizeof(ngx_http_variable_value_t));
            if (vv == NULL) {
                return NULL;
            }

            vv->value = 0;
            vv->text = header[i].value;
            return vv;
        }
    }

    return NGX_HTTP_VAR_NOT_FOUND;
}


static ngx_http_variable_value_t *
ngx_http_variable_host(ngx_http_request_t *r, uintptr_t data)
{
    ngx_http_variable_value_t  *vv;

    vv = ngx_palloc(r->pool, sizeof(ngx_http_variable_value_t));
    if (vv == NULL) {
        return NULL;
    }

    vv->value = 0;

    if (r->headers_in.host) {
        vv->text.len = r->headers_in.host_name_len;
        vv->text.data = r->headers_in.host->value.data;

    } else {
        vv->text = r->server_name;
    }

    return vv;
}


static ngx_http_variable_value_t *
ngx_http_variable_remote_addr(ngx_http_request_t *r, uintptr_t data)
{
    ngx_http_variable_value_t  *vv;

    vv = ngx_palloc(r->pool, sizeof(ngx_http_variable_value_t));
    if (vv == NULL) {
        return NULL;
    }

    vv->value = 0;
    vv->text = r->connection->addr_text;

    return vv;
}


static ngx_http_variable_value_t *
ngx_http_variable_remote_port(ngx_http_request_t *r, uintptr_t data)
{
    ngx_uint_t                  port;
    struct sockaddr_in         *sin;
    ngx_http_variable_value_t  *vv;

    vv = ngx_palloc(r->pool, sizeof(ngx_http_variable_value_t));
    if (vv == NULL) {
        return NULL;
    }

    vv->value = 0;
    vv->text.len = 0;

    vv->text.data = ngx_palloc(r->pool, sizeof("65535") - 1);
    if (vv->text.data == NULL) {
        return NULL;
    }

    /* AF_INET only */
    
    if (r->connection->sockaddr->sa_family == AF_INET) {
        sin = (struct sockaddr_in *) r->connection->sockaddr;
    
        port = ntohs(sin->sin_port);
                             
        if (port > 0 && port < 65536) {
            vv->value = port;
            vv->text.len = ngx_sprintf(vv->text.data, "%ui", port)
                           - vv->text.data;
        }
    }

    return vv;
}


static ngx_http_variable_value_t *
ngx_http_variable_server_addr(ngx_http_request_t *r, uintptr_t data)
{
    socklen_t                   len;
    ngx_connection_t           *c;
    struct sockaddr_in          sin;
    ngx_http_variable_value_t  *vv;

    vv = ngx_palloc(r->pool, sizeof(ngx_http_variable_value_t));
    if (vv == NULL) {
        return NULL;
    }

    vv->value = 0;

    vv->text.data = ngx_palloc(r->pool, INET_ADDRSTRLEN);
    if (vv->text.data == NULL) {
        return NULL;
    }

    c = r->connection;

    if (r->in_addr == 0) {
        len = sizeof(struct sockaddr_in);
        if (getsockname(c->fd, (struct sockaddr *) &sin, &len) == -1) {
            ngx_log_error(NGX_LOG_CRIT, c->log,
                          ngx_socket_errno, "getsockname() failed");
            return NULL;
        }

        r->in_addr = sin.sin_addr.s_addr;
    }

    vv->text.len = ngx_inet_ntop(c->listening->family, &r->in_addr,
                                 vv->text.data, INET_ADDRSTRLEN);

    return vv;
}


static ngx_http_variable_value_t *
ngx_http_variable_server_port(ngx_http_request_t *r, uintptr_t data)
{
    ngx_http_variable_value_t  *vv;

    vv = ngx_palloc(r->pool, sizeof(ngx_http_variable_value_t));
    if (vv == NULL) {
        return NULL;
    }

    vv->value = r->port;
    vv->text.len = r->port_text->len - 1;
    vv->text.data = r->port_text->data + 1;

    return vv;
}


static ngx_http_variable_value_t *
ngx_http_variable_document_root(ngx_http_request_t *r, uintptr_t data)
{
    ngx_http_core_loc_conf_t   *clcf;
    ngx_http_variable_value_t  *vv;

    vv = ngx_palloc(r->pool, sizeof(ngx_http_variable_value_t));
    if (vv == NULL) {
        return NULL;
    }

    clcf = ngx_http_get_module_loc_conf(r, ngx_http_core_module);

    vv->value = 0;
    vv->text = clcf->root;

    return vv;
}


static ngx_http_variable_value_t *
ngx_http_variable_request_filename(ngx_http_request_t *r, uintptr_t data)
{
    u_char                     *p;
    ngx_http_core_loc_conf_t   *clcf;
    ngx_http_variable_value_t  *vv;

    vv = ngx_palloc(r->pool, sizeof(ngx_http_variable_value_t));
    if (vv == NULL) {
        return NULL;
    }

    vv->value = 0;

    clcf = ngx_http_get_module_loc_conf(r, ngx_http_core_module);

    if (!clcf->alias) {
        vv->text.len = clcf->root.len + r->uri.len;
        vv->text.data = ngx_palloc(r->pool, vv->text.len);
        if (vv->text.data == NULL) {
            return NULL;
        }

        p = ngx_cpymem(vv->text.data, clcf->root.data, clcf->root.len);
        ngx_memcpy(p, r->uri.data, r->uri.len + 1);

    } else {
        vv->text.len = clcf->root.len + r->uri.len + 2 - clcf->name.len;
        vv->text.data = ngx_palloc(r->pool, vv->text.len);
        if (vv->text.data == NULL) {
            return NULL;
        }

        p = ngx_cpymem(vv->text.data, clcf->root.data, clcf->root.len);
        ngx_memcpy(p, r->uri.data + clcf->name.len,
                   r->uri.len + 1 - clcf->name.len);
    }

    return vv;
}


ngx_int_t
ngx_http_variables_add_core_vars(ngx_conf_t *cf)
{
    ngx_http_variable_t        *v, *cv;
    ngx_http_core_main_conf_t  *cmcf;

    cmcf = ngx_http_conf_get_module_main_conf(cf, ngx_http_core_module);

    if (ngx_array_init(&cmcf->all_variables, cf->pool, 32,
                       sizeof(ngx_http_variable_t)) == NGX_ERROR)
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
            v[i].handler = ngx_http_variable_unknown_header;
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


    /* init the all http variables hash */

    cmcf->variables_hash.max_size = 500;
    cmcf->variables_hash.bucket_limit = 1;
    cmcf->variables_hash.bucket_size = sizeof(ngx_http_variable_t);
    cmcf->variables_hash.name = "http variables";

    if (ngx_hash_init(&cmcf->variables_hash, cf->pool,
            cmcf->all_variables.elts, cmcf->all_variables.nelts) != NGX_OK)
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
