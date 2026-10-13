
/*
 * Copyright (C) Nginx, Inc.
 */


#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>
#include <ngx_json_parse.h>


#define NGX_HTTP_JSON_DEFAULT_MAX_DEPTH       32

typedef struct {
    ngx_uint_t                     is_index;
    ngx_str_t                      key;
    ngx_uint_t                     index;
} ngx_http_json_seg_t;


typedef struct ngx_http_json_node_s  ngx_http_json_node_t;


struct ngx_http_json_node_s {
    ngx_http_json_seg_t            seg;
    ngx_array_t                   *children;  /* ngx_http_json_node_t */
    ngx_uint_t                    *dests;
    ngx_uint_t                     ndests;
};


typedef struct {
    ngx_int_t                      index;
    ngx_http_json_node_t          *root;
} ngx_http_json_source_t;


typedef struct {
    ngx_uint_t                     source_index;
} ngx_http_json_variable_t;


typedef struct {
    ngx_uint_t                     index;
    u_char                        *start;
    ngx_http_json_node_t          *node;
    ngx_uint_t                     is_array;
} ngx_http_json_frame_t;


typedef struct {
    ngx_int_t                      max_depth;
    ngx_array_t                   *sources;
    ngx_array_t                   *variables;
} ngx_http_json_main_conf_t;


typedef struct {
    ngx_http_request_t            *r;
    ngx_http_variable_value_t     *values;
    ngx_array_t                    stack;
    ngx_str_t                      current_key;
    ngx_http_json_node_t          *current_node;
    ngx_http_json_node_t          *root;
} ngx_http_json_state_t;


static char *ngx_http_json_set(ngx_conf_t *cf, ngx_command_t *cmd, void *conf);
static ngx_int_t ngx_http_json_variable(ngx_http_request_t *r,
    ngx_http_variable_value_t *v, uintptr_t data);
static void ngx_http_json_reset(ngx_http_variable_value_t *values,
    ngx_http_json_main_conf_t *jmcf, ngx_uint_t source_index);
static char *ngx_http_json_insert_path(ngx_conf_t *cf,
    ngx_http_json_node_t *root, ngx_uint_t dest, ngx_str_t *path);
static ngx_http_json_node_t *ngx_http_json_child(ngx_conf_t *cf,
    ngx_http_json_node_t *parent, ngx_http_json_seg_t *seg);
static ngx_int_t ngx_http_json_handler(ngx_json_ctx_t *ctx,
    ngx_json_event_e event, ngx_str_t *token);
static void ngx_http_json_inc_index(ngx_http_json_state_t *state);
static ngx_http_json_node_t *ngx_http_json_lookup_key(
    ngx_http_json_node_t *parent, ngx_str_t *key);
static ngx_http_json_node_t *ngx_http_json_lookup_index(
    ngx_http_json_node_t *parent, ngx_uint_t index);
static ngx_int_t ngx_http_json_store(ngx_http_json_state_t *state,
    ngx_http_json_node_t *node, ngx_str_t *value, ngx_uint_t unescape);
static ngx_int_t ngx_http_json_push(ngx_http_json_state_t *state,
    ngx_json_event_e event, u_char *start, ngx_http_json_node_t *node);
static void *ngx_http_json_create_main_conf(ngx_conf_t *cf);
static char *ngx_http_json_init_main_conf(ngx_conf_t *cf, void *conf);


static ngx_conf_num_bounds_t  ngx_http_json_max_depth_bounds = {
    ngx_conf_check_num_bounds, 1, 256
};


static ngx_command_t  ngx_http_json_commands[] = {

    { ngx_string("json_set"),
      NGX_HTTP_MAIN_CONF|NGX_CONF_TAKE3,
      ngx_http_json_set,
      NGX_HTTP_MAIN_CONF_OFFSET,
      0,
      NULL },

    { ngx_string("json_max_depth"),
      NGX_HTTP_MAIN_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_num_slot,
      NGX_HTTP_MAIN_CONF_OFFSET,
      offsetof(ngx_http_json_main_conf_t, max_depth),
      &ngx_http_json_max_depth_bounds },

      ngx_null_command
};


static ngx_http_module_t  ngx_http_json_module_ctx = {
    NULL,                            /* preconfiguration */
    NULL,                            /* postconfiguration */

    ngx_http_json_create_main_conf,  /* create main configuration */
    ngx_http_json_init_main_conf,    /* init main configuration */

    NULL,                            /* create server configuration */
    NULL,                            /* merge server configuration */

    NULL,                            /* create location configuration */
    NULL                             /* merge location configuration */
};


ngx_module_t  ngx_http_json_module = {
    NGX_MODULE_V1,
    &ngx_http_json_module_ctx,       /* module context */
    ngx_http_json_commands,          /* module directives */
    NGX_HTTP_MODULE,                 /* module type */
    NULL,                            /* init master */
    NULL,                            /* init module */
    NULL,                            /* init process */
    NULL,                            /* init thread */
    NULL,                            /* exit thread */
    NULL,                            /* exit process */
    NULL,                            /* exit master */
    NGX_MODULE_V1_PADDING
};


static char *
ngx_http_json_set(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    ngx_http_json_main_conf_t  *jmcf = conf;

    ngx_str_t                 *value, name, source;
    ngx_int_t                  sindex;
    ngx_uint_t                 i, oi, si;
    ngx_http_variable_t       *var;
    ngx_http_json_source_t    *src, *srcs;
    ngx_http_json_variable_t  *jv;

    value = cf->args->elts;

    name = value[1];

    if (name.data[0] != '$') {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                           "invalid variable name \"%V\"", &name);
        return NGX_CONF_ERROR;
    }

    name.len--;
    name.data++;

    var = ngx_http_add_variable(cf, &name, NGX_HTTP_VAR_CHANGEABLE);
    if (var == NULL) {
        return NGX_CONF_ERROR;
    }

    if (var->get_handler == ngx_http_json_variable) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                           "json_set variable \"%V\" is already defined",
                           &name);
        return NGX_CONF_ERROR;
    }

    source = value[2];

    if (source.data[0] != '$') {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                           "invalid variable name \"%V\"", &source);
        return NGX_CONF_ERROR;
    }

    source.len--;
    source.data++;

    sindex = ngx_http_get_variable_index(cf, &source);
    if (sindex == NGX_ERROR) {
        return NGX_CONF_ERROR;
    }

    if (jmcf->sources == NULL) {
        jmcf->sources = ngx_array_create(cf->pool, 4,
                                         sizeof(ngx_http_json_source_t));
        if (jmcf->sources == NULL) {
            return NGX_CONF_ERROR;
        }
    }

    srcs = jmcf->sources->elts;
    si = jmcf->sources->nelts;

    for (i = 0; i < jmcf->sources->nelts; i++) {
        if (srcs[i].index == sindex) {
            si = i;
            break;
        }
    }

    if (si == jmcf->sources->nelts) {
        src = ngx_array_push(jmcf->sources);
        if (src == NULL) {
            return NGX_CONF_ERROR;
        }

        src->index = sindex;

        src->root = ngx_pcalloc(cf->pool, sizeof(ngx_http_json_node_t));
        if (src->root == NULL) {
            return NGX_CONF_ERROR;
        }

    } else {
        src = &srcs[si];
    }

    if (jmcf->variables == NULL) {
        jmcf->variables = ngx_array_create(cf->pool, 4,
                                           sizeof(ngx_http_json_variable_t));
        if (jmcf->variables == NULL) {
            return NGX_CONF_ERROR;
        }
    }

    oi = jmcf->variables->nelts;

    jv = ngx_array_push(jmcf->variables);
    if (jv == NULL) {
        return NGX_CONF_ERROR;
    }

    jv->source_index = si;

    if (ngx_http_json_insert_path(cf, src->root, oi, &value[3])
        != NGX_CONF_OK)
    {
        return NGX_CONF_ERROR;
    }

    var->get_handler = ngx_http_json_variable;
    var->data = (uintptr_t) oi;

    return NGX_CONF_OK;
}


static ngx_int_t
ngx_http_json_variable(ngx_http_request_t *r, ngx_http_variable_value_t *v,
    uintptr_t data)
{
    ngx_int_t                   rc;
    ngx_uint_t                  oi, si;
    ngx_json_ctx_t              jctx;
    ngx_http_json_state_t       state;
    ngx_http_json_source_t     *src, *srcs;
    ngx_http_json_variable_t   *jv;
    ngx_http_variable_value_t  *cached, *values, *vv;
    ngx_http_json_main_conf_t  *jmcf;

    oi = (ngx_uint_t) data;

    jmcf = ngx_http_get_module_main_conf(r, ngx_http_json_module);

    if (jmcf->variables == NULL || oi >= jmcf->variables->nelts) {
        v->not_found = 1;
        return NGX_OK;
    }

    values = ngx_http_get_module_ctx(r, ngx_http_json_module);

    if (values == NULL) {
        values = ngx_pcalloc(r->pool, jmcf->variables->nelts
                             * sizeof(ngx_http_variable_value_t));
        if (values == NULL) {
            return NGX_ERROR;
        }

        ngx_http_set_ctx(r, values, ngx_http_json_module);
    }

    cached = &values[oi];

    if (cached->valid || cached->not_found) {
        *v = *cached;
        return NGX_OK;
    }

    jv = jmcf->variables->elts;
    si = jv[oi].source_index;

    srcs = jmcf->sources->elts;
    src = &srcs[si];

    vv = ngx_http_get_flushed_variable(r, (ngx_uint_t) src->index);

    if (vv == NULL) {
        return NGX_ERROR;
    }

    ngx_http_json_reset(values, jmcf, si);

    if (vv->not_found || vv->len == 0) {
        *v = *cached;
        return NGX_OK;
    }

    ngx_memzero(&state, sizeof(ngx_http_json_state_t));

    state.r = r;
    state.values = values;
    state.root = src->root;

    if (ngx_array_init(&state.stack, r->pool, 8, sizeof(ngx_http_json_frame_t))
        != NGX_OK)
    {
        return NGX_ERROR;
    }

    ngx_json_ctx_init(&jctx, r->pool);

    jctx.handler = ngx_http_json_handler;
    jctx.data = &state;
    jctx.max_depth = jmcf->max_depth;

    rc = ngx_json_parse_ctx(&jctx, vv->data, vv->len);

    if (rc == NGX_OK) {
        *v = *cached;
        return NGX_OK;
    }

    ngx_http_json_reset(values, jmcf, si);

    if (rc == NGX_DECLINED) {
        ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                       "json_set: invalid JSON source");
    }

    if (rc == NGX_ERROR) {
        return NGX_ERROR;
    }

    *v = *cached;

    return NGX_OK;
}


static void
ngx_http_json_reset(ngx_http_variable_value_t *values,
    ngx_http_json_main_conf_t *jmcf, ngx_uint_t source_index)
{
    ngx_uint_t                 i;
    ngx_http_json_variable_t  *jv;

    jv = jmcf->variables->elts;

    for (i = 0; i < jmcf->variables->nelts; i++) {
        if (jv[i].source_index != source_index) {
            continue;
        }

        values[i].valid = 0;
        values[i].not_found = 1;
    }
}


static char *
ngx_http_json_insert_path(ngx_conf_t *cf, ngx_http_json_node_t *root,
    ngx_uint_t dest, ngx_str_t *path)
{
    u_char                *p, *last, *start, *dst;
    ngx_int_t              index;
    ngx_uint_t            *term;
    ngx_http_json_seg_t    seg;
    ngx_http_json_node_t  *node;
    enum {
        sw_start = 0,
        sw_key,
        sw_dot,
        sw_bracket,
        sw_index,
        sw_quoted,
        sw_quoted_escape,
        sw_quoted_close,
        sw_after_bracket
    } state;

    if (path->len == 0) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0, "empty json_set path");
        return NGX_CONF_ERROR;
    }

    node = root;
    start = NULL;

    last = path->data + path->len;
    state = sw_start;

    for (p = path->data; p < last; p++) {

        switch (state) {

        case sw_start:

            if (*p == '[') {
                state = sw_bracket;
                break;
            }

            if (*p == '.' || *p == '$') {
                goto invalid;
            }

            start = p;
            state = sw_key;
            break;

        case sw_key:

            if (*p == '.' || *p == '[') {

                seg.is_index = 0;
                seg.key.data = start;
                seg.key.len = p - start;
                seg.index = 0;

                node = ngx_http_json_child(cf, node, &seg);
                if (node == NULL) {
                    return NGX_CONF_ERROR;
                }

                state = (*p == '.') ? sw_dot : sw_bracket;
            }

            break;

        case sw_dot:

            if (*p == '.' || *p == '[' || *p == '$') {
                goto invalid;
            }

            start = p;
            state = sw_key;
            break;

        case sw_bracket:

            if (*p == '"') {
                start = p + 1;
                state = sw_quoted;
                break;
            }

            if (*p >= '0' && *p <= '9') {
                start = p;
                state = sw_index;
                break;
            }

            goto invalid;

        case sw_index:

            if (*p >= '0' && *p <= '9') {
                break;
            }

            if (*p != ']') {
                goto invalid;
            }

            index = ngx_atoi(start, p - start);
            if (index == NGX_ERROR) {
                goto invalid;
            }

            seg.is_index = 1;
            seg.index = index;
            ngx_str_null(&seg.key);

            node = ngx_http_json_child(cf, node, &seg);
            if (node == NULL) {
                return NGX_CONF_ERROR;
            }

            state = sw_after_bracket;
            break;

        case sw_quoted:

            if (*p == '\\') {
                state = sw_quoted_escape;
                break;
            }

            if (*p == '"') {

                dst = ngx_pnalloc(cf->pool, (size_t) (p - start));
                if (dst == NULL) {
                    return NGX_CONF_ERROR;
                }

                ngx_memcpy(dst, start, p - start);

                seg.is_index = 0;
                seg.key.data = dst;
                seg.key.len = p - start;
                seg.index = 0;

                if (ngx_json_unescape_string(&seg.key) != NGX_OK) {
                    goto invalid;
                }

                node = ngx_http_json_child(cf, node, &seg);
                if (node == NULL) {
                    return NGX_CONF_ERROR;
                }

                state = sw_quoted_close;
            }

            break;

        case sw_quoted_escape:

            state = sw_quoted;
            break;

        case sw_quoted_close:

            if (*p != ']') {
                goto invalid;
            }

            state = sw_after_bracket;
            break;

        case sw_after_bracket:

            if (*p == '.') {
                state = sw_dot;
                break;
            }

            if (*p == '[') {
                state = sw_bracket;
                break;
            }

            goto invalid;
        }
    }

    switch (state) {

    case sw_key:

        seg.is_index = 0;
        seg.key.data = start;
        seg.key.len = last - start;
        seg.index = 0;

        node = ngx_http_json_child(cf, node, &seg);
        if (node == NULL) {
            return NGX_CONF_ERROR;
        }

        break;

    case sw_after_bracket:
        break;

    default:
        goto invalid;
    }

    term = ngx_palloc(cf->pool, (node->ndests + 1) * sizeof(ngx_uint_t));
    if (term == NULL) {
        return NGX_CONF_ERROR;
    }

    if (node->ndests) {
        ngx_memcpy(term, node->dests, node->ndests * sizeof(ngx_uint_t));
    }

    term[node->ndests] = dest;
    node->dests = term;
    node->ndests++;

    return NGX_CONF_OK;

invalid:

    ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                       "invalid json_set path \"%V\"", path);
    return NGX_CONF_ERROR;
}


static ngx_http_json_node_t *
ngx_http_json_child(ngx_conf_t *cf, ngx_http_json_node_t *parent,
    ngx_http_json_seg_t *seg)
{
    ngx_uint_t             i;
    ngx_http_json_seg_t   *cseg;
    ngx_http_json_node_t  *child, *elts;

    if (parent->children != NULL) {
        elts = parent->children->elts;

        for (i = 0; i < parent->children->nelts; i++) {
            child = &elts[i];
            cseg = &child->seg;

            if (seg->is_index) {
                if (cseg->is_index && cseg->index == seg->index) {
                    return child;
                }

            } else {
                if (!cseg->is_index
                    && cseg->key.len == seg->key.len
                    && ngx_memcmp(cseg->key.data, seg->key.data, seg->key.len)
                       == 0)
                {
                    return child;
                }
            }
        }

    } else {
        parent->children = ngx_array_create(cf->pool, 1,
                                            sizeof(ngx_http_json_node_t));
        if (parent->children == NULL) {
            return NULL;
        }
    }

    child = ngx_array_push(parent->children);
    if (child == NULL) {
        return NULL;
    }

    ngx_memzero(child, sizeof(ngx_http_json_node_t));

    child->seg = *seg;

    return child;
}


static ngx_int_t
ngx_http_json_handler(ngx_json_ctx_t *ctx, ngx_json_event_e event,
    ngx_str_t *token)
{
    ngx_str_t               slice, value;
    ngx_uint_t              is_member;
    ngx_http_json_node_t   *node;
    ngx_http_json_state_t  *state;
    ngx_http_json_frame_t  *top;

    state = ctx->data;

    top = NULL;
    if (state->stack.nelts) {
        top = (ngx_http_json_frame_t *) state->stack.elts
              + state->stack.nelts - 1;
    }

    switch (event) {

    case NGX_JSON_OBJECT_OPEN:
    case NGX_JSON_ARRAY_OPEN:

        if (state->stack.nelts == 0) {

            ngx_str_null(&state->current_key);
            state->current_node = NULL;

            return ngx_http_json_push(state, event, token->data, state->root);
        }

        is_member = (state->current_key.data != NULL);
        ngx_str_null(&state->current_key);

        if (is_member) {

            node = state->current_node;
            state->current_node = NULL;

        } else {

            node = ngx_http_json_lookup_index(top->node, top->index);

            ngx_http_json_inc_index(state);

            if (node == NULL) {
                return NGX_JSON_SKIP;
            }
        }

        return ngx_http_json_push(state, event, token->data, node);

    case NGX_JSON_OBJECT_CLOSE:
    case NGX_JSON_ARRAY_CLOSE:

        if (top != NULL) {

            if (top->node->ndests > 0) {
                slice.data = top->start;
                slice.len = token->data - top->start + 1;

                if (ngx_http_json_store(state, top->node, &slice, 0)
                    != NGX_OK)
                {
                    return NGX_ERROR;
                }
            }

            state->stack.nelts--;
        }

        break;

    case NGX_JSON_KEY:

        if (ngx_strlchr(token->data, token->data + token->len, '\\') == NULL) {
            state->current_key = *token;

        } else {
            state->current_key.data = ngx_pstrdup(ctx->pool, token);
            if (state->current_key.data == NULL) {
                return NGX_ERROR;
            }

            state->current_key.len = token->len;

            if (ngx_json_unescape_string(&state->current_key) != NGX_OK) {
                return NGX_ERROR;
            }
        }

        node = ngx_http_json_lookup_key(top->node, &state->current_key);
        if (node == NULL) {
            ngx_str_null(&state->current_key);
            state->current_node = NULL;
            return NGX_JSON_SKIP;
        }

        state->current_node = node;

        break;

    case NGX_JSON_VALUE_STRING:
    case NGX_JSON_VALUE_NUMBER:
    case NGX_JSON_VALUE_BOOL:
    case NGX_JSON_VALUE_NULL:

        if (top == NULL) {
            ngx_str_null(&state->current_key);
            state->current_node = NULL;
            break;
        }

        is_member = (state->current_key.data != NULL);
        ngx_str_null(&state->current_key);

        if (is_member) {

            node = state->current_node;
            state->current_node = NULL;

        } else {

            node = ngx_http_json_lookup_index(top->node, top->index);

            ngx_http_json_inc_index(state);
        }

        if (node != NULL && node->ndests > 0) {

            value = *token;

            if (ngx_http_json_store(state, node, &value,
                                          event == NGX_JSON_VALUE_STRING)
                != NGX_OK)
            {
                return NGX_ERROR;
            }
        }

        break;
    }

    return NGX_OK;
}


static void
ngx_http_json_inc_index(ngx_http_json_state_t *state)
{
    ngx_http_json_frame_t  *top;

    if (state->stack.nelts == 0) {
        return;
    }

    top = state->stack.elts;
    top += state->stack.nelts - 1;

    if (top->is_array) {
        top->index++;
    }
}


static ngx_http_json_node_t *
ngx_http_json_lookup_key(ngx_http_json_node_t *parent, ngx_str_t *key)
{
    ngx_uint_t             i;
    ngx_http_json_seg_t   *seg;
    ngx_http_json_node_t  *child, *elts;

    if (parent->children == NULL) {
        return NULL;
    }

    elts = parent->children->elts;

    for (i = 0; i < parent->children->nelts; i++) {
        child = &elts[i];
        seg = &child->seg;

        if (!seg->is_index
            && seg->key.len == key->len
            && ngx_memcmp(seg->key.data, key->data, key->len) == 0)
        {
            return child;
        }
    }

    return NULL;
}


static ngx_http_json_node_t *
ngx_http_json_lookup_index(ngx_http_json_node_t *parent, ngx_uint_t index)
{
    ngx_uint_t             i;
    ngx_http_json_seg_t   *seg;
    ngx_http_json_node_t  *child, *elts;

    if (parent->children == NULL) {
        return NULL;
    }

    elts = parent->children->elts;

    for (i = 0; i < parent->children->nelts; i++) {
        child = &elts[i];
        seg = &child->seg;

        if (seg->is_index && seg->index == index) {
            return child;
        }
    }

    return NULL;
}


static ngx_int_t
ngx_http_json_store(ngx_http_json_state_t *state, ngx_http_json_node_t *node,
    ngx_str_t *value, ngx_uint_t unescape)
{
    ngx_str_t                   val;
    ngx_uint_t                  i;
    ngx_http_variable_value_t  *slot;

    if (value->len == 0) {
        val.len = 0;
        val.data = (u_char *) "";

    } else {
        val.data = ngx_pstrdup(state->r->pool, value);
        if (val.data == NULL) {
            return NGX_ERROR;
        }

        val.len = value->len;

        if (unescape && ngx_json_unescape_string(&val) != NGX_OK) {
            return NGX_ERROR;
        }
    }

    for (i = 0; i < node->ndests; i++) {
        slot = &state->values[node->dests[i]];
        slot->valid = 1;
        slot->not_found = 0;
        slot->no_cacheable = 0;
        slot->escape = 0;
        slot->len = val.len;
        slot->data = val.data;
    }

    return NGX_OK;
}


static ngx_int_t
ngx_http_json_push(ngx_http_json_state_t *state, ngx_json_event_e event,
    u_char *start, ngx_http_json_node_t *node)
{
    ngx_http_json_frame_t  *frame;

    frame = ngx_array_push(&state->stack);
    if (frame == NULL) {
        return NGX_ERROR;
    }

    frame->index = 0;
    frame->start = start;
    frame->is_array = (event == NGX_JSON_ARRAY_OPEN);
    frame->node = node;

    return NGX_OK;
}


static void *
ngx_http_json_create_main_conf(ngx_conf_t *cf)
{
    ngx_http_json_main_conf_t  *jmcf;

    jmcf = ngx_pcalloc(cf->pool, sizeof(ngx_http_json_main_conf_t));
    if (jmcf == NULL) {
        return NULL;
    }

    jmcf->max_depth = NGX_CONF_UNSET;

    return jmcf;
}


static char *
ngx_http_json_init_main_conf(ngx_conf_t *cf, void *conf)
{
    ngx_http_json_main_conf_t  *jmcf = conf;

    ngx_conf_init_value(jmcf->max_depth, NGX_HTTP_JSON_DEFAULT_MAX_DEPTH);

    return NGX_CONF_OK;
}
