
/*
 * Copyright (C) Igor Sysoev
 */


#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>



static ngx_http_module_t  ngx_http_cache_module_ctx = {
    NULL,                                  /* pre conf */

    NULL,                                  /* create main configuration */
    NULL,                                  /* init main configuration */

    NULL,                                  /* create server configuration */
    NULL,                                  /* merge server configuration */

    NULL,                                  /* create location configuration */
    NULL                                   /* merge location configuration */
};


ngx_module_t  ngx_http_cache_module = {
    NGX_MODULE,
    &ngx_http_cache_module_ctx,            /* module context */
    NULL,                                  /* module directives */
    NGX_HTTP_MODULE,                       /* module type */
    NULL,                                  /* init module */
    NULL                                   /* init child */
};


ngx_http_cache_t *ngx_http_cache_get(ngx_http_cache_hash_t *hash,
                                     ngx_http_cleanup_t *cleanup,
                                     ngx_str_t *key, uint32_t *crc)
{
    ngx_uint_t         i;
    ngx_http_cache_t  *c;

    *crc = ngx_crc(key->data, key->len);

    c = hash->elts + *crc % hash->hash * hash->nelts;

    if (ngx_mutex_lock(&hash->mutex) == NGX_ERROR) {
        return (void *) NGX_ERROR;
    }

    for (i = 0; i < hash->nelts; i++) {
        if (c[i].crc == *crc
            && c[i].key.len == key->len
            && ngx_rstrncmp(c[i].key.data, key->data, key->len) == 0)
        {
#if 0
            if (c[i].expired) {
                ngx_mutex_unlock(&hash->mutex);
                return (void *) NGX_AGAIN;
            }
#endif

            c[i].refs++;

            if ((!(c[i].notify && (ngx_event_flags & NGX_HAVE_KQUEUE_EVENT)))
                && (ngx_cached_time - c[i].updated >= hash->update))
            {
                c[i].expired = 1;
            }

            ngx_mutex_unlock(&hash->mutex);

            if (cleanup) {
                cleanup->data.cache.hash = hash;
                cleanup->data.cache.cache = &c[i];
                cleanup->valid = 1;
                cleanup->cache = 1;
            }

            return &c[i];
        }
    }

    ngx_mutex_unlock(&hash->mutex);

    return NULL;
}


ngx_http_cache_t *ngx_http_cache_alloc(ngx_http_cache_hash_t *hash,
                                       ngx_http_cache_t *cache,
                                       ngx_http_cleanup_t *cleanup,
                                       ngx_str_t *key, uint32_t crc,
                                       ngx_str_t *value, ngx_log_t *log)
{
    time_t             old;
    ngx_uint_t         i;
    ngx_http_cache_t  *c;

    old = ngx_cached_time + 1;

    c = hash->elts + crc % hash->hash * hash->nelts;

    if (ngx_mutex_lock(&hash->mutex) == NGX_ERROR) {
        return (void *) NGX_ERROR;
    }

    if (cache == NULL) {

        /* allocate a new entry */

        for (i = 0; i < hash->nelts; i++) {
            if (c[i].refs > 0) {
                /* a busy entry */
                continue;
            }

            if (c[i].key.len == 0) {
                /* a free entry is found */
                cache = &c[i];
                break;
            }

            /* looking for the oldest cache entry */

            if (old > c[i].accessed) {

                old = c[i].accessed;
                cache = &c[i];
            }
        }

        if (cache == NULL) {
            ngx_mutex_unlock(&hash->mutex);
            return NULL;
        }

        ngx_http_cache_free(cache, key, value, log);

        if (cache->key.data == NULL) {
            cache->key.data = ngx_alloc(key->len, log);
            if (cache->key.data == NULL) {
                ngx_http_cache_free(cache, NULL, NULL, log);
                ngx_mutex_unlock(&hash->mutex);
                return NULL;
            }
        }

        cache->key.len = key->len;
        ngx_memcpy(cache->key.data, key->data, key->len);

    } else if (value) {
        ngx_http_cache_free(cache, key, value, log);
    }

    if (value) {
        if (cache->data.value.data == NULL) {
            cache->data.value.data = ngx_alloc(value->len, log);
            if (cache->data.value.data == NULL) {
                ngx_http_cache_free(cache, NULL, NULL, log);
                ngx_mutex_unlock(&hash->mutex);
                return NULL;
            }
        }

        cache->data.value.len = value->len;
        ngx_memcpy(cache->data.value.data, value->data, value->len);
    }

    cache->crc = crc;
    cache->key.len = key->len;

    cache->refs = 1;
    cache->count = 0;

    cache->deleted = 0;
    cache->expired = 0;
    cache->memory = 0;
    cache->mmap = 0;
    cache->notify = 0;

    if (cleanup) {
        cleanup->data.cache.hash = hash;
        cleanup->data.cache.cache = cache;
        cleanup->valid = 1;
        cleanup->cache = 1;
    }

    ngx_mutex_unlock(&hash->mutex);

    return cache;
}


void ngx_http_cache_free(ngx_http_cache_t *cache,
                         ngx_str_t *key, ngx_str_t *value, ngx_log_t *log)
{
    if (cache->memory) {
        if (cache->data.value.data
            && (value == NULL || value->len > cache->data.value.len))
        {
            ngx_free(cache->data.value.data);
            cache->data.value.data = NULL;
        }
    }

    /* TODO: mmap */

    cache->data.value.len = 0;

    if (cache->fd != NGX_INVALID_FILE) {

        ngx_log_debug1(NGX_LOG_DEBUG_HTTP, log, 0,
                       "http cache close fd: %d", cache->fd);

        if (ngx_close_file(cache->fd) == NGX_FILE_ERROR) {
            ngx_log_error(NGX_LOG_ALERT, log, ngx_errno,
                          ngx_close_file_n " \"%s\" failed",
                          cache->key.data);
        }

        cache->fd = NGX_INVALID_FILE;
    }

    if (cache->key.data && (key == NULL || key->len > cache->key.len)) {
        ngx_free(cache->key.data);
        cache->key.data = NULL;
    }

    cache->key.len = 0;

    cache->refs = 0;
}


void ngx_http_cache_lock(ngx_http_cache_hash_t *hash, ngx_http_cache_t *cache)
{
    if (ngx_mutex_lock(&hash->mutex) == NGX_ERROR) {
        return;
    }
}


void ngx_http_cache_unlock(ngx_http_cache_hash_t *hash,
                           ngx_http_cache_t *cache, ngx_log_t *log)
{
    if (ngx_mutex_lock(&hash->mutex) == NGX_ERROR) {
        return;
    }

    cache->refs--;

    if (cache->refs == 0 && cache->deleted) {
        ngx_http_cache_free(cache, NULL, NULL, log);
    }

    ngx_mutex_unlock(&hash->mutex);
}


#if 0

ngx_http_cache_add_file_event(ngx_http_cache_hash_t *hash,
                              ngx_http_cache_t *cache)
{
    ngx_event_t                 *ev;
    ngx_http_cache_event_ctx_t  *ctx;

    ev = &ngx_cycle->read_events[fd];
    ngx_memzero(ev, sizeof(ngx_event_t);

    ev->data = data;
    ev->event_handler = ngx_http_cache_invalidate;

    return ngx_add_event(ev, NGX_VNODE_EVENT, 0);
}


void ngx_http_cache_invalidate(ngx_event_t *ev)
{
    ngx_http_cache_event_ctx_t  *ctx;

    ctx = ev->data;

    ngx_http_cache_lock(&ctx->hash->mutex);

    if (ctx->cache->refs == 0)
        ngx_http_cache_free(ctx->cache, NULL, NULL, ctx->log);

    } else {
        ctx->cache->deleted = 1;
    }

    ngx_http_cache_unlock(&ctx->hash->mutex);
}

#endif


/* TODO: currently fd only */

ngx_int_t ngx_http_send_cached(ngx_http_request_t *r)
{
    ngx_int_t            rc;
    ngx_hunk_t          *h;
    ngx_chain_t          out;
    ngx_http_log_ctx_t  *ctx;

    ctx = r->connection->log->data;
    ctx->action = "sending response to client";

    r->headers_out.status = NGX_HTTP_OK;
    r->headers_out.content_length_n = r->cache->data.size;
    r->headers_out.last_modified_time = r->cache->last_modified;

    if (ngx_http_set_content_type(r) != NGX_OK) {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    /* we need to allocate all before the header would be sent */

    if (!(h = ngx_pcalloc(r->pool, sizeof(ngx_hunk_t)))) {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    if (!(h->file = ngx_pcalloc(r->pool, sizeof(ngx_file_t)))) {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    rc = ngx_http_send_header(r);

    if (rc == NGX_ERROR || rc > NGX_OK || r->header_only) {
        return rc;
    }

    h->type = r->main ? NGX_HUNK_FILE : NGX_HUNK_FILE|NGX_HUNK_LAST;

    h->file_pos = 0;
    h->file_last = r->cache->data.size;

    h->file->fd = r->cache->fd;
    h->file->log = r->connection->log;

    out.hunk = h;
    out.next = NULL;

    return ngx_http_output_filter(r, &out);
}


char *ngx_http_set_cache_slot(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    char  *p = conf;

    ngx_int_t              i, j, dup, invalid;
    ngx_str_t              *value, line;
    ngx_http_cache_t       *c;
    ngx_http_cache_hash_t  *ch, **chp;

    chp = (ngx_http_cache_hash_t **) (p + cmd->offset);
    if (*chp) {
        return "is duplicate";
    }

    if (!(ch = ngx_pcalloc(cf->pool, sizeof(ngx_http_cache_hash_t)))) {
        return NGX_CONF_ERROR;
    }
    *chp = ch;

    dup = 0;
    invalid = 0;

    value = cf->args->elts;

    for (i = 1; i < cf->args->nelts; i++) {

        if (value[i].data[1] != '=') {
            ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                           "invalid value \"%s\"", value[i].data);
            return NGX_CONF_ERROR;
        }

        switch (value[i].data[0]) {

        case 'h':
            if (ch->hash) {
                dup = 1;
                break;
            }

            ch->hash = ngx_atoi(value[i].data + 2, value[i].len - 2);
            if (ch->hash == (size_t)  NGX_ERROR || ch->hash == 0) {
                invalid = 1;
                break;
            }

            continue;

        case 'n':
            if (ch->nelts) {
                dup = 1;
                break;
            }

            ch->nelts = ngx_atoi(value[i].data + 2, value[i].len - 2);
            if (ch->nelts == (size_t) NGX_ERROR || ch->nelts == 0) {
                invalid = 1;
                break;
            }

            continue;

        case 'l':
            if (ch->life) {
                dup = 1;
                break;
            }

            line.len = value[i].len - 2;
            line.data = value[i].data + 2;

            ch->life = ngx_parse_time(&line, 1);
            if (ch->life == NGX_ERROR || ch->life == 0) {
                invalid = 1;
                break;
            }

            continue;

        case 'u':
            if (ch->update) {
                dup = 1;
                break;
            }

            line.len = value[i].len - 2;
            line.data = value[i].data + 2;

            ch->update = ngx_parse_time(&line, 1);
            if (ch->update == NGX_ERROR || ch->update == 0) {
                invalid = 1;
                break;
            }

            continue;

        default:
            invalid = 1;
        }

        if (dup) {
            ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                               "duplicate value \"%s\"", value[i].data);
            return NGX_CONF_ERROR;
        }

        if (invalid) {
            ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                               "invalid value \"%s\"", value[i].data);
            return NGX_CONF_ERROR;
        }
    }

    ch->elts = ngx_pcalloc(cf->pool,
                           ch->hash * ch->nelts * sizeof(ngx_http_cache_t));
    if (ch->elts == NULL) {
        return NGX_CONF_ERROR;
    }

    for (i = 0; i < (ngx_int_t) ch->hash; i++) {
        c = ch->elts + i * ch->nelts;

        for (j = 0; j < (ngx_int_t) ch->nelts; j++) {
            c[j].fd = NGX_INVALID_FILE;
        }
    }

    return NGX_CONF_OK;
}
