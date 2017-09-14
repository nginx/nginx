
/*
 * Copyright (C) Nginx, Inc.
 * Copyright (C) Valentin V. Bartenev
 */


#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>


#define NGX_HTTP_V2_TABLE_SIZE  4096


static ngx_int_t ngx_http_v2_table_account(ngx_http_v2_connection_t *h2c,
    size_t size);


static ngx_http_v2_header_t  ngx_http_v2_static_table[] = {
    { ngx_string(":authority"), ngx_string("") },
    { ngx_string(":method"), ngx_string("GET") },
    { ngx_string(":method"), ngx_string("POST") },
    { ngx_string(":path"), ngx_string("/") },
    { ngx_string(":path"), ngx_string("/index.html") },
    { ngx_string(":scheme"), ngx_string("http") },
    { ngx_string(":scheme"), ngx_string("https") },
    { ngx_string(":status"), ngx_string("200") },
    { ngx_string(":status"), ngx_string("204") },
    { ngx_string(":status"), ngx_string("206") },
    { ngx_string(":status"), ngx_string("304") },
    { ngx_string(":status"), ngx_string("400") },
    { ngx_string(":status"), ngx_string("404") },
    { ngx_string(":status"), ngx_string("500") },
    { ngx_string("accept-charset"), ngx_string("") },
    { ngx_string("accept-encoding"), ngx_string("gzip, deflate") },
    { ngx_string("accept-language"), ngx_string("") },
    { ngx_string("accept-ranges"), ngx_string("") },
    { ngx_string("accept"), ngx_string("") },
    { ngx_string("access-control-allow-origin"), ngx_string("") },
    { ngx_string("age"), ngx_string("") },
    { ngx_string("allow"), ngx_string("") },
    { ngx_string("authorization"), ngx_string("") },
    { ngx_string("cache-control"), ngx_string("") },
    { ngx_string("content-disposition"), ngx_string("") },
    { ngx_string("content-encoding"), ngx_string("") },
    { ngx_string("content-language"), ngx_string("") },
    { ngx_string("content-length"), ngx_string("") },
    { ngx_string("content-location"), ngx_string("") },
    { ngx_string("content-range"), ngx_string("") },
    { ngx_string("content-type"), ngx_string("") },
    { ngx_string("cookie"), ngx_string("") },
    { ngx_string("date"), ngx_string("") },
    { ngx_string("etag"), ngx_string("") },
    { ngx_string("expect"), ngx_string("") },
    { ngx_string("expires"), ngx_string("") },
    { ngx_string("from"), ngx_string("") },
    { ngx_string("host"), ngx_string("") },
    { ngx_string("if-match"), ngx_string("") },
    { ngx_string("if-modified-since"), ngx_string("") },
    { ngx_string("if-none-match"), ngx_string("") },
    { ngx_string("if-range"), ngx_string("") },
    { ngx_string("if-unmodified-since"), ngx_string("") },
    { ngx_string("last-modified"), ngx_string("") },
    { ngx_string("link"), ngx_string("") },
    { ngx_string("location"), ngx_string("") },
    { ngx_string("max-forwards"), ngx_string("") },
    { ngx_string("proxy-authenticate"), ngx_string("") },
    { ngx_string("proxy-authorization"), ngx_string("") },
    { ngx_string("range"), ngx_string("") },
    { ngx_string("referer"), ngx_string("") },
    { ngx_string("refresh"), ngx_string("") },
    { ngx_string("retry-after"), ngx_string("") },
    { ngx_string("server"), ngx_string("") },
    { ngx_string("set-cookie"), ngx_string("") },
    { ngx_string("strict-transport-security"), ngx_string("") },
    { ngx_string("transfer-encoding"), ngx_string("") },
    { ngx_string("user-agent"), ngx_string("") },
    { ngx_string("vary"), ngx_string("") },
    { ngx_string("via"), ngx_string("") },
    { ngx_string("www-authenticate"), ngx_string("") },
};

#define NGX_HTTP_V2_STATIC_TABLE_ENTRIES                                      \
    (sizeof(ngx_http_v2_static_table)                                         \
     / sizeof(ngx_http_v2_header_t))


ngx_int_t
ngx_http_v2_get_indexed_header(ngx_http_v2_connection_t *h2c, ngx_uint_t index,
    ngx_uint_t name_only)
{
    u_char                *p;
    size_t                 rest;
    ngx_http_v2_header_t  *entry;

    if (index == 0) {
        ngx_log_error(NGX_LOG_INFO, h2c->connection->log, 0,
                      "client sent invalid hpack table index 0");
        return NGX_ERROR;
    }

    ngx_log_debug2(NGX_LOG_DEBUG_HTTP, h2c->connection->log, 0,
                   "http2 get indexed %s: %ui",
                   name_only ? "name" : "header", index);

    index--;

    if (index < NGX_HTTP_V2_STATIC_TABLE_ENTRIES) {
        h2c->state.header = ngx_http_v2_static_table[index];
        return NGX_OK;
    }

    index -= NGX_HTTP_V2_STATIC_TABLE_ENTRIES;

    if (index < h2c->hpack.added - h2c->hpack.deleted) {
        index = (h2c->hpack.added - index - 1) % h2c->hpack.allocated;
        entry = h2c->hpack.entries[index];

        p = ngx_pnalloc(h2c->state.pool, entry->name.len + 1);
        if (p == NULL) {
            return NGX_ERROR;
        }

        h2c->state.header.name.len = entry->name.len;
        h2c->state.header.name.data = p;

        rest = h2c->hpack.storage + NGX_HTTP_V2_TABLE_SIZE - entry->name.data;

        if (entry->name.len > rest) {
            p = ngx_cpymem(p, entry->name.data, rest);
            p = ngx_cpymem(p, h2c->hpack.storage, entry->name.len - rest);

        } else {
            p = ngx_cpymem(p, entry->name.data, entry->name.len);
        }

        *p = '\0';

        if (name_only) {
            return NGX_OK;
        }

        p = ngx_pnalloc(h2c->state.pool, entry->value.len + 1);
        if (p == NULL) {
            return NGX_ERROR;
        }

        h2c->state.header.value.len = entry->value.len;
        h2c->state.header.value.data = p;

        rest = h2c->hpack.storage + NGX_HTTP_V2_TABLE_SIZE - entry->value.data;

        if (entry->value.len > rest) {
            p = ngx_cpymem(p, entry->value.data, rest);
            p = ngx_cpymem(p, h2c->hpack.storage, entry->value.len - rest);

        } else {
            p = ngx_cpymem(p, entry->value.data, entry->value.len);
        }

        *p = '\0';

        return NGX_OK;
    }

    ngx_log_error(NGX_LOG_INFO, h2c->connection->log, 0,
                  "client sent out of bound hpack table index: %ui", index);

    return NGX_ERROR;
}


ngx_int_t
ngx_http_v2_add_header(ngx_http_v2_connection_t *h2c,
    ngx_http_v2_header_t *header)
{
    size_t                 avail;
    ngx_uint_t             index;
    ngx_http_v2_header_t  *entry, **entries;

    ngx_log_debug2(NGX_LOG_DEBUG_HTTP, h2c->connection->log, 0,
                   "http2 add header to hpack table: \"%V: %V\"",
                   &header->name, &header->value);

    if (h2c->hpack.entries == NULL) {
        h2c->hpack.allocated = 64;
        h2c->hpack.size = NGX_HTTP_V2_TABLE_SIZE;
        h2c->hpack.free = NGX_HTTP_V2_TABLE_SIZE;

        h2c->hpack.entries = ngx_palloc(h2c->connection->pool,
                                        sizeof(ngx_http_v2_header_t *)
                                        * h2c->hpack.allocated);
        if (h2c->hpack.entries == NULL) {
            return NGX_ERROR;
        }

        h2c->hpack.storage = ngx_palloc(h2c->connection->pool,
                                        h2c->hpack.free);
        if (h2c->hpack.storage == NULL) {
            return NGX_ERROR;
        }

        h2c->hpack.pos = h2c->hpack.storage;
    }

    if (ngx_http_v2_table_account(h2c, header->name.len + header->value.len)
        != NGX_OK)
    {
        return NGX_OK;
    }

    if (h2c->hpack.reused == h2c->hpack.deleted) {
        entry = ngx_palloc(h2c->connection->pool, sizeof(ngx_http_v2_header_t));
        if (entry == NULL) {
            return NGX_ERROR;
        }

    } else {
        entry = h2c->hpack.entries[h2c->hpack.reused++ % h2c->hpack.allocated];
    }

    avail = h2c->hpack.storage + NGX_HTTP_V2_TABLE_SIZE - h2c->hpack.pos;

    entry->name.len = header->name.len;
    entry->name.data = h2c->hpack.pos;

    if (avail >= header->name.len) {
        h2c->hpack.pos = ngx_cpymem(h2c->hpack.pos, header->name.data,
                                    header->name.len);
    } else {
        ngx_memcpy(h2c->hpack.pos, header->name.data, avail);
        h2c->hpack.pos = ngx_cpymem(h2c->hpack.storage,
                                    header->name.data + avail,
                                    header->name.len - avail);
        avail = NGX_HTTP_V2_TABLE_SIZE;
    }

    avail -= header->name.len;

    entry->value.len = header->value.len;
    entry->value.data = h2c->hpack.pos;

    if (avail >= header->value.len) {
        h2c->hpack.pos = ngx_cpymem(h2c->hpack.pos, header->value.data,
                                    header->value.len);
    } else {
        ngx_memcpy(h2c->hpack.pos, header->value.data, avail);
        h2c->hpack.pos = ngx_cpymem(h2c->hpack.storage,
                                    header->value.data + avail,
                                    header->value.len - avail);
    }

    if (h2c->hpack.allocated == h2c->hpack.added - h2c->hpack.deleted) {

        entries = ngx_palloc(h2c->connection->pool,
                             sizeof(ngx_http_v2_header_t *)
                             * (h2c->hpack.allocated + 64));
        if (entries == NULL) {
            return NGX_ERROR;
        }

        index = h2c->hpack.deleted % h2c->hpack.allocated;

        ngx_memcpy(entries, &h2c->hpack.entries[index],
                   (h2c->hpack.allocated - index)
                   * sizeof(ngx_http_v2_header_t *));

        ngx_memcpy(&entries[h2c->hpack.allocated - index], h2c->hpack.entries,
                   index * sizeof(ngx_http_v2_header_t *));

        (void) ngx_pfree(h2c->connection->pool, h2c->hpack.entries);

        h2c->hpack.entries = entries;

        h2c->hpack.added = h2c->hpack.allocated;
        h2c->hpack.deleted = 0;
        h2c->hpack.reused = 0;
        h2c->hpack.allocated += 64;
    }

    h2c->hpack.entries[h2c->hpack.added++ % h2c->hpack.allocated] = entry;

    return NGX_OK;
}


static ngx_int_t
ngx_http_v2_table_account(ngx_http_v2_connection_t *h2c, size_t size)
{
    ngx_http_v2_header_t  *entry;

    size += 32;

    ngx_log_debug2(NGX_LOG_DEBUG_HTTP, h2c->connection->log, 0,
                   "http2 hpack table account: %uz free:%uz",
                   size, h2c->hpack.free);

    if (size <= h2c->hpack.free) {
        h2c->hpack.free -= size;
        return NGX_OK;
    }

    if (size > h2c->hpack.size) {
        h2c->hpack.deleted = h2c->hpack.added;
        h2c->hpack.free = h2c->hpack.size;
        return NGX_DECLINED;
    }

    do {
        entry = h2c->hpack.entries[h2c->hpack.deleted++ % h2c->hpack.allocated];
        h2c->hpack.free += 32 + entry->name.len + entry->value.len;
    } while (size > h2c->hpack.free);

    h2c->hpack.free -= size;

    return NGX_OK;
}


ngx_int_t
ngx_http_v2_table_size(ngx_http_v2_connection_t *h2c, size_t size)
{
    ssize_t                needed;
    ngx_http_v2_header_t  *entry;

    if (size > NGX_HTTP_V2_TABLE_SIZE) {
        ngx_log_error(NGX_LOG_INFO, h2c->connection->log, 0,
                      "client sent invalid table size update: %uz", size);

        return NGX_ERROR;
    }

    ngx_log_debug2(NGX_LOG_DEBUG_HTTP, h2c->connection->log, 0,
                   "http2 new hpack table size: %uz was:%uz",
                   size, h2c->hpack.size);

    needed = h2c->hpack.size - size;

    while (needed > (ssize_t) h2c->hpack.free) {
        entry = h2c->hpack.entries[h2c->hpack.deleted++ % h2c->hpack.allocated];
        h2c->hpack.free += 32 + entry->name.len + entry->value.len;
    }

    h2c->hpack.size = size;
    h2c->hpack.free -= needed;

    return NGX_OK;
}
