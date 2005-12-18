
/*
 * Copyright (C) Igor Sysoev
 */


#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_event.h>
#include <ngx_http.h>


ngx_int_t
ngx_http_config_add_hash(ngx_http_hash_conf_t *h, ngx_str_t *key, void *value,
    ngx_uint_t flags)
{
    size_t           len;
    ngx_str_t       *name;
    ngx_uint_t       i, k, n, skip;
    ngx_hash_key_t  *hk;
    u_char           buf[2048];

    if (!(flags & NGX_HTTP_WILDCARD_HASH)) {

        /* exact hash */

        k = 0;

        for (i = 0; i < key->len; i++) {
            key->data[i] = ngx_tolower(key->data[i]);
            k = ngx_hash(k, key->data[i]);
        }

        k %= NGX_HTTP_CONFIG_HASH;

        /* check conflicts in exact hash */

        name = h->keys_hash[k].elts;

        if (name) {
            for (i = 0; i < h->keys_hash[k].nelts; i++) {
                if (key->len != name[i].len) {
                    continue;
                }

                if (ngx_strncmp(key->data, name[i].data, key->len) == 0) {
                    return NGX_BUSY;
                }
            }

        } else {
            if (ngx_array_init(&h->keys_hash[k], h->temp_pool, 4,
                               sizeof(ngx_str_t))
                != NGX_OK)
            {
                return NGX_ERROR;
            }
        }

        name = ngx_array_push(&h->keys_hash[k]);
        if (name == NULL) {
            return NGX_ERROR;
        }

        *name = *key;

        hk = ngx_array_push(&h->keys);
        if (hk == NULL) {
            return NGX_ERROR;
        }

        hk->key = *key;
        hk->key_hash = ngx_hash_key(key->data, key->len);
        hk->value = value;

    } else {

        /* wildcard hash */

        skip = (key->data[0] == '*') ? 2 : 1;
        k = 0;

        for (i = skip; i < key->len; i++) {
            key->data[i] = ngx_tolower(key->data[i]);
            k = ngx_hash(k, key->data[i]);
        }

        k %= NGX_HTTP_CONFIG_HASH;

        if (skip == 1) {

            /* check conflicts in exact hash for ".example.com" */

            name = h->keys_hash[k].elts;

            if (name) {
                len = key->len - skip;

                for (i = 0; i < h->keys_hash[k].nelts; i++) {
                    if (len != name[i].len) {
                        continue;
                    }

                    if (ngx_strncmp(&key->data[1], name[i].data, len) == 0) {
                        return NGX_BUSY;
                    }
                }

            } else {
                if (ngx_array_init(&h->keys_hash[k], h->temp_pool, 4,
                                   sizeof(ngx_str_t))
                    != NGX_OK)
                {
                    return NGX_ERROR;
                }
            }

            name = ngx_array_push(&h->keys_hash[k]);
            if (name == NULL) {
                return NGX_ERROR;
            }

            name->len = key->len - 1;
            name->data = ngx_palloc(h->temp_pool, name->len);
            if (name->data == NULL) {
                return NGX_ERROR;
            }

            ngx_memcpy(name->data, &key->data[1], name->len);
        }


        /*
         * convert "*.example.com" to "com.example.\0"
         *      and ".example.com" to "com.example\0"
         */

        len = 0;
        n = 0;

        for (i = key->len - 1; i; i--) {
            if (key->data[i] == '.') {
                ngx_memcpy(&buf[n], &key->data[i + 1], len);
                n += len;
                buf[n++] = '.';
                len = 0;
                continue;
            }

            len++;
        }

        if (len) {
            ngx_memcpy(&buf[n], &key->data[1], len);
            n += len;
        }

        buf[n] = '\0';


        /* check conflicts in wildcard hash */

        name = h->dns_hash[k].elts;

        if (name) {
            len = key->len - skip;

            for (i = 0; i < h->dns_hash[k].nelts; i++) {
                if (len != name[i].len) {
                    continue;
                }

                if (ngx_strncmp(key->data + skip, name[i].data, len) == 0) {
                    return NGX_BUSY;
                }
            }

        } else {
            if (ngx_array_init(&h->dns_hash[k], h->temp_pool, 4,
                               sizeof(ngx_str_t))
                != NGX_OK)
            {
                return NGX_ERROR;
            }
        }

        name = ngx_array_push(&h->dns_hash[k]);
        if (name == NULL) {
            return NGX_ERROR;
        }

        name->len = key->len - skip;
        name->data = ngx_palloc(h->temp_pool, name->len);
        if (name->data == NULL) {
            return NGX_ERROR;
        }
        ngx_memcpy(name->data, key->data + skip, name->len);


        ngx_memcpy(key->data, buf, key->len);
        key->len--;

        hk = ngx_array_push(&h->dns_wildcards);
        if (hk == NULL) {
            return NGX_ERROR;
        }

        hk->key = *key;
        hk->key_hash = 0;
        hk->value = value;
    }

    return NGX_OK;
}
