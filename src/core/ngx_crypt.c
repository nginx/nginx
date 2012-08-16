
/*
 * Copyright (C) Maxim Dounin
 */


#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_crypt.h>
#include <ngx_md5.h>
#if (NGX_HAVE_SHA1)
#include <ngx_sha1.h>
#endif


#if (NGX_CRYPT)

static ngx_int_t ngx_crypt_apr1(ngx_pool_t *pool, u_char *key, u_char *salt,
    u_char **encrypted);
static ngx_int_t ngx_crypt_plain(ngx_pool_t *pool, u_char *key, u_char *salt,
    u_char **encrypted);

#if (NGX_HAVE_SHA1)

static ngx_int_t ngx_crypt_ssha(ngx_pool_t *pool, u_char *key, u_char *salt,
    u_char **encrypted);

#endif


static u_char *ngx_crypt_to64(u_char *p, uint32_t v, size_t n);


ngx_int_t
ngx_crypt(ngx_pool_t *pool, u_char *key, u_char *salt, u_char **encrypted)
{
    if (ngx_strncmp(salt, "$apr1$", sizeof("$apr1$") - 1) == 0) {
        return ngx_crypt_apr1(pool, key, salt, encrypted);

    } else if (ngx_strncmp(salt, "{PLAIN}", sizeof("{PLAIN}") - 1) == 0) {
        return ngx_crypt_plain(pool, key, salt, encrypted);

#if (NGX_HAVE_SHA1)
    } else if (ngx_strncmp(salt, "{SSHA}", sizeof("{SSHA}") - 1) == 0) {
        return ngx_crypt_ssha(pool, key, salt, encrypted);
#endif
    }

    /* fallback to libc crypt() */

    return ngx_libc_crypt(pool, key, salt, encrypted);
}


static ngx_int_t
ngx_crypt_apr1(ngx_pool_t *pool, u_char *key, u_char *salt, u_char **encrypted)
{
    ngx_int_t          n;
    ngx_uint_t         i;
    u_char            *p, *last, final[16];
    size_t             saltlen, keylen;
    ngx_md5_t          md5, ctx1;

    /* Apache's apr1 crypt is Paul-Henning Kamp's md5 crypt with $apr1$ magic */

    keylen = ngx_strlen(key);

    /* true salt: no magic, max 8 chars, stop at first $ */

    salt += sizeof("$apr1$") - 1;
    last = salt + 8;
    for (p = salt; *p && *p != '$' && p < last; p++) { /* void */ }
    saltlen = p - salt;

    /* hash key and salt */

    ngx_md5_init(&md5);
    ngx_md5_update(&md5, key, keylen);
    ngx_md5_update(&md5, (u_char *) "$apr1$", sizeof("$apr1$") - 1);
    ngx_md5_update(&md5, salt, saltlen);

    ngx_md5_init(&ctx1);
    ngx_md5_update(&ctx1, key, keylen);
    ngx_md5_update(&ctx1, salt, saltlen);
    ngx_md5_update(&ctx1, key, keylen);
    ngx_md5_final(final, &ctx1);

    for (n = keylen; n > 0; n -= 16) {
        ngx_md5_update(&md5, final, n > 16 ? 16 : n);
    }

    ngx_memzero(final, sizeof(final));

    for (i = keylen; i; i >>= 1) {
        if (i & 1) {
            ngx_md5_update(&md5, final, 1);

        } else {
            ngx_md5_update(&md5, key, 1);
        }
    }

    ngx_md5_final(final, &md5);

    for (i = 0; i < 1000; i++) {
        ngx_md5_init(&ctx1);

        if (i & 1) {
            ngx_md5_update(&ctx1, key, keylen);

        } else {
            ngx_md5_update(&ctx1, final, 16);
        }

        if (i % 3) {
            ngx_md5_update(&ctx1, salt, saltlen);
        }

        if (i % 7) {
            ngx_md5_update(&ctx1, key, keylen);
        }

        if (i & 1) {
            ngx_md5_update(&ctx1, final, 16);

        } else {
            ngx_md5_update(&ctx1, key, keylen);
        }

        ngx_md5_final(final, &ctx1);
    }

    /* output */

    *encrypted = ngx_pnalloc(pool, sizeof("$apr1$") - 1 + saltlen + 16 + 1);
    if (*encrypted == NULL) {
        return NGX_ERROR;
    }

    p = ngx_cpymem(*encrypted, "$apr1$", sizeof("$apr1$") - 1);
    p = ngx_copy(p, salt, saltlen);
    *p++ = '$';

    p = ngx_crypt_to64(p, (final[ 0]<<16) | (final[ 6]<<8) | final[12], 4);
    p = ngx_crypt_to64(p, (final[ 1]<<16) | (final[ 7]<<8) | final[13], 4);
    p = ngx_crypt_to64(p, (final[ 2]<<16) | (final[ 8]<<8) | final[14], 4);
    p = ngx_crypt_to64(p, (final[ 3]<<16) | (final[ 9]<<8) | final[15], 4);
    p = ngx_crypt_to64(p, (final[ 4]<<16) | (final[10]<<8) | final[ 5], 4);
    p = ngx_crypt_to64(p, final[11], 2);
    *p = '\0';

    return NGX_OK;
}


static u_char *
ngx_crypt_to64(u_char *p, uint32_t v, size_t n)
{
    static u_char   itoa64[] =
        "./0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz";

    while (n--) {
       *p++ = itoa64[v & 0x3f];
       v >>= 6;
    }

    return p;
}


static ngx_int_t
ngx_crypt_plain(ngx_pool_t *pool, u_char *key, u_char *salt, u_char **encrypted)
{
    size_t   len;
    u_char  *p;

    len = ngx_strlen(key);

    *encrypted = ngx_pnalloc(pool, sizeof("{PLAIN}") - 1 + len + 1);
    if (*encrypted == NULL) {
        return NGX_ERROR;
    }

    p = ngx_cpymem(*encrypted, "{PLAIN}", sizeof("{PLAIN}") - 1);
    ngx_memcpy(p, key, len + 1);

    return NGX_OK;
}


#if (NGX_HAVE_SHA1)

static ngx_int_t
ngx_crypt_ssha(ngx_pool_t *pool, u_char *key, u_char *salt, u_char **encrypted)
{
    size_t       len;
    ngx_int_t    rc;
    ngx_str_t    encoded, decoded;
    ngx_sha1_t   sha1;

    /* "{SSHA}" base64(SHA1(key salt) salt) */

    /* decode base64 salt to find out true salt */

    encoded.data = salt + sizeof("{SSHA}") - 1;
    encoded.len = ngx_strlen(encoded.data);

    len = ngx_max(ngx_base64_decoded_length(encoded.len), 20);

    decoded.data = ngx_pnalloc(pool, len);
    if (decoded.data == NULL) {
        return NGX_ERROR;
    }

    rc = ngx_decode_base64(&decoded, &encoded);

    if (rc != NGX_OK || decoded.len < 20) {
        decoded.len = 20;
    }

    /* update SHA1 from key and salt */

    ngx_sha1_init(&sha1);
    ngx_sha1_update(&sha1, key, ngx_strlen(key));
    ngx_sha1_update(&sha1, decoded.data + 20, decoded.len - 20);
    ngx_sha1_final(decoded.data, &sha1);

    /* encode it back to base64 */

    len = sizeof("{SSHA}") - 1 + ngx_base64_encoded_length(decoded.len) + 1;

    *encrypted = ngx_pnalloc(pool, len);
    if (*encrypted == NULL) {
        return NGX_ERROR;
    }

    encoded.data = ngx_cpymem(*encrypted, "{SSHA}", sizeof("{SSHA}") - 1);
    ngx_encode_base64(&encoded, &decoded);
    encoded.data[encoded.len] = '\0';

    return NGX_OK;
}

#endif /* NGX_HAVE_SHA1 */

#endif /* NGX_CRYPT */
