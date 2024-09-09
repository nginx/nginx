
/*
 * Copyright (C) Nginx, Inc.
 */


#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_event.h>


#define NGX_SSL_CACHE_PATH    0
#define NGX_SSL_CACHE_DATA    1
#define NGX_SSL_CACHE_ENGINE  2


typedef struct {
    unsigned                    type:2;
    unsigned                    len:30;
    u_char                     *data;
} ngx_ssl_cache_key_t;


typedef void *(*ngx_ssl_cache_create_pt)(ngx_ssl_cache_key_t *id, char **err,
    void *data);
typedef void (*ngx_ssl_cache_free_pt)(void *data);
typedef void *(*ngx_ssl_cache_ref_pt)(char **err, void *data);


typedef struct {
    ngx_ssl_cache_create_pt     create;
    ngx_ssl_cache_free_pt       free;
    ngx_ssl_cache_ref_pt        ref;
} ngx_ssl_cache_type_t;


typedef struct {
    ngx_rbtree_node_t           node;
    ngx_ssl_cache_key_t         id;
    ngx_ssl_cache_type_t       *type;
    void                       *value;
} ngx_ssl_cache_node_t;


typedef struct {
    ngx_rbtree_t                rbtree;
    ngx_rbtree_node_t           sentinel;
} ngx_ssl_cache_t;


static ngx_int_t ngx_ssl_cache_init_key(ngx_pool_t *pool, ngx_uint_t index,
    ngx_str_t *path, ngx_ssl_cache_key_t *id);
static ngx_ssl_cache_node_t *ngx_ssl_cache_lookup(ngx_ssl_cache_t *cache,
    ngx_ssl_cache_type_t *type, ngx_ssl_cache_key_t *id, uint32_t hash);

static void *ngx_ssl_cache_cert_create(ngx_ssl_cache_key_t *id, char **err,
    void *data);
static void ngx_ssl_cache_cert_free(void *data);
static void *ngx_ssl_cache_cert_ref(char **err, void *data);

static void *ngx_ssl_cache_pkey_create(ngx_ssl_cache_key_t *id, char **err,
    void *data);
static int ngx_ssl_cache_pkey_password_callback(char *buf, int size, int rwflag,
    void *userdata);
static void ngx_ssl_cache_pkey_free(void *data);
static void *ngx_ssl_cache_pkey_ref(char **err, void *data);

static void *ngx_ssl_cache_crl_create(ngx_ssl_cache_key_t *id, char **err,
    void *data);
static void ngx_ssl_cache_crl_free(void *data);
static void *ngx_ssl_cache_crl_ref(char **err, void *data);

static void *ngx_ssl_cache_ca_create(ngx_ssl_cache_key_t *id, char **err,
    void *data);

static BIO *ngx_ssl_cache_create_bio(ngx_ssl_cache_key_t *id, char **err);

static void *ngx_openssl_cache_create_conf(ngx_cycle_t *cycle);
static void ngx_ssl_cache_cleanup(void *data);
static void ngx_ssl_cache_node_insert(ngx_rbtree_node_t *temp,
    ngx_rbtree_node_t *node, ngx_rbtree_node_t *sentinel);


static ngx_core_module_t  ngx_openssl_cache_module_ctx = {
    ngx_string("openssl_cache"),
    ngx_openssl_cache_create_conf,
    NULL
};


ngx_module_t  ngx_openssl_cache_module = {
    NGX_MODULE_V1,
    &ngx_openssl_cache_module_ctx,         /* module context */
    NULL,                                  /* module directives */
    NGX_CORE_MODULE,                       /* module type */
    NULL,                                  /* init master */
    NULL,                                  /* init module */
    NULL,                                  /* init process */
    NULL,                                  /* init thread */
    NULL,                                  /* exit thread */
    NULL,                                  /* exit process */
    NULL,                                  /* exit master */
    NGX_MODULE_V1_PADDING
};


static ngx_ssl_cache_type_t  ngx_ssl_cache_types[] = {

    /* NGX_SSL_CACHE_CERT */
    { ngx_ssl_cache_cert_create,
      ngx_ssl_cache_cert_free,
      ngx_ssl_cache_cert_ref },

    /* NGX_SSL_CACHE_PKEY */
    { ngx_ssl_cache_pkey_create,
      ngx_ssl_cache_pkey_free,
      ngx_ssl_cache_pkey_ref },

    /* NGX_SSL_CACHE_CRL */
    { ngx_ssl_cache_crl_create,
      ngx_ssl_cache_crl_free,
      ngx_ssl_cache_crl_ref },

    /* NGX_SSL_CACHE_CA */
    { ngx_ssl_cache_ca_create,
      ngx_ssl_cache_cert_free,
      ngx_ssl_cache_cert_ref }
};


void *
ngx_ssl_cache_fetch(ngx_conf_t *cf, ngx_uint_t index, char **err,
    ngx_str_t *path, void *data)
{
    uint32_t               hash;
    ngx_ssl_cache_t       *cache;
    ngx_ssl_cache_key_t    id;
    ngx_ssl_cache_type_t  *type;
    ngx_ssl_cache_node_t  *cn;

    if (ngx_ssl_cache_init_key(cf->pool, index, path, &id) != NGX_OK) {
        return NULL;
    }

    cache = (ngx_ssl_cache_t *) ngx_get_conf(cf->cycle->conf_ctx,
                                             ngx_openssl_cache_module);

    type = &ngx_ssl_cache_types[index];
    hash = ngx_murmur_hash2(id.data, id.len);

    cn = ngx_ssl_cache_lookup(cache, type, &id, hash);
    if (cn != NULL) {
        return type->ref(err, cn->value);
    }

    cn = ngx_palloc(cf->pool, sizeof(ngx_ssl_cache_node_t) + id.len + 1);
    if (cn == NULL) {
        return NULL;
    }

    cn->node.key = hash;
    cn->id.data = (u_char *)(cn + 1);
    cn->id.len = id.len;
    cn->id.type = id.type;
    cn->type = type;

    ngx_cpystrn(cn->id.data, id.data, id.len + 1);

    cn->value = type->create(&id, err, data);
    if (cn->value == NULL) {
        return NULL;
    }

    ngx_rbtree_insert(&cache->rbtree, &cn->node);

    return type->ref(err, cn->value);
}


void *
ngx_ssl_cache_connection_fetch(ngx_pool_t *pool, ngx_uint_t index, char **err,
    ngx_str_t *path, void *data)
{
    ngx_ssl_cache_key_t  id;

    if (ngx_ssl_cache_init_key(pool, index, path, &id) != NGX_OK) {
        return NULL;
    }

    return ngx_ssl_cache_types[index].create(&id, err, data);
}


static ngx_int_t
ngx_ssl_cache_init_key(ngx_pool_t *pool, ngx_uint_t index, ngx_str_t *path,
    ngx_ssl_cache_key_t *id)
{
    if (index <= NGX_SSL_CACHE_PKEY
        && ngx_strncmp(path->data, "data:", sizeof("data:") - 1) == 0)
    {
        id->type = NGX_SSL_CACHE_DATA;

    } else if (index == NGX_SSL_CACHE_PKEY
        && ngx_strncmp(path->data, "engine:", sizeof("engine:") - 1) == 0)
    {
        id->type = NGX_SSL_CACHE_ENGINE;

    } else {
        if (ngx_get_full_name(pool, (ngx_str_t *) &ngx_cycle->conf_prefix, path)
            != NGX_OK)
        {
            return NGX_ERROR;
        }

        id->type = NGX_SSL_CACHE_PATH;
    }

    id->len = path->len;
    id->data = path->data;

    return NGX_OK;
}


static ngx_ssl_cache_node_t *
ngx_ssl_cache_lookup(ngx_ssl_cache_t *cache, ngx_ssl_cache_type_t *type,
    ngx_ssl_cache_key_t *id, uint32_t hash)
{
    ngx_int_t              rc;
    ngx_rbtree_node_t     *node, *sentinel;
    ngx_ssl_cache_node_t  *cn;

    node = cache->rbtree.root;
    sentinel = cache->rbtree.sentinel;

    while (node != sentinel) {

        if (hash < node->key) {
            node = node->left;
            continue;
        }

        if (hash > node->key) {
            node = node->right;
            continue;
        }

        /* hash == node->key */

        cn = (ngx_ssl_cache_node_t *) node;

        if (type < cn->type) {
            node = node->left;
            continue;
        }

        if (type > cn->type) {
            node = node->right;
            continue;
        }

        /* type == cn->type */

        rc = ngx_memn2cmp(id->data, cn->id.data, id->len, cn->id.len);

        if (rc == 0) {
            return cn;
        }

        node = (rc < 0) ? node->left : node->right;
    }

    return NULL;
}


static void *
ngx_ssl_cache_cert_create(ngx_ssl_cache_key_t *id, char **err, void *data)
{
    BIO             *bio;
    X509            *x509;
    u_long           n;
    STACK_OF(X509)  *chain;

    chain = sk_X509_new_null();
    if (chain == NULL) {
        *err = "sk_X509_new_null() failed";
        return NULL;
    }

    bio = ngx_ssl_cache_create_bio(id, err);
    if (bio == NULL) {
        sk_X509_pop_free(chain, X509_free);
        return NULL;
    }

    /* certificate itself */

    x509 = PEM_read_bio_X509_AUX(bio, NULL, NULL, NULL);
    if (x509 == NULL) {
        *err = "PEM_read_bio_X509_AUX() failed";
        BIO_free(bio);
        sk_X509_pop_free(chain, X509_free);
        return NULL;
    }

    if (sk_X509_push(chain, x509) == 0) {
        *err = "sk_X509_push() failed";
        BIO_free(bio);
        X509_free(x509);
        sk_X509_pop_free(chain, X509_free);
        return NULL;
    }

    /* rest of the chain */

    for ( ;; ) {

        x509 = PEM_read_bio_X509(bio, NULL, NULL, NULL);
        if (x509 == NULL) {
            n = ERR_peek_last_error();

            if (ERR_GET_LIB(n) == ERR_LIB_PEM
                && ERR_GET_REASON(n) == PEM_R_NO_START_LINE)
            {
                /* end of file */
                ERR_clear_error();
                break;
            }

            /* some real error */

            *err = "PEM_read_bio_X509() failed";
            BIO_free(bio);
            sk_X509_pop_free(chain, X509_free);
            return NULL;
        }

        if (sk_X509_push(chain, x509) == 0) {
            *err = "sk_X509_push() failed";
            BIO_free(bio);
            X509_free(x509);
            sk_X509_pop_free(chain, X509_free);
            return NULL;
        }
    }

    BIO_free(bio);

    return chain;
}


static void
ngx_ssl_cache_cert_free(void *data)
{
    sk_X509_pop_free(data, X509_free);
}


static void *
ngx_ssl_cache_cert_ref(char **err, void *data)
{
    int              n, i;
    X509            *x509;
    STACK_OF(X509)  *chain;

    chain = sk_X509_dup(data);
    if (chain == NULL) {
        *err = "sk_X509_dup() failed";
        return NULL;
    }

    n = sk_X509_num(chain);

    for (i = 0; i < n; i++) {
        x509 = sk_X509_value(chain, i);

#if (OPENSSL_VERSION_NUMBER >= 0x10100000L)
        X509_up_ref(x509);
#else
        CRYPTO_add(&x509->references, 1, CRYPTO_LOCK_X509);
#endif
    }

    return chain;
}


static void *
ngx_ssl_cache_pkey_create(ngx_ssl_cache_key_t *id, char **err, void *data)
{
    ngx_array_t  *passwords = data;

    BIO              *bio;
    EVP_PKEY         *pkey;
    ngx_str_t        *pwd;
    ngx_uint_t        tries;
    pem_password_cb  *cb;

    if (id->type == NGX_SSL_CACHE_ENGINE) {

#ifndef OPENSSL_NO_ENGINE

        u_char  *p, *last;
        ENGINE  *engine;

        p = id->data + sizeof("engine:") - 1;
        last = (u_char *) ngx_strchr(p, ':');

        if (last == NULL) {
            *err = "invalid syntax";
            return NULL;
        }

        *last = '\0';

        engine = ENGINE_by_id((char *) p);

        *last++ = ':';

        if (engine == NULL) {
            *err = "ENGINE_by_id() failed";
            return NULL;
        }

        pkey = ENGINE_load_private_key(engine, (char *) last, 0, 0);

        if (pkey == NULL) {
            *err = "ENGINE_load_private_key() failed";
            ENGINE_free(engine);
            return NULL;
        }

        ENGINE_free(engine);

        return pkey;

#else

        *err = "loading \"engine:...\" certificate keys is not supported";
        return NULL;

#endif
    }

    bio = ngx_ssl_cache_create_bio(id, err);
    if (bio == NULL) {
        return NULL;
    }

    if (passwords) {
        tries = passwords->nelts;
        pwd = passwords->elts;
        cb = ngx_ssl_cache_pkey_password_callback;

    } else {
        tries = 1;
        pwd = NULL;
        cb = NULL;
    }

    for ( ;; ) {

        pkey = PEM_read_bio_PrivateKey(bio, NULL, cb, pwd);
        if (pkey != NULL) {
            break;
        }

        if (tries-- > 1) {
            ERR_clear_error();
            (void) BIO_reset(bio);
            pwd++;
            continue;
        }

        *err = "PEM_read_bio_PrivateKey() failed";
        BIO_free(bio);
        return NULL;
    }

    BIO_free(bio);

    return pkey;
}


static int
ngx_ssl_cache_pkey_password_callback(char *buf, int size, int rwflag,
    void *userdata)
{
    ngx_str_t  *pwd = userdata;

    if (rwflag) {
        ngx_log_error(NGX_LOG_ALERT, ngx_cycle->log, 0,
                      "ngx_ssl_cache_pkey_password_callback() is called "
                      "for encryption");
        return 0;
    }

    if (pwd == NULL) {
        return 0;
    }

    if (pwd->len > (size_t) size) {
        ngx_log_error(NGX_LOG_ERR, ngx_cycle->log, 0,
                      "password is truncated to %d bytes", size);
    } else {
        size = pwd->len;
    }

    ngx_memcpy(buf, pwd->data, size);

    return size;
}


static void
ngx_ssl_cache_pkey_free(void *data)
{
    EVP_PKEY_free(data);
}


static void *
ngx_ssl_cache_pkey_ref(char **err, void *data)
{
    EVP_PKEY  *pkey = data;

#if (OPENSSL_VERSION_NUMBER >= 0x10100000L)
    EVP_PKEY_up_ref(pkey);
#else
    CRYPTO_add(&pkey->references, 1, CRYPTO_LOCK_EVP_PKEY);
#endif

    return data;
}


static void *
ngx_ssl_cache_crl_create(ngx_ssl_cache_key_t *id, char **err, void *data)
{
    BIO                 *bio;
    u_long               n;
    X509_CRL            *x509;
    STACK_OF(X509_CRL)  *chain;

    chain = sk_X509_CRL_new_null();
    if (chain == NULL) {
        *err = "sk_X509_CRL_new_null() failed";
        return NULL;
    }

    bio = ngx_ssl_cache_create_bio(id, err);
    if (bio == NULL) {
        sk_X509_CRL_pop_free(chain, X509_CRL_free);
        return NULL;
    }

    for ( ;; ) {

        x509 = PEM_read_bio_X509_CRL(bio, NULL, NULL, NULL);
        if (x509 == NULL) {
            n = ERR_peek_last_error();

            if (ERR_GET_LIB(n) == ERR_LIB_PEM
                && ERR_GET_REASON(n) == PEM_R_NO_START_LINE
                && sk_X509_CRL_num(chain) > 0)
            {
                /* end of file */
                ERR_clear_error();
                break;
            }

            /* some real error */

            *err = "PEM_read_bio_X509_CRL() failed";
            BIO_free(bio);
            sk_X509_CRL_pop_free(chain, X509_CRL_free);
            return NULL;
        }

        if (sk_X509_CRL_push(chain, x509) == 0) {
            *err = "sk_X509_CRL_push() failed";
            BIO_free(bio);
            X509_CRL_free(x509);
            sk_X509_CRL_pop_free(chain, X509_CRL_free);
            return NULL;
        }
    }

    BIO_free(bio);

    return chain;
}


static void
ngx_ssl_cache_crl_free(void *data)
{
    sk_X509_CRL_pop_free(data, X509_CRL_free);
}


static void *
ngx_ssl_cache_crl_ref(char **err, void *data)
{
    int                  n, i;
    X509_CRL            *x509;
    STACK_OF(X509_CRL)  *chain;

    chain = sk_X509_CRL_dup(data);
    if (chain == NULL) {
        *err = "sk_X509_CRL_dup() failed";
        return NULL;
    }

    n = sk_X509_CRL_num(chain);

    for (i = 0; i < n; i++) {
        x509 = sk_X509_CRL_value(chain, i);

#if (OPENSSL_VERSION_NUMBER >= 0x10100000L)
        X509_CRL_up_ref(x509);
#else
        CRYPTO_add(&x509->references, 1, CRYPTO_LOCK_X509_CRL);
#endif
    }

    return chain;
}


static void *
ngx_ssl_cache_ca_create(ngx_ssl_cache_key_t *id, char **err, void *data)
{
    BIO             *bio;
    X509            *x509;
    u_long           n;
    STACK_OF(X509)  *chain;

    chain = sk_X509_new_null();
    if (chain == NULL) {
        *err = "sk_X509_new_null() failed";
        return NULL;
    }

    bio = ngx_ssl_cache_create_bio(id, err);
    if (bio == NULL) {
        sk_X509_pop_free(chain, X509_free);
        return NULL;
    }

    for ( ;; ) {

        x509 = PEM_read_bio_X509_AUX(bio, NULL, NULL, NULL);
        if (x509 == NULL) {
            n = ERR_peek_last_error();

            if (ERR_GET_LIB(n) == ERR_LIB_PEM
                && ERR_GET_REASON(n) == PEM_R_NO_START_LINE
                && sk_X509_num(chain) > 0)
            {
                /* end of file */
                ERR_clear_error();
                break;
            }

            /* some real error */

            *err = "PEM_read_bio_X509_AUX() failed";
            BIO_free(bio);
            sk_X509_pop_free(chain, X509_free);
            return NULL;
        }

        if (sk_X509_push(chain, x509) == 0) {
            *err = "sk_X509_push() failed";
            BIO_free(bio);
            X509_free(x509);
            sk_X509_pop_free(chain, X509_free);
            return NULL;
        }
    }

    BIO_free(bio);

    return chain;
}


static BIO *
ngx_ssl_cache_create_bio(ngx_ssl_cache_key_t *id, char **err)
{
    BIO  *bio;

    if (id->type == NGX_SSL_CACHE_DATA) {

        bio = BIO_new_mem_buf(id->data + sizeof("data:") - 1,
                              id->len - (sizeof("data:") - 1));
        if (bio == NULL) {
            *err = "BIO_new_mem_buf() failed";
        }

        return bio;
    }

    bio = BIO_new_file((char *) id->data, "r");
    if (bio == NULL) {
        *err = "BIO_new_file() failed";
    }

    return bio;
}


static void *
ngx_openssl_cache_create_conf(ngx_cycle_t *cycle)
{
    ngx_ssl_cache_t     *cache;
    ngx_pool_cleanup_t  *cln;

    cache = ngx_pcalloc(cycle->pool, sizeof(ngx_ssl_cache_t));
    if (cache == NULL) {
        return NULL;
    }

    cln = ngx_pool_cleanup_add(cycle->pool, 0);
    if (cln == NULL) {
        return NULL;
    }

    cln->handler = ngx_ssl_cache_cleanup;
    cln->data = cache;

    ngx_rbtree_init(&cache->rbtree, &cache->sentinel,
                    ngx_ssl_cache_node_insert);

    return cache;
}


static void
ngx_ssl_cache_cleanup(void *data)
{
    ngx_ssl_cache_t  *cache = data;

    ngx_rbtree_t          *tree;
    ngx_rbtree_node_t     *node;
    ngx_ssl_cache_node_t  *cn;

    tree = &cache->rbtree;

    if (tree->root == tree->sentinel) {
        return;
    }

    for (node = ngx_rbtree_min(tree->root, tree->sentinel);
         node;
         node = ngx_rbtree_next(tree, node))
    {
        cn = ngx_rbtree_data(node, ngx_ssl_cache_node_t, node);
        cn->type->free(cn->value);
    }
}


static void
ngx_ssl_cache_node_insert(ngx_rbtree_node_t *temp,
    ngx_rbtree_node_t *node, ngx_rbtree_node_t *sentinel)
{
    ngx_rbtree_node_t     **p;
    ngx_ssl_cache_node_t   *n, *t;

    for ( ;; ) {

        n = ngx_rbtree_data(node, ngx_ssl_cache_node_t, node);
        t = ngx_rbtree_data(temp, ngx_ssl_cache_node_t, node);

        if (node->key != temp->key) {

            p = (node->key < temp->key) ? &temp->left : &temp->right;

        } else if (n->type != t->type) {

            p = (n->type < t->type) ? &temp->left : &temp->right;

        } else {

            p = (ngx_memn2cmp(n->id.data, t->id.data, n->id.len, t->id.len)
                 < 0) ? &temp->left : &temp->right;
        }

        if (*p == sentinel) {
            break;
        }

        temp = *p;
    }

    *p = node;
    node->parent = temp;
    node->left = sentinel;
    node->right = sentinel;
    ngx_rbt_red(node);
}
