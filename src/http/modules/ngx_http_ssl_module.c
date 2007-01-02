
/*
 * Copyright (C) Igor Sysoev
 */


#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>


typedef ngx_int_t (*ngx_ssl_variable_handler_pt)(ngx_connection_t *c,
    ngx_pool_t *pool, ngx_str_t *s);


#define NGX_DEFLAUT_CERTIFICATE      "cert.pem"
#define NGX_DEFLAUT_CERTIFICATE_KEY  "cert.pem"
#define NGX_DEFLAUT_CIPHERS  "ALL:!ADH:RC4+RSA:+HIGH:+MEDIUM:+LOW:+SSLv2:+EXP"


#define NGX_HTTP_SSL_MAX_SESSION_SIZE                                         \
    (4096 - offsetof(ngx_http_ssl_cached_sess_t, asn1))


#define NGX_HTTP_SSL_DFLT_BUILTIN_SCACHE  -2
#define NGX_HTTP_SSL_NO_BUILTIN_SCACHE    -3


static void ngx_http_ssl_expire_sessions(ngx_http_ssl_sesssion_cache_t *cache,
    ngx_slab_pool_t *shpool, ngx_uint_t expire);

static ngx_int_t ngx_http_ssl_static_variable(ngx_http_request_t *r,
    ngx_http_variable_value_t *v, uintptr_t data);
static ngx_int_t ngx_http_ssl_variable(ngx_http_request_t *r,
    ngx_http_variable_value_t *v, uintptr_t data);

static ngx_int_t ngx_http_ssl_add_variables(ngx_conf_t *cf);
static void *ngx_http_ssl_create_srv_conf(ngx_conf_t *cf);
static char *ngx_http_ssl_merge_srv_conf(ngx_conf_t *cf,
    void *parent, void *child);

static char *ngx_http_ssl_session_cache(ngx_conf_t *cf, ngx_command_t *cmd,
    void *conf);

#if !defined (SSL_OP_CIPHER_SERVER_PREFERENCE)

static char *ngx_http_ssl_nosupported(ngx_conf_t *cf, ngx_command_t *cmd,
    void *conf);

static char  ngx_http_ssl_openssl097[] = "OpenSSL 0.9.7 and higher";

#endif


static ngx_conf_bitmask_t  ngx_http_ssl_protocols[] = {
    { ngx_string("SSLv2"), NGX_SSL_SSLv2 },
    { ngx_string("SSLv3"), NGX_SSL_SSLv3 },
    { ngx_string("TLSv1"), NGX_SSL_TLSv1 },
    { ngx_null_string, 0 }
};


static ngx_command_t  ngx_http_ssl_commands[] = {

    { ngx_string("ssl"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_CONF_FLAG,
      ngx_conf_set_flag_slot,
      NGX_HTTP_SRV_CONF_OFFSET,
      offsetof(ngx_http_ssl_srv_conf_t, enable),
      NULL },

    { ngx_string("ssl_certificate"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_str_slot,
      NGX_HTTP_SRV_CONF_OFFSET,
      offsetof(ngx_http_ssl_srv_conf_t, certificate),
      NULL },

    { ngx_string("ssl_certificate_key"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_str_slot,
      NGX_HTTP_SRV_CONF_OFFSET,
      offsetof(ngx_http_ssl_srv_conf_t, certificate_key),
      NULL },

    { ngx_string("ssl_protocols"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_CONF_1MORE,
      ngx_conf_set_bitmask_slot,
      NGX_HTTP_SRV_CONF_OFFSET,
      offsetof(ngx_http_ssl_srv_conf_t, protocols),
      &ngx_http_ssl_protocols },

    { ngx_string("ssl_ciphers"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_str_slot,
      NGX_HTTP_SRV_CONF_OFFSET,
      offsetof(ngx_http_ssl_srv_conf_t, ciphers),
      NULL },

    { ngx_string("ssl_verify_client"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_CONF_FLAG,
      ngx_conf_set_flag_slot,
      NGX_HTTP_SRV_CONF_OFFSET,
      offsetof(ngx_http_ssl_srv_conf_t, verify),
      NULL },

    { ngx_string("ssl_verify_depth"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_CONF_1MORE,
      ngx_conf_set_num_slot,
      NGX_HTTP_SRV_CONF_OFFSET,
      offsetof(ngx_http_ssl_srv_conf_t, verify_depth),
      NULL },

    { ngx_string("ssl_client_certificate"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_str_slot,
      NGX_HTTP_SRV_CONF_OFFSET,
      offsetof(ngx_http_ssl_srv_conf_t, client_certificate),
      NULL },

    { ngx_string("ssl_prefer_server_ciphers"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_CONF_FLAG,
#ifdef SSL_OP_CIPHER_SERVER_PREFERENCE
      ngx_conf_set_flag_slot,
      NGX_HTTP_SRV_CONF_OFFSET,
      offsetof(ngx_http_ssl_srv_conf_t, prefer_server_ciphers),
      NULL },
#else
      ngx_http_ssl_nosupported, 0, 0, ngx_http_ssl_openssl097 },
#endif

    { ngx_string("ssl_session_cache"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_CONF_TAKE12,
      ngx_http_ssl_session_cache,
      NGX_HTTP_SRV_CONF_OFFSET,
      0,
      NULL },

    { ngx_string("ssl_session_timeout"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_sec_slot,
      NGX_HTTP_SRV_CONF_OFFSET,
      offsetof(ngx_http_ssl_srv_conf_t, session_timeout),
      NULL },

      ngx_null_command
};


static ngx_http_module_t  ngx_http_ssl_module_ctx = {
    ngx_http_ssl_add_variables,            /* preconfiguration */
    NULL,                                  /* postconfiguration */

    NULL,                                  /* create main configuration */
    NULL,                                  /* init main configuration */

    ngx_http_ssl_create_srv_conf,          /* create server configuration */
    ngx_http_ssl_merge_srv_conf,           /* merge server configuration */

    NULL,                                  /* create location configuration */
    NULL                                   /* merge location configuration */
};


ngx_module_t  ngx_http_ssl_module = {
    NGX_MODULE_V1,
    &ngx_http_ssl_module_ctx,              /* module context */
    ngx_http_ssl_commands,                 /* module directives */
    NGX_HTTP_MODULE,                       /* module type */
    NULL,                                  /* init master */
    NULL,                                  /* init module */
    NULL,                                  /* init process */
    NULL,                                  /* init thread */
    NULL,                                  /* exit thread */
    NULL,                                  /* exit process */
    NULL,                                  /* exit master */
    NGX_MODULE_V1_PADDING
};


static ngx_http_variable_t  ngx_http_ssl_vars[] = {

    { ngx_string("ssl_protocol"), NULL, ngx_http_ssl_static_variable,
      (uintptr_t) ngx_ssl_get_protocol, NGX_HTTP_VAR_CHANGABLE, 0 },

    { ngx_string("ssl_cipher"), NULL, ngx_http_ssl_static_variable,
      (uintptr_t) ngx_ssl_get_cipher_name, NGX_HTTP_VAR_CHANGABLE, 0 },

    { ngx_string("ssl_client_s_dn"), NULL, ngx_http_ssl_variable,
      (uintptr_t) ngx_ssl_get_subject_dn, NGX_HTTP_VAR_CHANGABLE, 0 },

    { ngx_string("ssl_client_i_dn"), NULL, ngx_http_ssl_variable,
      (uintptr_t) ngx_ssl_get_issuer_dn, NGX_HTTP_VAR_CHANGABLE, 0 },

    { ngx_string("ssl_client_serial"), NULL, ngx_http_ssl_variable,
      (uintptr_t) ngx_ssl_get_serial_number, NGX_HTTP_VAR_CHANGABLE, 0 },

    { ngx_null_string, NULL, NULL, 0, 0, 0 }
};


static u_char ngx_http_session_id_ctx[] = "HTTP";


static ngx_int_t
ngx_http_ssl_session_cache_init(ngx_shm_zone_t *shm_zone)
{
    ngx_slab_pool_t                *shpool;
    ngx_rbtree_node_t              *sentinel;
    ngx_http_ssl_sesssion_cache_t  *cache;

    shpool = (ngx_slab_pool_t *) shm_zone->shm.addr;

    cache = ngx_slab_alloc(shpool, sizeof(ngx_http_ssl_sesssion_cache_t));
    if (cache == NULL) {
        return NGX_ERROR;
    }

    cache->session_cache_head.prev = NULL;
    cache->session_cache_head.next = &cache->session_cache_tail;

    cache->session_cache_tail.prev = &cache->session_cache_head;
    cache->session_cache_tail.next = NULL;

    cache->session_rbtree = ngx_slab_alloc(shpool, sizeof(ngx_rbtree_t));
    if (cache->session_rbtree == NULL) {
        return NGX_ERROR;
    }

    sentinel = ngx_slab_alloc(shpool, sizeof(ngx_rbtree_node_t));
    if (sentinel == NULL) {
        return NGX_ERROR;
    }

    ngx_rbtree_sentinel_init(sentinel);

    cache->session_rbtree->root = sentinel;
    cache->session_rbtree->sentinel = sentinel;
    cache->session_rbtree->insert = ngx_rbtree_insert_value;

    shm_zone->data = cache;

    return NGX_OK;
}


/*
 * OpenSSL's i2d_SSL_SESSION() and d2i_SSL_SESSION are slow,
 * so they are outside the code locked by shared pool mutex
 */

static int
ngx_http_ssl_new_session(ngx_ssl_conn_t *ssl_conn, ngx_ssl_session_t *sess)
{
    int                             len;
    u_char                         *p, *id;
    uint32_t                        hash;
    ngx_time_t                     *tp;
    ngx_slab_pool_t                *shpool;
    ngx_connection_t               *c;
    ngx_http_request_t             *r;
    ngx_http_ssl_sess_id_t         *sess_id;
    ngx_http_ssl_srv_conf_t        *sscf;
    ngx_http_ssl_cached_sess_t     *cached_sess;
    ngx_http_ssl_sesssion_cache_t  *cache;
    u_char                          buf[NGX_HTTP_SSL_MAX_SESSION_SIZE];

    len = i2d_SSL_SESSION(sess, NULL);

    /* do not cache too big session */

    if (len > (int) NGX_HTTP_SSL_MAX_SESSION_SIZE) {
        return 0;
    }

    c = ngx_ssl_get_connection(ssl_conn);
    r = c->data;

    p = buf;
    i2d_SSL_SESSION(sess, &p);

    sscf = ngx_http_get_module_srv_conf(r, ngx_http_ssl_module);

    cache = sscf->shm_zone->data;
    shpool = (ngx_slab_pool_t *) sscf->shm_zone->shm.addr;

    ngx_shmtx_lock(&shpool->mutex);

    /* drop one or two expired sessions */
    ngx_http_ssl_expire_sessions(cache, shpool, 1);

    cached_sess = ngx_slab_alloc_locked(shpool,
                             offsetof(ngx_http_ssl_cached_sess_t, asn1) + len);

    if (cached_sess == NULL) {

        /* drop the oldest non-expired session and try once more */

        ngx_http_ssl_expire_sessions(cache, shpool, 0);

        cached_sess = ngx_slab_alloc_locked(shpool,
                             offsetof(ngx_http_ssl_cached_sess_t, asn1) + len);

        if (cached_sess == NULL) {
            id = NULL;
            goto failed;
        }
    }

    id = ngx_slab_alloc_locked(shpool, sess->session_id_length);
    if (id == NULL) {
        goto failed;
    }

    sess_id = ngx_slab_alloc_locked(shpool, sizeof(ngx_http_ssl_sess_id_t));
    if (sess_id == NULL) {
        goto failed;
    }

    ngx_memcpy(&cached_sess->asn1[0], buf, len);

    ngx_memcpy(id, sess->session_id, sess->session_id_length);

    hash = ngx_crc32_short(sess->session_id, sess->session_id_length);

    ngx_log_debug3(NGX_LOG_DEBUG_HTTP, c->log, 0,
                   "http ssl new session: %08XD:%d:%d",
                   hash, sess->session_id_length, len);

    sess_id->node.key = hash;
    sess_id->node.data = (u_char) sess->session_id_length;
    sess_id->id = id;
    sess_id->len = len;
    sess_id->session = cached_sess;

    tp = ngx_timeofday();

    cached_sess->expire = tp->sec + sscf->session_timeout;
    cached_sess->sess_id = sess_id;

    cached_sess->next = cache->session_cache_head.next;
    cached_sess->next->prev = cached_sess;
    cached_sess->prev = &cache->session_cache_head;
    cache->session_cache_head.next = cached_sess;

    ngx_rbtree_insert(cache->session_rbtree, &sess_id->node);

    ngx_shmtx_unlock(&shpool->mutex);

    return 0;

failed:

    if (cached_sess) {
        ngx_slab_free_locked(shpool, cached_sess);
    }

    if (id) {
        ngx_slab_free_locked(shpool, id);
    }

    ngx_shmtx_unlock(&shpool->mutex);

    ngx_log_error(NGX_LOG_ALERT, c->log, 0,
                  "could not add new SSL session to the session cache");

    return 0;
}


static ngx_ssl_session_t *
ngx_http_ssl_get_session(ngx_ssl_conn_t *ssl_conn, u_char *id, int len,
    int *copy)
{
#if OPENSSL_VERSION_NUMBER >= 0x00908000
    const
#endif
    u_char                         *p;
    uint32_t                        hash;
    ngx_time_t                     *tp;
    ngx_slab_pool_t                *shpool;
    ngx_connection_t               *c;
    ngx_rbtree_node_t              *node, *sentinel;
    ngx_ssl_session_t              *sess;
    ngx_http_request_t             *r;
    ngx_http_ssl_sess_id_t         *sess_id;
    ngx_http_ssl_srv_conf_t        *sscf;
    ngx_http_ssl_cached_sess_t     *cached_sess;
    ngx_http_ssl_sesssion_cache_t  *cache;
    u_char                          buf[NGX_HTTP_SSL_MAX_SESSION_SIZE];

    c = ngx_ssl_get_connection(ssl_conn);
    r = c->data;

    sscf = ngx_http_get_module_srv_conf(r, ngx_http_ssl_module);

    hash = ngx_crc32_short(id, len);
    *copy = 0;

    ngx_log_debug2(NGX_LOG_DEBUG_HTTP, c->log, 0,
                   "http ssl get session: %08XD:%d", hash, len);

    cache = sscf->shm_zone->data;

    if (cache->session_rbtree == NULL) {
        return NULL;
    }

    sess = NULL;

    shpool = (ngx_slab_pool_t *) sscf->shm_zone->shm.addr;

    ngx_shmtx_lock(&shpool->mutex);

    node = cache->session_rbtree->root;
    sentinel = cache->session_rbtree->sentinel;

    while (node != sentinel) {

        if (hash < node->key) {
            node = node->left;
            continue;
        }

        if (hash > node->key) {
            node = node->right;
            continue;
        }

        if (hash == node->key && (u_char) len == node->data) {
            sess_id = (ngx_http_ssl_sess_id_t *) node;

            if (ngx_strncmp(id, sess_id->id, len) == 0) {

                cached_sess = sess_id->session;

                tp = ngx_timeofday();

                if (cached_sess->expire > tp->sec) {
                    ngx_memcpy(buf, &cached_sess->asn1[0], sess_id->len);

                    ngx_shmtx_unlock(&shpool->mutex);

                    p = buf;
                    sess = d2i_SSL_SESSION(NULL, &p, sess_id->len);

                    return sess;
                }

                cached_sess->next->prev = cached_sess->prev;
                cached_sess->prev->next = cached_sess->next;

                ngx_rbtree_delete(cache->session_rbtree, node);

                ngx_slab_free_locked(shpool, cached_sess);
                ngx_slab_free_locked(shpool, sess_id->id);
                ngx_slab_free_locked(shpool, sess_id);

                sess = NULL;

                break;
            }
        }

        node = node->right;
    }

    ngx_shmtx_unlock(&shpool->mutex);

    return sess;
}


static void
ngx_http_ssl_remove_session(SSL_CTX *ssl, ngx_ssl_session_t *sess)
{
    u_char                         *id, len;
    uint32_t                        hash;
    ngx_slab_pool_t                *shpool;
    ngx_rbtree_node_t              *node, *sentinel;
    ngx_http_ssl_sess_id_t         *sess_id;
    ngx_http_ssl_srv_conf_t        *sscf;
    ngx_http_ssl_cached_sess_t     *cached_sess;
    ngx_http_ssl_sesssion_cache_t  *cache;

    sscf = ngx_ssl_get_server_conf(ssl);

    cache = sscf->shm_zone->data;

    id = sess->session_id;
    len = (u_char) sess->session_id_length;

    hash = ngx_crc32_short(id, (size_t) len);

    ngx_log_debug2(NGX_LOG_DEBUG_HTTP, ngx_cycle->log, 0,
                   "http ssl remove session: %08XD:%d", hash, len);

    shpool = (ngx_slab_pool_t *) sscf->shm_zone->shm.addr;

    ngx_shmtx_lock(&shpool->mutex);

    node = cache->session_rbtree->root;
    sentinel = cache->session_rbtree->sentinel;

    while (node != sentinel) {

        if (hash < node->key) {
            node = node->left;
            continue;
        }

        if (hash > node->key) {
            node = node->right;
            continue;
        }

        if (hash == node->key && len == node->data) {
            sess_id = (ngx_http_ssl_sess_id_t *) node;

            if (ngx_strncmp(id, sess_id->id, (size_t) len) == 0) {

                cached_sess = sess_id->session;

                cached_sess->next->prev = cached_sess->prev;
                cached_sess->prev->next = cached_sess->next;

                ngx_rbtree_delete(cache->session_rbtree, node);

                ngx_slab_free_locked(shpool, cached_sess);
                ngx_slab_free_locked(shpool, sess_id->id);
                ngx_slab_free_locked(shpool, sess_id);

                break;
            }
        }

        node = node->right;
    }

    ngx_shmtx_unlock(&shpool->mutex);
}


static void
ngx_http_ssl_expire_sessions(ngx_http_ssl_sesssion_cache_t *cache,
    ngx_slab_pool_t *shpool, ngx_uint_t n)
{
    ngx_time_t                  *tp;
    ngx_http_ssl_sess_id_t      *sess_id;
    ngx_http_ssl_cached_sess_t  *sess;

    tp = ngx_timeofday();

    while (n < 3) {

        sess = cache->session_cache_tail.prev;

        if (sess == &cache->session_cache_head) {
            return;
        }

        if (n++ != 0 && sess->expire > tp->sec) {
            break;
        }

        sess->next->prev = sess->prev;
        sess->prev->next = sess->next;

        sess_id = sess->sess_id;

        ngx_rbtree_delete(cache->session_rbtree, &sess_id->node);

        ngx_log_debug1(NGX_LOG_DEBUG_HTTP, ngx_cycle->log, 0,
                       "expire session: %08Xi", sess_id->node.key);

        ngx_slab_free_locked(shpool, sess);
        ngx_slab_free_locked(shpool, sess_id->id);
        ngx_slab_free_locked(shpool, sess_id);
    }
}


static ngx_int_t
ngx_http_ssl_static_variable(ngx_http_request_t *r,
    ngx_http_variable_value_t *v, uintptr_t data)
{
    ngx_ssl_variable_handler_pt  handler = (ngx_ssl_variable_handler_pt) data;

    size_t  len;

    if (r->connection->ssl) {

        (void) handler(r->connection, NULL, (ngx_str_t *) v);

        for (len = 0; v->data[len]; len++) { /* void */ }

        v->len = len;
        v->valid = 1;
        v->no_cachable = 0;
        v->not_found = 0;

        return NGX_OK;
    }

    v->not_found = 1;

    return NGX_OK;
}


static ngx_int_t
ngx_http_ssl_variable(ngx_http_request_t *r, ngx_http_variable_value_t *v,
    uintptr_t data)
{
    ngx_ssl_variable_handler_pt  handler = (ngx_ssl_variable_handler_pt) data;

    if (r->connection->ssl) {
        if (handler(r->connection, r->pool, (ngx_str_t *) v) != NGX_OK) {
            return NGX_ERROR;
        }

        if (v->len) {
            v->valid = 1;
            v->no_cachable = 0;
            v->not_found = 0;

            return NGX_OK;
        }
    }

    v->not_found = 1;

    return NGX_OK;
}


static ngx_int_t
ngx_http_ssl_add_variables(ngx_conf_t *cf)
{
    ngx_http_variable_t  *var, *v;

    for (v = ngx_http_ssl_vars; v->name.len; v++) {
        var = ngx_http_add_variable(cf, &v->name, v->flags);
        if (var == NULL) {
            return NGX_ERROR;
        }

        var->get_handler = v->get_handler;
        var->data = v->data;
    }

    return NGX_OK;
}


static void *
ngx_http_ssl_create_srv_conf(ngx_conf_t *cf)
{
    ngx_http_ssl_srv_conf_t  *sscf;

    sscf = ngx_pcalloc(cf->pool, sizeof(ngx_http_ssl_srv_conf_t));
    if (sscf == NULL) {
        return NGX_CONF_ERROR;
    }

    /*
     * set by ngx_pcalloc():
     *
     *     sscf->protocols = 0;
     *     sscf->certificate.len = 0;
     *     sscf->certificate.data = NULL;
     *     sscf->certificate_key.len = 0;
     *     sscf->certificate_key.data = NULL;
     *     sscf->client_certificate.len = 0;
     *     sscf->client_certificate.data = NULL;
     *     sscf->ciphers.len = 0;
     *     sscf->ciphers.data = NULL;
     *     sscf->shm_zone = NULL;
     */

    sscf->enable = NGX_CONF_UNSET;
    sscf->verify = NGX_CONF_UNSET;
    sscf->verify_depth = NGX_CONF_UNSET;
    sscf->prefer_server_ciphers = NGX_CONF_UNSET;
    sscf->builtin_session_cache = NGX_CONF_UNSET;
    sscf->session_timeout = NGX_CONF_UNSET;

    return sscf;
}


static char *
ngx_http_ssl_merge_srv_conf(ngx_conf_t *cf, void *parent, void *child)
{
    ngx_http_ssl_srv_conf_t *prev = parent;
    ngx_http_ssl_srv_conf_t *conf = child;

    long                 cache_mode;
    ngx_pool_cleanup_t  *cln;

    ngx_conf_merge_value(conf->enable, prev->enable, 0);

    if (conf->enable == 0) {
        return NGX_CONF_OK;
    }

    ngx_conf_merge_value(conf->session_timeout,
                         prev->session_timeout, 300);

    ngx_conf_merge_value(conf->prefer_server_ciphers,
                         prev->prefer_server_ciphers, 0);

    ngx_conf_merge_bitmask_value(conf->protocols, prev->protocols,
                         (NGX_CONF_BITMASK_SET
                          |NGX_SSL_SSLv2|NGX_SSL_SSLv3|NGX_SSL_TLSv1));

    ngx_conf_merge_value(conf->verify, prev->verify, 0);
    ngx_conf_merge_value(conf->verify_depth, prev->verify_depth, 1);

    ngx_conf_merge_str_value(conf->certificate, prev->certificate,
                         NGX_DEFLAUT_CERTIFICATE);

    ngx_conf_merge_str_value(conf->certificate_key, prev->certificate_key,
                         NGX_DEFLAUT_CERTIFICATE_KEY);

    ngx_conf_merge_str_value(conf->client_certificate, prev->client_certificate,
                         "");

    ngx_conf_merge_str_value(conf->ciphers, prev->ciphers, NGX_DEFLAUT_CIPHERS);


    conf->ssl.log = cf->log;

    if (ngx_ssl_create(&conf->ssl, conf->protocols, conf) != NGX_OK) {
        return NGX_CONF_ERROR;
    }

    cln = ngx_pool_cleanup_add(cf->pool, 0);
    if (cln == NULL) {
        return NGX_CONF_ERROR;
    }

    cln->handler = ngx_ssl_cleanup_ctx;
    cln->data = &conf->ssl;

    if (ngx_ssl_certificate(cf, &conf->ssl, &conf->certificate,
                            &conf->certificate_key)
        != NGX_OK)
    {
        return NGX_CONF_ERROR;
    }

    if (SSL_CTX_set_cipher_list(conf->ssl.ctx,
                                (const char *) conf->ciphers.data)
        == 0)
    {
        ngx_ssl_error(NGX_LOG_EMERG, cf->log, 0,
                      "SSL_CTX_set_cipher_list(\"%V\") failed",
                      &conf->ciphers);
    }

    if (conf->verify) {
        if (ngx_ssl_client_certificate(cf, &conf->ssl,
                                       &conf->client_certificate,
                                       conf->verify_depth)
            != NGX_OK)
        {
            return NGX_CONF_ERROR;
        }
    }

#ifdef SSL_OP_CIPHER_SERVER_PREFERENCE

    if (conf->prefer_server_ciphers) {
        SSL_CTX_set_options(conf->ssl.ctx, SSL_OP_CIPHER_SERVER_PREFERENCE);
    }

#endif

    /* a temporary 512-bit RSA key is required for export versions of MSIE */
    if (ngx_ssl_generate_rsa512_key(&conf->ssl) != NGX_OK) {
        return NGX_CONF_ERROR;
    }

    ngx_conf_merge_value(conf->builtin_session_cache,
                         prev->builtin_session_cache,
                         NGX_HTTP_SSL_DFLT_BUILTIN_SCACHE);

    if (conf->shm_zone == NULL) {
        conf->shm_zone = prev->shm_zone;
    }

    cache_mode = SSL_SESS_CACHE_SERVER;

    if (conf->shm_zone
        && conf->builtin_session_cache == NGX_HTTP_SSL_NO_BUILTIN_SCACHE)
    {
        cache_mode |= SSL_SESS_CACHE_NO_INTERNAL;
    }

    SSL_CTX_set_session_cache_mode(conf->ssl.ctx, cache_mode);

    SSL_CTX_set_session_id_context(conf->ssl.ctx, ngx_http_session_id_ctx,
                                   sizeof(ngx_http_session_id_ctx) - 1);

    if (conf->builtin_session_cache != NGX_HTTP_SSL_NO_BUILTIN_SCACHE) {

        if (conf->builtin_session_cache != NGX_HTTP_SSL_DFLT_BUILTIN_SCACHE) {
            SSL_CTX_sess_set_cache_size(conf->ssl.ctx,
                                        conf->builtin_session_cache);
        }

        SSL_CTX_set_timeout(conf->ssl.ctx, conf->session_timeout);
    }

    if (conf->shm_zone) {
        SSL_CTX_sess_set_new_cb(conf->ssl.ctx, ngx_http_ssl_new_session);
        SSL_CTX_sess_set_get_cb(conf->ssl.ctx, ngx_http_ssl_get_session);
        SSL_CTX_sess_set_remove_cb(conf->ssl.ctx, ngx_http_ssl_remove_session);
    }

    return NGX_CONF_OK;
}


static char *
ngx_http_ssl_session_cache(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    ngx_http_ssl_srv_conf_t *sscf = conf;

    size_t       len;
    ngx_str_t   *value, name, size;
    ngx_int_t    n;
    ngx_uint_t   i, j;

    value = cf->args->elts;

    for (i = 1; i < cf->args->nelts; i++) {

        if (ngx_strcmp(value[i].data, "builtin") == 0) {
            sscf->builtin_session_cache = NGX_HTTP_SSL_DFLT_BUILTIN_SCACHE;
            continue;
        }

        if (value[i].len > sizeof("builtin:") - 1
            && ngx_strncmp(value[i].data, "builtin:", sizeof("builtin:") - 1)
               == 0)
        {
            n = ngx_atoi(value[i].data + sizeof("builtin:") - 1,
                         value[i].len - (sizeof("builtin:") - 1));

            if (n == NGX_ERROR) {
                goto invalid;
            }

            sscf->builtin_session_cache = n;

            continue;
        }

        if (value[i].len > sizeof("shared:") - 1
            && ngx_strncmp(value[i].data, "shared:", sizeof("shared:") - 1)
               == 0)
        {
            len = 0;

            for (j = sizeof("shared:") - 1; j < value[i].len; j++) {
                if (value[i].data[j] == ':') {
                    break;
                }

                len++;
            }

            if (len == 0) {
                goto invalid;
            }

            name.len = len;
            name.data = value[i].data + sizeof("shared:") - 1;

            size.len = value[i].len - j - 1;
            size.data = name.data + len + 1;

            n = ngx_parse_size(&size);

            if (n == NGX_ERROR) {
                goto invalid;
            }

            if (n < (ngx_int_t) (8 * ngx_pagesize)) {
                ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                                   "session cache \"%V\" to small",
                                   &value[i]);

                return NGX_CONF_ERROR;
            }

            sscf->shm_zone = ngx_shared_memory_add(cf, &name, n,
                                                   &ngx_http_ssl_module);
            if (sscf->shm_zone == NULL) {
                return NGX_CONF_ERROR;
            }

            sscf->shm_zone->init = ngx_http_ssl_session_cache_init;

            continue;
        }

        goto invalid;
    }

    if (sscf->shm_zone && sscf->builtin_session_cache == NGX_CONF_UNSET) {
        sscf->builtin_session_cache = NGX_HTTP_SSL_NO_BUILTIN_SCACHE;
    }

    return NGX_CONF_OK;

invalid:

    ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                       "invalid session cache \"%V\"", &value[i]);

    return NGX_CONF_ERROR;
}


#if !defined (SSL_OP_CIPHER_SERVER_PREFERENCE)

static char *
ngx_http_ssl_nosupported(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                       "\"%V\" directive is available only in %s,",
                       &cmd->name, cmd->post);

    return NGX_CONF_ERROR;
}

#endif
