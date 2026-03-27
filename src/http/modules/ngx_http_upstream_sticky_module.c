
/*
 * Copyright (C) Nginx, Inc.
 */


#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>
#include <ngx_md5.h>


#define NGX_HTTP_STICKY_COOKIE_MAX_EXPIRES  2145916555

#define ngx_http_upstream_sticky_sess_node(rbn, mb)                           \
    (ngx_http_upstream_sticky_sess_node_t *)                                  \
        ((char *) (rbn) - offsetof(ngx_http_upstream_sticky_sess_node_t, mb))


typedef union {
    u_char                                      md5[16];
    ngx_uint_t                                  hash;
} ngx_http_upstream_sticky_sess_key_t;


typedef struct {
    ngx_rbtree_t                                rbtree;
    ngx_rbtree_node_t                           sentinel;

    ngx_rbtree_t                                exp_rbtree;
    ngx_rbtree_node_t                           exp_sentinel;
} ngx_http_upstream_sticky_sess_shared_t;


typedef struct {
    ngx_http_upstream_sticky_sess_shared_t     *sh;
    ngx_slab_pool_t                            *shpool;
    ngx_str_t                                  *host;

    ngx_msec_t                                  timeout;
    ngx_event_t                                 event;
} ngx_http_upstream_sticky_sess_t;


/* session data: mapping of session ID hash to server ID */
typedef struct {
    ngx_rbtree_node_t                           rbnode;
    ngx_rbtree_node_t                           enode;

    union {
        u_char                                  md5[16];
        ngx_uint_t                              hash;
    } u;

    ngx_msec_t                                  last;

    u_char                                      sid_len;
    u_char                                      sid[NGX_HTTP_UPSTREAM_SID_LEN];
} ngx_http_upstream_sticky_sess_node_t;


/* per-upstream sticky configuration */
typedef struct {
    ngx_http_upstream_init_pt                   original_init_upstream;
    ngx_http_upstream_init_peer_pt              original_init_peer;

    ngx_array_t                                *lookup_vars; /* of ngx_int_t */
    ngx_array_t                                *create_vars; /* of ngx_int_t */
    ngx_shm_zone_t                             *shm_zone;    /* sessions */

    ngx_str_t                                   cookie_name;
    ngx_http_complex_value_t                   *cookie_domain;
    ngx_str_t                                   cookie_path;
    time_t                                      cookie_expires;
    ngx_http_complex_value_t                   *cookie_samesite;
    unsigned                                    cookie_httponly:1;
    unsigned                                    cookie_secure:1;
    unsigned                                    learn_after_headers:1;
} ngx_http_upstream_sticky_srv_conf_t;


typedef struct {
    void                                       *original_data;
    ngx_http_request_t                         *request;

    ngx_http_upstream_sticky_srv_conf_t        *conf;

    ngx_str_t                                   id;
    ngx_table_elt_t                            *cookie;

    ngx_event_get_peer_pt                       original_get_peer;
    ngx_event_free_peer_pt                      original_free_peer;

#if (NGX_HTTP_SSL)
    ngx_event_set_peer_session_pt               original_set_session;
    ngx_event_save_peer_session_pt              original_save_session;
#endif

    ngx_event_notify_peer_pt                    original_notify;

} ngx_http_upstream_sticky_peer_data_t;


static ngx_int_t ngx_http_upstream_sticky_init_upstream(ngx_conf_t *cf,
    ngx_http_upstream_srv_conf_t *us);
static ngx_int_t ngx_http_upstream_sticky_init_peer(ngx_http_request_t *r,
    ngx_http_upstream_srv_conf_t *us);
static ngx_int_t ngx_http_upstream_sticky_get_id(
    ngx_http_upstream_sticky_srv_conf_t *stcf, ngx_http_request_t *r,
    ngx_array_t *vars, ngx_str_t *id);
static void ngx_http_upstream_sticky_sess_init_key(ngx_str_t *sess_id,
    ngx_http_upstream_sticky_sess_key_t *key);
static ngx_int_t ngx_http_upstream_sticky_get_peer(ngx_peer_connection_t *pc,
    void *data);
static void ngx_http_upstream_sticky_free_peer(ngx_peer_connection_t *pc,
    void *data, ngx_uint_t state);
static void ngx_http_upstream_sticky_learn_peer(
    ngx_http_upstream_sticky_peer_data_t *stp, ngx_peer_connection_t *pc);


#if (NGX_HTTP_SSL)
static ngx_int_t ngx_http_upstream_sticky_set_session(
    ngx_peer_connection_t *pc, void *data);
static void ngx_http_upstream_sticky_save_session(ngx_peer_connection_t *pc,
    void *data);
#endif


static void ngx_http_upstream_sticky_notify_peer(
    ngx_peer_connection_t *pc, void *data, ngx_uint_t type);
static ngx_int_t ngx_http_upstream_sticky_cookie_insert(
    ngx_peer_connection_t *pc, ngx_http_upstream_sticky_peer_data_t *stp);
static ngx_int_t ngx_http_upstream_sticky_samesite(ngx_str_t *value);


static ngx_http_upstream_sticky_sess_node_t *
    ngx_http_upstream_sticky_sess_lookup(ngx_http_upstream_sticky_sess_t *sess,
    ngx_http_upstream_sticky_sess_key_t *key);
static ngx_http_upstream_sticky_sess_node_t *
    ngx_http_upstream_sticky_sess_create(ngx_http_upstream_sticky_sess_t *sess,
    ngx_http_upstream_sticky_sess_key_t *key, ngx_str_t *sid);
static void ngx_http_upstream_sticky_sess_rbtree_insert_value(
    ngx_rbtree_node_t *temp, ngx_rbtree_node_t *node,
    ngx_rbtree_node_t *sentinel);
static void ngx_http_upstream_sticky_sess_timer_handler(ngx_event_t *ev);
static ngx_msec_t ngx_http_upstream_sticky_sess_expire(
    ngx_http_upstream_sticky_sess_t *sess, ngx_uint_t force);
static ngx_int_t ngx_http_upstream_sticky_sess_init_zone(
    ngx_shm_zone_t *shm_zone, void *data);

static void *ngx_http_upstream_sticky_create_conf(ngx_conf_t *cf);
static char *ngx_http_upstream_sticky(ngx_conf_t *cf, ngx_command_t *cmd,
    void *conf);
static char *ngx_http_upstream_sticky_cookie(ngx_conf_t *cf,
    ngx_http_upstream_sticky_srv_conf_t *stcf);
static char *ngx_http_upstream_sticky_learn(ngx_conf_t *cf,
    ngx_http_upstream_sticky_srv_conf_t *stcf,
    ngx_http_upstream_srv_conf_t *us);

static ngx_int_t ngx_http_upstream_sticky_init_worker(ngx_cycle_t *cycle);


static u_char expires[] =
    "; expires=Thu, 31-Dec-37 23:55:55 GMT; max-age=315360000";
static u_char httponly[] = "; httponly";
static u_char secure[] = "; secure";


static ngx_command_t  ngx_http_upstream_sticky_commands[] = {

    { ngx_string("sticky"),
      NGX_HTTP_UPS_CONF|NGX_CONF_2MORE,
      ngx_http_upstream_sticky,
      0,
      0,
      NULL },

      ngx_null_command
};


static ngx_http_module_t
ngx_http_upstream_sticky_module_ctx = {
    NULL,                                 /* preconfiguration */
    NULL,                                 /* postconfiguration */

    NULL,                                 /* create main configuration */
    NULL,                                 /* init main configuration */

    ngx_http_upstream_sticky_create_conf, /* create server configuration */
    NULL,                                 /* merge server configuration */

    NULL,                                 /* create location configuration */
    NULL                                  /* merge location configuration */
};


ngx_module_t
ngx_http_upstream_sticky_module =
{
    NGX_MODULE_V1,

    &ngx_http_upstream_sticky_module_ctx, /* module context */
    ngx_http_upstream_sticky_commands,    /* module directives */

    NGX_HTTP_MODULE,                      /* module type */
    NULL,                                 /* init master */

    NULL,                                 /* init module */
    ngx_http_upstream_sticky_init_worker, /* init process */

    NULL,                                 /* init thread */
    NULL,                                 /* exit thread */

    NULL,                                 /* exit process */
    NULL,                                 /* exit master */

    NGX_MODULE_V1_PADDING
};


static ngx_int_t
ngx_http_upstream_sticky_init_upstream(ngx_conf_t *cf,
    ngx_http_upstream_srv_conf_t *us)
{
    ngx_http_upstream_sticky_srv_conf_t  *stcf;

    stcf = ngx_http_conf_upstream_srv_conf(us, ngx_http_upstream_sticky_module);

    if (stcf->original_init_upstream(cf, us) != NGX_OK) {
        return NGX_ERROR;
    }

    stcf->original_init_peer = us->peer.init;
    us->peer.init = ngx_http_upstream_sticky_init_peer;

    return NGX_OK;
}


static ngx_int_t
ngx_http_upstream_sticky_init_peer(ngx_http_request_t *r,
    ngx_http_upstream_srv_conf_t *us)
{
    ngx_int_t                              rc;
    ngx_http_upstream_t                   *u;
    ngx_http_upstream_sticky_srv_conf_t   *stcf;
    ngx_http_upstream_sticky_peer_data_t  *stp;

    stcf = ngx_http_conf_upstream_srv_conf(us, ngx_http_upstream_sticky_module);

    stp = ngx_pcalloc(r->pool, sizeof(ngx_http_upstream_sticky_peer_data_t));
    if (stp == NULL) {
        return NGX_ERROR;
    }

    rc = stcf->original_init_peer(r, us);

    if (rc != NGX_OK) {
        return rc;
    }

    u = r->upstream;

    stp->original_data = u->peer.data;
    stp->original_get_peer = u->peer.get;
    stp->original_free_peer = u->peer.free;

    stp->request = r;
    stp->conf = stcf;

    u->peer.get = ngx_http_upstream_sticky_get_peer;
    u->peer.free = ngx_http_upstream_sticky_free_peer;
    u->peer.data = stp;

#if (NGX_HTTP_SSL)
    stp->original_set_session = u->peer.set_session;
    stp->original_save_session = u->peer.save_session;
    u->peer.set_session = ngx_http_upstream_sticky_set_session;
    u->peer.save_session = ngx_http_upstream_sticky_save_session;
#endif

    if (u->peer.notify || stcf->learn_after_headers) {
        stp->original_notify = u->peer.notify;
        u->peer.notify = ngx_http_upstream_sticky_notify_peer;
    }

    ngx_http_upstream_sticky_get_id(stcf, r, stcf->lookup_vars, &stp->id);

    return NGX_OK;
}


static ngx_int_t
ngx_http_upstream_sticky_get_id(ngx_http_upstream_sticky_srv_conf_t *stcf,
    ngx_http_request_t *r, ngx_array_t *vars, ngx_str_t *id)
{
    ngx_int_t                  *index;
    ngx_uint_t                  i;
    ngx_http_variable_value_t  *v;

    index = vars->elts;

    for (i = 0; i < vars->nelts; i++) {

        v = ngx_http_get_flushed_variable(r, index[i]);

        if (v == NULL || v->not_found || v->len == 0) {
            continue;
        }

        id->data = v->data;
        id->len = v->len;

        ngx_log_debug2(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                       "sticky: using \"%v\" found in variable #%i", v, i + 1);

        return NGX_OK;
    }

    ngx_str_null(id);

    return NGX_DONE;
}


static ngx_inline void
ngx_http_upstream_sticky_sess_init_key(ngx_str_t *sess_id,
    ngx_http_upstream_sticky_sess_key_t *key)
{
    ngx_md5_t  md5;

    ngx_md5_init(&md5);
    ngx_md5_update(&md5, sess_id->data, sess_id->len);
    ngx_md5_final(key->md5, &md5);
}


static ngx_int_t
ngx_http_upstream_sticky_get_peer(ngx_peer_connection_t *pc, void *data)
{
    ngx_http_upstream_sticky_peer_data_t  *stp = data;

    ngx_int_t                              rc;
    ngx_str_t                              sid;
    ngx_http_upstream_sticky_sess_t       *sess;
    ngx_http_upstream_sticky_sess_key_t    key;
    ngx_http_upstream_sticky_sess_node_t  *sn;
    u_char                                 sid_data[NGX_HTTP_UPSTREAM_SID_LEN];

    if (pc->hint == NULL && stp->conf->shm_zone && stp->id.len) {

        /* request holds session ID, extract server ID from session */

        sess = stp->conf->shm_zone->data;

        ngx_http_upstream_sticky_sess_init_key(&stp->id, &key);

        ngx_shmtx_lock(&sess->shpool->mutex);

        sn = ngx_http_upstream_sticky_sess_lookup(sess, &key);
        if (sn == NULL) {
            ngx_log_debug1(NGX_LOG_DEBUG_HTTP, pc->log, 0,
                           "sticky: session \"%V\" not found", &stp->id);

        } else {
            ngx_memcpy(sid_data, sn->sid, sn->sid_len);
            sid.len = sn->sid_len;
            sid.data = sid_data;
            pc->hint = &sid;

            ngx_log_debug2(NGX_LOG_DEBUG_HTTP, pc->log, 0,
                           "sticky: session \"%V\", SID \"%V\"",
                           &stp->id, &sid);
        }

        ngx_shmtx_unlock(&sess->shpool->mutex);

    } else if (pc->hint == NULL && stp->id.len) {

        /* request holds server ID */

        pc->hint = &stp->id;
    }

    rc = stp->original_get_peer(pc, stp->original_data);

    pc->hint = NULL;

    if (rc != NGX_OK && rc != NGX_DONE) {
        return rc;
    }

    if (stp->conf->cookie_name.len == 0) {
        return rc;
    }

    if (ngx_http_upstream_sticky_cookie_insert(pc, stp) != NGX_OK) {
        return NGX_ERROR;
    }

    return rc;
}


static void
ngx_http_upstream_sticky_free_peer(ngx_peer_connection_t *pc, void *data,
    ngx_uint_t state)
{
    ngx_http_upstream_sticky_peer_data_t  *stp = data;

    if (state & (NGX_PEER_FAILED|NGX_PEER_NEXT)) {
        goto done;
    }

    if (stp->conf->shm_zone && !stp->conf->learn_after_headers) {
        ngx_http_upstream_sticky_learn_peer(stp, pc);
    }

done:

    stp->original_free_peer(pc, stp->original_data, state);
}


static void
ngx_http_upstream_sticky_learn_peer(ngx_http_upstream_sticky_peer_data_t *stp,
    ngx_peer_connection_t *pc)
{
    ngx_str_t                              sess_id;
    ngx_msec_t                             now;
    ngx_time_t                            *tp;
    ngx_uint_t                             create;
    ngx_http_request_t                    *r;
    ngx_http_upstream_sticky_sess_t       *sess;
    ngx_http_upstream_sticky_sess_key_t    key;
    ngx_http_upstream_sticky_srv_conf_t   *stcf;
    ngx_http_upstream_sticky_sess_node_t  *sn;

    if (pc->sid == NULL) {
        ngx_log_error(NGX_LOG_WARN, pc->log, 0,
                      "balancer does not support sticky");
        return;
    }

    stcf = stp->conf;

    r = stp->request;

    sess = stcf->shm_zone->data;

    if (ngx_http_upstream_sticky_get_id(stcf, r, stcf->create_vars, &sess_id)
        == NGX_OK)
    {
        create = 1;

    } else if (stp->id.len) {
        sess_id = stp->id;
        create = 0;

    } else {
        return;
    }

    tp = ngx_timeofday();
    now = tp->sec * 1000 + tp->msec;

    ngx_http_upstream_sticky_sess_init_key(&sess_id, &key);

    ngx_shmtx_lock(&sess->shpool->mutex);

    sn = ngx_http_upstream_sticky_sess_lookup(sess, &key);

    if (sn) {
        if (pc->sid->len != sn->sid_len
            || ngx_memcmp(pc->sid->data, sn->sid, sn->sid_len) != 0)
        {
            ngx_log_debug2(NGX_LOG_DEBUG_HTTP, pc->log, 0,
                           "sticky: session \"%V\" reused for SID \"%V\"",
                           &sess_id, pc->sid);

            sn->sid_len = pc->sid->len;
            ngx_memcpy(sn->sid, pc->sid->data, pc->sid->len);
        }

        ngx_rbtree_delete(&sess->sh->exp_rbtree, &sn->enode);
        sn->last = now;
        sn->enode.key = sn->last;
        ngx_rbtree_insert(&sess->sh->exp_rbtree, &sn->enode);

        ngx_shmtx_unlock(&sess->shpool->mutex);
        return;
    }

    if (create) {
        ngx_log_debug2(NGX_LOG_DEBUG_HTTP, pc->log, 0,
                       "sticky: creating session \"%V\", SID \"%V\"",
                       &sess_id, pc->sid);

        sn = ngx_http_upstream_sticky_sess_create(sess, &key, pc->sid);

        if (sn) {
            sn->last = now;
            sn->enode.key = sn->last;
            ngx_rbtree_insert(&sess->sh->exp_rbtree, &sn->enode);

            if (!sess->event.timer_set) {
                ngx_add_timer(&sess->event, sess->timeout);
            }
        }
    }

    ngx_shmtx_unlock(&sess->shpool->mutex);
}


#if (NGX_HTTP_SSL)

static ngx_int_t
ngx_http_upstream_sticky_set_session(ngx_peer_connection_t *pc, void *data)
{
    ngx_http_upstream_sticky_peer_data_t  *stp = data;

    return stp->original_set_session(pc, stp->original_data);
}


static void
ngx_http_upstream_sticky_save_session(ngx_peer_connection_t *pc, void *data)
{
    ngx_http_upstream_sticky_peer_data_t  *stp = data;

    stp->original_save_session(pc, stp->original_data);
}

#endif


static void
ngx_http_upstream_sticky_notify_peer(ngx_peer_connection_t *pc, void *data,
    ngx_uint_t type)
{
    ngx_http_upstream_sticky_peer_data_t  *stp = data;

    if (type == NGX_HTTP_UPSTREAM_NOTIFY_HEADER
        && stp->conf->learn_after_headers)
    {
        ngx_http_upstream_sticky_learn_peer(stp, pc);
    }

    if (stp->original_notify) {
        stp->original_notify(pc, stp->original_data, type);
    }
}


static ngx_int_t
ngx_http_upstream_sticky_cookie_insert(ngx_peer_connection_t *pc,
    ngx_http_upstream_sticky_peer_data_t *stp)
{
    size_t                                len;
    u_char                               *data, *p;
    ngx_str_t                             domain, samesite;
    ngx_table_elt_t                      *cookie;
    ngx_http_request_t                   *r;
    ngx_http_upstream_sticky_srv_conf_t  *stcf;

    stcf = stp->conf;
    r = stp->request;

    if (pc->sid == NULL) {
        ngx_log_error(NGX_LOG_WARN, pc->log, 0,
                      "balancer does not support sticky");
        return NGX_OK;
    }

#if (NGX_DEBUG)

    if (stp->id.len) {

        /* check that the selected peer matches SID from request */

        if (pc->sid->len != stp->id.len
            || ngx_memcmp(pc->sid->data, stp->id.data, stp->id.len) != 0)
        {
            ngx_log_debug0(NGX_LOG_DEBUG_HTTP, pc->log, 0,
                           "sticky: server with requested SID is unavailable");
        }
    }

#endif

    len = stcf->cookie_name.len + 1 + pc->sid->len + stcf->cookie_path.len;

    ngx_str_set(&domain, "");

    if (stcf->cookie_domain) {
        if (ngx_http_complex_value(r, stcf->cookie_domain, &domain)
            != NGX_OK)
        {
            return NGX_ERROR;
        }
    }

    if (domain.len) {
        len += sizeof("; domain=") - 1 + domain.len;
    }

    if (stcf->cookie_expires != (time_t) NGX_CONF_UNSET) {
        len += sizeof(expires) - 1 + NGX_TIME_T_LEN;
    }

    if (stcf->cookie_httponly) {
        len += sizeof(httponly) - 1;
    }

    if (stcf->cookie_secure) {
        len += sizeof(secure) - 1;
    }

    ngx_str_set(&samesite, "");

    if (stcf->cookie_samesite) {

        if (ngx_http_complex_value(r, stcf->cookie_samesite, &samesite)
            != NGX_OK)
        {
            return NGX_ERROR;
        }

        if (stcf->cookie_samesite->lengths && samesite.len
            && ngx_http_upstream_sticky_samesite(&samesite) != NGX_OK)
        {
            ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                           "sticky: invalid cookie samesite value \"%V\"",
                           &samesite);
            ngx_str_set(&samesite, "strict");
        }
    }

    if (samesite.len) {
        len += sizeof("; samesite=") - 1 + samesite.len;
    }

    data = ngx_pnalloc(r->pool, len);
    if (data == NULL) {
        return NGX_ERROR;
    }

    p = ngx_copy(data, stcf->cookie_name.data, stcf->cookie_name.len);
    *p++ = '=';
    p = ngx_copy(p, pc->sid->data, pc->sid->len);

    if (stcf->cookie_expires != (time_t) NGX_CONF_UNSET) {

        if (stcf->cookie_expires == NGX_HTTP_STICKY_COOKIE_MAX_EXPIRES) {
            p = ngx_cpymem(p, expires, sizeof(expires) - 1);

        } else {
            p = ngx_cpymem(p, "; expires=", 10);
            p = ngx_http_cookie_time(p, ngx_time() + stcf->cookie_expires);
            p = ngx_sprintf(p, "; max-age=%T", stcf->cookie_expires);
        }
    }

    if (domain.len) {
        p = ngx_cpymem(p, "; domain=", 9);
        p = ngx_copy(p, domain.data, domain.len);
    }

    if (stcf->cookie_httponly) {
        p = ngx_copy(p, httponly, sizeof(httponly) - 1);
    }

    if (stcf->cookie_secure) {
        p = ngx_copy(p, secure, sizeof(secure) - 1);
    }

    if (samesite.len) {
        p = ngx_cpymem(p, "; samesite=", 11);
        p = ngx_copy(p, samesite.data, samesite.len);
    }

    p = ngx_cpymem(p, stcf->cookie_path.data, stcf->cookie_path.len);

    cookie = stp->cookie;

    if (cookie == NULL) {

        cookie = ngx_list_push(&r->headers_out.headers);
        if (cookie == NULL) {
            return NGX_ERROR;
        }

        cookie->hash = 1;
        cookie->next = NULL;
        ngx_str_set(&cookie->key, "Set-Cookie");

        stp->cookie = cookie;
    }

    cookie->value.len = p - data;
    cookie->value.data = data;

    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "sticky: set cookie: \"%V\"", &cookie->value);

    return NGX_OK;
}


static ngx_int_t
ngx_http_upstream_sticky_samesite(ngx_str_t *value)
{
    ngx_uint_t  i;

    static ngx_str_t samesite[] = {
        ngx_string("strict"),
        ngx_string("lax"),
        ngx_string("none"),
        ngx_null_string
    };

    for (i = 0; samesite[i].len != 0; i++) {

        if (samesite[i].len == value->len
            && ngx_strncasecmp(samesite[i].data, value->data, value->len) == 0)
        {
            return NGX_OK;
        }
    }

    return NGX_ERROR;
}


static ngx_http_upstream_sticky_sess_node_t *
ngx_http_upstream_sticky_sess_lookup(ngx_http_upstream_sticky_sess_t *sess,
    ngx_http_upstream_sticky_sess_key_t *key)
{
    ngx_int_t                              rc;
    ngx_uint_t                             hash;
    ngx_rbtree_node_t                     *node, *sentinel;
    ngx_http_upstream_sticky_sess_node_t  *sn;

    hash = key->hash;
    node = sess->sh->rbtree.root;
    sentinel = sess->sh->rbtree.sentinel;

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

        do {

            sn = (ngx_http_upstream_sticky_sess_node_t *) node;

            rc = ngx_memcmp(key->md5, sn->u.md5, 16);

            if (rc == 0) {
                return sn;
            }

            node = (rc < 0) ? node->left : node->right;

        } while (node != sentinel && hash == node->key);

        break;
    }

    return NULL;
}


static ngx_http_upstream_sticky_sess_node_t *
ngx_http_upstream_sticky_sess_create(ngx_http_upstream_sticky_sess_t *sess,
    ngx_http_upstream_sticky_sess_key_t *key, ngx_str_t *sid)
{
    size_t                                 n;
    ngx_rbtree_node_t                     *node;
    ngx_http_upstream_sticky_sess_node_t  *sn;

    n = sizeof(ngx_http_upstream_sticky_sess_node_t);

    sn = ngx_slab_alloc_locked(sess->shpool, n);
    if (sn == NULL) {

        ngx_log_error(NGX_LOG_WARN, ngx_cycle->log, 0,
                      "could not allocate node%s, expiring least "
                      "recently used session", sess->shpool->log_ctx);

        (void) ngx_http_upstream_sticky_sess_expire(sess, 1);

        sn = ngx_slab_alloc_locked(sess->shpool, n);
        if (sn == NULL) {
            ngx_log_error(NGX_LOG_ALERT, ngx_cycle->log, 0,
                          "could not allocate node%s", sess->shpool->log_ctx);
            return NULL;
        }
    }

    ngx_memcpy(sn->u.md5, key->md5, 16);

    sn->sid_len = sid->len;
    ngx_memcpy(sn->sid, sid->data, sid->len);

    node = &sn->rbnode;
    node->key = sn->u.hash;

    ngx_rbtree_insert(&sess->sh->rbtree, node);

    return sn;
}


static void
ngx_http_upstream_sticky_sess_rbtree_insert_value(ngx_rbtree_node_t *temp,
    ngx_rbtree_node_t *node, ngx_rbtree_node_t *sentinel)
{
    ngx_rbtree_node_t                     **p;
    ngx_http_upstream_sticky_sess_node_t  *sn, *snt;

    for ( ;; ) {

        if (node->key < temp->key) {

            p = &temp->left;

        } else if (node->key > temp->key) {

            p = &temp->right;

        } else { /* node->key == temp->key */

            sn = (ngx_http_upstream_sticky_sess_node_t *) node;
            snt = (ngx_http_upstream_sticky_sess_node_t *) temp;

            p = (ngx_memcmp(sn->u.md5, snt->u.md5, 16) < 0)
                ? &temp->left : &temp->right;
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


static void
ngx_http_upstream_sticky_sess_timer_handler(ngx_event_t *ev)
{
    ngx_msec_t                        wait;
    ngx_http_upstream_sticky_sess_t  *sess;

    sess = ev->data;

    ngx_log_debug0(NGX_LOG_DEBUG_EVENT, ev->log, 0,
                   "sticky: session timer");

    ngx_shmtx_lock(&sess->shpool->mutex);

    wait = ngx_http_upstream_sticky_sess_expire(sess, 0);

    ngx_shmtx_unlock(&sess->shpool->mutex);

    if (wait > 0) {
        ngx_add_timer(&sess->event, wait);
    }
}


static ngx_msec_t
ngx_http_upstream_sticky_sess_expire(ngx_http_upstream_sticky_sess_t *sess,
    ngx_uint_t force)
{
    ngx_msec_t                             now, wait;
    ngx_time_t                            *tp;
    ngx_rbtree_node_t                     *node, *next;
    ngx_http_upstream_sticky_sess_node_t  *sn;

    wait = 0;

    tp = ngx_timeofday();
    now = tp->sec * 1000 + tp->msec;

    if (sess->sh->exp_rbtree.root == sess->sh->exp_rbtree.sentinel) {
        return 0;
    }

#if (NGX_SUPPRESS_WARN)
    next = NULL;
#endif

    for (node = ngx_rbtree_min(sess->sh->exp_rbtree.root,
                               sess->sh->exp_rbtree.sentinel);
         node;
         node = next)
    {

        sn = ngx_http_upstream_sticky_sess_node(node, enode);
        wait = sn->last + sess->timeout - now;

        if (!force && (ngx_msec_int_t) wait > 0) {
            break;
        }

        force = 0;

        next = ngx_rbtree_next(&sess->sh->exp_rbtree, node);

        /* remove node */
        node = &sn->enode;
        ngx_rbtree_delete(&sess->sh->exp_rbtree, node);

        node = &sn->rbnode;
        ngx_rbtree_delete(&sess->sh->rbtree, node);
        ngx_slab_free_locked(sess->shpool, node);
    }

    return wait;
}


static ngx_int_t
ngx_http_upstream_sticky_sess_init_zone(ngx_shm_zone_t *shm_zone, void *data)
{
    ngx_http_upstream_sticky_sess_t  *old_sess = data;

    size_t                            len;
    ngx_http_upstream_sticky_sess_t  *sess;

    sess = shm_zone->data;

    if (old_sess) {

        if (ngx_strcmp(sess->host->data, old_sess->host->data) != 0) {

            ngx_log_error(NGX_LOG_EMERG, shm_zone->shm.log, 0,
                          "sticky zone \"%V\" is used in upstream \"%V\" "
                          "while previously it was used in upstream \"%V\"",
                          &shm_zone->shm.name, sess->host, old_sess->host);

            return NGX_ERROR;
        }

        sess->sh = old_sess->sh;
        sess->shpool = old_sess->shpool;
        return NGX_OK;
    }

    sess->shpool = (ngx_slab_pool_t *) shm_zone->shm.addr;

    if (shm_zone->shm.exists) {
        sess->sh = sess->shpool->data;
        return NGX_OK;
    }

    sess->sh = ngx_slab_alloc(sess->shpool,
                              sizeof(ngx_http_upstream_sticky_sess_shared_t));
    if (sess->sh == NULL) {
        return NGX_ERROR;
    }

    sess->shpool->data = sess->sh;

    ngx_rbtree_init(&sess->sh->rbtree, &sess->sh->sentinel,
                    ngx_http_upstream_sticky_sess_rbtree_insert_value);

    ngx_rbtree_init(&sess->sh->exp_rbtree, &sess->sh->exp_sentinel,
                    ngx_rbtree_insert_timer_value);

    len = sizeof(" in sticky session zone \"\"") + shm_zone->shm.name.len;

    sess->shpool->log_ctx = ngx_slab_alloc(sess->shpool, len);
    if (sess->shpool->log_ctx == NULL) {
        return NGX_ERROR;
    }

    ngx_sprintf(sess->shpool->log_ctx, " in sticky session zone \"%V\"%Z",
                &shm_zone->shm.name);

    sess->shpool->log_nomem = 0;

    return NGX_OK;
}


static void *
ngx_http_upstream_sticky_create_conf(ngx_conf_t *cf)
{
    ngx_http_upstream_sticky_srv_conf_t  *stcf;

    stcf = ngx_pcalloc(cf->pool, sizeof(ngx_http_upstream_sticky_srv_conf_t));
    if (stcf == NULL) {
        return NULL;
    }

    /*
     * set by ngx_pcalloc():
     *
     *     stcf->original_init_upstream = NULL;
     *     stcf->original_init_peer = NULL;
     *
     *     stcf->lookup_vars = NULL;
     *     stcf->create_vars = NULL;
     *     stcf->shm_zone = NULL;
     *
     *     stcf->cookie_name = { 0, NULL };
     *     stcf->cookie_domain = NULL;
     *     stcf->cookie_path = { 0, NULL };
     *     stcf->cookie_httponly = 0;
     *     stcf->cookie_secure = 0;
     *     stcf->cookie_samesite = NULL;
     *
     *     stcf->learn_after_headers = 0;
     */

    stcf->cookie_expires = NGX_CONF_UNSET;

    return stcf;
}


static char *
ngx_http_upstream_sticky(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    ngx_str_t                            *value;
    ngx_int_t                            *indexp, index;
    ngx_uint_t                            i;
    ngx_http_upstream_srv_conf_t         *us;
    ngx_http_upstream_sticky_srv_conf_t  *stcf;

    us = ngx_http_conf_get_module_srv_conf(cf, ngx_http_upstream_module);
    stcf = ngx_http_conf_upstream_srv_conf(us, ngx_http_upstream_sticky_module);

    if (stcf->lookup_vars != NULL) {
        return "is duplicate";
    }

    stcf->lookup_vars = ngx_array_create(cf->pool, 1, sizeof(ngx_int_t));
    if (stcf->lookup_vars == NULL) {
        return NGX_CONF_ERROR;
    }

    stcf->original_init_upstream = us->peer.init_upstream
                                   ? us->peer.init_upstream
                                   : ngx_http_upstream_init_round_robin;

    us->peer.init_upstream = ngx_http_upstream_sticky_init_upstream;

    value = cf->args->elts;

    if (ngx_strcmp(value[1].data, "cookie") == 0) {
        return ngx_http_upstream_sticky_cookie(cf, stcf);

    } else if (ngx_strcmp(value[1].data, "route") == 0) {

        for (i = 2; i < cf->args->nelts; i++) {

            if (value[i].data[0] != '$') {
                ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                                   "invalid variable name \"%V\"", &value[i]);
                return NGX_CONF_ERROR;
            }

            value[i].len--;
            value[i].data++;

            index = ngx_http_get_variable_index(cf, &value[i]);
            if (index == NGX_ERROR) {
                return NGX_CONF_ERROR;
            }

            indexp = ngx_array_push(stcf->lookup_vars);
            if (indexp == NULL) {
                return NGX_CONF_ERROR;
            }

            *indexp = index;
        }

        return NGX_CONF_OK;

    } else if (ngx_strcmp(value[1].data, "learn") == 0) {
        return ngx_http_upstream_sticky_learn(cf, stcf, us);
    }

    ngx_conf_log_error(NGX_LOG_EMERG, cf, 0, "unknown parameter \"%V\"",
                       &value[1]);
    return NGX_CONF_ERROR;
}


static char *
ngx_http_upstream_sticky_cookie(ngx_conf_t *cf,
    ngx_http_upstream_sticky_srv_conf_t *stcf)
{
    u_char                            *p;
    ngx_str_t                          name, *value;
    ngx_int_t                          index, *indexp;
    ngx_uint_t                         i;
    ngx_http_compile_complex_value_t   ccv;

    value = cf->args->elts;

    if (value[2].len == 0) {
        return "empty cookie name";
    }

    stcf->cookie_name = value[2];

    for (i = 3; i < cf->args->nelts; i++) {

        if (ngx_strncmp(value[i].data, "domain=", 7) == 0) {

            if (stcf->cookie_domain != NULL) {
                return "parameter \"domain\" is duplicate";
            }

            value[i].data += 7;
            value[i].len -= 7;

            if (value[i].len == 0) {
                return "no value for \"domain\"";
            }

            ngx_memzero(&ccv, sizeof(ngx_http_compile_complex_value_t));

            stcf->cookie_domain = ngx_palloc(cf->pool,
                                             sizeof(ngx_http_complex_value_t));
            if (stcf->cookie_domain == NULL) {
                return NGX_CONF_ERROR;
            }

            ccv.cf = cf;
            ccv.value = &value[i];
            ccv.complex_value = stcf->cookie_domain;

            if (ngx_http_compile_complex_value(&ccv) != NGX_OK) {
                return NGX_CONF_ERROR;
            }

        } else if (ngx_strncmp(value[i].data, "path=", 5) == 0) {

            if (stcf->cookie_path.data != NULL) {
                return "parameter \"path\" is duplicate";
            }

            value[i].data += 5;
            value[i].len -= 5;

            if (value[i].len == 0) {
                return "no value for \"path\"";
            }

            stcf->cookie_path.len = sizeof("; path=") - 1 + value[i].len;

            stcf->cookie_path.data = ngx_pnalloc(cf->pool,
                                                 stcf->cookie_path.len);
            if (stcf->cookie_path.data == NULL) {
                return NGX_CONF_ERROR;
            }

            p = ngx_cpymem(stcf->cookie_path.data,
                           "; path=", sizeof("; path=") - 1);
            ngx_memcpy(p, value[i].data, value[i].len);


        } else if (ngx_strncmp(value[i].data, "expires=", 8) == 0) {

            if (stcf->cookie_expires != (time_t) NGX_CONF_UNSET) {
                return "parameter \"expires\" is duplicate";
            }

            value[i].data += 8;
            value[i].len -= 8;

            if (ngx_strcmp(value[i].data, "max") == 0) {
                stcf->cookie_expires = NGX_HTTP_STICKY_COOKIE_MAX_EXPIRES;

            } else {
                stcf->cookie_expires = ngx_parse_time(&value[i], 1);
                if (stcf->cookie_expires == (time_t) NGX_ERROR) {
                    return "invalid \"expires\" parameter value";
                }
            }

        } else if (ngx_strcmp(value[i].data, "httponly") == 0) {

            if (stcf->cookie_httponly) {
                return "parameter \"httponly\" is duplicate";
            }

            stcf->cookie_httponly = 1;

        } else if (ngx_strcmp(value[i].data, "secure") == 0) {

            if (stcf->cookie_secure) {
                return "parameter \"secure\" is duplicate";
            }

            stcf->cookie_secure = 1;

        } else if (ngx_strncmp(value[i].data, "samesite=", 9) == 0) {

            if (stcf->cookie_samesite) {
                return "parameter \"samesite\" is duplicate";
            }

            value[i].data += 9;
            value[i].len -= 9;

            ngx_memzero(&ccv, sizeof(ngx_http_compile_complex_value_t));

            stcf->cookie_samesite = ngx_palloc(cf->pool,
                                             sizeof(ngx_http_complex_value_t));
            if (stcf->cookie_samesite == NULL) {
                return NGX_CONF_ERROR;
            }

            ccv.cf = cf;
            ccv.value = &value[i];
            ccv.complex_value = stcf->cookie_samesite;

            if (ngx_http_compile_complex_value(&ccv) != NGX_OK) {
                return NGX_CONF_ERROR;
            }

            if (stcf->cookie_samesite->lengths == NULL
                && ngx_http_upstream_sticky_samesite(&value[i]) != NGX_OK)
            {
                return "invalid \"samesite\" parameter value";
            }

        } else {
            ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                               "unknown parameter \"%V\"", &value[i]);
            return NGX_CONF_ERROR;
        }
    }

    name.len = sizeof("cookie_") - 1  + stcf->cookie_name.len;
    name.data = ngx_pnalloc(cf->pool, name.len);
    if (name.data == NULL) {
         return NGX_CONF_ERROR;
    }

    ngx_sprintf(name.data, "cookie_%V", &stcf->cookie_name);

    index = ngx_http_get_variable_index(cf, &name);
    if (index == NGX_ERROR) {
        return NGX_CONF_ERROR;
    }

    indexp = ngx_array_push(stcf->lookup_vars);
    if (indexp == NULL) {
        return NGX_CONF_ERROR;
    }

    *indexp = index;

    return NGX_CONF_OK;
}


static char *
ngx_http_upstream_sticky_learn(ngx_conf_t *cf,
    ngx_http_upstream_sticky_srv_conf_t *stcf, ngx_http_upstream_srv_conf_t *us)
{
    u_char                           *p;
    ssize_t                           zone_size;
    ngx_str_t                        *value, name, size;
    ngx_int_t                         index, *indexp;
    ngx_uint_t                        i;
    ngx_msec_t                        timeout;
    ngx_shm_zone_t                   *shm_zone;
    ngx_http_upstream_sticky_sess_t  *sess;

    zone_size = 0;
    timeout = NGX_CONF_UNSET_MSEC;

    stcf->create_vars = ngx_array_create(cf->pool, 1, sizeof(ngx_int_t));
    if (stcf->create_vars == NULL) {
        return NGX_CONF_ERROR;
    }

    value = cf->args->elts;

    for (i = 2; i < cf->args->nelts; i++) {

        if (ngx_strncmp(value[i].data, "zone=", 5) == 0) {

            if (zone_size != 0) {
                return "duplicate zone";
            }

            name.data = value[i].data + 5;

            p = (u_char *) ngx_strchr(name.data, ':');

            if (p == NULL) {
                return "zone size is not specified";
            }

            name.len = p - name.data;

            if (name.len == 0) {
                return "zone name is not specified";
            }

            size.data = ++p;
            size.len = value[i].data + value[i].len - p;

            zone_size = ngx_parse_size(&size);
            if (zone_size == NGX_ERROR) {
                return "invalid zone size";
            }

            /* 32k ~ 200 sessions, 1m ~ 8000 sessions */
            if (zone_size < (ssize_t) (8 * ngx_pagesize)) {
                return "zone is too small";
            }

        } else if (ngx_strncmp(value[i].data, "timeout=", 8) == 0) {

            if (timeout != NGX_CONF_UNSET_MSEC) {
                return "duplicate timeout";
            }

            value[i].data += 8;
            value[i].len -= 8;

            timeout = ngx_parse_time(&value[i], 0);
            if (timeout == (ngx_msec_t) NGX_ERROR || timeout == 0) {
                return "invalid timeout";
            }

        } else if (ngx_strncmp(value[i].data, "create=", 7) == 0) {

            if (value[i].data[7] != '$') {
                return "missing variable in the \"create\" parameter";
            }

            value[i].data += 8;
            value[i].len -= 8;

            index = ngx_http_get_variable_index(cf, &value[i]);
            if (index == NGX_ERROR) {
                return NGX_CONF_ERROR;
            }

            indexp = ngx_array_push(stcf->create_vars);
            if (indexp == NULL) {
                return NGX_CONF_ERROR;
            }

            *indexp = index;

        } else if (ngx_strncmp(value[i].data, "lookup=", 7) == 0) {

            if (value[i].data[7] != '$') {
                return "missing variable in the \"lookup\" parameter";
            }

            value[i].data += 8;
            value[i].len -= 8;

            index = ngx_http_get_variable_index(cf, &value[i]);
            if (index == NGX_ERROR) {
                return NGX_CONF_ERROR;
            }

            indexp = ngx_array_push(stcf->lookup_vars);
            if (indexp == NULL) {
                return NGX_CONF_ERROR;
            }

            *indexp = index;

        } else if (ngx_strcmp(value[i].data, "header") == 0) {
            stcf->learn_after_headers = 1;

        } else {
            ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                               "unknown parameter \"%V\"", &value[i]);
            return NGX_CONF_ERROR;
        }
    }

    if (stcf->lookup_vars->nelts == 0) {
        return "\"lookup\" parameter is not specified";
    }

    if (stcf->create_vars->nelts == 0) {
        return "\"create\" parameter is not specified";
    }

    if (zone_size == 0) {
        return "\"zone\" parameter is not specified";
    }

    if (timeout == NGX_CONF_UNSET_MSEC) {
        timeout = 600000; /* 10m */
    }

    shm_zone = ngx_shared_memory_add(cf, &name, zone_size,
                                     &ngx_http_upstream_sticky_module);
    if (shm_zone == NULL) {
        return NGX_CONF_ERROR;
    }

    if (shm_zone->data) {
        sess = shm_zone->data;

        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                           "sticky zone \"%V\" is already used in "
                           "upstream \"%V\"", &name, sess->host);

        return NGX_CONF_ERROR;
    }

    sess = ngx_pcalloc(cf->pool, sizeof(ngx_http_upstream_sticky_sess_t));
    if (sess == NULL) {
        return NGX_CONF_ERROR;
    }

    sess->timeout = timeout;
    sess->host = &us->host;

    sess->event.data = sess;
    sess->event.log = &cf->cycle->new_log;
    sess->event.handler = ngx_http_upstream_sticky_sess_timer_handler;
    sess->event.cancelable = 1;

    shm_zone->init = ngx_http_upstream_sticky_sess_init_zone;
    shm_zone->data = sess;

    stcf->shm_zone = shm_zone;

    return NGX_CONF_OK;
}


static ngx_int_t
ngx_http_upstream_sticky_init_worker(ngx_cycle_t *cycle)
{
    ngx_msec_t                             wait;
    ngx_uint_t                             i;
    ngx_http_upstream_srv_conf_t         **uscfp;
    ngx_http_upstream_main_conf_t         *umcf;
    ngx_http_upstream_sticky_sess_t       *sess;
    ngx_http_upstream_sticky_srv_conf_t   *stcf;

    if ((ngx_process != NGX_PROCESS_WORKER || ngx_worker != 0)
        && ngx_process != NGX_PROCESS_SINGLE)
    {
        return NGX_OK;
    }

    umcf = ngx_http_cycle_get_module_main_conf(cycle, ngx_http_upstream_module);

    if (umcf == NULL) {
        return NGX_OK;
    }

    uscfp = umcf->upstreams.elts;

    for (i = 0; i < umcf->upstreams.nelts; i++) {

        if (uscfp[i]->srv_conf == NULL) {
            continue;
        }

        stcf = ngx_http_conf_upstream_srv_conf(uscfp[i],
                                               ngx_http_upstream_sticky_module);

        if (stcf == NULL || stcf->shm_zone == NULL) {
            continue;
        }

        sess = stcf->shm_zone->data;

        ngx_shmtx_lock(&sess->shpool->mutex);

        wait = ngx_http_upstream_sticky_sess_expire(sess, 0);

        ngx_shmtx_unlock(&sess->shpool->mutex);

        if (wait > 0) {
            ngx_add_timer(&sess->event, wait);
        }
    }

    return NGX_OK;
}
