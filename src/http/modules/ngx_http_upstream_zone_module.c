
/*
 * Copyright (C) Ruslan Ermilov
 * Copyright (C) Nginx, Inc.
 */


#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>


static char *ngx_http_upstream_zone(ngx_conf_t *cf, ngx_command_t *cmd,
    void *conf);
static ngx_int_t ngx_http_upstream_init_zone(ngx_shm_zone_t *shm_zone,
    void *data);
static ngx_int_t ngx_http_upstream_zone_copy_peers(ngx_slab_pool_t *shpool,
    ngx_http_upstream_srv_conf_t *uscf);


static ngx_command_t  ngx_http_upstream_zone_commands[] = {

    { ngx_string("zone"),
      NGX_HTTP_UPS_CONF|NGX_CONF_TAKE12,
      ngx_http_upstream_zone,
      0,
      0,
      NULL },

      ngx_null_command
};


static ngx_http_module_t  ngx_http_upstream_zone_module_ctx = {
    NULL,                                  /* preconfiguration */
    NULL,                                  /* postconfiguration */

    NULL,                                  /* create main configuration */
    NULL,                                  /* init main configuration */

    NULL,                                  /* create server configuration */
    NULL,                                  /* merge server configuration */

    NULL,                                  /* create location configuration */
    NULL                                   /* merge location configuration */
};


ngx_module_t  ngx_http_upstream_zone_module = {
    NGX_MODULE_V1,
    &ngx_http_upstream_zone_module_ctx,    /* module context */
    ngx_http_upstream_zone_commands,       /* module directives */
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


static char *
ngx_http_upstream_zone(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    ssize_t                         size;
    ngx_str_t                      *value;
    ngx_http_upstream_srv_conf_t   *uscf;
    ngx_http_upstream_main_conf_t  *umcf;

    uscf = ngx_http_conf_get_module_srv_conf(cf, ngx_http_upstream_module);
    umcf = ngx_http_conf_get_module_main_conf(cf, ngx_http_upstream_module);

    value = cf->args->elts;

    if (!value[1].len) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                           "invalid zone name \"%V\"", &value[1]);
        return NGX_CONF_ERROR;
    }

    if (cf->args->nelts == 3) {
        size = ngx_parse_size(&value[2]);

        if (size == NGX_ERROR) {
            ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                               "invalid zone size \"%V\"", &value[2]);
            return NGX_CONF_ERROR;
        }

        if (size < (ssize_t) (8 * ngx_pagesize)) {
            ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                               "zone \"%V\" is too small", &value[1]);
            return NGX_CONF_ERROR;
        }

    } else {
        size = 0;
    }

    uscf->shm_zone = ngx_shared_memory_add(cf, &value[1], size,
                                           &ngx_http_upstream_module);
    if (uscf->shm_zone == NULL) {
        return NGX_CONF_ERROR;
    }

    uscf->shm_zone->init = ngx_http_upstream_init_zone;
    uscf->shm_zone->data = umcf;

    uscf->shm_zone->noreuse = 1;

    return NGX_CONF_OK;
}


static ngx_int_t
ngx_http_upstream_init_zone(ngx_shm_zone_t *shm_zone, void *data)
{
    size_t                          len;
    ngx_uint_t                      i;
    ngx_slab_pool_t                *shpool;
    ngx_http_upstream_srv_conf_t   *uscf, **uscfp;
    ngx_http_upstream_main_conf_t  *umcf;

    shpool = (ngx_slab_pool_t *) shm_zone->shm.addr;

    if (shm_zone->shm.exists) {
        return NGX_ERROR;
    }

    len = sizeof(" in upstream zone \"\"") + shm_zone->shm.name.len;

    shpool->log_ctx = ngx_slab_alloc(shpool, len);
    if (shpool->log_ctx == NULL) {
        return NGX_ERROR;
    }

    ngx_sprintf(shpool->log_ctx, " in upstream zone \"%V\"%Z",
                &shm_zone->shm.name);


    /* copy peers to shared memory */

    umcf = shm_zone->data;
    uscfp = umcf->upstreams.elts;

    for (i = 0; i < umcf->upstreams.nelts; i++) {
        uscf = uscfp[i];

        if (uscf->shm_zone != shm_zone) {
            continue;
        }

        if (ngx_http_upstream_zone_copy_peers(shpool, uscf) != NGX_OK) {
            return NGX_ERROR;
        }
    }

    return NGX_OK;
}


static ngx_int_t
ngx_http_upstream_zone_copy_peers(ngx_slab_pool_t *shpool,
    ngx_http_upstream_srv_conf_t *uscf)
{
    ngx_http_upstream_rr_peer_t   *peer, **peerp;
    ngx_http_upstream_rr_peers_t  *peers, *backup;

    peers = ngx_slab_alloc(shpool, sizeof(ngx_http_upstream_rr_peers_t));
    if (peers == NULL) {
        return NGX_ERROR;
    }

    ngx_memcpy(peers, uscf->peer.data, sizeof(ngx_http_upstream_rr_peers_t));

    peers->shpool = shpool;

    for (peerp = &peers->peer; *peerp; peerp = &peer->next) {
        /* pool is unlocked */
        peer = ngx_slab_calloc_locked(shpool,
                                      sizeof(ngx_http_upstream_rr_peer_t));
        if (peer == NULL) {
            return NGX_ERROR;
        }

        ngx_memcpy(peer, *peerp, sizeof(ngx_http_upstream_rr_peer_t));

        *peerp = peer;
    }

    if (peers->next == NULL) {
        goto done;
    }

    backup = ngx_slab_alloc(shpool, sizeof(ngx_http_upstream_rr_peers_t));
    if (backup == NULL) {
        return NGX_ERROR;
    }

    ngx_memcpy(backup, peers->next, sizeof(ngx_http_upstream_rr_peers_t));

    backup->shpool = shpool;

    for (peerp = &backup->peer; *peerp; peerp = &peer->next) {
        /* pool is unlocked */
        peer = ngx_slab_calloc_locked(shpool,
                                      sizeof(ngx_http_upstream_rr_peer_t));
        if (peer == NULL) {
            return NGX_ERROR;
        }

        ngx_memcpy(peer, *peerp, sizeof(ngx_http_upstream_rr_peer_t));

        *peerp = peer;
    }

    peers->next = backup;

done:

    uscf->peer.data = peers;

    return NGX_OK;
}
