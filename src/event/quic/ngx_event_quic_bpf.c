
/*
 * Copyright (C) Nginx, Inc.
 */


#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_event.h>
#include <ngx_event_quic_connection.h>


#define NGX_QUIC_BPF_VARNAME  "NGINX_BPF_MAPS"
#define NGX_QUIC_BPF_VARSEP    ';'
#define NGX_QUIC_BPF_ADDRSEP   '#'
#define NGX_QUIC_BPF_GSEP      '|'

#define NGX_QUIC_BPF_NMASTERS_IDX 2
#define NGX_QUIC_BPF_ACT_MASTER_IDX 3

#define ngx_quic_bpf_get_conf(cycle)                                          \
    (ngx_quic_bpf_conf_t *) ngx_get_conf(cycle->conf_ctx, ngx_quic_bpf_module)

#define ngx_quic_bpf_get_old_conf(cycle)                                      \
    cycle->old_cycle->conf_ctx ? ngx_quic_bpf_get_conf(cycle->old_cycle)      \
                               : NULL

#define ngx_core_get_conf(cycle)                                              \
    (ngx_core_conf_t *) ngx_get_conf(cycle->conf_ctx, ngx_core_module)


typedef enum {
    NGX_QUIC_BPF_GROUP_INIT,
    NGX_QUIC_BPF_GROUP_RELOAD,
    NGX_QUIC_BPF_GROUP_INHERIT,
} ngx_quic_bpf_group_mode_t;


/* per reuseport group of socket */
typedef struct {
    ngx_queue_t           queue;

    int                   listen_map;
    int                   listen_map_array;
    int                   connection_map;

    struct sockaddr      *sockaddr;
    socklen_t             socklen;

    ngx_array_t           listening; /* of ngx_quic_bpf_listening_t */

    ngx_uint_t            nlisten;

#if (NGX_DEBUG)
    ngx_str_t             name;
#endif
} ngx_quic_bpf_group_t;


typedef struct {
    ngx_socket_t          fd;
    ngx_listening_t      *listening;
    ngx_connection_t     *connection;
} ngx_quic_bpf_listening_t;


typedef struct {
    ngx_flag_t            enabled;
    ngx_uint_t            max_connection_ids;
    ngx_queue_t           groups;
    int                   master_state_map;
    u_char               *env;
    ngx_uint_t            master_index; /* unsigned master_index:1 */
} ngx_quic_bpf_conf_t;


static void *ngx_quic_bpf_create_conf(ngx_cycle_t *cycle);
static char *ngx_quic_bpf_init_conf(ngx_cycle_t *cycle, void *conf);
static ngx_int_t ngx_quic_bpf_module_init(ngx_cycle_t *cycle);

static void ngx_quic_bpf_cleanup(void *data);
static ngx_inline void ngx_quic_bpf_close(ngx_log_t *log, int fd);

static ngx_quic_bpf_group_t *ngx_quic_bpf_find_group(ngx_cycle_t *cycle,
    ngx_listening_t *ls);
static ngx_quic_bpf_group_t *ngx_quic_bpf_create_group(ngx_cycle_t *cycle,
    ngx_quic_bpf_group_mode_t mode, struct sockaddr *sa, socklen_t socklen,
    int conn_map, int lma);
static ngx_inline void ngx_quic_bpf_group_delete(ngx_cycle_t *cycle,
    ngx_quic_bpf_group_t *grp);
static ngx_int_t ngx_quic_bpf_group_attach_prog(ngx_cycle_t *cycle,
    ngx_quic_bpf_group_t *grp, int fd);
static ngx_quic_bpf_group_t *ngx_quic_bpf_get_group(ngx_cycle_t *cycle,
    ngx_listening_t *ls);
static ngx_int_t ngx_quic_bpf_group_add_socket(ngx_cycle_t *cycle,
    ngx_listening_t *ls);
static ngx_int_t ngx_quic_bpf_add_worker_socket(ngx_cycle_t *cycle,
    ngx_quic_bpf_group_t *grp, ngx_listening_t *ls);

static int ngx_quic_bpf_create_map(ngx_cycle_t *cycle, enum bpf_map_type type,
    int key_size, int value_size, int max_entries, uint32_t map_flags,
    const char *name);
static int ngx_quic_bpf_create_outer_map(ngx_cycle_t *cycle,
    enum bpf_map_type outer_type, enum bpf_map_type inner_map_type,
    int inner_key_size, int inner_value_size, int max_entries,
    uint32_t map_flags, const char *name);

static ngx_inline ngx_int_t ngx_quic_bpf_setup_map_fd(ngx_log_t *log, int fd);
static ngx_inline ngx_int_t ngx_quic_bpf_map_set(ngx_log_t *log, int fd,
    uint64_t key, uint64_t value, const char *name);

static ngx_int_t ngx_quic_bpf_export_maps(ngx_cycle_t *cycle);
static ngx_int_t ngx_quic_bpf_import_maps(ngx_cycle_t *cycle);

extern ngx_bpf_program_t  ngx_quic_reuseport_helper;


static ngx_command_t  ngx_quic_bpf_commands[] = {

    { ngx_string("quic_bpf"),
      NGX_MAIN_CONF|NGX_DIRECT_CONF|NGX_CONF_FLAG,
      ngx_conf_set_flag_slot,
      0,
      offsetof(ngx_quic_bpf_conf_t, enabled),
      NULL },

      ngx_null_command
};


static ngx_core_module_t  ngx_quic_bpf_module_ctx = {
    ngx_string("quic_bpf"),
    ngx_quic_bpf_create_conf,
    ngx_quic_bpf_init_conf
};


ngx_module_t  ngx_quic_bpf_module = {
    NGX_MODULE_V1,
    &ngx_quic_bpf_module_ctx,              /* module context */
    ngx_quic_bpf_commands,                 /* module directives */
    NGX_CORE_MODULE,                       /* module type */
    NULL,                                  /* init master */
    ngx_quic_bpf_module_init,              /* init module */
    NULL,                                  /* init process */
    NULL,                                  /* init thread */
    NULL,                                  /* exit thread */
    NULL,                                  /* exit process */
    NULL,                                  /* exit master */
    NGX_MODULE_V1_PADDING
};


static void *
ngx_quic_bpf_create_conf(ngx_cycle_t *cycle)
{
    ngx_quic_bpf_conf_t  *bcf;

    bcf = ngx_pcalloc(cycle->pool, sizeof(ngx_quic_bpf_conf_t));
    if (bcf == NULL) {
        return NULL;
    }

    /*
     * set by ngx_pcalloc():
     *
     *     bcf->master_index = 0;
     *     bcf->env = NULL;
     */

    bcf->enabled = NGX_CONF_UNSET;
    bcf->master_state_map = -1;

    ngx_queue_init(&bcf->groups);

    return bcf;
}


static char *
ngx_quic_bpf_init_conf(ngx_cycle_t *cycle, void *conf)
{
    ngx_quic_bpf_conf_t *bcf = conf;

    u_char               *p;
    size_t                len;
    ngx_quic_bpf_conf_t  *obcf;

    ngx_conf_init_value(bcf->enabled, 0);

    /*
     * preserve environment variable value early, as it may be reset by
     * some module later, i.e. perl
     */
    p = (u_char *) getenv(NGX_QUIC_BPF_VARNAME);
    if (p) {
        len = ngx_strlen(p);
        bcf->env = ngx_pnalloc(cycle->pool, len + 1);
        if (bcf->env == NULL) {
            return NGX_CONF_ERROR;
        }
        ngx_memcpy(bcf->env, p, len + 1);
    }

    if (cycle->old_cycle->conf_ctx == NULL) {
        return NGX_CONF_OK;
    }

    obcf = ngx_quic_bpf_get_conf(cycle->old_cycle);
    if (obcf == NULL) {
        return NGX_CONF_OK;
    }

    if (obcf->enabled != bcf->enabled) {
        ngx_log_error(NGX_LOG_EMERG, cycle->log, 0,
                      "cannot change \"quic_bpf\" after reload, ignoring");
        bcf->enabled = obcf->enabled;
    }

    if (!bcf->enabled) {
        return NGX_CONF_OK;
    }

    /*
     * we have old configuration here, so this is reload;
     *
     * preserve reusable parts of global configuration:
     *  master_index (does not change)
     *  master_state fd - duplicate, as it is closed in conf cleanup
     */

    bcf->master_index = obcf->master_index;

    bcf->master_state_map = dup(obcf->master_state_map);
    if (bcf->master_state_map == -1) {
        ngx_log_error(NGX_LOG_EMERG, cycle->log, ngx_errno,
                      "quic bpf failed to duplicate master_state_map");

        return NGX_CONF_ERROR;
    }

    ngx_log_debug2(NGX_LOG_DEBUG_EVENT, cycle->log, 0,
                   "quic bpf init conf master_state map fd:%d master_index:%d",
                   bcf->master_state_map, bcf->master_index);

    return NGX_CONF_OK;
}


static ngx_int_t
ngx_quic_bpf_module_init(ngx_cycle_t *cycle)
{
    int                   mapfd;
    ngx_uint_t            i;
    ngx_queue_t          *q;
    ngx_listening_t      *ls;
    ngx_core_conf_t      *ccf;
    ngx_event_conf_t     *ecf;
    ngx_pool_cleanup_t   *cln;
    ngx_quic_bpf_conf_t  *bcf;
    ngx_quic_bpf_group_t *grp;

    if (ngx_test_config) {
        /*
         * during config test, SO_REUSEPORT socket option is
         * not set, thus making further processing meaningless
         */
        return NGX_OK;
    }

    bcf = ngx_quic_bpf_get_conf(cycle);
    if (!bcf->enabled) {
        return NGX_OK;
    }

    ccf = ngx_core_get_conf(cycle);
    ecf = ngx_event_get_conf(cycle->conf_ctx, ngx_event_core_module);

    bcf->max_connection_ids = ecf->connections * NGX_QUIC_MAX_SERVER_IDS;

    cln = ngx_pool_cleanup_add(cycle->pool, 0);
    if (cln == NULL) {
        goto failed;
    }

    cln->data = bcf;
    cln->handler = ngx_quic_bpf_cleanup;

    ls = cycle->listening.elts;

    if (ngx_inherited && ngx_is_init_cycle(cycle->old_cycle)) {
        if (ngx_quic_bpf_import_maps(cycle) != NGX_OK) {
            goto failed;
        }
    }

    if (bcf->master_state_map == -1) {
        /* initial master state creation */

        ngx_log_debug0(NGX_LOG_DEBUG_EVENT, cycle->log, 0,
                       "quic bpf init initial master");

        mapfd = ngx_quic_bpf_create_map(cycle, BPF_MAP_TYPE_ARRAY,
                                        sizeof(uint32_t), sizeof(uint32_t),
                                        4, 0, "master_state");
        if (mapfd == -1) {
            goto failed;
        }
        bcf->master_state_map = mapfd;

        /* we are the only (initial) master */
        if (ngx_quic_bpf_map_set(cycle->log, bcf->master_state_map,
                                 NGX_QUIC_BPF_NMASTERS_IDX, 1,
                                 "master_state")
            != NGX_OK)
        {
            goto failed;
        }

        /* set active master index */
        if (ngx_quic_bpf_map_set(cycle->log, bcf->master_state_map,
                                 NGX_QUIC_BPF_ACT_MASTER_IDX,
                                 bcf->master_index,
                                 "master_state")
            != NGX_OK)
        {
            goto failed;
        }
    }

    /* update worker process counter for this master */
    if (ngx_quic_bpf_map_set(cycle->log, bcf->master_state_map,
                             bcf->master_index, ccf->worker_processes,
                             "master_state")
        != NGX_OK)
    {
        goto failed;
    }

    ls = cycle->listening.elts;

    for (i = 0; i < cycle->listening.nelts; i++) {
        if (ls[i].quic && ls[i].reuseport) {
            if (ngx_quic_bpf_group_add_socket(cycle, &ls[i]) != NGX_OK) {
                goto failed;
            }
        }
    }

    /*
     * all worker sockets are now populated in each group's listen_map;
     * atomically publish by updating listen_map_array[master_index] now,
     * avoiding the window where BPF sees an empty map and drops packets
     */

    for (q = ngx_queue_head(&bcf->groups);
         q != ngx_queue_sentinel(&bcf->groups);
         q = ngx_queue_next(q))
    {
        grp = ngx_queue_data(q, ngx_quic_bpf_group_t, queue);

        if (ngx_quic_bpf_map_set(cycle->log, grp->listen_map_array,
                                 bcf->master_index, grp->listen_map,
                                 "listen_map_array")
            != NGX_OK)
        {
            goto failed;
        }
    }

    if (ngx_inherited && ngx_is_init_cycle(cycle->old_cycle)) {

        ngx_log_error(NGX_LOG_INFO, cycle->log, 0,
                      "quic bpf new master: running two simultaneously");

        if (ngx_quic_bpf_map_set(cycle->log, bcf->master_state_map,
                                 NGX_QUIC_BPF_NMASTERS_IDX, 2, "master_state")
            != NGX_OK)
        {
            goto failed;
        }
    }

    if (ngx_quic_bpf_export_maps(cycle) != NGX_OK) {
        goto failed;
    }

    return NGX_OK;

failed:

    if (bcf->master_state_map != -1) {
        ngx_quic_bpf_close(cycle->log, bcf->master_state_map);
    }

    if (ngx_is_init_cycle(cycle->old_cycle)) {
        ngx_log_error(NGX_LOG_EMERG, cycle->log, 0,
                      "ngx_quic_bpf_module failed to initialize, check limits");

        /* refuse to start */
        return NGX_ERROR;
    }

    /*
     * returning error now will lead to master process exiting immediately
     * leaving worker processes orphaned, what is really unexpected.
     * Instead, just issue a note about failed initialization and try
     * to cleanup a bit. Still program can be already loaded to kernel
     * for some reuseport groups, and there is no way to revert, so
     * behaviour may be inconsistent.
     */

    ngx_log_error(NGX_LOG_EMERG, cycle->log, 0,
                  "ngx_quic_bpf_module failed to initialize properly, ignored."
                  "please check limits and note that nginx state now "
                  "can be inconsistent and restart may be required");

    return NGX_OK;
}


static ngx_inline ngx_int_t
ngx_quic_bpf_map_set(ngx_log_t *log, int fd, uint64_t key, uint64_t value,
    const char *name)
{
    ngx_log_debug4(NGX_LOG_DEBUG_EVENT, log, 0,
                   "quic bpf update map fd:%d %s[%d]=%d", fd, name, key, value);

    if (ngx_bpf_map_update(fd, &key, &value, BPF_ANY) == -1) {
        ngx_log_error(NGX_LOG_EMERG, log, ngx_errno,
                      "quic bpf failed to update %s map fd:%d key:%d value:%d",
                      name, fd, key, value);

        return NGX_ERROR;
    }

    return NGX_OK;
}


ngx_uint_t
ngx_quic_bpf_enabled(ngx_cycle_t *cycle)
{
    ngx_quic_bpf_conf_t  *bcf;

    bcf = ngx_quic_bpf_get_conf(cycle);

    return bcf->enabled ? 1 : 0;
}


static void
ngx_quic_bpf_cleanup(void *data)
{
    ngx_quic_bpf_conf_t  *bcf = (ngx_quic_bpf_conf_t *) data;

    ngx_log_t                 *log;
    ngx_uint_t                 i;
    ngx_queue_t               *q;
    ngx_quic_bpf_group_t      *grp;
    ngx_quic_bpf_listening_t  *bls;

    log = ngx_cycle->log;

    for (q = ngx_queue_head(&bcf->groups);
         q != ngx_queue_sentinel(&bcf->groups);
         q = ngx_queue_next(q))
    {
        grp = ngx_queue_data(q, ngx_quic_bpf_group_t, queue);

        ngx_quic_bpf_close(log, grp->listen_map);
        ngx_quic_bpf_close(log, grp->listen_map_array);
        ngx_quic_bpf_close(log, grp->connection_map);

        bls = grp->listening.elts;

        for (i = 0; i < grp->listening.nelts; i++) {
            if (bls[i].fd != (ngx_socket_t) -1) {
                if (ngx_close_socket(bls[i].fd) == -1) {
                    ngx_log_error(NGX_LOG_ALERT, log, ngx_socket_errno,
                                  "quic bpf " ngx_close_socket_n " failed");
                }
            }
        }
    }

    if (ngx_process == NGX_PROCESS_MASTER) {

        if (ngx_quit) {

            ngx_log_error(NGX_LOG_INFO, log, 0,
                          "quic bpf old master exiting, new master is active");

            /* just 1 master left */
            if (ngx_quic_bpf_map_set(log, bcf->master_state_map,
                                     NGX_QUIC_BPF_NMASTERS_IDX, 1,
                                     "master_state")
                != NGX_OK)
            {
                goto oops;
            }

            /* and the active master is another one */
            if (ngx_quic_bpf_map_set(log, bcf->master_state_map,
                                     NGX_QUIC_BPF_ACT_MASTER_IDX,
                                     !bcf->master_index, "master_state")
                != NGX_OK)
            {
                goto oops;
            }


        } else if (ngx_terminate) {

            ngx_log_error(NGX_LOG_INFO, log, 0,
                          "quic bpf new master exiting, decrement nmasters");

            /*
             * only 1 master left - original, new one is exiting;
             * active is the old one; the active status is passed
             * when and old master exits, so things are untouched
             */
            if (ngx_quic_bpf_map_set(log, bcf->master_state_map,
                                     NGX_QUIC_BPF_NMASTERS_IDX, 1,
                                     "master_state")
                != NGX_OK)
            {
                goto oops;
            }
        }
    }

    ngx_quic_bpf_close(log, bcf->master_state_map);

    return;

oops:

    /*
     * Hopefully, this should never practically happen;
     * not that much we can do about it: we failed to update
     * global map that holds count of masters and worker processes in em.
     * the result is that reuseport helper will hit errors on lookups
     * and drop packets or redirect them to wrong workers.
     * restart is needed to recover.
     */

    ngx_log_error(NGX_LOG_ALERT, log, 0,
                  "quic bpf failed to update master_state map;"
                  "kernel packet helper is in inconsistent state;"
                  "restart may be needed");

    ngx_quic_bpf_close(log, bcf->master_state_map);
}


static ngx_inline void
ngx_quic_bpf_close(ngx_log_t *log, int fd)
{
    if (close(fd) == -1) {
        ngx_log_error(NGX_LOG_ALERT, log, ngx_errno,
                      "quic bpf close map fd:%d failed", fd);
    }
}


static ngx_quic_bpf_group_t *
ngx_quic_bpf_find_group(ngx_cycle_t *cycle, ngx_listening_t *ls)
{
    ngx_queue_t           *q;
    ngx_quic_bpf_conf_t   *bcf;
    ngx_quic_bpf_group_t  *grp;

    bcf = ngx_quic_bpf_get_conf(cycle);

    if (!bcf->enabled || !ls->quic || !ls->reuseport) {
        return NULL;
    }

    for (q = ngx_queue_head(&bcf->groups);
         q != ngx_queue_sentinel(&bcf->groups);
         q = ngx_queue_next(q))
    {
        grp = ngx_queue_data(q, ngx_quic_bpf_group_t, queue);

        if (ngx_cmp_sockaddr(ls->sockaddr, ls->socklen,
                             grp->sockaddr, grp->socklen, 1)
            == NGX_OK)
        {
            return grp;
        }
    }

    return NULL;
}


static int
ngx_quic_bpf_create_map(ngx_cycle_t *cycle, enum bpf_map_type type,
    int key_size, int value_size, int max_entries, uint32_t map_flags,
    const char *name)
{
    int  fd;

    fd = ngx_bpf_map_create(cycle->log, type, key_size, value_size,
                            max_entries, map_flags);
    if (fd == -1) {
        return -1;
    }

    if (ngx_quic_bpf_setup_map_fd(cycle->log, fd) != NGX_OK) {
        return -1;
    }

    ngx_log_debug2(NGX_LOG_DEBUG_EVENT, cycle->log, 0,
                   "quic bpf %s map created fd:%d", name, fd);

    return fd;
}


static int
ngx_quic_bpf_create_outer_map(ngx_cycle_t *cycle, enum bpf_map_type outer_type,
    enum bpf_map_type inner_map_type, int inner_key_size, int inner_value_size,
    int max_entries, uint32_t map_flags, const char *name)
{
    int  fd, tmpl;

    /* template map for array of maps - only needed on creation */
    tmpl = ngx_quic_bpf_create_map(cycle, inner_map_type, inner_key_size,
                                   inner_value_size, 1, 0, "template");
    if (tmpl == -1) {
        return -1;
    }

    fd = ngx_bpf_map_create_outer(cycle->log, outer_type, max_entries,
                                  map_flags, tmpl);

    ngx_quic_bpf_close(cycle->log, tmpl);

    if (fd == -1) {
        return -1;
    }

    if (ngx_quic_bpf_setup_map_fd(cycle->log, fd) != NGX_OK) {
        return -1;
    }

    ngx_log_debug2(NGX_LOG_DEBUG_EVENT, cycle->log, 0,
                   "quic bpf %s outer map created fd:%d", name, fd);

    return fd;
}


static ngx_inline ngx_int_t
ngx_quic_bpf_setup_map_fd(ngx_log_t *log, int fd)
{
    int  flags;

    flags = fcntl(fd, F_GETFD);
    if (flags == -1) {
        ngx_log_error(NGX_LOG_EMERG, log, ngx_errno,
                      "quic bpf fcntl(F_GETFD) failed");
        return NGX_ERROR;
    }

    flags &= ~FD_CLOEXEC;

    if (fcntl(fd, F_SETFD, flags) == -1) {
        ngx_log_error(NGX_LOG_EMERG, log, ngx_errno,
                      "quic bpf fcntl(F_SETFD) failed");
        return NGX_ERROR;
    }

    return NGX_OK;
}


static ngx_quic_bpf_group_t *
ngx_quic_bpf_create_group(ngx_cycle_t *cycle, ngx_quic_bpf_group_mode_t mode,
    struct sockaddr *sa, socklen_t socklen, int conn_map, int lma)
{
    ngx_core_conf_t       *ccf;
    ngx_quic_bpf_conf_t   *bcf;
    ngx_quic_bpf_group_t  *grp;

    grp = ngx_pcalloc(cycle->pool, sizeof(ngx_quic_bpf_group_t));
    if (grp == NULL) {
        return NULL;
    }

    grp->listen_map = -1;
    grp->listen_map_array = -1;
    grp->connection_map = -1;

    if (ngx_array_init(&grp->listening, cycle->pool, 1,
                       sizeof(ngx_quic_bpf_listening_t))
        != NGX_OK)
    {
        return NULL;
    }

    grp->socklen = socklen;

    if (mode == NGX_QUIC_BPF_GROUP_INHERIT) {
        grp->sockaddr = ngx_palloc(cycle->pool, socklen);
        if (grp->sockaddr == NULL) {
            return NULL;
        }

        ngx_memcpy(grp->sockaddr, sa, socklen);

    } else {
        grp->sockaddr = sa;
    }


#if (NGX_DEBUG)
    grp->name.data = ngx_pnalloc(cycle->pool, NGX_SOCKADDR_STRLEN);
    if (grp->name.data == NULL) {
        return NULL;
    }

    grp->name.len = ngx_sock_ntop(sa, socklen, grp->name.data,
                                  NGX_SOCKADDR_STRLEN, 1);

#endif

    ngx_log_debug2(NGX_LOG_DEBUG_EVENT, cycle->log, 0,
                   "quic bpf %s group for \"%V\"",
                   mode == NGX_QUIC_BPF_GROUP_INIT ? "creating"
                       : (mode == NGX_QUIC_BPF_GROUP_RELOAD ? "updating"
                                                            : "inheriting"),
                   &grp->name);

    bcf = ngx_quic_bpf_get_conf(cycle);

    switch (mode) {

    case NGX_QUIC_BPF_GROUP_RELOAD:

        /* reload: old configuration will close maps, create own descriptors */

        grp->connection_map = dup(conn_map);
        if (grp->connection_map == -1) {
            ngx_log_error(NGX_LOG_EMERG, cycle->log, ngx_errno,
                          "quic bpf failed to dup connection_map");
            goto failed;
        }

        grp->listen_map_array = dup(lma);
        if (grp->listen_map_array == -1) {
            ngx_log_error(NGX_LOG_EMERG, cycle->log, ngx_errno,
                          "quic bpf failed to dup listen_map_array");
            goto failed;
        }

        break;

    case NGX_QUIC_BPF_GROUP_INHERIT:

        /* we are the new master and inherited sockets and maps via env */

        grp->connection_map = conn_map;
        grp->listen_map_array = lma;

        ngx_log_debug2(NGX_LOG_DEBUG_EVENT, cycle->log, 0,
                       "quic bpf inherit connection_map:%d "
                       "listen_map_array:%d", conn_map, lma);
        break;

    case NGX_QUIC_BPF_GROUP_INIT:

        conn_map = ngx_quic_bpf_create_map(cycle, BPF_MAP_TYPE_SOCKHASH,
                                           NGX_QUIC_SERVER_CID_LEN,
                                           sizeof(uint64_t),
                                           bcf->max_connection_ids, 0,
                                           "connections");
        if (conn_map == -1) {
            goto failed;
        }

        grp->connection_map = conn_map;

        /* size: only two masters can exist at the same time */
        lma = ngx_quic_bpf_create_outer_map(cycle, BPF_MAP_TYPE_ARRAY_OF_MAPS,
                                            BPF_MAP_TYPE_SOCKMAP,
                                            sizeof(uint32_t), sizeof(uint64_t),
                                            2, 0, "listen_map_array");
        if (lma == -1) {
            goto failed;
        }

        grp->listen_map_array = lma;
        break;
    }

    ccf = ngx_core_get_conf(cycle);

    /* always created, specific for this configuration */
    grp->listen_map = ngx_quic_bpf_create_map(cycle, BPF_MAP_TYPE_SOCKMAP,
                                              sizeof(uint32_t),
                                              sizeof(uint64_t),
                                              ccf->worker_processes, 0,
                                              "listeners");
    if (grp->listen_map == -1) {
        goto failed;
    }

    /*
     * listen_map_array[master_index] is updated after all worker sockets
     * are added to listen_map, to avoid a window where the BPF program
     * sees an empty listen_map and drops new connection packets
     */

    ngx_queue_insert_tail(&bcf->groups, &grp->queue);

    return grp;

failed:

    ngx_quic_bpf_group_delete(cycle, grp);

    return NULL;
}


static ngx_inline void
ngx_quic_bpf_group_delete(ngx_cycle_t *cycle, ngx_quic_bpf_group_t *grp)
{
    if (grp->listen_map != -1) {
        ngx_quic_bpf_close(cycle->log, grp->listen_map);
    }

    if (grp->connection_map != -1) {
        ngx_quic_bpf_close(cycle->log, grp->connection_map);
    }

    if (grp->listen_map_array != -1) {
        ngx_quic_bpf_close(cycle->log, grp->listen_map_array);
    }
}


static ngx_int_t
ngx_quic_bpf_group_attach_prog(ngx_cycle_t *cycle, ngx_quic_bpf_group_t *grp,
    int fd)
{
    int                   progfd, rc;
    ngx_err_t             err;
    ngx_quic_bpf_conf_t  *bcf;

    bcf = ngx_quic_bpf_get_conf(cycle);

    ngx_bpf_program_link(&ngx_quic_reuseport_helper,
                         "ngx_quic_connections", grp->connection_map);

    ngx_bpf_program_link(&ngx_quic_reuseport_helper,
                         "ngx_quic_listen_maps", grp->listen_map_array);

    ngx_bpf_program_link(&ngx_quic_reuseport_helper,
                         "ngx_quic_master_state", bcf->master_state_map);

    progfd = ngx_bpf_load_program(cycle->log, &ngx_quic_reuseport_helper);
    if (progfd < 0) {
        return NGX_ERROR;
    }

    ngx_log_debug1(NGX_LOG_DEBUG_EVENT, cycle->log, 0,
                   "quic bpf program fd:%d", progfd);

    rc = setsockopt(fd, SOL_SOCKET, SO_ATTACH_REUSEPORT_EBPF,
                    &progfd, sizeof(int));

    err = ngx_socket_errno;

    ngx_quic_bpf_close(cycle->log, progfd);

    if (rc == -1) {
        ngx_log_error(NGX_LOG_EMERG, cycle->log, err,
                      "quic bpf setsockopt(SO_ATTACH_REUSEPORT_EBPF) failed");
        return NGX_ERROR;
    }

    ngx_log_debug1(NGX_LOG_DEBUG_EVENT, cycle->log, 0,
                   "quic bpf program attached to \"%V\"", &grp->name);

    return NGX_OK;
}


static ngx_quic_bpf_group_t *
ngx_quic_bpf_get_group(ngx_cycle_t *cycle, ngx_listening_t *ls)
{
    ngx_quic_bpf_conf_t   *old_bcf;
    ngx_quic_bpf_group_t  *grp, *ogrp;

    grp = ngx_quic_bpf_find_group(cycle, ls);
    if (grp) {
        return grp;
    }

    old_bcf = ngx_quic_bpf_get_old_conf(cycle);
    if (old_bcf == NULL) {
        goto init;
    }

    ogrp = ngx_quic_bpf_find_group(cycle->old_cycle, ls);
    if (ogrp == NULL) {
        goto init;
    }

    return ngx_quic_bpf_create_group(cycle, NGX_QUIC_BPF_GROUP_RELOAD,
                                     ls->sockaddr, ls->socklen,
                                     ogrp->connection_map,
                                     ogrp->listen_map_array);

init:

    grp = ngx_quic_bpf_create_group(cycle, NGX_QUIC_BPF_GROUP_INIT,
                                    ls->sockaddr, ls->socklen, -1, -1);
    if (grp == NULL) {
        return NULL;
    }

    if (ngx_quic_bpf_group_attach_prog(cycle, grp, ls->fd) != NGX_OK) {
        ngx_queue_remove(&grp->queue);
        ngx_quic_bpf_group_delete(cycle, grp);
        return NULL;
    }

    return grp;
}


static ngx_int_t
ngx_quic_bpf_group_add_socket(ngx_cycle_t *cycle, ngx_listening_t *ls)
{
    ngx_quic_bpf_group_t  *grp;

    grp = ngx_quic_bpf_get_group(cycle, ls);
    if (grp == NULL) {
        return NGX_ERROR;
    }

    if (ngx_quic_bpf_add_worker_socket(cycle, grp, ls) != NGX_OK) {
        return NGX_ERROR;
    }

    if (ngx_quic_bpf_map_set(cycle->log, grp->listen_map, ls->worker, ls->fd,
                             "listeners")
        != NGX_OK)
    {
        return NGX_ERROR;
    }

    grp->nlisten = ls->worker + 1;

    return NGX_OK;
}


static ngx_int_t
ngx_quic_bpf_add_worker_socket(ngx_cycle_t *cycle, ngx_quic_bpf_group_t *grp,
    ngx_listening_t *ls)
{
    int                        value;
    ngx_uint_t                 i, n;
    ngx_socket_t               s;
    ngx_quic_bpf_listening_t  *bls;

    s = ngx_socket(ls->sockaddr->sa_family, SOCK_DGRAM, 0);
    if (s == (ngx_socket_t) -1) {
        ngx_log_error(NGX_LOG_ERR, cycle->log, ngx_socket_errno,
                      "quic bpf " ngx_socket_n " failed");
        return NGX_ERROR;
    }

    if (ngx_nonblocking(s) == -1) {
        ngx_log_error(NGX_LOG_ALERT, cycle->log, ngx_socket_errno,
                      "quic bpf " ngx_nonblocking_n " worker socket failed");
        goto failed;
    }

    value = 1;

    if (setsockopt(s, SOL_SOCKET, SO_REUSEADDR,
                (const void *) &value, sizeof(int))
        == -1)
    {
        ngx_log_error(NGX_LOG_ALERT, cycle->log, ngx_socket_errno,
                      "quic bpf setsockopt(SO_REUSEADDR) worker socket failed");
        goto failed;
    }

    if (setsockopt(s, SOL_SOCKET, SO_REUSEPORT,
                   (const void *) &value, sizeof(int))
        == -1)
    {
        ngx_log_error(NGX_LOG_ALERT, cycle->log, ngx_socket_errno,
                      "quic bpf setsockopt(SO_REUSEPORT) worker socket failed");
        goto failed;
    }

#if (NGX_HAVE_IP_PKTINFO)
    if (ls->wildcard && ls->sockaddr->sa_family == AF_INET) {
        if (setsockopt(s, IPPROTO_IP, IP_PKTINFO,
                       (const void *) &value, sizeof(int))
            == -1)
        {
            ngx_log_error(NGX_LOG_ALERT, cycle->log, ngx_socket_errno,
                          "quic bpf setsockopt(IP_PKTINFO) "
                          "worker socket failed");
            goto failed;
        }
    }
#endif

#if (NGX_HAVE_INET6 && NGX_HAVE_IPV6_RECVPKTINFO)
    if (ls->wildcard && ls->sockaddr->sa_family == AF_INET6) {
        if (setsockopt(s, IPPROTO_IPV6, IPV6_RECVPKTINFO,
                       (const void *) &value, sizeof(int))
            == -1)
        {
            ngx_log_error(NGX_LOG_ALERT, cycle->log, ngx_socket_errno,
                          "quic bpf setsockopt(IPV6_RECVPKTINFO) "
                          "worker socket failed");
        }
    }
#endif

    if (bind(s, ls->sockaddr, ls->socklen) == -1) {
        ngx_log_error(NGX_LOG_ALERT, cycle->log, ngx_socket_errno,
                      "quic bpf bind() failed");
        goto failed;
    }

    if (ls->worker >= grp->listening.nelts) {
        n = ls->worker + 1 - grp->listening.nelts;

        bls = ngx_array_push_n(&grp->listening, n);
        if (bls == NULL) {
            goto failed;
        }

        ngx_memzero(bls, n * sizeof(ngx_quic_bpf_listening_t));

        for (i = 0; i < n; i++) {
            bls[i].fd = (ngx_socket_t) -1;
        }
    }

    bls = grp->listening.elts;
    bls[ls->worker].fd = s;
    bls[ls->worker].listening = ls;

    return NGX_OK;

failed:

    if (ngx_close_socket(s) == -1) {
        ngx_log_error(NGX_LOG_ALERT, cycle->log, ngx_socket_errno,
                      "quic bpf " ngx_close_socket_n " failed");
    }

    return NGX_ERROR;
}


static ngx_int_t
ngx_quic_bpf_export_maps(ngx_cycle_t *cycle)
{
    u_char                *p, *buf;
    size_t                 len;
    ngx_str_t             *var;
    ngx_queue_t           *q;
    ngx_core_conf_t       *ccf;
    ngx_quic_bpf_conf_t   *bcf;
    ngx_quic_bpf_group_t  *grp;

    bcf = ngx_quic_bpf_get_conf(cycle);
    if (!bcf->enabled) {
        return NGX_OK;
    }

    ccf = ngx_core_get_conf(cycle);

    len = sizeof(NGX_QUIC_BPF_VARNAME) + 1;

    q = ngx_queue_head(&bcf->groups);

    while (q != ngx_queue_sentinel(&bcf->groups)) {

        grp = ngx_queue_data(q, ngx_quic_bpf_group_t, queue);

        q = ngx_queue_next(q);

        if (grp->nlisten == 0) {
            /*
             * map was inherited, but it is not used in this configuration;
             * do not pass such map further and drop the group to prevent
             * interference with changes during reload
             */

            ngx_quic_bpf_close(cycle->log, grp->listen_map);
            ngx_quic_bpf_close(cycle->log, grp->connection_map);
            ngx_quic_bpf_close(cycle->log, grp->listen_map_array);

            ngx_queue_remove(&grp->queue);
            continue;
        }

        len += (NGX_INT32_LEN + 1) * 2 + NGX_SOCKADDR_STRLEN + 1;
    }

    len += (NGX_INT32_LEN + 1) * 2;
    len++;

    buf = ngx_palloc(cycle->pool, len);
    if (buf == NULL) {
        return NGX_ERROR;
    }

    p = ngx_cpymem(buf, NGX_QUIC_BPF_VARNAME "=",
                   sizeof(NGX_QUIC_BPF_VARNAME));


    p = ngx_sprintf(p, "%ud", !bcf->master_index);
    *p++ = NGX_QUIC_BPF_GSEP;
    p = ngx_sprintf(p, "%ud", bcf->master_state_map);
    *p++ = NGX_QUIC_BPF_GSEP;

    for (q = ngx_queue_head(&bcf->groups);
         q != ngx_queue_sentinel(&bcf->groups);
         q = ngx_queue_next(q))
    {
        grp = ngx_queue_data(q, ngx_quic_bpf_group_t, queue);

        p = ngx_sprintf(p, "%ud", grp->connection_map);
        *p++ = NGX_QUIC_BPF_ADDRSEP;
        p = ngx_sprintf(p, "%ud", grp->listen_map_array);
        *p++ = NGX_QUIC_BPF_ADDRSEP;

        p += ngx_sock_ntop(grp->sockaddr, grp->socklen, p,
                           NGX_SOCKADDR_STRLEN, 1);
        *p++ = NGX_QUIC_BPF_VARSEP;
    }

    *p = '\0';

    var = ngx_array_push(&ccf->env);
    if (var == NULL) {
        return NGX_ERROR;
    }

    var->data = buf;
    var->len = sizeof(NGX_QUIC_BPF_VARNAME) - 1;

    return NGX_OK;
}


static ngx_int_t
ngx_quic_bpf_import_maps(ngx_cycle_t *cycle)
{
    int                    fds[2], globs[2];
    u_char                *inherited, *p, *v;
    ngx_int_t              fd;
    ngx_uint_t             nfd, nglob;
    ngx_addr_t             tmp;
    ngx_quic_bpf_conf_t   *bcf;
    ngx_quic_bpf_group_t  *grp;

    bcf = ngx_quic_bpf_get_conf(cycle);

    inherited = bcf->env;

    if (inherited == NULL) {
        return NGX_OK;
    }

    ngx_log_error(NGX_LOG_NOTICE, cycle->log, 0,
                  "quic bpf using inherited maps from \"%s\"",
                  inherited);


    /* first, parse globals, they must be set before inheriting groups */

    nglob = 0;

    for (p = inherited, v = p; *p; p++) {

        switch (*p) {

        case NGX_QUIC_BPF_GSEP:

            if (nglob > 1) {
                goto failed;
            }

            fd = ngx_atoi(v, p - v);
            if (fd == NGX_ERROR) {
                goto failed;
            }

            globs[nglob++] = fd;
            v = p + 1;

            if (nglob == 2) {
                goto done;
            }

            break;

        default:
            break;
        }
    }

    if (nglob < 2) {
        goto failed;
    }

done:

    ngx_log_debug2(NGX_LOG_DEBUG_EVENT, cycle->log, 0,
                   "quic bpf inherited globals: master_index:%d "
                   "master_state_map fd:%d", globs[0], globs[1]);

    bcf->master_index = globs[0];
    bcf->master_state_map = globs[1];

    /* now, continue with reuseport groups */

    nfd = 0;

    for (/* void */; *p; p++) {

        switch (*p) {

        case NGX_QUIC_BPF_ADDRSEP:

            if (nfd > 1) {
                goto failed;
            }

            fd = ngx_atoi(v, p - v);
            if (fd == NGX_ERROR) {
                goto failed;
            }

            fds[nfd++] = fd;
            v = p + 1;
            break;

        case NGX_QUIC_BPF_VARSEP:

            if (nfd != 2) {
                goto failed;
            }

            if (ngx_parse_addr_port(cycle->pool, &tmp, v, p - v) != NGX_OK) {
                goto failed;
            }

            grp = ngx_quic_bpf_create_group(cycle, NGX_QUIC_BPF_GROUP_INHERIT,
                                            tmp.sockaddr, tmp.socklen,
                                            fds[0], fds[1]);
            if (grp == NULL) {
                return NGX_ERROR;
            }

            nfd = 0;
            v = p + 1;
            break;

        default:
            break;
        }
    }

    return NGX_OK;

failed:

    ngx_log_error(NGX_LOG_EMERG, cycle->log, 0,
                  "quic bpf failed to parse inherited variable \"%s\"",
                  NGX_QUIC_BPF_VARNAME);

    return NGX_ERROR;
}


ngx_int_t
ngx_quic_bpf_get_client_connection(ngx_connection_t *lc, ngx_connection_t **pc)
{
    ngx_event_t               *rev;
    ngx_connection_t          *c;
    ngx_quic_bpf_group_t      *grp;
    ngx_quic_bpf_listening_t  *bpf_listening, *bls;

    grp = ngx_quic_bpf_find_group((ngx_cycle_t *) ngx_cycle, lc->listening);

    if (grp == NULL || ngx_worker >= grp->listening.nelts) {
        return NGX_OK;
    }

    bpf_listening = grp->listening.elts;
    bls = &bpf_listening[ngx_worker];

    if (bls->fd == (ngx_socket_t) -1) {
        return NGX_OK;
    }

    if (bls->connection == NULL) {
        c = ngx_get_connection(bls->fd, lc->log);
        if (c == NULL) {
            return NGX_ERROR;
        }

        c->type = SOCK_DGRAM;
        c->log = lc->log;
        c->listening = bls->listening;

        rev = c->read;
        rev->quic = 1;
        rev->log = c->log;
        rev->handler = ngx_quic_recvmsg;

        if (ngx_add_event(rev, NGX_READ_EVENT, 0) == NGX_ERROR) {
            ngx_free_connection(c);
            return NGX_ERROR;
        }

        bls->connection = c;

        ngx_log_debug1(NGX_LOG_DEBUG_EVENT, lc->log, 0,
                       "quic bpf worker socket connection fd:%d", bls->fd);
    }

    *pc = ngx_get_connection(bls->fd, lc->log);
    if (*pc == NULL) {
        return NGX_ERROR;
    }

    (*pc)->shared = 1;

    ngx_log_debug1(NGX_LOG_DEBUG_EVENT, lc->log, 0,
                   "quic bpf client connection fd:%d", bls->fd);

    return NGX_OK;
}


ngx_int_t
ngx_quic_bpf_insert(ngx_connection_t *c, ngx_quic_connection_t *qc,
    ngx_quic_socket_t *qsock)
{
    ngx_quic_bpf_group_t  *grp;

    if (qsock->sid.len != NGX_QUIC_SERVER_CID_LEN) {
        /* route by address */
        return NGX_OK;
    }

    grp = ngx_quic_bpf_find_group((ngx_cycle_t *) ngx_cycle, c->listening);
    if (grp == NULL) {
        return NGX_OK;
    }

    if (ngx_bpf_map_update(grp->connection_map, qsock->sid.id, &c->fd, BPF_ANY)
        == -1)
    {
        ngx_log_error(NGX_LOG_ALERT, c->log, ngx_errno,
                      "quic bpf failed to update connections map");
        return NGX_ERROR;
    }

    return NGX_OK;
}


ngx_int_t
ngx_quic_bpf_delete(ngx_connection_t *c, ngx_quic_connection_t *qc,
    ngx_quic_socket_t *qsock)
{
    ngx_quic_bpf_group_t  *grp;

    if (qsock->sid.len != NGX_QUIC_SERVER_CID_LEN) {
        /* route by address */
        return NGX_OK;
    }

    grp = ngx_quic_bpf_find_group((ngx_cycle_t *) ngx_cycle, c->listening);
    if (grp == NULL) {
        return NGX_OK;
    }

    if (ngx_bpf_map_delete(grp->connection_map, qsock->sid.id) == -1) {
        ngx_log_error(NGX_LOG_ALERT, c->log, ngx_errno,
                      "quic bpf failed to update connections map");
        return NGX_ERROR;
    }

    return NGX_OK;
}
