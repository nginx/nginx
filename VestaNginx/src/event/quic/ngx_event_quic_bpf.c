
/*
 * Copyright (C) Nginx, Inc.
 */


#include <ngx_config.h>
#include <ngx_core.h>


#define NGX_QUIC_BPF_VARNAME  "NGINX_BPF_MAPS"
#define NGX_QUIC_BPF_VARSEP    ';'
#define NGX_QUIC_BPF_ADDRSEP   '#'


#define ngx_quic_bpf_get_conf(cycle)                                          \
    (ngx_quic_bpf_conf_t *) ngx_get_conf(cycle->conf_ctx, ngx_quic_bpf_module)

#define ngx_quic_bpf_get_old_conf(cycle)                                      \
    cycle->old_cycle->conf_ctx ? ngx_quic_bpf_get_conf(cycle->old_cycle)      \
                               : NULL

#define ngx_core_get_conf(cycle)                                              \
    (ngx_core_conf_t *) ngx_get_conf(cycle->conf_ctx, ngx_core_module)


typedef struct {
    ngx_queue_t           queue;
    int                   map_fd;

    struct sockaddr      *sockaddr;
    socklen_t             socklen;
    ngx_uint_t            unused;     /* unsigned  unused:1; */
} ngx_quic_sock_group_t;


typedef struct {
    ngx_flag_t            enabled;
    ngx_uint_t            map_size;
    ngx_queue_t           groups;     /* of ngx_quic_sock_group_t */
} ngx_quic_bpf_conf_t;


static void *ngx_quic_bpf_create_conf(ngx_cycle_t *cycle);
static ngx_int_t ngx_quic_bpf_module_init(ngx_cycle_t *cycle);

static void ngx_quic_bpf_cleanup(void *data);
static ngx_inline void ngx_quic_bpf_close(ngx_log_t *log, int fd,
    const char *name);

static ngx_quic_sock_group_t *ngx_quic_bpf_find_group(ngx_quic_bpf_conf_t *bcf,
    ngx_listening_t *ls);
static ngx_quic_sock_group_t *ngx_quic_bpf_alloc_group(ngx_cycle_t *cycle,
    struct sockaddr *sa, socklen_t socklen);
static ngx_quic_sock_group_t *ngx_quic_bpf_create_group(ngx_cycle_t *cycle,
    ngx_listening_t *ls);
static ngx_quic_sock_group_t *ngx_quic_bpf_get_group(ngx_cycle_t *cycle,
    ngx_listening_t *ls);
static ngx_int_t ngx_quic_bpf_group_add_socket(ngx_cycle_t *cycle,
    ngx_listening_t *ls);
static uint64_t ngx_quic_bpf_socket_key(ngx_fd_t fd, ngx_log_t *log);

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
    NULL
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

    bcf->enabled = NGX_CONF_UNSET;
    bcf->map_size = NGX_CONF_UNSET_UINT;

    ngx_queue_init(&bcf->groups);

    return bcf;
}


static ngx_int_t
ngx_quic_bpf_module_init(ngx_cycle_t *cycle)
{
    ngx_uint_t            i;
    ngx_listening_t      *ls;
    ngx_core_conf_t      *ccf;
    ngx_pool_cleanup_t   *cln;
    ngx_quic_bpf_conf_t  *bcf;

    if (ngx_test_config) {
        /*
         * during config test, SO_REUSEPORT socket option is
         * not set, thus making further processing meaningless
         */
        return NGX_OK;
    }

    ccf = ngx_core_get_conf(cycle);
    bcf = ngx_quic_bpf_get_conf(cycle);

    ngx_conf_init_value(bcf->enabled, 0);

    bcf->map_size = ccf->worker_processes * 4;

    cln = ngx_pool_cleanup_add(cycle->pool, 0);
    if (cln == NULL) {
        goto failed;
    }

    cln->data = bcf;
    cln->handler = ngx_quic_bpf_cleanup;

    if (ngx_inherited && ngx_is_init_cycle(cycle->old_cycle)) {
        if (ngx_quic_bpf_import_maps(cycle) != NGX_OK) {
            goto failed;
        }
    }

    ls = cycle->listening.elts;

    for (i = 0; i < cycle->listening.nelts; i++) {
        if (ls[i].quic && ls[i].reuseport) {
            if (ngx_quic_bpf_group_add_socket(cycle, &ls[i]) != NGX_OK) {
                goto failed;
            }
        }
    }

    if (ngx_quic_bpf_export_maps(cycle) != NGX_OK) {
        goto failed;
    }

    return NGX_OK;

failed:

    if (ngx_is_init_cycle(cycle->old_cycle)) {
        ngx_log_error(NGX_LOG_EMERG, cycle->log, 0,
                      "ngx_quic_bpf_module failed to initialize, check limits");

        /* refuse to start */
        return NGX_ERROR;
    }

    /*
     * returning error now will lead to master process exiting immediately
     * leaving worker processes orphaned, what is really unexpected.
     * Instead, just issue a not about failed initialization and try
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


static void
ngx_quic_bpf_cleanup(void *data)
{
    ngx_quic_bpf_conf_t  *bcf = (ngx_quic_bpf_conf_t *) data;

    ngx_queue_t            *q;
    ngx_quic_sock_group_t  *grp;

    for (q = ngx_queue_head(&bcf->groups);
         q != ngx_queue_sentinel(&bcf->groups);
         q = ngx_queue_next(q))
    {
        grp = ngx_queue_data(q, ngx_quic_sock_group_t, queue);

        ngx_quic_bpf_close(ngx_cycle->log, grp->map_fd, "map");
    }
}


static ngx_inline void
ngx_quic_bpf_close(ngx_log_t *log, int fd, const char *name)
{
    if (close(fd) != -1) {
        return;
    }

    ngx_log_error(NGX_LOG_EMERG, log, ngx_errno,
                  "quic bpf close %s fd:%d failed", name, fd);
}


static ngx_quic_sock_group_t *
ngx_quic_bpf_find_group(ngx_quic_bpf_conf_t *bcf, ngx_listening_t *ls)
{
    ngx_queue_t            *q;
    ngx_quic_sock_group_t  *grp;

    for (q = ngx_queue_head(&bcf->groups);
         q != ngx_queue_sentinel(&bcf->groups);
         q = ngx_queue_next(q))
    {
        grp = ngx_queue_data(q, ngx_quic_sock_group_t, queue);

        if (ngx_cmp_sockaddr(ls->sockaddr, ls->socklen,
                             grp->sockaddr, grp->socklen, 1)
            == NGX_OK)
        {
            return grp;
        }
    }

    return NULL;
}


static ngx_quic_sock_group_t *
ngx_quic_bpf_alloc_group(ngx_cycle_t *cycle, struct sockaddr *sa,
    socklen_t socklen)
{
    ngx_quic_bpf_conf_t    *bcf;
    ngx_quic_sock_group_t  *grp;

    bcf = ngx_quic_bpf_get_conf(cycle);

    grp = ngx_pcalloc(cycle->pool, sizeof(ngx_quic_sock_group_t));
    if (grp == NULL) {
        return NULL;
    }

    grp->socklen = socklen;
    grp->sockaddr = ngx_palloc(cycle->pool, socklen);
    if (grp->sockaddr == NULL) {
        return NULL;
    }
    ngx_memcpy(grp->sockaddr, sa, socklen);

    ngx_queue_insert_tail(&bcf->groups, &grp->queue);

    return grp;
}


static ngx_quic_sock_group_t *
ngx_quic_bpf_create_group(ngx_cycle_t *cycle, ngx_listening_t *ls)
{
    int                     progfd, failed, flags, rc;
    ngx_quic_bpf_conf_t    *bcf;
    ngx_quic_sock_group_t  *grp;

    bcf = ngx_quic_bpf_get_conf(cycle);

    if (!bcf->enabled) {
        return NULL;
    }

    grp = ngx_quic_bpf_alloc_group(cycle, ls->sockaddr, ls->socklen);
    if (grp == NULL) {
        return NULL;
    }

    grp->map_fd = ngx_bpf_map_create(cycle->log, BPF_MAP_TYPE_SOCKHASH,
                                     sizeof(uint64_t), sizeof(uint64_t),
                                     bcf->map_size, 0);
    if (grp->map_fd == -1) {
        goto failed;
    }

    flags = fcntl(grp->map_fd, F_GETFD);
    if (flags == -1) {
        ngx_log_error(NGX_LOG_EMERG, cycle->log, errno,
                      "quic bpf getfd failed");
        goto failed;
    }

    /* need to inherit map during binary upgrade after exec */
    flags &= ~FD_CLOEXEC;

    rc = fcntl(grp->map_fd, F_SETFD, flags);
    if (rc == -1) {
        ngx_log_error(NGX_LOG_EMERG, cycle->log, errno,
                      "quic bpf setfd failed");
        goto failed;
    }

    ngx_bpf_program_link(&ngx_quic_reuseport_helper,
                         "ngx_quic_sockmap", grp->map_fd);

    progfd = ngx_bpf_load_program(cycle->log, &ngx_quic_reuseport_helper);
    if (progfd < 0) {
        goto failed;
    }

    failed = 0;

    if (setsockopt(ls->fd, SOL_SOCKET, SO_ATTACH_REUSEPORT_EBPF,
                   &progfd, sizeof(int))
        == -1)
    {
        ngx_log_error(NGX_LOG_EMERG, cycle->log, ngx_socket_errno,
                      "quic bpf setsockopt(SO_ATTACH_REUSEPORT_EBPF) failed");
        failed = 1;
    }

    ngx_quic_bpf_close(cycle->log, progfd, "program");

    if (failed) {
        goto failed;
    }

    ngx_log_debug1(NGX_LOG_DEBUG_EVENT, cycle->log, 0,
                   "quic bpf sockmap created fd:%d", grp->map_fd);
    return grp;

failed:

    if (grp->map_fd != -1) {
        ngx_quic_bpf_close(cycle->log, grp->map_fd, "map");
    }

    ngx_queue_remove(&grp->queue);

    return NULL;
}


static ngx_quic_sock_group_t *
ngx_quic_bpf_get_group(ngx_cycle_t *cycle, ngx_listening_t *ls)
{
    ngx_quic_bpf_conf_t    *bcf, *old_bcf;
    ngx_quic_sock_group_t  *grp, *ogrp;

    bcf = ngx_quic_bpf_get_conf(cycle);

    grp = ngx_quic_bpf_find_group(bcf, ls);
    if (grp) {
        return grp;
    }

    old_bcf = ngx_quic_bpf_get_old_conf(cycle);

    if (old_bcf == NULL) {
        return ngx_quic_bpf_create_group(cycle, ls);
    }

    ogrp = ngx_quic_bpf_find_group(old_bcf, ls);
    if (ogrp == NULL) {
        return ngx_quic_bpf_create_group(cycle, ls);
    }

    grp = ngx_quic_bpf_alloc_group(cycle, ls->sockaddr, ls->socklen);
    if (grp == NULL) {
        return NULL;
    }

    grp->map_fd = dup(ogrp->map_fd);
    if (grp->map_fd == -1) {
        ngx_log_error(NGX_LOG_EMERG, cycle->log, ngx_errno,
                      "quic bpf failed to duplicate bpf map descriptor");

        ngx_queue_remove(&grp->queue);

        return NULL;
    }

    ngx_log_debug2(NGX_LOG_DEBUG_EVENT, cycle->log, 0,
                   "quic bpf sockmap fd duplicated old:%d new:%d",
                   ogrp->map_fd, grp->map_fd);

    return grp;
}


static ngx_int_t
ngx_quic_bpf_group_add_socket(ngx_cycle_t *cycle,  ngx_listening_t *ls)
{
    uint64_t                cookie;
    ngx_quic_bpf_conf_t    *bcf;
    ngx_quic_sock_group_t  *grp;

    bcf = ngx_quic_bpf_get_conf(cycle);

    grp = ngx_quic_bpf_get_group(cycle, ls);

    if (grp == NULL) {
        if (!bcf->enabled) {
            return NGX_OK;
        }

        return NGX_ERROR;
    }

    grp->unused = 0;

    cookie = ngx_quic_bpf_socket_key(ls->fd, cycle->log);
    if (cookie == (uint64_t) NGX_ERROR) {
        return NGX_ERROR;
    }

    /* map[cookie] = socket; for use in kernel helper */
    if (ngx_bpf_map_update(grp->map_fd, &cookie, &ls->fd, BPF_ANY) == -1) {
        ngx_log_error(NGX_LOG_EMERG, cycle->log, ngx_errno,
                      "quic bpf failed to update socket map key=%xL", cookie);
        return NGX_ERROR;
    }

    ngx_log_debug4(NGX_LOG_DEBUG_EVENT, cycle->log, 0,
                 "quic bpf sockmap fd:%d add socket:%d cookie:0x%xL worker:%ui",
                 grp->map_fd, ls->fd, cookie, ls->worker);

    /* do not inherit this socket */
    ls->ignore = 1;

    return NGX_OK;
}


static uint64_t
ngx_quic_bpf_socket_key(ngx_fd_t fd, ngx_log_t *log)
{
    uint64_t   cookie;
    socklen_t  optlen;

    optlen = sizeof(cookie);

    if (getsockopt(fd, SOL_SOCKET, SO_COOKIE, &cookie, &optlen) == -1) {
        ngx_log_error(NGX_LOG_EMERG, log, ngx_socket_errno,
                      "quic bpf getsockopt(SO_COOKIE) failed");

        return (ngx_uint_t) NGX_ERROR;
    }

    return cookie;
}


static ngx_int_t
ngx_quic_bpf_export_maps(ngx_cycle_t *cycle)
{
    u_char                 *p, *buf;
    size_t                  len;
    ngx_str_t              *var;
    ngx_queue_t            *q;
    ngx_core_conf_t        *ccf;
    ngx_quic_bpf_conf_t    *bcf;
    ngx_quic_sock_group_t  *grp;

    ccf = ngx_core_get_conf(cycle);
    bcf = ngx_quic_bpf_get_conf(cycle);

    len = sizeof(NGX_QUIC_BPF_VARNAME) + 1;

    q = ngx_queue_head(&bcf->groups);

    while (q != ngx_queue_sentinel(&bcf->groups)) {

        grp = ngx_queue_data(q, ngx_quic_sock_group_t, queue);

        q = ngx_queue_next(q);

        if (grp->unused) {
            /*
             * map was inherited, but it is not used in this configuration;
             * do not pass such map further and drop the group to prevent
             * interference with changes during reload
             */

            ngx_quic_bpf_close(cycle->log, grp->map_fd, "map");
            ngx_queue_remove(&grp->queue);

            continue;
        }

        len += NGX_INT32_LEN + 1 + NGX_SOCKADDR_STRLEN + 1;
    }

    len++;

    buf = ngx_palloc(cycle->pool, len);
    if (buf == NULL) {
        return NGX_ERROR;
    }

    p = ngx_cpymem(buf, NGX_QUIC_BPF_VARNAME "=",
                   sizeof(NGX_QUIC_BPF_VARNAME));

    for (q = ngx_queue_head(&bcf->groups);
         q != ngx_queue_sentinel(&bcf->groups);
         q = ngx_queue_next(q))
    {
        grp = ngx_queue_data(q, ngx_quic_sock_group_t, queue);

        p = ngx_sprintf(p, "%ud", grp->map_fd);

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
    int                     s;
    u_char                 *inherited, *p, *v;
    ngx_uint_t              in_fd;
    ngx_addr_t              tmp;
    ngx_quic_bpf_conf_t    *bcf;
    ngx_quic_sock_group_t  *grp;

    inherited = (u_char *) getenv(NGX_QUIC_BPF_VARNAME);

    if (inherited == NULL) {
        return NGX_OK;
    }

    bcf = ngx_quic_bpf_get_conf(cycle);

#if (NGX_SUPPRESS_WARN)
    s = -1;
#endif

    in_fd = 1;

    for (p = inherited, v = p; *p; p++) {

        switch (*p) {

        case NGX_QUIC_BPF_ADDRSEP:

            if (!in_fd) {
                ngx_log_error(NGX_LOG_EMERG, cycle->log, 0,
                              "quic bpf failed to parse inherited env");
                return NGX_ERROR;
            }
            in_fd = 0;

            s = ngx_atoi(v, p - v);
            if (s == NGX_ERROR) {
                ngx_log_error(NGX_LOG_EMERG, cycle->log, 0,
                              "quic bpf failed to parse inherited map fd");
                return NGX_ERROR;
            }

            v = p + 1;
            break;

        case NGX_QUIC_BPF_VARSEP:

            if (in_fd) {
                ngx_log_error(NGX_LOG_EMERG, cycle->log, 0,
                              "quic bpf failed to parse inherited env");
                return NGX_ERROR;
            }
            in_fd = 1;

            grp = ngx_pcalloc(cycle->pool,
                              sizeof(ngx_quic_sock_group_t));
            if (grp == NULL) {
                return NGX_ERROR;
            }

            grp->map_fd = s;

            if (ngx_parse_addr_port(cycle->pool, &tmp, v, p - v)
                != NGX_OK)
            {
                ngx_log_error(NGX_LOG_EMERG, cycle->log, 0,
                              "quic bpf failed to parse inherited"
                              " address '%*s'", p - v , v);

                ngx_quic_bpf_close(cycle->log, s, "inherited map");

                return NGX_ERROR;
            }

            grp->sockaddr = tmp.sockaddr;
            grp->socklen = tmp.socklen;

            grp->unused = 1;

            ngx_queue_insert_tail(&bcf->groups, &grp->queue);

            ngx_log_debug3(NGX_LOG_DEBUG_EVENT, cycle->log, 0,
                           "quic bpf sockmap inherited with "
                           "fd:%d address:%*s",
                           grp->map_fd, p - v, v);
            v = p + 1;
            break;

        default:
            break;
        }
    }

    return NGX_OK;
}
