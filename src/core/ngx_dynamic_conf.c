
/*
 * Copyright (C) Roman Arutyunyan
 * Copyright (C) Nginx, Inc.
 */


#include <ngx_config.h>
#include <ngx_core.h>
#include <nginx.h>
#include <ngx_thread_pool.h>
#include <ngx_dynamic_conf.h>


typedef struct {
    ngx_pool_t               *pool;
    ngx_log_t                *log;
    ngx_cycle_t              *main_cycle;
    ngx_cycle_t              *cycle;
    ngx_thread_task_t        *task;
    ngx_uint_t                count;
#if (NGX_DEBUG)
    ngx_uint_t                id;
#endif
} ngx_dynamic_conf_ctx_t;


typedef struct {
    ngx_str_t                 threads;
#if (NGX_DYNAMIC_CONF_PRELOAD)
    ngx_flag_t                preload;
#endif
    ngx_thread_pool_t        *thread_pool;
    ngx_dynamic_conf_ctx_t   *ctx;
#if (NGX_DEBUG)
    ngx_uint_t                id;
#endif
} ngx_dynamic_conf_t;


static void *ngx_dynamic_conf_create_conf(ngx_cycle_t *cycle);
static char *ngx_dynamic_conf_init_conf(ngx_cycle_t *cycle, void *conf);
#if (NGX_DYNAMIC_CONF_PRELOAD)
static ngx_int_t ngx_dynamic_conf_init_worker(ngx_cycle_t *cycle);
#endif
static void ngx_dynamic_conf_exit_worker(ngx_cycle_t *cycle);
static void ngx_dynamic_conf_load_handler(void *data, ngx_log_t *log);
static void ngx_dynamic_conf_loaded(ngx_event_t *event);
static void ngx_dynamic_conf_cleanup(void *data);
static void ngx_dynamic_conf_unload(ngx_dynamic_conf_ctx_t *ctx);
static void ngx_dynamic_conf_install(ngx_dynamic_conf_ctx_t *ctx);
static void ngx_dynamic_conf_pass_connection(ngx_connection_t *c);


static ngx_command_t  ngx_dynamic_conf_commands[] = {

    { ngx_string("dynamic_conf_threads"),
      NGX_MAIN_CONF|NGX_DIRECT_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_str_slot,
      0,
      offsetof(ngx_dynamic_conf_t, threads),
      NULL },

#if (NGX_DYNAMIC_CONF_PRELOAD)
    { ngx_string("dynamic_conf_preload"),
      NGX_MAIN_CONF|NGX_DIRECT_CONF|NGX_CONF_FLAG,
      ngx_conf_set_flag_slot,
      0,
      offsetof(ngx_dynamic_conf_t, preload),
      NULL },
#endif

      ngx_null_command
};


static ngx_core_module_t  ngx_dynamic_conf_module_ctx = {
    ngx_string("dynamic_conf"),
    ngx_dynamic_conf_create_conf,
    ngx_dynamic_conf_init_conf
};


ngx_module_t  ngx_dynamic_conf_module = {
    NGX_MODULE_V1,
    &ngx_dynamic_conf_module_ctx,          /* module context */
    ngx_dynamic_conf_commands,             /* module directives */
    NGX_CORE_MODULE,                       /* module type */
    NULL,                                  /* init master */
    NULL,                                  /* init module */
#if (NGX_DYNAMIC_CONF_PRELOAD)
    ngx_dynamic_conf_init_worker,          /* init process */
#else
    NULL,                                  /* init process */
#endif
    NULL,                                  /* init thread */
    NULL,                                  /* exit thread */
    ngx_dynamic_conf_exit_worker,          /* exit process */
    NULL,                                  /* exit master */
    NGX_MODULE_V1_PADDING
};


static void *
ngx_dynamic_conf_create_conf(ngx_cycle_t *cycle)
{
    ngx_dynamic_conf_t  *dcf;

    dcf = ngx_pcalloc(cycle->pool, sizeof(ngx_dynamic_conf_t));
    if (dcf == NULL) {
        return NULL;
    }

    /*
     * set by ngx_pcalloc():
     *
     *     dcf->threads = { 0, NULL };
     */

#if (NGX_DYNAMIC_CONF_PRELOAD)
    dcf->preload = NGX_CONF_UNSET;
#endif

    return dcf;
}


static char *
ngx_dynamic_conf_init_conf(ngx_cycle_t *cycle, void *conf)
{
    ngx_dynamic_conf_t  *dcf = conf;

#if (NGX_DYNAMIC_CONF_PRELOAD)
    ngx_conf_init_value(dcf->preload, 0);
#endif

    if (dcf->threads.data == NULL) {
        dcf->thread_pool = ngx_thread_pool_add(cycle, NULL);

    } else {
        dcf->thread_pool = ngx_thread_pool_add(cycle, &dcf->threads);
    }

    if (dcf->thread_pool == NULL) {
        return NGX_CONF_ERROR;
    }

    return NGX_CONF_OK;
}


#if (NGX_DYNAMIC_CONF_PRELOAD)

static ngx_int_t
ngx_dynamic_conf_init_worker(ngx_cycle_t *cycle)
{
    ngx_pool_t              *pool;
    ngx_dynamic_conf_t      *dcf;
    ngx_dynamic_conf_ctx_t  *ctx;

    if (ngx_process != NGX_PROCESS_WORKER
        && ngx_process != NGX_PROCESS_SINGLE)
    {
        return NGX_OK;
    }

    dcf = (ngx_dynamic_conf_t *) ngx_get_conf(cycle->conf_ctx,
                                              ngx_dynamic_conf_module);

    if (!dcf->preload) {
        return NGX_OK;
    }

    ngx_log_debug0(NGX_LOG_DEBUG_CORE, cycle->log, 0, "dynamic conf preload");

    pool = ngx_create_pool(NGX_CYCLE_POOL_SIZE, cycle->log);
    if (pool == NULL) {
        return NGX_ERROR;
    }

    ctx = ngx_pcalloc(pool, sizeof(ngx_dynamic_conf_ctx_t));
    if (ctx == NULL) {
        ngx_destroy_pool(pool);
        return NGX_ERROR;
    }

    ctx->pool = pool;
    ctx->log = cycle->log;
    ctx->main_cycle = cycle;
#if (NGX_DEBUG)
    ctx->id = dcf->id++;
#endif

    ngx_dynamic_conf_load_handler(ctx, cycle->log);

    if (ctx->cycle == NULL) {
        ngx_log_error(NGX_LOG_ALERT, ctx->log, 0,
                      "dynamic configuration preload failed");
        ngx_destroy_pool(pool);
        return NGX_ERROR;
    }

    ngx_dynamic_conf_install(ctx);

    dcf->ctx = ctx;
    ctx->count = 1;

    return NGX_OK;
}

#endif


static void
ngx_dynamic_conf_exit_worker(ngx_cycle_t *cycle)
{
    ngx_dynamic_conf_t      *dcf;
    ngx_dynamic_conf_ctx_t  *ctx;

    if (ngx_process != NGX_PROCESS_WORKER
        && ngx_process != NGX_PROCESS_SINGLE)
    {
        return;
    }

    dcf = (ngx_dynamic_conf_t *) ngx_get_conf(cycle->conf_ctx,
                                              ngx_dynamic_conf_module);

    ctx = dcf->ctx;

    if (ctx == NULL) {
        return;
    }

    if (ctx->cycle == NULL) {
        ngx_destroy_pool(ctx->pool);
        return;
    }

    ngx_dynamic_conf_unload(ctx);
}


ngx_int_t
ngx_dynamic_conf_update(ngx_cycle_t *cycle)
{
    ngx_pool_t              *pool;
    ngx_thread_task_t       *task;
    ngx_dynamic_conf_t      *dcf;
    ngx_dynamic_conf_ctx_t  *ctx;

    ngx_log_debug0(NGX_LOG_DEBUG_CORE, cycle->log, 0, "dynamic conf update");

    pool = ngx_create_pool(NGX_CYCLE_POOL_SIZE, cycle->log);
    if (pool == NULL) {
        return NGX_ERROR;
    }

    task = ngx_thread_task_alloc(pool, sizeof(ngx_dynamic_conf_ctx_t));
    if (task == NULL) {
        ngx_destroy_pool(pool);
        return NGX_ERROR;
    }

    task->handler = ngx_dynamic_conf_load_handler;
    task->event.handler = ngx_dynamic_conf_loaded;
    task->event.log = cycle->log;
    task->event.data = task->ctx;

    ctx = task->ctx;
    ctx->pool = pool;
    ctx->log = cycle->log;
    ctx->main_cycle = cycle;
    ctx->task = task;

    dcf = (ngx_dynamic_conf_t *) ngx_get_conf(cycle->conf_ctx,
                                              ngx_dynamic_conf_module);
#if (NGX_DEBUG)
    ctx->id = dcf->id++;
#endif

    return ngx_thread_task_post(dcf->thread_pool, task);
}


static void
ngx_dynamic_conf_load_handler(void *data, ngx_log_t *log)
{
    ngx_dynamic_conf_ctx_t  *ctx = data;

    void               *rv;
    ngx_int_t           rc;
    ngx_uint_t          i, n;
    ngx_conf_t          conf;
    ngx_pool_t         *pool;
    ngx_cycle_t        *cycle, *main_cycle;
    ngx_shm_zone_t     *shm_zone, *oshm_zone;
    ngx_listening_t    *ls, *nls;
    ngx_list_part_t    *part, *opart;
    ngx_open_file_t    *file, *ofile;
    ngx_core_conf_t    *main_ccf;
    ngx_core_module_t  *module;

    main_cycle = ctx->main_cycle;
    pool = ctx->pool;

    cycle = ngx_pcalloc(pool, sizeof(ngx_cycle_t));
    if (cycle == NULL) {
        return;
    }

    cycle->pool = pool;
    cycle->log = pool->log;
    cycle->old_cycle = main_cycle;
    cycle->dynamic = 1;
    cycle->conf_prefix = main_cycle->conf_prefix;
    cycle->prefix = main_cycle->prefix;
    cycle->error_log = main_cycle->error_log;
    cycle->conf_file = main_cycle->conf_file;
    cycle->conf_param = main_cycle->conf_param;
    cycle->hostname = main_cycle->hostname;
    cycle->modules = main_cycle->modules;
    cycle->modules_n = main_cycle->modules_n;

    n = main_cycle->paths.nelts;

    if (ngx_array_init(&cycle->paths, pool, n, sizeof(ngx_path_t *))
        != NGX_OK)
    {
        return;
    }

    ngx_memzero(cycle->paths.elts, n * sizeof(ngx_path_t *));


    if (ngx_array_init(&cycle->config_dump, pool, 1, sizeof(ngx_conf_dump_t))
        != NGX_OK)
    {
        return;
    }

    ngx_rbtree_init(&cycle->config_dump_rbtree, &cycle->config_dump_sentinel,
                    ngx_str_rbtree_insert_value);

    if (main_cycle->open_files.part.nelts) {
        n = main_cycle->open_files.part.nelts;
        for (part = main_cycle->open_files.part.next; part; part = part->next) {
            n += part->nelts;
        }

    } else {
        n = 20;
    }

    if (ngx_list_init(&cycle->open_files, pool, n, sizeof(ngx_open_file_t))
        != NGX_OK)
    {
        return;
    }

    if (main_cycle->shared_memory.part.nelts) {
        n = main_cycle->shared_memory.part.nelts;
        for (part = main_cycle->shared_memory.part.next; part;
             part = part->next)
        {
            n += part->nelts;
        }

    } else {
        n = 1;
    }

    if (ngx_list_init(&cycle->shared_memory, pool, n, sizeof(ngx_shm_zone_t))
        != NGX_OK)
    {
        return;
    }

    n = main_cycle->listening.nelts ? main_cycle->listening.nelts : 1;

    if (ngx_array_init(&cycle->listening, pool, n, sizeof(ngx_listening_t))
        != NGX_OK)
    {
        return;
    }

    ngx_memzero(cycle->listening.elts, n * sizeof(ngx_listening_t));

    cycle->conf_ctx = ngx_pcalloc(pool, ngx_max_module * sizeof(void *));
    if (cycle->conf_ctx == NULL) {
        return;
    }


    for (i = 0; cycle->modules[i]; i++) {
        if (cycle->modules[i]->type != NGX_CORE_MODULE) {
            continue;
        }

        module = cycle->modules[i]->ctx;

        if (module->create_conf) {
            rv = module->create_conf(cycle);
            if (rv == NULL) {
                return;
            }
            cycle->conf_ctx[cycle->modules[i]->index] = rv;
        }
    }


    ngx_memzero(&conf, sizeof(ngx_conf_t));
    /* STUB: init array ? */
    conf.args = ngx_array_create(pool, 10, sizeof(ngx_str_t));
    if (conf.args == NULL) {
        return;
    }

    conf.temp_pool = ngx_create_pool(NGX_CYCLE_POOL_SIZE, log);
    if (conf.temp_pool == NULL) {
        return;
    }


    conf.ctx = cycle->conf_ctx;
    conf.cycle = cycle;
    conf.pool = pool;
    conf.log = log;
    conf.module_type = NGX_CORE_MODULE;
    conf.cmd_type = NGX_MAIN_CONF;

#if 0
    log->log_level = NGX_LOG_DEBUG_ALL;
#endif

    if (ngx_conf_param(&conf) != NGX_CONF_OK) {
        goto destroy_pools;
    }

    if (ngx_conf_parse(&conf, &cycle->conf_file) != NGX_CONF_OK) {
        goto destroy_pools;
    }

    for (i = 0; cycle->modules[i]; i++) {
        if (cycle->modules[i]->type != NGX_CORE_MODULE) {
            continue;
        }

        module = cycle->modules[i]->ctx;

        if (module->init_conf) {
            if (module->init_conf(cycle,
                                  cycle->conf_ctx[cycle->modules[i]->index])
                == NGX_CONF_ERROR)
            {
                goto destroy_pools;
            }
        }
    }

    main_ccf = (ngx_core_conf_t *) ngx_get_conf(main_cycle->conf_ctx,
                                                ngx_core_module);

    if (ngx_create_paths(cycle, main_ccf->user) != NGX_OK) {
        goto failed;
    }

    if (ngx_log_open_default(cycle) != NGX_OK) {
        goto failed;
    }

    /* open the new files */

    part = &cycle->open_files.part;
    file = part->elts;

    for (i = 0; /* void */ ; i++) {

        if (i >= part->nelts) {
            if (part->next == NULL) {
                break;
            }
            part = part->next;
            file = part->elts;
            i = 0;
        }

        if (file[i].name.len == 0) {
            continue;
        }

        opart = (ngx_list_part_t *) &main_cycle->open_files.part;
        ofile = opart->elts;

        for (n = 0; /* void */ ; n++) {

            if (n >= opart->nelts) {
                if (opart->next == NULL) {
                    break;
                }
                opart = opart->next;
                ofile = opart->elts;
                n = 0;
            }

            if (file[i].name.len != ofile[n].name.len) {
                continue;
            }

            if (ngx_strncmp(file[i].name.data, ofile[n].name.data,
                            file[i].name.len)
                != 0)
            {
                continue;
            }

            file[i].fd = ngx_dup(ofile[n].fd);

            ngx_log_debug4(NGX_LOG_DEBUG_CORE, log, 0,
                           "log: %p %d (dup %d) \"%s\"",
                           &file[i], file[i].fd, ofile[i].fd,
                           file[i].name.data);

            if (file[i].fd == NGX_INVALID_FILE) {
                ngx_log_error(NGX_LOG_EMERG, log, ngx_errno,
                              ngx_dup_n " \"%s\" failed",
                              file[i].name.data);
                goto failed;
            }

            goto file_found;
        }

        file[i].fd = ngx_open_file(file[i].name.data,
                                   NGX_FILE_APPEND,
                                   NGX_FILE_CREATE_OR_OPEN,
                                   NGX_FILE_DEFAULT_ACCESS);

        ngx_log_debug3(NGX_LOG_DEBUG_CORE, log, 0,
                       "log: %p %d \"%s\"",
                       &file[i], file[i].fd, file[i].name.data);

        if (file[i].fd == NGX_INVALID_FILE) {
            ngx_log_error(NGX_LOG_EMERG, log, ngx_errno,
                          ngx_open_file_n " \"%s\" failed",
                          file[i].name.data);
            goto failed;
        }

    file_found:

        continue;
    }

    cycle->log = &cycle->new_log;
    pool->log = &cycle->new_log;


    /* create shared memory */

    part = &cycle->shared_memory.part;
    shm_zone = part->elts;

    for (i = 0; /* void */ ; i++) {

        if (i >= part->nelts) {
            if (part->next == NULL) {
                break;
            }
            part = part->next;
            shm_zone = part->elts;
            i = 0;
        }

        shm_zone[i].shm.log = cycle->log;

        opart = (ngx_list_part_t *) &main_cycle->shared_memory.part;
        oshm_zone = opart->elts;

        for (n = 0; /* void */ ; n++) {

            if (n >= opart->nelts) {
                if (opart->next == NULL) {
                    break;
                }
                opart = opart->next;
                oshm_zone = opart->elts;
                n = 0;
            }

            if (shm_zone[i].shm.name.len != oshm_zone[n].shm.name.len) {
                continue;
            }

            if (ngx_strncmp(shm_zone[i].shm.name.data,
                            oshm_zone[n].shm.name.data,
                            shm_zone[i].shm.name.len)
                != 0)
            {
                continue;
            }

            if (shm_zone[i].tag == oshm_zone[n].tag && shm_zone[i].noreuse) {
                ngx_log_error(NGX_LOG_ERR, cycle->log, 0,
                              "non-reusable shared zone \"%V\"",
                              &shm_zone[i].shm.name);
                goto failed;
            }

            if (shm_zone[i].tag == oshm_zone[n].tag
                && shm_zone[i].shm.size == oshm_zone[n].shm.size)
            {
                shm_zone[i].shm.addr = oshm_zone[n].shm.addr;
#if (NGX_WIN32)
                shm_zone[i].shm.handle = oshm_zone[n].shm.handle;
#endif

                rc = shm_zone[i].init(&shm_zone[i], oshm_zone[n].data);

                if (rc == NGX_DECLINED) {
                    shm_zone[i].shm.addr = NULL;
#if (NGX_WIN32)
                    shm_zone[i].shm.handle = NULL;
#endif
                    ngx_log_error(NGX_LOG_ERR, cycle->log, 0,
                                  "cannot reuse shared zone \"%V\"",
                                  &shm_zone[i].shm.name);
                    goto failed;
                }

                if (rc != NGX_OK) {
                    goto failed;
                }

                goto shm_zone_found;
            }

            ngx_log_error(NGX_LOG_ERR, cycle->log, 0,
                          "cannot reuse shared zone \"%V\"",
                          &shm_zone[i].shm.name);

            goto failed;
        }

        ngx_log_error(NGX_LOG_ERR, cycle->log, 0,
                      "cannot find a matching shared zone \"%V\"",
                      &shm_zone[i].shm.name);

        goto failed;

    shm_zone_found:

        continue;
    }


    /* handle the listening sockets */

    ls = (ngx_listening_t *) main_cycle->listening.elts;
    nls = cycle->listening.elts;

    for (n = 0; n < cycle->listening.nelts; n++) {

        for (i = 0; i < main_cycle->listening.nelts; i++) {

#if (NGX_HAVE_REUSEPORT)
            if (ls[i].reuseport && ls[i].worker != ngx_worker) {
                continue;
            }
#endif

            if (ls[i].type != nls[n].type) {
                continue;
            }

#if (NGX_QUIC)
            if (ls[i].quic != nls[n].quic) {
                continue;
            }
#endif

#if (NGX_HAVE_REUSEPORT)
            if (ls[i].reuseport != nls[n].reuseport) {
                continue;
            }
#endif

            if (ngx_cmp_sockaddr(ls[i].sockaddr, ls[i].socklen,
                                 nls[n].sockaddr, nls[n].socklen, 1)
                != NGX_OK)
            {
                continue;
            }

            nls[n].previous = &ls[i];

#if (NGX_HAVE_REUSEPORT)
            if (nls[n].reuseport) {
                nls[n].worker = ngx_worker;
            }
#endif

            goto listening_found;
        }

        if (ngx_exiting) {
            /*
             * An exiting worker calls ngx_close_listening_sockets()
             * which resets the c->listening array.  Avoid logging an
             * error in this case
             */
            goto failed;
        }

        ngx_log_error(NGX_LOG_ERR, cycle->log, 0,
                      "unexpected listen port for \"%V\"", &nls[n].addr_text);
        goto failed;

    listening_found:

        continue;
    }


    /* commit the new cycle configuration */

    pool->log = cycle->log;

    if (ngx_init_modules(cycle) != NGX_OK) {
        /* fatal */
        exit(1);
    }

    ngx_destroy_pool(conf.temp_pool);

    ctx->cycle = cycle;

    return;


failed:

    /* rollback the new cycle configuration */

    part = &cycle->open_files.part;
    file = part->elts;

    for (i = 0; /* void */ ; i++) {

        if (i >= part->nelts) {
            if (part->next == NULL) {
                break;
            }
            part = part->next;
            file = part->elts;
            i = 0;
        }

        if (file[i].fd == NGX_INVALID_FILE || file[i].fd == ngx_stderr) {
            continue;
        }

        if (ngx_close_file(file[i].fd) == NGX_FILE_ERROR) {
            ngx_log_error(NGX_LOG_EMERG, log, ngx_errno,
                          ngx_close_file_n " \"%s\" failed",
                          file[i].name.data);
        }
    }

destroy_pools:

    ngx_destroy_pool(conf.temp_pool);
}


static void
ngx_dynamic_conf_loaded(ngx_event_t *event)
{
    ngx_dynamic_conf_t      *dcf;
    ngx_dynamic_conf_ctx_t  *ctx;

    ctx = event->data;

    ngx_log_debug2(NGX_LOG_DEBUG_CORE, ctx->log, 0,
                   "dynamic conf load %p n:%ui", ctx->cycle, ctx->id);

    if (ctx->cycle == NULL && !ngx_exiting) {
        ngx_log_error(NGX_LOG_ALERT, ctx->log, 0,
                      "dynamic configuration load failed");
    }

    if (ctx->cycle == NULL || ngx_exiting) {
        ngx_destroy_pool(ctx->pool);
        return;
    }

    ngx_dynamic_conf_install(ctx);

    dcf = (ngx_dynamic_conf_t *) ngx_get_conf(ctx->main_cycle->conf_ctx,
                                              ngx_dynamic_conf_module);

    if (dcf->ctx) {
        ngx_dynamic_conf_cleanup(dcf->ctx);
    }

    dcf->ctx = ctx;
    ctx->count++;
}


static void
ngx_dynamic_conf_cleanup(void *data)
{
    ngx_dynamic_conf_ctx_t *ctx = data;

    if (--ctx->count) {
        ngx_log_debug3(NGX_LOG_DEBUG_CORE, ctx->log, 0,
                       "dynamic conf hold %p n:%ui c:%ui",
                       ctx->cycle, ctx->id, ctx->count);
        return;
    }

    ngx_dynamic_conf_unload(ctx);
}


static void
ngx_dynamic_conf_unload(ngx_dynamic_conf_ctx_t *ctx)
{
    ngx_uint_t        i;
    ngx_list_part_t  *part;
    ngx_open_file_t  *file;

    part = &ctx->cycle->open_files.part;
    file = part->elts;

    for (i = 0; /* void */ ; i++) {

        if (i >= part->nelts) {
            if (part->next == NULL) {
                break;
            }
            part = part->next;
            file = part->elts;
            i = 0;
        }

        if (file[i].flush) {
            file[i].flush(&file[i], ctx->log);
        }

        if (file[i].fd == NGX_INVALID_FILE || file[i].fd == ngx_stderr) {
            continue;
        }

        if (ngx_close_file(file[i].fd) == NGX_FILE_ERROR) {
            ngx_log_error(NGX_LOG_EMERG, ctx->log, ngx_errno,
                          ngx_close_file_n " \"%s\" failed", file[i].name.data);
        }
    }

    ngx_log_debug2(NGX_LOG_DEBUG_CORE, ctx->log, 0,
                   "dynamic conf free %p n:%ui", 
                   ctx->cycle, ctx->id);

    ngx_destroy_pool(ctx->pool);

#if (NGX_HAVE_MALLOC_TRIM)
    malloc_trim(0);
#endif
}


static void
ngx_dynamic_conf_install(ngx_dynamic_conf_ctx_t *ctx)
{
    ngx_uint_t        n, i;
    ngx_listening_t  *ls, *nls;

    ls = (ngx_listening_t *) ctx->main_cycle->listening.elts;
    nls = (ngx_listening_t *) ctx->cycle->listening.elts;

    for (n = 0; n < ctx->main_cycle->listening.nelts; n++) {

        ls[n].handler = ngx_dynamic_conf_pass_connection;
        ls[n].next = NULL;

        for (i = 0; i < ctx->cycle->listening.nelts; i++) {
            if (&ls[n] == nls[i].previous) {
                ls[n].next = &nls[i];
                break;
            }
        }
    }
}


static void
ngx_dynamic_conf_pass_connection(ngx_connection_t *c)
{
    ngx_pool_t              *pool;
    ngx_pool_cleanup_t      *cln;
    ngx_dynamic_conf_t      *dcf;
    ngx_dynamic_conf_ctx_t  *ctx;

    dcf = (ngx_dynamic_conf_t *) ngx_get_conf(ngx_cycle->conf_ctx,
                                              ngx_dynamic_conf_module);

    ctx = dcf->ctx;

    if (ctx == NULL || c->listening->next == NULL) {
        goto close;
    }

    ngx_log_debug2(NGX_LOG_DEBUG_CORE, c->log, 0,
                   "dynamic conf pass %p n:%ui", ctx->cycle, ctx->id);

    cln = ngx_pool_cleanup_add(c->pool, 0);
    if (cln == NULL) {
        goto close;
    }

    cln->handler = ngx_dynamic_conf_cleanup;
    cln->data = ctx;
    ctx->count++;

    c->listening = c->listening->next;
    c->listening->handler(c);

    return;

close:

    pool = c->pool;
    ngx_close_connection(c);
    ngx_destroy_pool(pool);
}


void
ngx_dynamic_conf_reopen_files(ngx_cycle_t *cycle)
{
    ngx_dynamic_conf_t      *dcf;
    ngx_dynamic_conf_ctx_t  *ctx;

    dcf = (ngx_dynamic_conf_t *) ngx_get_conf(cycle->conf_ctx,
                                              ngx_dynamic_conf_module);

    ctx = dcf->ctx;

    if (ctx == NULL || ctx->cycle == NULL) {
        return;
    }

    ngx_log_debug2(NGX_LOG_DEBUG_CORE, cycle->log, 0,
                   "dynamic conf reopen files %p n:%ui", ctx->cycle, ctx->id);

    ngx_reopen_files(ctx->cycle, -1);
}
