
/*
 * Copyright (C) Igor Sysoev
 */


#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_event.h>


#define DEFAULT_CONNECTIONS  512


extern ngx_module_t ngx_select_module;
extern ngx_event_module_t ngx_select_module_ctx;

#if (HAVE_KQUEUE)
#include <ngx_kqueue_module.h>
#endif

#if (HAVE_DEVPOLL)
extern ngx_module_t ngx_devpoll_module;
extern ngx_event_module_t ngx_devpoll_module_ctx;
#endif

#if (HAVE_EPOLL)
extern ngx_module_t ngx_epoll_module;
extern ngx_event_module_t ngx_epoll_module_ctx;
#endif

#if (HAVE_RTSIG)
extern ngx_module_t ngx_rtsig_module;
extern ngx_event_module_t ngx_rtsig_module_ctx;
#endif

#if (HAVE_AIO)
#include <ngx_aio_module.h>
#endif

static ngx_int_t ngx_event_module_init(ngx_cycle_t *cycle);
static ngx_int_t ngx_event_process_init(ngx_cycle_t *cycle);
static char *ngx_events_block(ngx_conf_t *cf, ngx_command_t *cmd, void *conf);

static char *ngx_event_connections(ngx_conf_t *cf, ngx_command_t *cmd,
                                   void *conf);
static char *ngx_event_use(ngx_conf_t *cf, ngx_command_t *cmd, void *conf);
static char *ngx_event_debug_connection(ngx_conf_t *cf, ngx_command_t *cmd,
                                        void *conf);

static void *ngx_event_create_conf(ngx_cycle_t *cycle);
static char *ngx_event_init_conf(ngx_cycle_t *cycle, void *conf);
static char *ngx_accept_mutex_check(ngx_conf_t *cf, void *post, void *data);


static ngx_uint_t                 ngx_event_max_module;

ngx_uint_t                        ngx_event_flags;
ngx_event_actions_t               ngx_event_actions;


ngx_atomic_t                      connection_counter;
ngx_atomic_t                     *ngx_connection_counter = &connection_counter;


ngx_atomic_t                     *ngx_accept_mutex_ptr;
ngx_atomic_t                     *ngx_accept_mutex;
ngx_uint_t                        ngx_accept_mutex_held;
ngx_msec_t                        ngx_accept_mutex_delay;
ngx_int_t                         ngx_accept_disabled;


#if (NGX_STAT_STUB)

ngx_atomic_t   ngx_stat_accepted0;
ngx_atomic_t  *ngx_stat_accepted = &ngx_stat_accepted0;
ngx_atomic_t   ngx_stat_requests0;
ngx_atomic_t  *ngx_stat_requests = &ngx_stat_requests0;
ngx_atomic_t   ngx_stat_active0;
ngx_atomic_t  *ngx_stat_active = &ngx_stat_active0;
ngx_atomic_t   ngx_stat_reading0;
ngx_atomic_t  *ngx_stat_reading = &ngx_stat_reading0;
ngx_atomic_t   ngx_stat_writing0;
ngx_atomic_t  *ngx_stat_writing = &ngx_stat_reading0;

#endif



static ngx_command_t  ngx_events_commands[] = {

    { ngx_string("events"),
      NGX_MAIN_CONF|NGX_CONF_BLOCK|NGX_CONF_NOARGS,
      ngx_events_block,
      0,
      0,
      NULL },

      ngx_null_command
};

    
static ngx_core_module_t  ngx_events_module_ctx = {
    ngx_string("events"),
    NULL,
    NULL
};  


ngx_module_t  ngx_events_module = {
    NGX_MODULE,
    &ngx_events_module_ctx,                /* module context */
    ngx_events_commands,                   /* module directives */
    NGX_CORE_MODULE,                       /* module type */
    NULL,                                  /* init module */
    NULL                                   /* init process */
};


static ngx_str_t  event_core_name = ngx_string("event_core");

static ngx_conf_post_t  ngx_accept_mutex_post = { ngx_accept_mutex_check } ;


static ngx_command_t  ngx_event_core_commands[] = {

    { ngx_string("connections"),
      NGX_EVENT_CONF|NGX_CONF_TAKE1,
      ngx_event_connections,
      0,
      0,
      NULL },

    { ngx_string("use"),
      NGX_EVENT_CONF|NGX_CONF_TAKE1,
      ngx_event_use,
      0,
      0,
      NULL },

    { ngx_string("multi_accept"),
      NGX_EVENT_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_flag_slot,
      0,
      offsetof(ngx_event_conf_t, multi_accept),
      NULL },

    { ngx_string("accept_mutex"),
      NGX_EVENT_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_flag_slot,
      0,
      offsetof(ngx_event_conf_t, accept_mutex),
      &ngx_accept_mutex_post },

    { ngx_string("accept_mutex_delay"),
      NGX_EVENT_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_msec_slot,
      0,
      offsetof(ngx_event_conf_t, accept_mutex_delay),
      NULL },

    { ngx_string("debug_connection"),
      NGX_EVENT_CONF|NGX_CONF_TAKE1,
      ngx_event_debug_connection,
      0,
      0,
      NULL },

      ngx_null_command
};


ngx_event_module_t  ngx_event_core_module_ctx = {
    &event_core_name,
    ngx_event_create_conf,                 /* create configuration */
    ngx_event_init_conf,                   /* init configuration */

    { NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL }
};


ngx_module_t  ngx_event_core_module = {
    NGX_MODULE,
    &ngx_event_core_module_ctx,            /* module context */
    ngx_event_core_commands,               /* module directives */
    NGX_EVENT_MODULE,                      /* module type */
    ngx_event_module_init,                 /* init module */
    ngx_event_process_init                 /* init process */
};


static ngx_int_t ngx_event_module_init(ngx_cycle_t *cycle)
{
#if !(WIN32)

    size_t             size;
    char              *shared;
    ngx_core_conf_t   *ccf;
    ngx_event_conf_t  *ecf;

    ccf = (ngx_core_conf_t *) ngx_get_conf(cycle->conf_ctx, ngx_core_module);

    if (ccf->master == 0 || ngx_accept_mutex_ptr) {
        return NGX_OK;
    }

    ecf = ngx_event_get_conf(cycle->conf_ctx, ngx_event_core_module);


    /* TODO: 128 is cache line size */

    size = 128            /* ngx_accept_mutex */
           + 128;         /* ngx_connection_counter */

#if (NGX_STAT_STUB)

    size += 128           /* ngx_stat_accepted */
           + 128          /* ngx_stat_requests */
           + 128          /* ngx_stat_active */
           + 128          /* ngx_stat_reading */
           + 128;         /* ngx_stat_writing */

#endif

    if (!(shared = ngx_create_shared_memory(size, cycle->log))) {
        return NGX_ERROR;
    }

    ngx_accept_mutex_ptr = (ngx_atomic_t *) shared;
    ngx_connection_counter = (ngx_atomic_t *) (shared + 128);

#if (NGX_STAT_STUB)

    ngx_stat_accepted = (ngx_atomic_t *) (shared + 2 * 128);
    ngx_stat_requests = (ngx_atomic_t *) (shared + 3 * 128);
    ngx_stat_active = (ngx_atomic_t *) (shared + 4 * 128);
    ngx_stat_reading = (ngx_atomic_t *) (shared + 5 * 128);
    ngx_stat_writing = (ngx_atomic_t *) (shared + 6 * 128);

#endif

    ngx_log_debug2(NGX_LOG_DEBUG_EVENT, cycle->log, 0,
                   "counter: " PTR_FMT ", %d",
                   ngx_connection_counter, *ngx_connection_counter);

#endif

    return NGX_OK;
}


static ngx_int_t ngx_event_process_init(ngx_cycle_t *cycle)
{
    ngx_uint_t           m, i;
    ngx_socket_t         fd;
    ngx_event_t         *rev, *wev;
    ngx_listening_t     *s;
    ngx_connection_t    *c;
    ngx_core_conf_t     *ccf;
    ngx_event_conf_t    *ecf;
    ngx_event_module_t  *module;
#if (WIN32)
    ngx_iocp_conf_t     *iocpcf;
#endif

    ccf = (ngx_core_conf_t *) ngx_get_conf(cycle->conf_ctx, ngx_core_module);
    ecf = ngx_event_get_conf(cycle->conf_ctx, ngx_event_core_module);

    if (ngx_accept_mutex_ptr && ccf->worker_processes > 1 && ecf->accept_mutex)
    {
        ngx_accept_mutex = ngx_accept_mutex_ptr;
        ngx_accept_mutex_held = 0;
        ngx_accept_mutex_delay = ecf->accept_mutex_delay;
    }

#if (NGX_THREADS)
    if (!(ngx_posted_events_mutex = ngx_mutex_init(cycle->log, 0))) {
        return NGX_ERROR;
    }
#endif

    if (ngx_event_timer_init(cycle->log) == NGX_ERROR) {
        return NGX_ERROR;
    }

    cycle->connection_n = ecf->connections;

    for (m = 0; ngx_modules[m]; m++) {
        if (ngx_modules[m]->type != NGX_EVENT_MODULE) {
            continue;
        }

        if (ngx_modules[m]->ctx_index == ecf->use) {
            module = ngx_modules[m]->ctx;
            if (module->actions.init(cycle) == NGX_ERROR) {
                /* fatal */
                exit(2);
            }
            break;
        }
    }

    cycle->connections = ngx_alloc(sizeof(ngx_connection_t) * ecf->connections,
                                   cycle->log);
    if (cycle->connections == NULL) {
        return NGX_ERROR;
    }

    c = cycle->connections;
    for (i = 0; i < cycle->connection_n; i++) {
        c[i].fd = (ngx_socket_t) -1;
        c[i].data = NULL;
#if (NGX_THREADS)
        c[i].lock = 0;
#endif
    }

    cycle->read_events = ngx_alloc(sizeof(ngx_event_t) * ecf->connections,
                                   cycle->log);
    if (cycle->read_events == NULL) {
        return NGX_ERROR;
    }

    rev = cycle->read_events;
    for (i = 0; i < cycle->connection_n; i++) {
        rev[i].closed = 1;
#if (NGX_THREADS)
        rev[i].lock = &c[i].lock;
        rev[i].own_lock = &c[i].lock;
#endif
    }

    cycle->write_events = ngx_alloc(sizeof(ngx_event_t) * ecf->connections,
                                   cycle->log);
    if (cycle->write_events == NULL) {
        return NGX_ERROR;
    }

    wev = cycle->write_events;
    for (i = 0; i < cycle->connection_n; i++) {
        wev[i].closed = 1;
#if (NGX_THREADS)
        wev[i].lock = &c[i].lock;
        wev[i].own_lock = &c[i].lock;
#endif
    }

    /* for each listening socket */

    s = cycle->listening.elts;
    for (i = 0; i < cycle->listening.nelts; i++) {

        fd = s[i].fd;

#if (WIN32)
        /*
         * Winsock assignes a socket number divisible by 4
         * so to find a connection we divide a socket number by 4.
         */

        fd /= 4;
#endif

        c = &cycle->connections[fd];
        rev = &cycle->read_events[fd];
        wev = &cycle->write_events[fd];

        ngx_memzero(c, sizeof(ngx_connection_t));
        ngx_memzero(rev, sizeof(ngx_event_t));

        c->fd = s[i].fd;
        c->listening = &s[i];

        c->ctx = s[i].ctx;
        c->servers = s[i].servers;
        c->log = s[i].log;
        c->read = rev;

        /* required by iocp in "c->write->active = 1" */
        c->write = wev;

        /* required by poll */
        wev->index = NGX_INVALID_INDEX;

        rev->log = c->log;
        rev->data = c;
        rev->index = NGX_INVALID_INDEX;

        rev->available = 0;

        rev->accept = 1;

#if (HAVE_DEFERRED_ACCEPT)
        rev->deferred_accept = s[i].deferred_accept;
#endif

        if (!(ngx_event_flags & NGX_USE_IOCP_EVENT)) {
            if (s[i].remain) {

                /*
                 * delete the old accept events that were bound to
                 * the old cycle read events array
                 */

                if (ngx_del_event(&cycle->old_cycle->read_events[fd],
                                 NGX_READ_EVENT, NGX_CLOSE_EVENT) == NGX_ERROR)
                {
                    return NGX_ERROR;
                }

                cycle->old_cycle->connections[fd].fd = (ngx_socket_t) -1;
            }
        }

#if (WIN32)

        if (ngx_event_flags & NGX_USE_IOCP_EVENT) {
            rev->event_handler = &ngx_event_acceptex;

            if (ngx_add_event(rev, 0, NGX_IOCP_ACCEPT) == NGX_ERROR) {
                return NGX_ERROR;
            }

            iocpcf = ngx_event_get_conf(cycle->conf_ctx, ngx_iocp_module);
            if (ngx_event_post_acceptex(&s[i], iocpcf->post_acceptex)
                                                                  == NGX_ERROR)
            {
                return NGX_ERROR;
            }

        } else {
            rev->event_handler = &ngx_event_accept;
            if (ngx_add_event(rev, NGX_READ_EVENT, 0) == NGX_ERROR) {
                return NGX_ERROR;
            }
        }

#else

        rev->event_handler = &ngx_event_accept;

        if (ngx_accept_mutex) {
            continue;
        }

        if (ngx_event_flags & NGX_USE_RTSIG_EVENT) {
            if (ngx_add_conn(c) == NGX_ERROR) {
                return NGX_ERROR;
            }

        } else {
            if (ngx_add_event(rev, NGX_READ_EVENT, 0) == NGX_ERROR) {
                return NGX_ERROR;
            }
        }

#endif
    }

    return NGX_OK;
}


static char *ngx_events_block(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    int                    m;
    char                  *rv;
    void               ***ctx;
    ngx_conf_t            pcf;
    ngx_event_module_t   *module;

    /* count the number of the event modules and set up their indices */

    ngx_event_max_module = 0;
    for (m = 0; ngx_modules[m]; m++) {
        if (ngx_modules[m]->type != NGX_EVENT_MODULE) {
            continue;
        }

        ngx_modules[m]->ctx_index = ngx_event_max_module++;
    }

    ngx_test_null(ctx, ngx_pcalloc(cf->pool, sizeof(void *)), NGX_CONF_ERROR);

    ngx_test_null(*ctx,
                  ngx_pcalloc(cf->pool, ngx_event_max_module * sizeof(void *)),
                  NGX_CONF_ERROR);

    *(void **) conf = ctx;

    for (m = 0; ngx_modules[m]; m++) {
        if (ngx_modules[m]->type != NGX_EVENT_MODULE) {
            continue;
        }

        module = ngx_modules[m]->ctx;

        if (module->create_conf) {
            ngx_test_null((*ctx)[ngx_modules[m]->ctx_index],
                          module->create_conf(cf->cycle),
                          NGX_CONF_ERROR);
        }
    }

    pcf = *cf;
    cf->ctx = ctx;
    cf->module_type = NGX_EVENT_MODULE;
    cf->cmd_type = NGX_EVENT_CONF;
    rv = ngx_conf_parse(cf, NULL);
    *cf = pcf;

    if (rv != NGX_CONF_OK)
        return rv;

    for (m = 0; ngx_modules[m]; m++) {
        if (ngx_modules[m]->type != NGX_EVENT_MODULE) {
            continue;
        }

        module = ngx_modules[m]->ctx;

        if (module->init_conf) {
            rv = module->init_conf(cf->cycle,
                                   (*ctx)[ngx_modules[m]->ctx_index]);
            if (rv != NGX_CONF_OK) {
                return rv;
            }
        }
    }

    return NGX_CONF_OK;
}


static char *ngx_event_connections(ngx_conf_t *cf, ngx_command_t *cmd,
                                   void *conf)
{
    ngx_event_conf_t  *ecf = conf;

    ngx_str_t  *value;

    if (ecf->connections != NGX_CONF_UNSET_UINT) {
        return "is duplicate" ;
    }

    value = cf->args->elts;
    ecf->connections = ngx_atoi(value[1].data, value[1].len);
    if (ecf->connections == (ngx_uint_t) NGX_ERROR) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                           "invalid number \"%s\"", value[1].data);

        return NGX_CONF_ERROR;
    }

    cf->cycle->connection_n = ecf->connections;

    return NGX_CONF_OK;
}


static char *ngx_event_use(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    ngx_event_conf_t  *ecf = conf;

    ngx_int_t             m;
    ngx_str_t            *value;
    ngx_event_conf_t     *old_ecf;
    ngx_event_module_t   *module;

    if (ecf->use != NGX_CONF_UNSET_UINT) {
        return "is duplicate" ;
    }

    value = cf->args->elts;

    if (cf->cycle->old_cycle->conf_ctx) {
        old_ecf = ngx_event_get_conf(cf->cycle->old_cycle->conf_ctx,
                                     ngx_event_core_module);
    } else {
        old_ecf = NULL;
    }


    for (m = 0; ngx_modules[m]; m++) {
        if (ngx_modules[m]->type != NGX_EVENT_MODULE) {
            continue;
        }

        module = ngx_modules[m]->ctx;
        if (module->name->len == value[1].len) {
            if (ngx_strcmp(module->name->data, value[1].data) == 0) {
                ecf->use = ngx_modules[m]->ctx_index;
                ecf->name = module->name->data;

                if (ngx_process == NGX_PROCESS_SINGLE
                    && old_ecf
                    && old_ecf->use != ecf->use)
                {
                    ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                        "when the server runs without a master process "
                        "the \"%s\" event type must be the same as "
                        "in previous configuration - \"%s\" "
                        "and it can not be changed on the fly, "
                        "to change it you need to stop server "
                        "and start it again",
                        value[1].data, old_ecf->name);

                    return NGX_CONF_ERROR;
                }

                return NGX_CONF_OK;
            }
        }
    }

    ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                       "invalid event type \"%s\"", value[1].data);

    return NGX_CONF_ERROR;
}


static char *ngx_event_debug_connection(ngx_conf_t *cf, ngx_command_t *cmd,
                                        void *conf)
{
#if (NGX_DEBUG)
    ngx_event_conf_t  *ecf = conf;

    in_addr_t       *addr;
    ngx_str_t       *value;
    struct hostent  *h;

    value = cf->args->elts;

    /* AF_INET only */

    if (!(addr = ngx_push_array(&ecf->debug_connection))) {
        return NGX_CONF_ERROR;
    }

    *addr = inet_addr((char *) value[1].data);

    if (*addr != INADDR_NONE) {
        return NGX_OK;
    }

    h = gethostbyname((char *) value[1].data);

    if (h == NULL || h->h_addr_list[0] == NULL) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                           "host %s not found", value[1].data);
        return NGX_CONF_ERROR;
    }

    *addr = *(in_addr_t *)(h->h_addr_list[0]);

#else

    ngx_conf_log_error(NGX_LOG_WARN, cf, 0,
                       "\"debug_connection\" is ignored, you need to rebuild "
                       "nginx using --with-debug option to enable it");

#endif

    return NGX_OK;
}


static void *ngx_event_create_conf(ngx_cycle_t *cycle)
{
    ngx_event_conf_t  *ecf;

    ngx_test_null(ecf, ngx_palloc(cycle->pool, sizeof(ngx_event_conf_t)),
                  NGX_CONF_ERROR);

    ecf->connections = NGX_CONF_UNSET_UINT;
    ecf->use = NGX_CONF_UNSET_UINT;
    ecf->multi_accept = NGX_CONF_UNSET;
    ecf->accept_mutex = NGX_CONF_UNSET;
    ecf->accept_mutex_delay = NGX_CONF_UNSET_MSEC;
    ecf->name = (void *) NGX_CONF_UNSET;

#if (NGX_DEBUG)
    ngx_init_array(ecf->debug_connection, cycle->pool, 5, sizeof(in_addr_t),
                   NGX_CONF_ERROR);
#endif

    return ecf;
}


static char *ngx_event_init_conf(ngx_cycle_t *cycle, void *conf)
{
    ngx_event_conf_t  *ecf = conf;
#if (HAVE_RTSIG)
    ngx_core_conf_t  *ccf;
#endif

#if (HAVE_KQUEUE)

    ngx_conf_init_unsigned_value(ecf->connections, DEFAULT_CONNECTIONS);
    ngx_conf_init_unsigned_value(ecf->use, ngx_kqueue_module.ctx_index);
    ngx_conf_init_ptr_value(ecf->name, ngx_kqueue_module_ctx.name->data);

#elif (HAVE_DEVPOLL)

    ngx_conf_init_unsigned_value(ecf->connections, DEFAULT_CONNECTIONS);
    ngx_conf_init_unsigned_value(ecf->use, ngx_devpoll_module.ctx_index);
    ngx_conf_init_ptr_value(ecf->name, ngx_devpoll_module_ctx.name->data);

#elif (HAVE_EPOLL)

    ngx_conf_init_unsigned_value(ecf->connections, DEFAULT_CONNECTIONS);
    ngx_conf_init_unsigned_value(ecf->use, ngx_epoll_module.ctx_index);
    ngx_conf_init_ptr_value(ecf->name, ngx_epoll_module_ctx.name->data);

#elif (HAVE_RTSIG)

    ngx_conf_init_unsigned_value(ecf->connections, DEFAULT_CONNECTIONS);
    ngx_conf_init_unsigned_value(ecf->use, ngx_rtsig_module.ctx_index);
    ngx_conf_init_ptr_value(ecf->name, ngx_rtsig_module_ctx.name->data);

#elif (HAVE_SELECT)

#if (WIN32)
    ngx_conf_init_unsigned_value(ecf->connections, DEFAULT_CONNECTIONS);
#else
    ngx_conf_init_unsigned_value(ecf->connections,
          FD_SETSIZE < DEFAULT_CONNECTIONS ? FD_SETSIZE : DEFAULT_CONNECTIONS);
#endif

    ngx_conf_init_unsigned_value(ecf->use, ngx_select_module.ctx_index);
    ngx_conf_init_ptr_value(ecf->name, ngx_select_module_ctx.name->data);

#else

    ngx_int_t            i, m;
    ngx_event_module_t  *module;

    m = -1;
    module = NULL;

    for (i = 0; ngx_modules[i]; i++) {
        if (ngx_modules[i]->type == NGX_EVENT_MODULE) {
            module = ngx_modules[i]->ctx;

            if (ngx_strcmp(module->name->data, event_core_name.data) == 0) {
                continue;
            }

            m = ngx_modules[i]->ctx_index;
            break;
        }
    }

    if (m == -1) {
        ngx_log_error(NGX_LOG_EMERG, cycle->log, 0, "no events module found");
        return NGX_CONF_ERROR;
    }

    ngx_conf_init_unsigned_value(ecf->connections, DEFAULT_CONNECTIONS);

    ngx_conf_init_unsigned_value(ecf->use, m);
    ngx_conf_init_ptr_value(ecf->name, module->name->data);

#endif

    cycle->connection_n = ecf->connections;

    ngx_conf_init_value(ecf->multi_accept, 0);
    ngx_conf_init_value(ecf->accept_mutex, 1);
    ngx_conf_init_msec_value(ecf->accept_mutex_delay, 500);

#if (HAVE_RTSIG)
    if (ecf->use == ngx_rtsig_module.ctx_index && ecf->accept_mutex == 0) {
        ccf = (ngx_core_conf_t *) ngx_get_conf(cycle->conf_ctx,
                                               ngx_core_module);
        if (ccf->worker_processes) {
            ngx_log_error(NGX_LOG_EMERG, cycle->log, 0,
                          "the \"rtsig\" method requires "
                          "\"accept_mutex\" to be on");
            return NGX_CONF_ERROR;
        }
    }
#endif

    return NGX_CONF_OK;
}


static char *ngx_accept_mutex_check(ngx_conf_t *cf, void *post, void *data)
{
#if !(NGX_HAVE_ATOMIC_OPS)

    ngx_flag_t *fp = data;

    *fp = 0;

    ngx_conf_log_error(NGX_LOG_WARN, cf, 0,
                       "\"accept_mutex\" is not supported, ignored");

#endif

    return NGX_CONF_OK;
}
