
#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_event.h>


#define DEF_CONNECTIONS  512


extern ngx_module_t ngx_select_module;

#if (HAVE_KQUEUE)
#include <ngx_kqueue_module.h>
#endif

#if (HAVE_DEVPOLL)
extern ngx_module_t ngx_devpoll_module;
#endif

#if (HAVE_AIO)
#include <ngx_aio_module.h>
#endif


static char *ngx_events_block(ngx_conf_t *cf, ngx_command_t *cmd, void *conf);
static char *ngx_event_use(ngx_conf_t *cf, ngx_command_t *cmd, void *conf);
static void *ngx_event_create_conf(ngx_pool_t *pool);
static char *ngx_event_init_conf(ngx_pool_t *pool, void *conf);


int                  ngx_event_flags;
ngx_event_actions_t  ngx_event_actions;

ngx_connection_t    *ngx_connections;
ngx_event_t         *ngx_read_events, *ngx_write_events;


static int  ngx_event_max_module;


static int  ngx_event_connections;


static ngx_str_t  events_name = ngx_string("events");

static ngx_command_t  ngx_events_commands[] = {

    {ngx_string("events"),
     NGX_MAIN_CONF|NGX_CONF_BLOCK|NGX_CONF_NOARGS,
     ngx_events_block,
     0,
     0,
     NULL},

    ngx_null_command
};


ngx_module_t  ngx_events_module = {
    NGX_MODULE,
    &events_name,                          /* module context */
    ngx_events_commands,                   /* module directives */
    NGX_CORE_MODULE,                       /* module type */
    NULL                                   /* init module */
};


static ngx_str_t  event_name = ngx_string("event");

static ngx_command_t  ngx_event_commands[] = {

    {ngx_string("connections"),
     NGX_EVENT_CONF|NGX_CONF_TAKE1,
     ngx_conf_set_num_slot,
     0,
     offsetof(ngx_event_conf_t, connections),
     NULL},

    {ngx_string("use"),
     NGX_EVENT_CONF|NGX_CONF_TAKE1,
     ngx_event_use,
     0,
     0,
     NULL},

    {ngx_string("timer_queues"),
     NGX_EVENT_CONF|NGX_CONF_TAKE1,
     ngx_conf_set_num_slot,
     0,
     offsetof(ngx_event_conf_t, timer_queues),
     NULL},

    ngx_null_command
};


ngx_event_module_t  ngx_event_module_ctx = {
    &event_name,
    ngx_event_create_conf,                 /* create configuration */
    ngx_event_init_conf,                   /* init configuration */

    { NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL }
};


ngx_module_t  ngx_event_module = {
    NGX_MODULE,
    &ngx_event_module_ctx,                 /* module context */
    ngx_event_commands,                    /* module directives */
    NGX_EVENT_MODULE,                      /* module type */
    NULL                                   /* init module */
};



int ngx_pre_thread(ngx_array_t *ls, ngx_pool_t *pool, ngx_log_t *log)
{
    int                  m, i, fd;
    ngx_event_t         *rev, *wev;
    ngx_listening_t     *s;
    ngx_connection_t    *c;
    ngx_event_conf_t    *ecf;
    ngx_event_module_t  *module;
#if (WIN32)
    ngx_iocp_conf_t     *iocpcf;
#endif

    ecf = ngx_event_get_conf(ngx_event_module);

ngx_log_debug(log, "CONN: %d" _ ecf->connections);
ngx_log_debug(log, "TYPE: %d" _ ecf->use);

    for (m = 0; ngx_modules[m]; m++) {
        if (ngx_modules[m]->type != NGX_EVENT_MODULE) {
            continue;
        }

        if (ngx_modules[m]->ctx_index == ecf->use) {
            module = ngx_modules[m]->ctx;
            if (module->actions.init(log) == NGX_ERROR) {
                return NGX_ERROR;
            }
            break;
        }
    }

    ngx_test_null(ngx_connections,
                  ngx_alloc(sizeof(ngx_connection_t) * ecf->connections, log),
                  NGX_ERROR);

    ngx_test_null(ngx_read_events,
                  ngx_alloc(sizeof(ngx_event_t) * ecf->connections, log),
                  NGX_ERROR);

    ngx_test_null(ngx_write_events,
                  ngx_alloc(sizeof(ngx_event_t) * ecf->connections, log),
                  NGX_ERROR);

    /* for each listening socket */

    for (s = ls->elts, i = 0; i < ls->nelts; i++) {

        fd = s[i].fd;

#if (WIN32)
        /*
         * Winsock assignes a socket number divisible by 4
         * so to find a connection we divide a socket number by 4.
         */

        c = &ngx_connections[fd / 4];
        rev = &ngx_read_events[fd / 4];
        wev = &ngx_write_events[fd / 4];
#else
        c = &ngx_connections[fd];
        rev = &ngx_read_events[fd];
        wev = &ngx_write_events[fd];
#endif

        ngx_memzero(c, sizeof(ngx_connection_t));
        ngx_memzero(rev, sizeof(ngx_event_t));

        c->fd = fd;
        c->listening = &s[i];

        c->ctx = s[i].ctx;
        c->servers = s[i].servers;
        c->log = s[i].log;

        ngx_test_null(rev->log, ngx_palloc(pool, sizeof(ngx_log_t)), NGX_ERROR);

        ngx_memcpy(rev->log, c->log, sizeof(ngx_log_t));
        c->read = rev;
        c->write = wev;
        rev->data = c;
        rev->index = NGX_INVALID_INDEX;
#if 0
        rev->listening = 1;
#endif

        rev->available = 0;

#if (HAVE_DEFERRED_ACCEPT)
        rev->deferred_accept = s[i].deferred_accept;
#endif

#if (WIN32)

        if (ngx_event_flags & NGX_HAVE_IOCP_EVENT) {
            rev->event_handler = &ngx_event_acceptex;

            if (ngx_add_event(rev, 0, NGX_IOCP_ACCEPT) == NGX_ERROR) {
                return NGX_ERROR;
            }

            iocpcf = ngx_event_get_conf(ngx_iocp_module);
            if (ngx_event_post_acceptex(&s[i], iocpcf->acceptex) == NGX_ERROR) {
                return NGX_ERROR;
            }

        } else {
            rev->event_handler = &ngx_event_accept;
            ngx_add_event(rev, NGX_READ_EVENT, 0);
        }

#else

        rev->event_handler = &ngx_event_accept;
        ngx_add_event(rev, NGX_READ_EVENT, 0);

#endif
    }

    return NGX_OK;
}


void ngx_worker(ngx_log_t *log)
{
    for ( ;; ) {
        ngx_log_debug(log, "ngx_worker cycle");

        ngx_process_events(log);
    }
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
                          module->create_conf(cf->pool),
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
            rv = module->init_conf(cf->pool, (*ctx)[ngx_modules[m]->ctx_index]);
            if (rv != NGX_CONF_OK) {
                return rv;
            }
        }
    }

    return NGX_CONF_OK;
}


static char *ngx_event_use(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    ngx_event_conf_t  *ecf = conf;

    int                   m;
    ngx_str_t            *args;
    ngx_event_module_t   *module;

    if (ecf->use != NGX_CONF_UNSET) {
        return "is duplicate" ;
    }

    args = cf->args->elts;

    for (m = 0; ngx_modules[m]; m++) {
        if (ngx_modules[m]->type != NGX_EVENT_MODULE) {
            continue;
        }

        module = ngx_modules[m]->ctx;
        if (module->name->len == args[1].len) {
            if (ngx_strcmp(module->name->data, args[1].data) == 0) {
                ecf->use = ngx_modules[m]->ctx_index;
                return NGX_CONF_OK;
            }
        }
    }

    return "invalid event type";
}


static void *ngx_event_create_conf(ngx_pool_t *pool)
{
    ngx_event_conf_t  *ecf;

    ngx_test_null(ecf, ngx_palloc(pool, sizeof(ngx_event_conf_t)),
                  NGX_CONF_ERROR);

    ecf->connections = NGX_CONF_UNSET;
    ecf->timer_queues = NGX_CONF_UNSET;
    ecf->use = NGX_CONF_UNSET;

    return ecf;
}


static char *ngx_event_init_conf(ngx_pool_t *pool, void *conf)
{
    ngx_event_conf_t *ecf = conf;

#if (HAVE_KQUEUE)

    ngx_conf_init_value(ecf->connections, DEF_CONNECTIONS);
    ngx_conf_init_value(ecf->use, ngx_kqueue_module.ctx_index);

#elif (HAVE_DEVPOLL)

    ngx_conf_init_value(ecf->connections, DEF_CONNECTIONS);
    ngx_conf_init_value(ecf->use, ngx_devpoll_module.ctx_index);

#else /* HAVE_SELECT */

    ngx_conf_init_value(ecf->connections,
                  FD_SETSIZE < DEF_CONNECTIONS ? FD_SETSIZE : DEF_CONNECTIONS);

    ngx_conf_init_value(ecf->use, ngx_select_module.ctx_index);

#endif

    ngx_conf_init_value(ecf->timer_queues, 10);

    return NGX_CONF_OK;
}
