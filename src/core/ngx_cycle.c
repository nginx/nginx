
/*
 * Copyright (C) Igor Sysoev
 */


#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_event.h>


static void ngx_clean_old_cycles(ngx_event_t *ev);


volatile ngx_cycle_t  *ngx_cycle;
ngx_array_t            ngx_old_cycles;

static ngx_pool_t     *ngx_temp_pool;
static ngx_event_t     ngx_cleaner_event;

ngx_uint_t             ngx_test_config;

#if (NGX_THREADS)
ngx_tls_key_t          ngx_core_tls_key;
#endif


/* STUB NAME */
static ngx_connection_t  dumb;
/* STUB */

#ifdef NGX_ERROR_LOG_PATH
static ngx_str_t  error_log = ngx_string(NGX_ERROR_LOG_PATH);
#else
static ngx_str_t  error_log = ngx_null_string;
#endif


ngx_cycle_t *ngx_init_cycle(ngx_cycle_t *old_cycle)
{
    void               *rv;
    ngx_uint_t          i, n, failed;
    ngx_log_t          *log;
    ngx_conf_t          conf;
    ngx_pool_t         *pool;
    ngx_cycle_t        *cycle, **old;
    ngx_socket_t        fd;
    ngx_list_part_t    *part;
    ngx_open_file_t    *file;
    ngx_listening_t    *ls, *nls;
    ngx_core_module_t  *module;

    log = old_cycle->log;

    if (!(pool = ngx_create_pool(16 * 1024, log))) {
        return NULL;
    }
    pool->log = log;

    if (!(cycle = ngx_pcalloc(pool, sizeof(ngx_cycle_t)))) {
        ngx_destroy_pool(pool);
        return NULL;
    }
    cycle->pool = pool;
    cycle->log = log;
    cycle->old_cycle = old_cycle;
    cycle->conf_file = old_cycle->conf_file;
    cycle->root.len = sizeof(NGX_PREFIX) - 1;
    cycle->root.data = (u_char *) NGX_PREFIX;


    n = old_cycle->pathes.nelts ? old_cycle->pathes.nelts : 10;
    if (!(cycle->pathes.elts = ngx_pcalloc(pool, n * sizeof(ngx_path_t *)))) {
        ngx_destroy_pool(pool);
        return NULL;
    }
    cycle->pathes.nelts = 0;
    cycle->pathes.size = sizeof(ngx_path_t *);
    cycle->pathes.nalloc = n;
    cycle->pathes.pool = pool;


    if (old_cycle->open_files.part.nelts) {
        n = old_cycle->open_files.part.nelts;
        for (part = old_cycle->open_files.part.next; part; part = part->next) {
            n += part->nelts;
        }

    } else {
        n = 20;
    }

    if (ngx_list_init(&cycle->open_files, pool, n, sizeof(ngx_open_file_t))
                                                                  == NGX_ERROR)
    {
        ngx_destroy_pool(pool);
        return NULL;
    }


    if (!(cycle->new_log = ngx_log_create_errlog(cycle, NULL))) {
        ngx_destroy_pool(pool);
        return NULL;
    }

    cycle->new_log->file->name = error_log;


    n = old_cycle->listening.nelts ? old_cycle->listening.nelts : 10;
    cycle->listening.elts = ngx_pcalloc(pool, n * sizeof(ngx_listening_t));
    if (cycle->listening.elts == NULL) {
        ngx_destroy_pool(pool);
        return NULL;
    }
    cycle->listening.nelts = 0;
    cycle->listening.size = sizeof(ngx_listening_t);
    cycle->listening.nalloc = n;
    cycle->listening.pool = pool;


    cycle->conf_ctx = ngx_pcalloc(pool, ngx_max_module * sizeof(void *));
    if (cycle->conf_ctx == NULL) {
        ngx_destroy_pool(pool);
        return NULL;
    }


    for (i = 0; ngx_modules[i]; i++) {
        if (ngx_modules[i]->type != NGX_CORE_MODULE) {
            continue;
        }

        module = ngx_modules[i]->ctx;

        if (module->create_conf) {
            rv = module->create_conf(cycle);
            if (rv == NGX_CONF_ERROR) {
                ngx_destroy_pool(pool);
                return NULL;
            }
            cycle->conf_ctx[ngx_modules[i]->index] = rv;
        }
    }


    ngx_memzero(&conf, sizeof(ngx_conf_t));
    /* STUB: init array ? */
    conf.args = ngx_create_array(pool, 10, sizeof(ngx_str_t));
    if (conf.args == NULL) {
        ngx_destroy_pool(pool);
        return NULL;
    }

    conf.ctx = cycle->conf_ctx;
    conf.cycle = cycle;
    conf.pool = pool;
    conf.log = log;
    conf.module_type = NGX_CORE_MODULE;
    conf.cmd_type = NGX_MAIN_CONF;


    if (ngx_conf_parse(&conf, &cycle->conf_file) != NGX_CONF_OK) {
        ngx_destroy_pool(pool);
        return NULL;
    }

    if (ngx_test_config) {
        ngx_log_error(NGX_LOG_INFO, log, 0,
                      "the configuration file %s syntax is ok",
                      cycle->conf_file.data);
    }


    for (i = 0; ngx_modules[i]; i++) {
        if (ngx_modules[i]->type != NGX_CORE_MODULE) {
            continue;
        }

        module = ngx_modules[i]->ctx;

        if (module->init_conf) {
            if (module->init_conf(cycle, cycle->conf_ctx[ngx_modules[i]->index])
                                                              == NGX_CONF_ERROR)
            {
                ngx_destroy_pool(pool);
                return NULL;
            }
        }
    }


    failed = 0;


#if !(WIN32)
    if (ngx_create_pidfile(cycle, old_cycle) == NGX_ERROR) {
        failed = 1;
    }
#endif


    if (!failed) {

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

            if (file[i].name.data == NULL) {
                continue;
            }

            file[i].fd = ngx_open_file(file[i].name.data,
                                       NGX_FILE_RDWR,
                                       NGX_FILE_CREATE_OR_OPEN|NGX_FILE_APPEND);

#if 0
            log->log_level = NGX_LOG_DEBUG_ALL;
#endif
            ngx_log_debug3(NGX_LOG_DEBUG_CORE, log, 0,
                           "log: %0X %d \"%s\"",
                           &file[i], file[i].fd, file[i].name.data);

            if (file[i].fd == NGX_INVALID_FILE) {
                ngx_log_error(NGX_LOG_EMERG, log, ngx_errno,
                              ngx_open_file_n " \"%s\" failed",
                              file[i].name.data);
                failed = 1;
                break;
            }

#if (WIN32)
            if (ngx_file_append_mode(file[i].fd) == NGX_ERROR) {
                ngx_log_error(NGX_LOG_EMERG, log, ngx_errno,
                              ngx_file_append_mode_n " \"%s\" failed",
                              file[i].name.data);
                failed = 1;
                break;
            }
#else
            if (fcntl(file[i].fd, F_SETFD, FD_CLOEXEC) == -1) {
                ngx_log_error(NGX_LOG_EMERG, log, ngx_errno,
                              "fcntl(FD_CLOEXEC) \"%s\" failed",
                              file[i].name.data);
                failed = 1;
                break;
            }
#endif
        }
    }

    cycle->log = cycle->new_log;
    pool->log = cycle->new_log;

    if (cycle->log->log_level == 0) {
        cycle->log->log_level = NGX_LOG_ERR;
    }

    if (!failed) {
        if (old_cycle->listening.nelts) {
            ls = old_cycle->listening.elts;
            for (i = 0; i < old_cycle->listening.nelts; i++) {
                ls[i].remain = 0;
            }

            nls = cycle->listening.elts;
            for (n = 0; n < cycle->listening.nelts; n++) {
                for (i = 0; i < old_cycle->listening.nelts; i++) {
                    if (ls[i].ignore) {
                        continue;
                    }

                    if (ngx_memcmp(nls[n].sockaddr,
                                   ls[i].sockaddr, ls[i].socklen) == 0)
                    {
                        fd = ls[i].fd;
#if (WIN32)
                        /*
                         * Winsock assignes a socket number divisible by 4 so
                         * to find a connection we divide a socket number by 4.
                         */

                        fd /= 4;
#endif
                        if (fd >= (ngx_socket_t) cycle->connection_n) {
                            ngx_log_error(NGX_LOG_EMERG, log, 0,
                                        "%d connections is not enough to hold "
                                        "an open listening socket on %s, "
                                        "required at least %d connections",
                                        cycle->connection_n,
                                        ls[i].addr_text.data, fd);
                            failed = 1;
                            break;
                        }

                        nls[n].fd = ls[i].fd;
                        nls[i].remain = 1;
                        ls[i].remain = 1;
                        break;
                    }
                }

                if (nls[n].fd == -1) {
                    nls[n].new = 1;
                }
            }

        } else {
            ls = cycle->listening.elts;
            for (i = 0; i < cycle->listening.nelts; i++) {
                ls[i].new = 1;
            }
        }

        if (!ngx_test_config && !failed) {
            if (ngx_open_listening_sockets(cycle) == NGX_ERROR) {
                failed = 1;
            }
        }
    }

    if (failed) {

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

            if (file[i].fd == NGX_INVALID_FILE
                || file[i].fd == ngx_stderr_fileno)
            {
                continue;
            }

            if (ngx_close_file(file[i].fd) == NGX_FILE_ERROR) {
                ngx_log_error(NGX_LOG_EMERG, log, ngx_errno,
                              ngx_close_file_n " \"%s\" failed",
                              file[i].name.data);
            }
        }

        if (ngx_test_config) {
            ngx_destroy_pool(pool);
            return NULL;
        }

        ls = cycle->listening.elts;
        for (i = 0; i < cycle->listening.nelts; i++) {
            if (ls[i].fd == -1 || !ls[i].new) {
                continue;
            }

            if (ngx_close_socket(ls[i].fd) == -1) {
                ngx_log_error(NGX_LOG_EMERG, log, ngx_socket_errno,
                              ngx_close_socket_n " %s failed",
                              ls[i].addr_text.data);
            }
        }

        ngx_destroy_pool(pool);
        return NULL;
    }


    /* commit the new cycle configuration */

#if !(WIN32)

    if (!ngx_test_config && cycle->log->file->fd != STDERR_FILENO) {

        ngx_log_debug3(NGX_LOG_DEBUG_CORE, log, 0,
                       "dup2: %0X %d \"%s\"",
                       cycle->log->file,
                       cycle->log->file->fd, cycle->log->file->name.data);

        if (dup2(cycle->log->file->fd, STDERR_FILENO) == NGX_ERROR) {
            ngx_log_error(NGX_LOG_EMERG, log, ngx_errno,
                          "dup2(STDERR) failed");
            /* fatal */
            exit(1);
        }
    }

#endif

    pool->log = cycle->log;

    for (i = 0; ngx_modules[i]; i++) {
        if (ngx_modules[i]->init_module) {
            if (ngx_modules[i]->init_module(cycle) == NGX_ERROR) {
                /* fatal */
                exit(1);
            }
        }
    }

    /* close and delete stuff that lefts from an old cycle */

    /* close the unneeded listening sockets */

    ls = old_cycle->listening.elts;
    for (i = 0; i < old_cycle->listening.nelts; i++) {
        if (ls[i].remain) {
            continue;
        }

        if (ngx_close_socket(ls[i].fd) == -1) {
            ngx_log_error(NGX_LOG_EMERG, log, ngx_socket_errno,
                          ngx_close_socket_n " %s failed",
                          ls[i].addr_text.data);
        }
    }


    /* close the unneeded open files */

    part = &old_cycle->open_files.part;
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

        if (file[i].fd == NGX_INVALID_FILE || file[i].fd == ngx_stderr_fileno) {
            continue;
        }

        if (ngx_close_file(file[i].fd) == NGX_FILE_ERROR) {
            ngx_log_error(NGX_LOG_EMERG, log, ngx_errno,
                          ngx_close_file_n " \"%s\" failed",
                          file[i].name.data);
        }
    }

    if (old_cycle->connections == NULL) {
        /* an old cycle is an init cycle */
        ngx_destroy_pool(old_cycle->pool);
        return cycle;
    }

    if (ngx_process == NGX_PROCESS_MASTER) {
        ngx_destroy_pool(old_cycle->pool);
        return cycle;
    }

    if (ngx_temp_pool == NULL) {
        ngx_temp_pool = ngx_create_pool(128, cycle->log);
        if (ngx_temp_pool == NULL) {
            ngx_log_error(NGX_LOG_EMERG, cycle->log, 0,
                          "can not create ngx_temp_pool");
            exit(1);
        }

        n = 10;
        ngx_old_cycles.elts = ngx_pcalloc(ngx_temp_pool,
                                          n * sizeof(ngx_cycle_t *));
        if (ngx_old_cycles.elts == NULL) {
            exit(1);
        }
        ngx_old_cycles.nelts = 0;
        ngx_old_cycles.size = sizeof(ngx_cycle_t *);
        ngx_old_cycles.nalloc = n;
        ngx_old_cycles.pool = ngx_temp_pool;

        ngx_cleaner_event.event_handler = ngx_clean_old_cycles;
        ngx_cleaner_event.log = cycle->log;
        ngx_cleaner_event.data = &dumb;
        dumb.fd = (ngx_socket_t) -1;
    }

    ngx_temp_pool->log = cycle->log;

    old = ngx_push_array(&ngx_old_cycles);
    if (old == NULL) {
        exit(1);
    }
    *old = old_cycle;

    if (!ngx_cleaner_event.timer_set) {
        ngx_add_timer(&ngx_cleaner_event, 30000);
        ngx_cleaner_event.timer_set = 1;
    }

    return cycle;
}


#if !(WIN32)

ngx_int_t ngx_create_pidfile(ngx_cycle_t *cycle, ngx_cycle_t *old_cycle)
{
    ngx_uint_t        trunc;
    size_t            len;
    u_char           *name, pid[NGX_INT64_LEN + 1];
    ngx_file_t        file;
    ngx_core_conf_t  *ccf, *old_ccf;

    if (!ngx_test_config && old_cycle && old_cycle->conf_ctx == NULL) {

        /*
         * do not create the pid file in the first ngx_init_cycle() call
         * because we need to write the demonized process pid 
         */

        return NGX_OK;
    }

    ccf = (ngx_core_conf_t *) ngx_get_conf(cycle->conf_ctx, ngx_core_module);

    if (!ngx_test_config && old_cycle) {
        old_ccf = (ngx_core_conf_t *) ngx_get_conf(old_cycle->conf_ctx,
                                                   ngx_core_module);

        if (ccf->pid.len == old_ccf->pid.len
            && ngx_strcmp(ccf->pid.data, old_ccf->pid.data) == 0)
        {

            /* pid file name is the same */

            return NGX_OK;
        }
    }

    len = ngx_snprintf((char *) pid, NGX_INT64_LEN + 1, PID_T_FMT, ngx_pid);

    ngx_memzero(&file, sizeof(ngx_file_t));
    file.name = (ngx_inherited && getppid() > 1) ? ccf->newpid : ccf->pid;
    file.log = cycle->log;

    trunc = ngx_test_config ? 0: NGX_FILE_TRUNCATE;

    file.fd = ngx_open_file(file.name.data, NGX_FILE_RDWR,
                            NGX_FILE_CREATE_OR_OPEN|trunc);

    if (file.fd == NGX_INVALID_FILE) {
        ngx_log_error(NGX_LOG_EMERG, cycle->log, ngx_errno,
                      ngx_open_file_n " \"%s\" failed", file.name.data);
        return NGX_ERROR;
    }

    if (!ngx_test_config) {
        if (ngx_write_file(&file, pid, len, 0) == NGX_ERROR) {
            return NGX_ERROR;
        }
    }

    if (ngx_close_file(file.fd) == NGX_FILE_ERROR) {
        ngx_log_error(NGX_LOG_ALERT, cycle->log, ngx_errno,
                      ngx_close_file_n " \"%s\" failed", file.name.data);
    }

    ngx_delete_pidfile(old_cycle);

    return NGX_OK;
}


void ngx_delete_pidfile(ngx_cycle_t *cycle)
{   
    u_char           *name;
    ngx_core_conf_t  *ccf;

    if (cycle == NULL || cycle->conf_ctx == NULL) {
        return;
    }

    ccf = (ngx_core_conf_t *) ngx_get_conf(cycle->conf_ctx, ngx_core_module);

    if (ngx_inherited && getppid() > 1) {
        name = ccf->newpid.data;

    } else { 
        name = ccf->pid.data;
    }

    if (ngx_delete_file(name) == NGX_FILE_ERROR) {
        ngx_log_error(NGX_LOG_ALERT, cycle->log, ngx_errno,
                      ngx_delete_file_n " \"%s\" failed", name);
    }
}

#endif


void ngx_reopen_files(ngx_cycle_t *cycle, ngx_uid_t user)
{
    ngx_fd_t          fd;
    ngx_uint_t        i;
    ngx_list_part_t  *part;
    ngx_open_file_t  *file;

    part = &cycle->open_files.part;
    file = part->elts;

    for (i = 0; /* void */ ; i++) {

        if (i >= part->nelts) {
            if (part->next == NULL) {
                break;
            }
            part = part->next;
            i = 0;
        }

        if (file[i].name.data == NULL) {
            continue;
        }

        fd = ngx_open_file(file[i].name.data, NGX_FILE_RDWR,
                           NGX_FILE_CREATE_OR_OPEN|NGX_FILE_APPEND);

        ngx_log_debug3(NGX_LOG_DEBUG_EVENT, cycle->log, 0,
                       "reopen file \"%s\", old:%d new:%d",
                       file[i].name.data, file[i].fd, fd);

        if (fd == NGX_INVALID_FILE) {
            ngx_log_error(NGX_LOG_EMERG, cycle->log, ngx_errno,
                          ngx_open_file_n " \"%s\" failed", file[i].name.data);
            continue;
        }

#if (WIN32)
        if (ngx_file_append_mode(fd) == NGX_ERROR) {
            ngx_log_error(NGX_LOG_EMERG, cycle->log, ngx_errno,
                          ngx_file_append_mode_n " \"%s\" failed",
                          file[i].name.data);

            if (ngx_close_file(fd) == NGX_FILE_ERROR) {
                ngx_log_error(NGX_LOG_EMERG, cycle->log, ngx_errno,
                              ngx_close_file_n " \"%s\" failed",
                              file[i].name.data);
            }

            continue;
        }
#else
        if (user != (ngx_uid_t) -1) {
            if (chown((const char *) file[i].name.data, user, -1) == -1) {
                ngx_log_error(NGX_LOG_EMERG, cycle->log, ngx_errno,
                              "chown \"%s\" failed", file[i].name.data);

                if (ngx_close_file(fd) == NGX_FILE_ERROR) {
                    ngx_log_error(NGX_LOG_EMERG, cycle->log, ngx_errno,
                                  ngx_close_file_n " \"%s\" failed",
                                  file[i].name.data);
                }
            }
        }

        if (fcntl(fd, F_SETFD, FD_CLOEXEC) == -1) {
            ngx_log_error(NGX_LOG_EMERG, cycle->log, ngx_errno,
                          "fcntl(FD_CLOEXEC) \"%s\" failed",
                          file[i].name.data);

            if (ngx_close_file(fd) == NGX_FILE_ERROR) {
                ngx_log_error(NGX_LOG_EMERG, cycle->log, ngx_errno,
                              ngx_close_file_n " \"%s\" failed",
                              file[i].name.data);
            }

            continue;
        }
#endif

        if (ngx_close_file(file[i].fd) == NGX_FILE_ERROR) {
            ngx_log_error(NGX_LOG_EMERG, cycle->log, ngx_errno,
                          ngx_close_file_n " \"%s\" failed",
                          file[i].name.data);
        }

        file[i].fd = fd;
    }

#if !(WIN32)

    if (cycle->log->file->fd != STDERR_FILENO) {
        if (dup2(cycle->log->file->fd, STDERR_FILENO) == -1) {
            ngx_log_error(NGX_LOG_EMERG, cycle->log, ngx_errno,
                          "dup2(STDERR) failed");
        }
    }

#endif
}


static void ngx_clean_old_cycles(ngx_event_t *ev)
{
    ngx_uint_t     i, n, found, live;
    ngx_log_t     *log;
    ngx_cycle_t  **cycle;

    log = ngx_cycle->log;
    ngx_temp_pool->log = log;

    ngx_log_debug0(NGX_LOG_DEBUG_CORE, log, 0, "clean old cycles");

    live = 0;

    cycle = ngx_old_cycles.elts;
    for (i = 0; i < ngx_old_cycles.nelts; i++) {

        if (cycle[i] == NULL) {
            continue;
        }

        found = 0;

        for (n = 0; n < cycle[i]->connection_n; n++) {
            if (cycle[i]->connections[n].fd != (ngx_socket_t) -1) {
                found = 1;

                ngx_log_debug1(NGX_LOG_DEBUG_CORE, log, 0, "live fd:%d", n);

                break;
            }
        }

        if (found) {
            live = 1;
            continue;
        }

        ngx_log_debug1(NGX_LOG_DEBUG_CORE, log, 0, "clean old cycle: %d", i);

        ngx_destroy_pool(cycle[i]->pool);
        cycle[i] = NULL;
    }

    ngx_log_debug1(NGX_LOG_DEBUG_CORE, log, 0, "old cycles status: %d", live);

    if (live) {
        ngx_add_timer(ev, 30000);

    } else {
        ngx_destroy_pool(ngx_temp_pool);
        ngx_temp_pool = NULL;
        ngx_old_cycles.nelts = 0;
    }
}
