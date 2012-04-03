
/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) Nginx, Inc.
 */


#include <ngx_config.h>
#include <ngx_core.h>


#if (NGX_SETPROCTITLE_USES_ENV)

/*
 * To change the process title in Linux and Solaris we have to set argv[1]
 * to NULL and to copy the title to the same place where the argv[0] points to.
 * However, argv[0] may be too small to hold a new title.  Fortunately, Linux
 * and Solaris store argv[] and environ[] one after another.  So we should
 * ensure that is the continuous memory and then we allocate the new memory
 * for environ[] and copy it.  After this we could use the memory starting
 * from argv[0] for our process title.
 *
 * The Solaris's standard /bin/ps does not show the changed process title.
 * You have to use "/usr/ucb/ps -w" instead.  Besides, the UCB ps does not
 * show a new title if its length less than the origin command line length.
 * To avoid it we append to a new title the origin command line in the
 * parenthesis.
 */

extern char **environ;

static char *ngx_os_argv_last;

ngx_int_t
ngx_init_setproctitle(ngx_log_t *log)
{
    u_char      *p;
    size_t       size;
    ngx_uint_t   i;

    size = 0;

    for (i = 0; environ[i]; i++) {
        size += ngx_strlen(environ[i]) + 1;
    }

    p = ngx_alloc(size, log);
    if (p == NULL) {
        return NGX_ERROR;
    }

    ngx_os_argv_last = ngx_os_argv[0];

    for (i = 0; ngx_os_argv[i]; i++) {
        if (ngx_os_argv_last == ngx_os_argv[i]) {
            ngx_os_argv_last = ngx_os_argv[i] + ngx_strlen(ngx_os_argv[i]) + 1;
        }
    }

    for (i = 0; environ[i]; i++) {
        if (ngx_os_argv_last == environ[i]) {

            size = ngx_strlen(environ[i]) + 1;
            ngx_os_argv_last = environ[i] + size;

            ngx_cpystrn(p, (u_char *) environ[i], size);
            environ[i] = (char *) p;
            p += size;
        }
    }

    ngx_os_argv_last--;

    return NGX_OK;
}


void
ngx_setproctitle(char *title)
{
    u_char     *p;

#if (NGX_SOLARIS)

    ngx_int_t   i;
    size_t      size;

#endif

    ngx_os_argv[1] = NULL;

    p = ngx_cpystrn((u_char *) ngx_os_argv[0], (u_char *) "nginx: ",
                    ngx_os_argv_last - ngx_os_argv[0]);

    p = ngx_cpystrn(p, (u_char *) title, ngx_os_argv_last - (char *) p);

#if (NGX_SOLARIS)

    size = 0;

    for (i = 0; i < ngx_argc; i++) {
        size += ngx_strlen(ngx_argv[i]) + 1;
    }

    if (size > (size_t) ((char *) p - ngx_os_argv[0])) {

        /*
         * ngx_setproctitle() is too rare operation so we use
         * the non-optimized copies
         */

        p = ngx_cpystrn(p, (u_char *) " (", ngx_os_argv_last - (char *) p);

        for (i = 0; i < ngx_argc; i++) {
            p = ngx_cpystrn(p, (u_char *) ngx_argv[i],
                            ngx_os_argv_last - (char *) p);
            p = ngx_cpystrn(p, (u_char *) " ", ngx_os_argv_last - (char *) p);
        }

        if (*(p - 1) == ' ') {
            *(p - 1) = ')';
        }
    }

#endif

    if (ngx_os_argv_last - (char *) p) {
        ngx_memset(p, NGX_SETPROCTITLE_PAD, ngx_os_argv_last - (char *) p);
    }

    ngx_log_debug1(NGX_LOG_DEBUG_CORE, ngx_cycle->log, 0,
                   "setproctitle: \"%s\"", ngx_os_argv[0]);
}

#endif /* NGX_SETPROCTITLE_USES_ENV */
