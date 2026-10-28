
/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) Nginx, Inc.
 */


#ifndef _NGX_SETPROCTITLE_H_INCLUDED_
#define _NGX_SETPROCTITLE_H_INCLUDED_


#if (NGX_HAVE_SETPROCTITLE)

/* FreeBSD, NetBSD, OpenBSD */

#define ngx_init_setproctitle(log) NGX_OK
#define ngx_setproctitle_fmt       setproctitle


#else /* !NGX_HAVE_SETPROCTITLE */

#if !defined NGX_SETPROCTITLE_USES_ENV

#if (NGX_SOLARIS)

#define NGX_SETPROCTITLE_USES_ENV  1
#define NGX_SETPROCTITLE_PAD       ' '

ngx_int_t ngx_init_setproctitle(ngx_log_t *log);
void ngx_setproctitle_fmt(const char *fmt, ...);

#elif (NGX_LINUX) || (NGX_DARWIN)

#define NGX_SETPROCTITLE_USES_ENV  1
#define NGX_SETPROCTITLE_PAD       '\0'

ngx_int_t ngx_init_setproctitle(ngx_log_t *log);
void ngx_setproctitle_fmt(const char *fmt, ...);

#else

#define ngx_init_setproctitle(log) NGX_OK
static ngx_inline void ngx_setproctitle_fmt(const char *fmt, ...) { /* void */ }

#endif /* OSes */

#endif /* NGX_SETPROCTITLE_USES_ENV */

#endif /* NGX_HAVE_SETPROCTITLE */


#define ngx_setproctitle(title)           ngx_setproctitle_fmt("%s", title)

#define ngx_setproctitle_gen(title, gen)                                      \
    ngx_setproctitle_fmt("%s #%llu", title, (unsigned long long) gen)


#endif /* _NGX_SETPROCTITLE_H_INCLUDED_ */
