
/*
 * Copyright (C) Igor Sysoev
 */


#ifndef _NGX_SETPROCTITLE_H_INCLUDED_
#define _NGX_SETPROCTITLE_H_INCLUDED_


#if (NGX_HAVE_SETPROCTITLE)

/* FreeBSD, NetBSD, OpenBSD */

#define ngx_init_setproctitle(log)
#define ngx_setproctitle           setproctitle


#else /* !NGX_HAVE_SETPROCTITLE */

#if !defined NGX_SETPROCTITLE_USES_ENV

#if (NGX_SOLARIS)

#define NGX_SETPROCTITLE_USES_ENV  1
#define NGX_SETPROCTITLE_PAD       ' '

ngx_int_t ngx_init_setproctitle(ngx_log_t *log);
void ngx_setproctitle(char *title);

#elif (NGX_LINUX) || (NGX_DARWIN)

#define NGX_SETPROCTITLE_USES_ENV  1
#define NGX_SETPROCTITLE_PAD       '\0'

ngx_int_t ngx_init_setproctitle(ngx_log_t *log);
void ngx_setproctitle(char *title);

#else

#define ngx_init_setproctitle(log)
#define ngx_setproctitle(title)

#endif /* OSes */

#endif /* NGX_SETPROCTITLE_USES_ENV */

#endif /* NGX_HAVE_SETPROCTITLE */


#endif /* _NGX_SETPROCTITLE_H_INCLUDED_ */
