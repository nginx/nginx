
/*
 * Copyright (C) Igor Sysoev
 */


#ifndef _NGX_SETPROCTITLE_H_INCLUDED_
#define _NGX_SETPROCTITLE_H_INCLUDED_


#if (NGX_HAVE_SETPROCTITLE)

/* FreeBSD, NetBSD, OpenBSD */

#define ngx_init_setproctitle(log)
#define ngx_setproctitle           setproctitle


#elif !defined NGX_SETPROCTITLE_USES_ENV

#define NGX_SETPROCTITLE_USES_ENV  1

#if (NGX_SOLARIS)

#define NGX_SETPROCTITLE_PAD       ' '

#elif (NGX_LINUX) || (NGX_DARWIN)

#define NGX_SETPROCTITLE_PAD       '\0'

#endif

ngx_int_t ngx_init_setproctitle(ngx_log_t *log);
void ngx_setproctitle(char *title);


#else /* !NGX_SETPROCTITLE_USES_ENV */

#define ngx_init_setproctitle(log)
#define ngx_setproctitle(title)

#endif


#endif /* _NGX_SETPROCTITLE_H_INCLUDED_ */
