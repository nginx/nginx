
/*
 * Copyright (C) Andy Pan
 * Copyright (C) Nginx, Inc.
 */


#include <ngx_config.h>
#include <ngx_core.h>

int
ngx_tcp_keepalive(ngx_socket_t s, int idle, int interval, int count)
{
#if (NGX_HAVE_KEEPALIVE_TUNABLE)
    int sockval;

    if (idle < 1 || interval < 1 || count < 1) {
        return NGX_ERROR;
    }

    sockval = idle;

#if (NGX_KEEPALIVE_FACTOR)
    sockval *= NGX_KEEPALIVE_FACTOR;
#endif

#ifdef TCP_KEEPIDLE
    if (setsockopt(s, IPPROTO_TCP, TCP_KEEPIDLE,
                   (const void *) &sockval, sizeof(int))
        == -1)
    {
        return NGX_ERROR;
    }
#elif defined(TCP_KEEPALIVE)
    /* Darwin/macOS uses TCP_KEEPALIVE in place of TCP_KEEPIDLE. */
    if (setsockopt(s, IPPROTO_TCP, TCP_KEEPALIVE,
                   (const void *) &sockval, sizeof(int))
        == -1)
    {
        return NGX_ERROR;
    }
#endif

    sockval = interval;

#if (NGX_KEEPALIVE_FACTOR)
    sockval *= NGX_KEEPALIVE_FACTOR;
#endif

    if (setsockopt(s, IPPROTO_TCP, TCP_KEEPINTVL,
                   (const void *) &sockval, sizeof(int))
        == -1)
    {
        return NGX_ERROR;
    }

    sockval = count;

    if (setsockopt(s, IPPROTO_TCP, TCP_KEEPCNT,
                   (const void *) &sockval, sizeof(int))
        == -1)
    {
        return NGX_ERROR;
    }

    return NGX_OK;

#else /* !(NGX_HAVE_KEEPALIVE_TUNABLE) */

  return NGX_ERROR;

#endif
}
