
/*
 * Copyright (C) Igor Sysoev
 */


#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_event.h>
#include <ngx_event_connect.h>


/* Solaris has predefined "#define sun 1" */
#undef sun


ngx_peers_t *ngx_unix_upstream_parse(ngx_conf_t *cf,
                                     ngx_unix_domain_upstream_t *u)
{
    size_t               len;
    ngx_uint_t           i;
    ngx_peers_t         *peers;
    struct sockaddr_un  *sun;

    len = u->url.len - 5;

    if (u->uri_part) {
        for (i = 5; i < u->url.len; i++) {
            if (u->url.data[i] == ':') {
                len = i - 5;
                u->uri.len = u->url.len - 5 - len - 1;
                u->uri.data = u->url.data + 5 + len + 1;

                break;
            }
        }

        if (u->uri.len == 0) {
            ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                               "the unix domain upstream \"%V\" has no URI",
                               &u->name);
            return NULL;
        }
    }

    if (len == 0) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                           "the unix domain socket \"%V\" has no path",
                           &u->name);
        return NULL;
    }

    if (len + 1 > sizeof(sun->sun_path)) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                           "the unix domain socket path \"%V\" is too long",
                           &u->name);
        return NULL;
    }

    /* MP: ngx_shared_palloc() */

    peers = ngx_pcalloc(cf->pool, sizeof(ngx_peers_t));
    if (peers == NULL) {
        return NULL;
    }

    sun = ngx_pcalloc(cf->pool, sizeof(struct sockaddr_un));
    if (sun == NULL) {
        return NULL;
    }

    peers->number = 1;

    sun->sun_family = AF_UNIX;
    ngx_cpystrn((u_char *) sun->sun_path, u->url.data + 5, len + 1);

    peers->peer[0].sockaddr = (struct sockaddr *) sun;
    peers->peer[0].socklen = sizeof(struct sockaddr_un);

    peers->peer[0].name.len = 5 + len;
    peers->peer[0].name.data = u->url.data;

    peers->peer[0].uri_separator = ":";

    return peers;
}
