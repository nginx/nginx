
#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>


int ngx_http_busy_lock(ngx_http_busy_lock_t *bl, u_char *md5)
{
    int    i, b, busy, free;
    u_int  mask;

    b = 0;
    busy = 0;
    free = -1;

#if (NGX_SUPPRESS_WARN)
    mask = 0;
#endif

    for (i = 0; i < bl->max_conn; i++) {

        if ((b & 7) == 0) {
            mask = bl->busy_mask[i / 8];
        }

        if (mask & 1) {
            if (ngx_memcmp(&bl->busy[i * 16], md5, 16) == 0) {
                return NGX_AGAIN;
            }
            busy++;

        } else if (free == -1) {
            free = i;
        }

        if (busy == bl->busy_n) {
            if (busy < bl->max_conn) {
                free = i + 1;
            }

            break;
        }

        mask >>= 1;
        b++;
    }

    if (free == -1) {
        return NGX_ERROR;
    }

    ngx_memcpy(&bl->busy[free * 16], md5, 16);
    bl->busy_mask[free / 8] |= free % 8;

    bl->busy_n++;
    bl->conn_n++;

    return NGX_OK;
}


char *ngx_http_set_busy_lock_slot(ngx_conf_t *cf, ngx_command_t *cmd,
                                  void *conf)
{
    char  *p = conf;

    int                    i;
    ngx_str_t             *value;
    ngx_http_busy_lock_t  *bl, **blp;

    blp = (ngx_http_busy_lock_t **) (p + cmd->offset);
    if (*blp) {
        return "is duplicate";
    }

    /* ngx_calloc_shared() */
    if (!(bl = ngx_pcalloc(cf->pool, sizeof(ngx_http_busy_lock_t)))) {
        return NGX_CONF_ERROR;
    }
    *blp = bl;

    value = (ngx_str_t *) cf->args->elts;

    for (i = 1; i < 4; i++) {

        if (value[i].len > 2 && ngx_strncasecmp(value[i].data, "c:", 2) == 0) {
            if (bl->max_conn) {
                ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                               "duplicate \"%s\"", value[i].data);
                return NGX_CONF_ERROR;
            }

            bl->max_conn = ngx_atoi(value[i].data + 2, value[i].len - 2);
            if (bl->max_conn == NGX_ERROR) {
                ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                               "invalid value \"%s\"", value[i].data);
                return NGX_CONF_ERROR;
            }

            continue;
        }

        if (value[i].len > 2 && ngx_strncasecmp(value[i].data, "w:", 2) == 0) {
            if (bl->max_waiting) {
                ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                               "duplicate \"%s\"", value[i].data);
                return NGX_CONF_ERROR;
            }

            bl->max_waiting = ngx_atoi(value[i].data + 2, value[i].len - 2);
            if (bl->max_waiting == NGX_ERROR) {
                ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                               "invalid value \"%s\"", value[i].data);
                return NGX_CONF_ERROR;
            }

            continue;
        }

        if (bl->timeout) {
            ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                               "duplicate timeout \"%s\"", value[i].data);
            return NGX_CONF_ERROR;
        }

        bl->timeout = ngx_parse_time(&value[1], 1);
        if (bl->timeout == NGX_ERROR) {
            ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                               "invalid timeout \"%s\"", value[i].data);
            return NGX_CONF_ERROR;
        }
    }

    return NGX_CONF_OK;
}
