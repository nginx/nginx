

int ngx_unix_init(ngx_log_t *log)
{
    struct rlimit  rlmt;

    if (getrlimit(RLIMIT_NOFILE, &rlmt) == -1) {
        ngx_log_error(NGX_LOG_ALERT, log, errno,
                      "getrlimit(RLIMIT_NOFILE) failed)");
        return NGX_ERROR;
    }

    ngx_log_error(NGX_LOG_INFO, log, 0,
                  "getrlimit(RLIMIT_NOFILE): %d", rlmt.rlim_cur);

    RLIM_INFINITY
    max_connections =< rlmt.rlim_cur;

    return NGX_OK;
}
