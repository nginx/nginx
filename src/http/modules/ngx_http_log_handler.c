
#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>


typedef struct {
    ngx_file_t  file;
} ngx_http_log_conf_t;


static void *ngx_http_log_create_conf(ngx_pool_t *pool);
static char *ngx_http_log_merge_conf(ngx_pool_t *p, void *parent, void *child);
static char *ngx_http_log_set_log(ngx_conf_t *cf, ngx_command_t *cmd,
                                                                   void *conf);

static ngx_command_t ngx_http_log_commands[] = {

    {ngx_string("access_log"),
     NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
     ngx_http_log_set_log,
     NGX_HTTP_LOC_CONF_OFFSET,
     0,
     NULL},

    ngx_null_command
};


ngx_http_module_t  ngx_http_log_module_ctx = {
    NULL,                                  /* create main configuration */
    NULL,                                  /* init main configuration */

    NULL,                                  /* create server configuration */
    NULL,                                  /* merge server configuration */

    ngx_http_log_create_conf,              /* create location configration */
    ngx_http_log_merge_conf                /* merge location configration */
};


ngx_module_t  ngx_http_log_module = {
    NGX_MODULE,
    &ngx_http_log_module_ctx,              /* module context */
    ngx_http_log_commands,                 /* module directives */
    NGX_HTTP_MODULE,                       /* module type */
    NULL,                                  /* init module */
};



static char *months[] = { "Jan", "Feb", "Mar", "Apr", "May", "Jun",
                          "Jul", "Aug", "Sep", "Oct", "Nov", "Dec" };


int ngx_http_log_handler(ngx_http_request_t *r)
{
    char                 *line, *p;
    size_t                len;
    ngx_tm_t              tm;
    ngx_http_log_conf_t  *lcf;

    ngx_log_debug(r->connection->log, "log handler");

    lcf = ngx_http_get_module_loc_conf(r, ngx_http_log_module);

    /* 10:%con, 1:%pipe, 22:%date, 2:"%r", 3:%status, 20:%bytes, 2:%user-agent,
       7*" ", 2/1: "\r\n" */
#if (WIN32)
    len = 10 + 1 + 22 + 2 + 3 + 20 + 2 + 7 + 2;
#else
    len = 10 + 1 + 22 + 2 + 3 + 20 + 2 + 7 + 1;
#endif

    len += r->connection->addr_text.len;
    len += r->request_line.len;
    if (r->headers_in.user_agent) {
        len += r->headers_in.user_agent->value.len;
    }

    ngx_test_null(line, ngx_palloc(r->pool, len), NGX_ERROR);
    p = line;

    ngx_memcpy(p, r->connection->addr_text.data, r->connection->addr_text.len);
    p += r->connection->addr_text.len;

    *p++ = ' ';

    p += ngx_snprintf(p, 21, "%u", r->connection->number);

    *p++ = ' ';

    if (r->pipeline) {
        *p++ = 'p';
    } else {
        *p++ = '.';
    }

    *p++ = ' ';

    ngx_localtime(&tm);

    *p++ = '[';
    p += ngx_snprintf(p, 21, "%02d/%s/%d:%02d:%02d:%02d",
                      tm.ngx_tm_mday, months[tm.ngx_tm_mon - 1],
                      tm.ngx_tm_year,
                      tm.ngx_tm_hour, tm.ngx_tm_min, tm.ngx_tm_sec);

    *p++ = ']';

    *p++ = ' ';

    *p++ = '"';
    ngx_memcpy(p, r->request_line.data, r->request_line.len);
    p += r->request_line.len;
    *p++ = '"';

    *p++ = ' ';

    p += ngx_snprintf(p, 4, "%d", r->headers_out.status);

    *p++ = ' ';

    p += ngx_snprintf(p, 21, OFF_FMT, r->connection->sent);

    *p++ = ' ';

    *p++ = '"';
    if (r->headers_in.user_agent) {
        ngx_memcpy(p, r->headers_in.user_agent->value.data,
                   r->headers_in.user_agent->value.len);
        p += r->headers_in.user_agent->value.len;
    }
    *p++ = '"';

#if (WIN32)
    *p++ = CR; *p++ = LF;
#else
    *p++ = LF;
#endif

    write(lcf->file.fd, line, p - line);

    return NGX_OK;
}


static void *ngx_http_log_create_conf(ngx_pool_t *pool)
{
    ngx_http_log_conf_t  *conf;

    ngx_test_null(conf, ngx_pcalloc(pool, sizeof(ngx_http_log_conf_t)),
                  NGX_CONF_ERROR);

    return conf;
}


static char *ngx_http_log_merge_conf(ngx_pool_t *p, void *parent, void *child)
{
    ngx_http_log_conf_t *prev = parent;
    ngx_http_log_conf_t *conf = child;

    /* STUB */
    *conf = *prev;

    return NGX_CONF_OK;
}


static char *ngx_http_log_set_log(ngx_conf_t *cf, ngx_command_t *cmd,
                                  void *conf)
{
    ngx_http_log_conf_t *lcf = conf;

    int         len;
    ngx_err_t   err;
    ngx_str_t  *value;

    value = cf->args->elts;

    lcf->file.name.len = value[1].len;
    lcf->file.name.data = value[1].data;

    lcf->file.fd = ngx_open_file(lcf->file.name.data,
                                 NGX_FILE_RDWR,
                                 NGX_FILE_CREATE_OR_OPEN|NGX_FILE_APPEND);

    if (lcf->file.fd == NGX_INVALID_FILE) {
        err = ngx_errno;
        len = ngx_snprintf(ngx_conf_errstr, sizeof(ngx_conf_errstr) - 1,
                          ngx_open_file_n " \"%s\" failed (%d: ",
                          lcf->file.name.data, err);
        len += ngx_strerror_r(err, ngx_conf_errstr + len,
                              sizeof(ngx_conf_errstr) - len - 1);
        ngx_conf_errstr[len++] = ')';
        ngx_conf_errstr[len++] = '\0';
        return ngx_conf_errstr;
    }

    return NGX_CONF_OK;
}
