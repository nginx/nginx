
#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>


typedef struct {
    ngx_str_t   from;
    ngx_str_t   to;
    char       *table;
} ngx_http_charset_table_t;


typedef struct {
    ngx_array_t  tables;                 /* ngx_http_charset_table_t */
} ngx_http_charset_main_conf_t;


typedef struct {
    ngx_str_t  default_charset;
} ngx_http_charset_loc_conf_t;


static char *ngx_charset_map_block(ngx_conf_t *cf, ngx_command_t *cmd,
                                   void *conf);
static char *ngx_charset_map(ngx_conf_t *cf, ngx_command_t *dummy, void *conf);

static int ngx_http_charset_filter_init(ngx_cycle_t *cycle);

static void *ngx_http_charset_create_main_conf(ngx_conf_t *cf);
static void *ngx_http_charset_create_loc_conf(ngx_conf_t *cf);
static char *ngx_http_charset_merge_loc_conf(ngx_conf_t *cf,
                                             void *parent, void *child);


static ngx_command_t  ngx_http_charset_filter_commands[] = {

    { ngx_string("charset_map"),
      NGX_HTTP_MAIN_CONF|NGX_CONF_BLOCK|NGX_CONF_TAKE2,
      ngx_charset_map_block,
      NGX_HTTP_MAIN_CONF_OFFSET,
      0,
      NULL },

    { ngx_string("default_charset"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_str_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_charset_loc_conf_t, default_charset),
      NULL },

      ngx_null_command
};


static ngx_http_module_t  ngx_http_charset_filter_module_ctx = {
    NULL,                                  /* pre conf */

    ngx_http_charset_create_main_conf,     /* create main configuration */
    NULL,                                  /* init main configuration */

    NULL,                                  /* create server configuration */
    NULL,                                  /* merge server configuration */

    ngx_http_charset_create_loc_conf,      /* create location configuration */
    ngx_http_charset_merge_loc_conf        /* merge location configuration */
};


ngx_module_t  ngx_http_charset_filter_module = {
    NGX_MODULE,
    &ngx_http_charset_filter_module_ctx,   /* module context */
    ngx_http_charset_filter_commands,      /* module directives */
    NGX_HTTP_MODULE,                       /* module type */
    ngx_http_charset_filter_init,          /* init module */
    NULL                                   /* init child */
};


static ngx_http_output_header_filter_pt  ngx_http_next_header_filter;
#if 0
static ngx_http_output_body_filter_pt    ngx_http_next_body_filter;
#endif


static int ngx_http_charset_header_filter(ngx_http_request_t *r)
{
    ngx_http_charset_loc_conf_t  *lcf;

    lcf = ngx_http_get_module_loc_conf(r, ngx_http_charset_filter_module);

    if (lcf->default_charset.len == 0) {
        return ngx_http_next_header_filter(r);
    }

    if (r->headers_out.content_type == NULL
        || ngx_strncasecmp(r->headers_out.content_type->value.data,
                                                              "text/", 5) != 0
        || ngx_strstr(r->headers_out.content_type->value.data, "charset")
                                                                       != NULL
       )
    {
        return ngx_http_next_header_filter(r);
    }

    if (r->headers_out.status == NGX_HTTP_MOVED_PERMANENTLY
        && r->headers_out.status == NGX_HTTP_MOVED_TEMPORARILY)
    {

        /*
         * do not set charset for the redirect because NN 4.x uses this
         * charset instead of the next page charset
         */

        r->headers_out.charset.len = 0;

    } else if (r->headers_out.charset.len == 0) {
        r->headers_out.charset = lcf->default_charset;
    }

    return ngx_http_next_header_filter(r);
}


#if 0
static int ngx_http_charset_body_filter(ngx_http_request_t *r, ngx_chain_t *in)
{
    ngx_log_debug(r->connection->log, "CHARSET BODY");
    return ngx_http_next_body_filter(r, in);
}
#endif


static char *ngx_charset_map_block(ngx_conf_t *cf, ngx_command_t *cmd,
                                   void *conf)
{
    char        *rv;
    ngx_conf_t   pcf;

    pcf = *cf;
    cf->handler = ngx_charset_map;
    cf->handler_conf = conf;
    rv = ngx_conf_parse(cf, NULL);
    *cf = pcf;

    return rv;
}


static char *ngx_charset_map(ngx_conf_t *cf, ngx_command_t *dummy, void *conf)
{
    ngx_http_charset_main_conf_t  *mcf = conf;

    ngx_int_t   src, dst;
    ngx_str_t  *args;

    if (cf->args->nelts != 2) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0, "invalid parameters number");
        return NGX_CONF_ERROR;
    }

    args = cf->args->elts;

    src = ngx_hextoi(args[0].data, args[0].len);
    if (src == NGX_ERROR || src > 255) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                           "invalid value \"%s\"", args[0].data);
        return NGX_CONF_ERROR;
    }

    dst = ngx_hextoi(args[1].data, args[1].len);
    if (dst == NGX_ERROR || dst > 255) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                           "invalid value \"%s\"", args[1].data);
        return NGX_CONF_ERROR;
    }

#if 0
    mcf->tables[src] = dst;
#endif

    return NGX_CONF_OK;
}


static int ngx_http_charset_filter_init(ngx_cycle_t *cycle)
{
    ngx_http_next_header_filter = ngx_http_top_header_filter;
    ngx_http_top_header_filter = ngx_http_charset_header_filter;

#if 0
    ngx_http_next_body_filter = ngx_http_top_body_filter;
    ngx_http_top_body_filter = ngx_http_charset_body_filter;
#endif

    return NGX_OK;
}


static void *ngx_http_charset_create_main_conf(ngx_conf_t *cf)
{
    ngx_http_charset_main_conf_t  *mcf;

    ngx_test_null(mcf,
                  ngx_pcalloc(cf->pool, sizeof(ngx_http_charset_main_conf_t)),
                  NGX_CONF_ERROR);

    ngx_init_array(mcf->tables, cf->pool, 10, sizeof(ngx_http_charset_table_t),
                   NGX_CONF_ERROR);

    return mcf;
}


static void *ngx_http_charset_create_loc_conf(ngx_conf_t *cf)
{
    ngx_http_charset_loc_conf_t  *lcf;

    ngx_test_null(lcf,
                  ngx_pcalloc(cf->pool, sizeof(ngx_http_charset_loc_conf_t)),
                  NGX_CONF_ERROR);

    return lcf;
}


static char *ngx_http_charset_merge_loc_conf(ngx_conf_t *cf,
                                             void *parent, void *child)
{
    ngx_http_charset_loc_conf_t *prev = parent;
    ngx_http_charset_loc_conf_t *conf = child;

    ngx_conf_merge_str_value(conf->default_charset,
                             prev->default_charset, "");

    return NGX_CONF_OK;
}
