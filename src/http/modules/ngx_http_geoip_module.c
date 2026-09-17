
/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) Nitin Swami
 * Copyright (C) Nginx, Inc.
 */


#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>

#if (NGX_HAVE_LIBGEOIP)
#include <GeoIP.h>
#include <GeoIPCity.h>
#endif

#if (NGX_HAVE_MAXMINDDB)
#include <maxminddb.h>
#endif


#define NGX_GEOIP_COUNTRY_CODE   0
#define NGX_GEOIP_COUNTRY_CODE3  1
#define NGX_GEOIP_COUNTRY_NAME   2

#define NGX_GEOIP_CITY_CONTINENT_CODE  0
#define NGX_GEOIP_CITY_COUNTRY_CODE    1
#define NGX_GEOIP_CITY_COUNTRY_CODE3   2
#define NGX_GEOIP_CITY_COUNTRY_NAME    3
#define NGX_GEOIP_CITY_REGION          4
#define NGX_GEOIP_CITY_REGION_NAME     5
#define NGX_GEOIP_CITY_NAME            6
#define NGX_GEOIP_CITY_POSTAL_CODE     7
#define NGX_GEOIP_CITY_LATITUDE        8
#define NGX_GEOIP_CITY_LONGITUDE       9
#define NGX_GEOIP_CITY_DMA_CODE        10
#define NGX_GEOIP_CITY_AREA_CODE       11


typedef struct {
#if (NGX_HAVE_LIBGEOIP)
    GeoIP        *country;
    GeoIP        *org;
    GeoIP        *city;
#endif
#if (NGX_HAVE_MAXMINDDB)
    MMDB_s       *country_mmdb;
    MMDB_s       *org_mmdb;
    MMDB_s       *city_mmdb;
#endif
    ngx_array_t  *proxies;    /* array of ngx_cidr_t */
    ngx_flag_t    proxy_recursive;
#if (NGX_HAVE_GEOIP_V6)
    unsigned      country_v6:1;
    unsigned      org_v6:1;
    unsigned      city_v6:1;
#endif
} ngx_http_geoip_conf_t;


typedef struct {
    ngx_str_t    *name;
    uintptr_t     data;
} ngx_http_geoip_var_t;


#if (NGX_HAVE_LIBGEOIP)

typedef const char *(*ngx_http_geoip_variable_handler_pt)(GeoIP *,
    u_long addr);


ngx_http_geoip_variable_handler_pt ngx_http_geoip_country_functions[] = {
    GeoIP_country_code_by_ipnum,
    GeoIP_country_code3_by_ipnum,
    GeoIP_country_name_by_ipnum,
};


#if (NGX_HAVE_GEOIP_V6)

typedef const char *(*ngx_http_geoip_variable_handler_v6_pt)(GeoIP *,
    geoipv6_t addr);


ngx_http_geoip_variable_handler_v6_pt ngx_http_geoip_country_v6_functions[] = {
    GeoIP_country_code_by_ipnum_v6,
    GeoIP_country_code3_by_ipnum_v6,
    GeoIP_country_name_by_ipnum_v6,
};

#endif


/* indexed by NGX_GEOIP_CITY_* */

static size_t  ngx_http_geoip_city_offsets[] = {
    offsetof(GeoIPRecord, continent_code),
    offsetof(GeoIPRecord, country_code),
    offsetof(GeoIPRecord, country_code3),
    offsetof(GeoIPRecord, country_name),
    offsetof(GeoIPRecord, region),
    0,                                     /* region name, see below */
    offsetof(GeoIPRecord, city),
    offsetof(GeoIPRecord, postal_code),
    offsetof(GeoIPRecord, latitude),
    offsetof(GeoIPRecord, longitude),
    offsetof(GeoIPRecord, dma_code),
    offsetof(GeoIPRecord, area_code)
};

#endif


#if (NGX_HAVE_MAXMINDDB)

typedef struct {
    const char   *alpha2;
    const char   *alpha3;
} ngx_http_geoip_ccode_t;


static const char  *ngx_http_geoip_mmdb_country_code[] = {
    "country", "iso_code", NULL
};

static const char  *ngx_http_geoip_mmdb_country_name[] = {
    "country", "names", "en", NULL
};

static const char  *ngx_http_geoip_mmdb_continent_code[] = {
    "continent", "code", NULL
};

static const char  *ngx_http_geoip_mmdb_region[] = {
    "subdivisions", "0", "iso_code", NULL
};

static const char  *ngx_http_geoip_mmdb_region_name[] = {
    "subdivisions", "0", "names", "en", NULL
};

static const char  *ngx_http_geoip_mmdb_city[] = {
    "city", "names", "en", NULL
};

static const char  *ngx_http_geoip_mmdb_postal_code[] = {
    "postal", "code", NULL
};

static const char  *ngx_http_geoip_mmdb_latitude[] = {
    "location", "latitude", NULL
};

static const char  *ngx_http_geoip_mmdb_longitude[] = {
    "location", "longitude", NULL
};

static const char  *ngx_http_geoip_mmdb_dma_code[] = {
    "location", "metro_code", NULL
};

static const char  *ngx_http_geoip_mmdb_asorg[] = {
    "autonomous_system_organization", NULL
};

static const char  *ngx_http_geoip_mmdb_isp[] = {
    "isp", NULL
};

static const char  *ngx_http_geoip_mmdb_organization[] = {
    "organization", NULL
};

static const char  *ngx_http_geoip_mmdb_domain[] = {
    "domain", NULL
};


/* indexed by NGX_GEOIP_COUNTRY_* */

static const char  **ngx_http_geoip_mmdb_country_paths[] = {
    ngx_http_geoip_mmdb_country_code,
    ngx_http_geoip_mmdb_country_code,      /* converted to alpha-3 */
    ngx_http_geoip_mmdb_country_name
};


/* indexed by NGX_GEOIP_CITY_* */

static const char  **ngx_http_geoip_mmdb_city_paths[] = {
    ngx_http_geoip_mmdb_continent_code,
    ngx_http_geoip_mmdb_country_code,
    ngx_http_geoip_mmdb_country_code,      /* converted to alpha-3 */
    ngx_http_geoip_mmdb_country_name,
    ngx_http_geoip_mmdb_region,
    ngx_http_geoip_mmdb_region_name,
    ngx_http_geoip_mmdb_city,
    ngx_http_geoip_mmdb_postal_code,
    ngx_http_geoip_mmdb_latitude,
    ngx_http_geoip_mmdb_longitude,
    ngx_http_geoip_mmdb_dma_code,
    NULL                                   /* no area code in MaxMind DB */
};


/*
 * a legacy GeoIP database used by the "geoip_org" directive provided
 * an ISP, organization, domain, or AS organization name, depending on
 * the database type; the MaxMind DB counterparts are looked up in turn
 */

static const char  **ngx_http_geoip_mmdb_org_paths[] = {
    ngx_http_geoip_mmdb_asorg,
    ngx_http_geoip_mmdb_isp,
    ngx_http_geoip_mmdb_organization,
    ngx_http_geoip_mmdb_domain,
    NULL
};

#endif


static ngx_int_t ngx_http_geoip_country_variable(ngx_http_request_t *r,
    ngx_http_variable_value_t *v, uintptr_t data);
static ngx_int_t ngx_http_geoip_org_variable(ngx_http_request_t *r,
    ngx_http_variable_value_t *v, uintptr_t data);
static ngx_int_t ngx_http_geoip_city_variable(ngx_http_request_t *r,
    ngx_http_variable_value_t *v, uintptr_t data);
static ngx_int_t ngx_http_geoip_region_name_variable(ngx_http_request_t *r,
    ngx_http_variable_value_t *v, uintptr_t data);
static ngx_int_t ngx_http_geoip_city_float_variable(ngx_http_request_t *r,
    ngx_http_variable_value_t *v, uintptr_t data);
static ngx_int_t ngx_http_geoip_city_int_variable(ngx_http_request_t *r,
    ngx_http_variable_value_t *v, uintptr_t data);
static struct sockaddr *ngx_http_geoip_sockaddr(ngx_http_request_t *r,
    ngx_http_geoip_conf_t *gcf);
#if (NGX_HAVE_LIBGEOIP)
static GeoIPRecord *ngx_http_geoip_get_city_record(ngx_http_request_t *r);
#endif
#if (NGX_HAVE_MAXMINDDB)
static ngx_int_t ngx_http_geoip_mmdb_lookup(ngx_http_request_t *r,
    MMDB_s *mmdb, const char **path, MMDB_entry_data_s *entry_data);
static ngx_int_t ngx_http_geoip_mmdb_str(ngx_http_request_t *r, MMDB_s *mmdb,
    const char **path, ngx_http_variable_value_t *v);
static ngx_int_t ngx_http_geoip_mmdb_code3(ngx_http_request_t *r, MMDB_s *mmdb,
    ngx_http_variable_value_t *v);
static ngx_int_t ngx_http_geoip_mmdb_float(ngx_http_request_t *r, MMDB_s *mmdb,
    const char **path, ngx_http_variable_value_t *v);
static ngx_int_t ngx_http_geoip_mmdb_int(ngx_http_request_t *r, MMDB_s *mmdb,
    const char **path, ngx_http_variable_value_t *v);
static ngx_int_t ngx_http_geoip_mmdb_open(ngx_conf_t *cf, ngx_str_t *name,
    MMDB_s **db);
static char *ngx_http_geoip_mmdb_charset(ngx_conf_t *cf);
#endif

static ngx_int_t ngx_http_geoip_add_variables(ngx_conf_t *cf);
static void *ngx_http_geoip_create_conf(ngx_conf_t *cf);
static char *ngx_http_geoip_init_conf(ngx_conf_t *cf, void *conf);
static char *ngx_http_geoip_country(ngx_conf_t *cf, ngx_command_t *cmd,
    void *conf);
static char *ngx_http_geoip_org(ngx_conf_t *cf, ngx_command_t *cmd,
    void *conf);
static char *ngx_http_geoip_city(ngx_conf_t *cf, ngx_command_t *cmd,
    void *conf);
static char *ngx_http_geoip_proxy(ngx_conf_t *cf, ngx_command_t *cmd,
    void *conf);
static ngx_int_t ngx_http_geoip_cidr_value(ngx_conf_t *cf, ngx_str_t *net,
    ngx_cidr_t *cidr);
static void ngx_http_geoip_cleanup(void *data);


static ngx_command_t  ngx_http_geoip_commands[] = {

    { ngx_string("geoip_country"),
      NGX_HTTP_MAIN_CONF|NGX_CONF_TAKE12,
      ngx_http_geoip_country,
      NGX_HTTP_MAIN_CONF_OFFSET,
      0,
      NULL },

    { ngx_string("geoip_org"),
      NGX_HTTP_MAIN_CONF|NGX_CONF_TAKE12,
      ngx_http_geoip_org,
      NGX_HTTP_MAIN_CONF_OFFSET,
      0,
      NULL },

    { ngx_string("geoip_city"),
      NGX_HTTP_MAIN_CONF|NGX_CONF_TAKE12,
      ngx_http_geoip_city,
      NGX_HTTP_MAIN_CONF_OFFSET,
      0,
      NULL },

    { ngx_string("geoip_proxy"),
      NGX_HTTP_MAIN_CONF|NGX_CONF_TAKE1,
      ngx_http_geoip_proxy,
      NGX_HTTP_MAIN_CONF_OFFSET,
      0,
      NULL },

    { ngx_string("geoip_proxy_recursive"),
      NGX_HTTP_MAIN_CONF|NGX_CONF_FLAG,
      ngx_conf_set_flag_slot,
      NGX_HTTP_MAIN_CONF_OFFSET,
      offsetof(ngx_http_geoip_conf_t, proxy_recursive),
      NULL },

      ngx_null_command
};


static ngx_http_module_t  ngx_http_geoip_module_ctx = {
    ngx_http_geoip_add_variables,          /* preconfiguration */
    NULL,                                  /* postconfiguration */

    ngx_http_geoip_create_conf,            /* create main configuration */
    ngx_http_geoip_init_conf,              /* init main configuration */

    NULL,                                  /* create server configuration */
    NULL,                                  /* merge server configuration */

    NULL,                                  /* create location configuration */
    NULL                                   /* merge location configuration */
};


ngx_module_t  ngx_http_geoip_module = {
    NGX_MODULE_V1,
    &ngx_http_geoip_module_ctx,            /* module context */
    ngx_http_geoip_commands,               /* module directives */
    NGX_HTTP_MODULE,                       /* module type */
    NULL,                                  /* init master */
    NULL,                                  /* init module */
    NULL,                                  /* init process */
    NULL,                                  /* init thread */
    NULL,                                  /* exit thread */
    NULL,                                  /* exit process */
    NULL,                                  /* exit master */
    NGX_MODULE_V1_PADDING
};


static ngx_http_variable_t  ngx_http_geoip_vars[] = {

    { ngx_string("geoip_country_code"), NULL,
      ngx_http_geoip_country_variable,
      NGX_GEOIP_COUNTRY_CODE, 0, 0 },

    { ngx_string("geoip_country_code3"), NULL,
      ngx_http_geoip_country_variable,
      NGX_GEOIP_COUNTRY_CODE3, 0, 0 },

    { ngx_string("geoip_country_name"), NULL,
      ngx_http_geoip_country_variable,
      NGX_GEOIP_COUNTRY_NAME, 0, 0 },

    { ngx_string("geoip_org"), NULL,
      ngx_http_geoip_org_variable,
      0, 0, 0 },

    { ngx_string("geoip_city_continent_code"), NULL,
      ngx_http_geoip_city_variable,
      NGX_GEOIP_CITY_CONTINENT_CODE, 0, 0 },

    { ngx_string("geoip_city_country_code"), NULL,
      ngx_http_geoip_city_variable,
      NGX_GEOIP_CITY_COUNTRY_CODE, 0, 0 },

    { ngx_string("geoip_city_country_code3"), NULL,
      ngx_http_geoip_city_variable,
      NGX_GEOIP_CITY_COUNTRY_CODE3, 0, 0 },

    { ngx_string("geoip_city_country_name"), NULL,
      ngx_http_geoip_city_variable,
      NGX_GEOIP_CITY_COUNTRY_NAME, 0, 0 },

    { ngx_string("geoip_region"), NULL,
      ngx_http_geoip_city_variable,
      NGX_GEOIP_CITY_REGION, 0, 0 },

    { ngx_string("geoip_region_name"), NULL,
      ngx_http_geoip_region_name_variable,
      NGX_GEOIP_CITY_REGION_NAME, 0, 0 },

    { ngx_string("geoip_city"), NULL,
      ngx_http_geoip_city_variable,
      NGX_GEOIP_CITY_NAME, 0, 0 },

    { ngx_string("geoip_postal_code"), NULL,
      ngx_http_geoip_city_variable,
      NGX_GEOIP_CITY_POSTAL_CODE, 0, 0 },

    { ngx_string("geoip_latitude"), NULL,
      ngx_http_geoip_city_float_variable,
      NGX_GEOIP_CITY_LATITUDE, 0, 0 },

    { ngx_string("geoip_longitude"), NULL,
      ngx_http_geoip_city_float_variable,
      NGX_GEOIP_CITY_LONGITUDE, 0, 0 },

    { ngx_string("geoip_dma_code"), NULL,
      ngx_http_geoip_city_int_variable,
      NGX_GEOIP_CITY_DMA_CODE, 0, 0 },

    { ngx_string("geoip_area_code"), NULL,
      ngx_http_geoip_city_int_variable,
      NGX_GEOIP_CITY_AREA_CODE, 0, 0 },

      ngx_http_null_variable
};


static struct sockaddr *
ngx_http_geoip_sockaddr(ngx_http_request_t *r, ngx_http_geoip_conf_t *gcf)
{
    ngx_addr_t        addr;
    ngx_table_elt_t  *xfwd;

    addr.sockaddr = r->connection->sockaddr;
    addr.socklen = r->connection->socklen;
    /* addr.name = r->connection->addr_text; */

    xfwd = r->headers_in.x_forwarded_for;

    if (xfwd != NULL && gcf->proxies != NULL) {
        (void) ngx_http_get_forwarded_addr(r, &addr, xfwd, NULL,
                                           gcf->proxies, gcf->proxy_recursive);
    }

    return addr.sockaddr;
}


#if (NGX_HAVE_LIBGEOIP)

static u_long
ngx_http_geoip_addr(ngx_http_request_t *r, ngx_http_geoip_conf_t *gcf)
{
    struct sockaddr     *sa;
    struct sockaddr_in  *sin;

    sa = ngx_http_geoip_sockaddr(r, gcf);

#if (NGX_HAVE_INET6)

    if (sa->sa_family == AF_INET6) {
        u_char           *p;
        in_addr_t         inaddr;
        struct in6_addr  *inaddr6;

        inaddr6 = &((struct sockaddr_in6 *) sa)->sin6_addr;

        if (IN6_IS_ADDR_V4MAPPED(inaddr6)) {
            p = inaddr6->s6_addr;

            inaddr = (in_addr_t) p[12] << 24;
            inaddr += p[13] << 16;
            inaddr += p[14] << 8;
            inaddr += p[15];

            return inaddr;
        }
    }

#endif

    if (sa->sa_family != AF_INET) {
        return INADDR_NONE;
    }

    sin = (struct sockaddr_in *) sa;
    return ntohl(sin->sin_addr.s_addr);
}


#if (NGX_HAVE_GEOIP_V6)

static geoipv6_t
ngx_http_geoip_addr_v6(ngx_http_request_t *r, ngx_http_geoip_conf_t *gcf)
{
    in_addr_t             addr4;
    struct in6_addr       addr6;
    struct sockaddr      *sa;
    struct sockaddr_in   *sin;
    struct sockaddr_in6  *sin6;

    sa = ngx_http_geoip_sockaddr(r, gcf);

    switch (sa->sa_family) {

    case AF_INET:
        /* Produce IPv4-mapped IPv6 address. */
        sin = (struct sockaddr_in *) sa;
        addr4 = ntohl(sin->sin_addr.s_addr);

        ngx_memzero(&addr6, sizeof(struct in6_addr));
        addr6.s6_addr[10] = 0xff;
        addr6.s6_addr[11] = 0xff;
        addr6.s6_addr[12] = addr4 >> 24;
        addr6.s6_addr[13] = addr4 >> 16;
        addr6.s6_addr[14] = addr4 >> 8;
        addr6.s6_addr[15] = addr4;
        return addr6;

    case AF_INET6:
        sin6 = (struct sockaddr_in6 *) sa;
        return sin6->sin6_addr;

    default:
        return in6addr_any;
    }
}

#endif

#endif


static ngx_int_t
ngx_http_geoip_country_variable(ngx_http_request_t *r,
    ngx_http_variable_value_t *v, uintptr_t data)
{
#if (NGX_HAVE_LIBGEOIP)
    ngx_http_geoip_variable_handler_pt     handler =
        ngx_http_geoip_country_functions[data];
#if (NGX_HAVE_GEOIP_V6)
    ngx_http_geoip_variable_handler_v6_pt  handler_v6 =
        ngx_http_geoip_country_v6_functions[data];
#endif

    const char             *val;
#endif

    ngx_http_geoip_conf_t  *gcf;

    gcf = ngx_http_get_module_main_conf(r, ngx_http_geoip_module);

#if (NGX_HAVE_MAXMINDDB)

    if (gcf->country_mmdb) {

        if (data == NGX_GEOIP_COUNTRY_CODE3) {
            return ngx_http_geoip_mmdb_code3(r, gcf->country_mmdb, v);
        }

        return ngx_http_geoip_mmdb_str(r, gcf->country_mmdb,
                                      ngx_http_geoip_mmdb_country_paths[data],
                                      v);
    }

#endif

#if (NGX_HAVE_LIBGEOIP)

    if (gcf->country == NULL) {
        goto not_found;
    }

#if (NGX_HAVE_GEOIP_V6)
    val = gcf->country_v6
              ? handler_v6(gcf->country, ngx_http_geoip_addr_v6(r, gcf))
              : handler(gcf->country, ngx_http_geoip_addr(r, gcf));
#else
    val = handler(gcf->country, ngx_http_geoip_addr(r, gcf));
#endif

    if (val == NULL) {
        goto not_found;
    }

    v->len = ngx_strlen(val);
    v->valid = 1;
    v->no_cacheable = 0;
    v->not_found = 0;
    v->data = (u_char *) val;

    return NGX_OK;

not_found:

#endif

    v->not_found = 1;

    return NGX_OK;
}


static ngx_int_t
ngx_http_geoip_org_variable(ngx_http_request_t *r,
    ngx_http_variable_value_t *v, uintptr_t data)
{
#if (NGX_HAVE_LIBGEOIP)
    size_t                  len;
    char                   *val;
#endif
#if (NGX_HAVE_MAXMINDDB)
    ngx_int_t               rc;
    const char           ***path;
#endif
    ngx_http_geoip_conf_t  *gcf;

    gcf = ngx_http_get_module_main_conf(r, ngx_http_geoip_module);

#if (NGX_HAVE_MAXMINDDB)

    if (gcf->org_mmdb) {

        for (path = ngx_http_geoip_mmdb_org_paths; *path; path++) {

            rc = ngx_http_geoip_mmdb_str(r, gcf->org_mmdb, *path, v);

            if (rc != NGX_OK || !v->not_found) {
                return rc;
            }
        }

        v->not_found = 1;

        return NGX_OK;
    }

#endif

#if (NGX_HAVE_LIBGEOIP)

    if (gcf->org == NULL) {
        goto not_found;
    }

#if (NGX_HAVE_GEOIP_V6)
    val = gcf->org_v6
              ? GeoIP_name_by_ipnum_v6(gcf->org,
                                       ngx_http_geoip_addr_v6(r, gcf))
              : GeoIP_name_by_ipnum(gcf->org,
                                    ngx_http_geoip_addr(r, gcf));
#else
    val = GeoIP_name_by_ipnum(gcf->org, ngx_http_geoip_addr(r, gcf));
#endif

    if (val == NULL) {
        goto not_found;
    }

    len = ngx_strlen(val);
    v->data = ngx_pnalloc(r->pool, len);
    if (v->data == NULL) {
        ngx_free(val);
        return NGX_ERROR;
    }

    ngx_memcpy(v->data, val, len);

    v->len = len;
    v->valid = 1;
    v->no_cacheable = 0;
    v->not_found = 0;

    ngx_free(val);

    return NGX_OK;

not_found:

#endif

    v->not_found = 1;

    return NGX_OK;
}


static ngx_int_t
ngx_http_geoip_city_variable(ngx_http_request_t *r,
    ngx_http_variable_value_t *v, uintptr_t data)
{
#if (NGX_HAVE_LIBGEOIP)
    char                   *val;
    size_t                  len;
    GeoIPRecord            *gr;
#endif
#if (NGX_HAVE_MAXMINDDB)
    ngx_http_geoip_conf_t  *gcf;

    gcf = ngx_http_get_module_main_conf(r, ngx_http_geoip_module);

    if (gcf->city_mmdb) {

        if (data == NGX_GEOIP_CITY_COUNTRY_CODE3) {
            return ngx_http_geoip_mmdb_code3(r, gcf->city_mmdb, v);
        }

        return ngx_http_geoip_mmdb_str(r, gcf->city_mmdb,
                                       ngx_http_geoip_mmdb_city_paths[data], v);
    }

#endif

#if (NGX_HAVE_LIBGEOIP)

    gr = ngx_http_geoip_get_city_record(r);
    if (gr == NULL) {
        goto not_found;
    }

    val = *(char **) ((char *) gr + ngx_http_geoip_city_offsets[data]);
    if (val == NULL) {
        goto no_value;
    }

    len = ngx_strlen(val);
    v->data = ngx_pnalloc(r->pool, len);
    if (v->data == NULL) {
        GeoIPRecord_delete(gr);
        return NGX_ERROR;
    }

    ngx_memcpy(v->data, val, len);

    v->len = len;
    v->valid = 1;
    v->no_cacheable = 0;
    v->not_found = 0;

    GeoIPRecord_delete(gr);

    return NGX_OK;

no_value:

    GeoIPRecord_delete(gr);

not_found:

#endif

    v->not_found = 1;

    return NGX_OK;
}


static ngx_int_t
ngx_http_geoip_region_name_variable(ngx_http_request_t *r,
    ngx_http_variable_value_t *v, uintptr_t data)
{
#if (NGX_HAVE_LIBGEOIP)
    size_t                  len;
    const char             *val;
    GeoIPRecord            *gr;
#endif
#if (NGX_HAVE_MAXMINDDB)
    ngx_http_geoip_conf_t  *gcf;

    gcf = ngx_http_get_module_main_conf(r, ngx_http_geoip_module);

    if (gcf->city_mmdb) {
        return ngx_http_geoip_mmdb_str(r, gcf->city_mmdb,
                                       ngx_http_geoip_mmdb_city_paths[data], v);
    }

#endif

#if (NGX_HAVE_LIBGEOIP)

    gr = ngx_http_geoip_get_city_record(r);
    if (gr == NULL) {
        goto not_found;
    }

    val = GeoIP_region_name_by_code(gr->country_code, gr->region);

    GeoIPRecord_delete(gr);

    if (val == NULL) {
        goto not_found;
    }

    len = ngx_strlen(val);
    v->data = ngx_pnalloc(r->pool, len);
    if (v->data == NULL) {
        return NGX_ERROR;
    }

    ngx_memcpy(v->data, val, len);

    v->len = len;
    v->valid = 1;
    v->no_cacheable = 0;
    v->not_found = 0;

    return NGX_OK;

not_found:

#endif

    v->not_found = 1;

    return NGX_OK;
}


static ngx_int_t
ngx_http_geoip_city_float_variable(ngx_http_request_t *r,
    ngx_http_variable_value_t *v, uintptr_t data)
{
#if (NGX_HAVE_LIBGEOIP)
    float                   val;
    GeoIPRecord            *gr;
#endif
#if (NGX_HAVE_MAXMINDDB)
    ngx_http_geoip_conf_t  *gcf;

    gcf = ngx_http_get_module_main_conf(r, ngx_http_geoip_module);

    if (gcf->city_mmdb) {
        return ngx_http_geoip_mmdb_float(r, gcf->city_mmdb,
                                       ngx_http_geoip_mmdb_city_paths[data], v);
    }

#endif

#if (NGX_HAVE_LIBGEOIP)

    gr = ngx_http_geoip_get_city_record(r);
    if (gr == NULL) {
        v->not_found = 1;
        return NGX_OK;
    }

    v->data = ngx_pnalloc(r->pool, NGX_INT64_LEN + 5);
    if (v->data == NULL) {
        GeoIPRecord_delete(gr);
        return NGX_ERROR;
    }

    val = *(float *) ((char *) gr + ngx_http_geoip_city_offsets[data]);

    v->len = ngx_sprintf(v->data, "%.4f", val) - v->data;
    v->valid = 1;
    v->no_cacheable = 0;
    v->not_found = 0;

    GeoIPRecord_delete(gr);

    return NGX_OK;

#else

    v->not_found = 1;

    return NGX_OK;

#endif
}


static ngx_int_t
ngx_http_geoip_city_int_variable(ngx_http_request_t *r,
    ngx_http_variable_value_t *v, uintptr_t data)
{
#if (NGX_HAVE_LIBGEOIP)
    int                     val;
    GeoIPRecord            *gr;
#endif
#if (NGX_HAVE_MAXMINDDB)
    ngx_http_geoip_conf_t  *gcf;

    gcf = ngx_http_get_module_main_conf(r, ngx_http_geoip_module);

    if (gcf->city_mmdb) {
        return ngx_http_geoip_mmdb_int(r, gcf->city_mmdb,
                                       ngx_http_geoip_mmdb_city_paths[data], v);
    }

#endif

#if (NGX_HAVE_LIBGEOIP)

    gr = ngx_http_geoip_get_city_record(r);
    if (gr == NULL) {
        v->not_found = 1;
        return NGX_OK;
    }

    v->data = ngx_pnalloc(r->pool, NGX_INT64_LEN);
    if (v->data == NULL) {
        GeoIPRecord_delete(gr);
        return NGX_ERROR;
    }

    val = *(int *) ((char *) gr + ngx_http_geoip_city_offsets[data]);

    v->len = ngx_sprintf(v->data, "%d", val) - v->data;
    v->valid = 1;
    v->no_cacheable = 0;
    v->not_found = 0;

    GeoIPRecord_delete(gr);

    return NGX_OK;

#else

    v->not_found = 1;

    return NGX_OK;

#endif
}


#if (NGX_HAVE_LIBGEOIP)

static GeoIPRecord *
ngx_http_geoip_get_city_record(ngx_http_request_t *r)
{
    ngx_http_geoip_conf_t  *gcf;

    gcf = ngx_http_get_module_main_conf(r, ngx_http_geoip_module);

    if (gcf->city) {
#if (NGX_HAVE_GEOIP_V6)
        return gcf->city_v6
                   ? GeoIP_record_by_ipnum_v6(gcf->city,
                                              ngx_http_geoip_addr_v6(r, gcf))
                   : GeoIP_record_by_ipnum(gcf->city,
                                           ngx_http_geoip_addr(r, gcf));
#else
        return GeoIP_record_by_ipnum(gcf->city, ngx_http_geoip_addr(r, gcf));
#endif
    }

    return NULL;
}

#endif


#if (NGX_HAVE_MAXMINDDB)

/*
 * the MaxMind DB databases provide ISO 3166-1 alpha-2 country codes only,
 * while the legacy GeoIP library used to provide alpha-3 codes as well
 */

static ngx_http_geoip_ccode_t  ngx_http_geoip_country_codes[] = {
    { "AD", "AND" }, { "AE", "ARE" }, { "AF", "AFG" }, { "AG", "ATG" },
    { "AI", "AIA" }, { "AL", "ALB" }, { "AM", "ARM" }, { "AO", "AGO" },
    { "AQ", "ATA" }, { "AR", "ARG" }, { "AS", "ASM" }, { "AT", "AUT" },
    { "AU", "AUS" }, { "AW", "ABW" }, { "AX", "ALA" }, { "AZ", "AZE" },
    { "BA", "BIH" }, { "BB", "BRB" }, { "BD", "BGD" }, { "BE", "BEL" },
    { "BF", "BFA" }, { "BG", "BGR" }, { "BH", "BHR" }, { "BI", "BDI" },
    { "BJ", "BEN" }, { "BL", "BLM" }, { "BM", "BMU" }, { "BN", "BRN" },
    { "BO", "BOL" }, { "BQ", "BES" }, { "BR", "BRA" }, { "BS", "BHS" },
    { "BT", "BTN" }, { "BV", "BVT" }, { "BW", "BWA" }, { "BY", "BLR" },
    { "BZ", "BLZ" }, { "CA", "CAN" }, { "CC", "CCK" }, { "CD", "COD" },
    { "CF", "CAF" }, { "CG", "COG" }, { "CH", "CHE" }, { "CI", "CIV" },
    { "CK", "COK" }, { "CL", "CHL" }, { "CM", "CMR" }, { "CN", "CHN" },
    { "CO", "COL" }, { "CR", "CRI" }, { "CU", "CUB" }, { "CV", "CPV" },
    { "CW", "CUW" }, { "CX", "CXR" }, { "CY", "CYP" }, { "CZ", "CZE" },
    { "DE", "DEU" }, { "DJ", "DJI" }, { "DK", "DNK" }, { "DM", "DMA" },
    { "DO", "DOM" }, { "DZ", "DZA" }, { "EC", "ECU" }, { "EE", "EST" },
    { "EG", "EGY" }, { "EH", "ESH" }, { "ER", "ERI" }, { "ES", "ESP" },
    { "ET", "ETH" }, { "FI", "FIN" }, { "FJ", "FJI" }, { "FK", "FLK" },
    { "FM", "FSM" }, { "FO", "FRO" }, { "FR", "FRA" }, { "GA", "GAB" },
    { "GB", "GBR" }, { "GD", "GRD" }, { "GE", "GEO" }, { "GF", "GUF" },
    { "GG", "GGY" }, { "GH", "GHA" }, { "GI", "GIB" }, { "GL", "GRL" },
    { "GM", "GMB" }, { "GN", "GIN" }, { "GP", "GLP" }, { "GQ", "GNQ" },
    { "GR", "GRC" }, { "GS", "SGS" }, { "GT", "GTM" }, { "GU", "GUM" },
    { "GW", "GNB" }, { "GY", "GUY" }, { "HK", "HKG" }, { "HM", "HMD" },
    { "HN", "HND" }, { "HR", "HRV" }, { "HT", "HTI" }, { "HU", "HUN" },
    { "ID", "IDN" }, { "IE", "IRL" }, { "IL", "ISR" }, { "IM", "IMN" },
    { "IN", "IND" }, { "IO", "IOT" }, { "IQ", "IRQ" }, { "IR", "IRN" },
    { "IS", "ISL" }, { "IT", "ITA" }, { "JE", "JEY" }, { "JM", "JAM" },
    { "JO", "JOR" }, { "JP", "JPN" }, { "KE", "KEN" }, { "KG", "KGZ" },
    { "KH", "KHM" }, { "KI", "KIR" }, { "KM", "COM" }, { "KN", "KNA" },
    { "KP", "PRK" }, { "KR", "KOR" }, { "KW", "KWT" }, { "KY", "CYM" },
    { "KZ", "KAZ" }, { "LA", "LAO" }, { "LB", "LBN" }, { "LC", "LCA" },
    { "LI", "LIE" }, { "LK", "LKA" }, { "LR", "LBR" }, { "LS", "LSO" },
    { "LT", "LTU" }, { "LU", "LUX" }, { "LV", "LVA" }, { "LY", "LBY" },
    { "MA", "MAR" }, { "MC", "MCO" }, { "MD", "MDA" }, { "ME", "MNE" },
    { "MF", "MAF" }, { "MG", "MDG" }, { "MH", "MHL" }, { "MK", "MKD" },
    { "ML", "MLI" }, { "MM", "MMR" }, { "MN", "MNG" }, { "MO", "MAC" },
    { "MP", "MNP" }, { "MQ", "MTQ" }, { "MR", "MRT" }, { "MS", "MSR" },
    { "MT", "MLT" }, { "MU", "MUS" }, { "MV", "MDV" }, { "MW", "MWI" },
    { "MX", "MEX" }, { "MY", "MYS" }, { "MZ", "MOZ" }, { "NA", "NAM" },
    { "NC", "NCL" }, { "NE", "NER" }, { "NF", "NFK" }, { "NG", "NGA" },
    { "NI", "NIC" }, { "NL", "NLD" }, { "NO", "NOR" }, { "NP", "NPL" },
    { "NR", "NRU" }, { "NU", "NIU" }, { "NZ", "NZL" }, { "OM", "OMN" },
    { "PA", "PAN" }, { "PE", "PER" }, { "PF", "PYF" }, { "PG", "PNG" },
    { "PH", "PHL" }, { "PK", "PAK" }, { "PL", "POL" }, { "PM", "SPM" },
    { "PN", "PCN" }, { "PR", "PRI" }, { "PS", "PSE" }, { "PT", "PRT" },
    { "PW", "PLW" }, { "PY", "PRY" }, { "QA", "QAT" }, { "RE", "REU" },
    { "RO", "ROU" }, { "RS", "SRB" }, { "RU", "RUS" }, { "RW", "RWA" },
    { "SA", "SAU" }, { "SB", "SLB" }, { "SC", "SYC" }, { "SD", "SDN" },
    { "SE", "SWE" }, { "SG", "SGP" }, { "SH", "SHN" }, { "SI", "SVN" },
    { "SJ", "SJM" }, { "SK", "SVK" }, { "SL", "SLE" }, { "SM", "SMR" },
    { "SN", "SEN" }, { "SO", "SOM" }, { "SR", "SUR" }, { "SS", "SSD" },
    { "ST", "STP" }, { "SV", "SLV" }, { "SX", "SXM" }, { "SY", "SYR" },
    { "SZ", "SWZ" }, { "TC", "TCA" }, { "TD", "TCD" }, { "TF", "ATF" },
    { "TG", "TGO" }, { "TH", "THA" }, { "TJ", "TJK" }, { "TK", "TKL" },
    { "TL", "TLS" }, { "TM", "TKM" }, { "TN", "TUN" }, { "TO", "TON" },
    { "TR", "TUR" }, { "TT", "TTO" }, { "TV", "TUV" }, { "TW", "TWN" },
    { "TZ", "TZA" }, { "UA", "UKR" }, { "UG", "UGA" }, { "UM", "UMI" },
    { "US", "USA" }, { "UY", "URY" }, { "UZ", "UZB" }, { "VA", "VAT" },
    { "VC", "VCT" }, { "VE", "VEN" }, { "VG", "VGB" }, { "VI", "VIR" },
    { "VN", "VNM" }, { "VU", "VUT" }, { "WF", "WLF" }, { "WS", "WSM" },
    { "YE", "YEM" }, { "YT", "MYT" }, { "ZA", "ZAF" }, { "ZM", "ZMB" },
    { "ZW", "ZWE" },
    { NULL, NULL }
};


static const char *
ngx_http_geoip_code3(const char *code2)
{
    ngx_http_geoip_ccode_t  *cc;

    for (cc = ngx_http_geoip_country_codes; cc->alpha2; cc++) {
        if (code2[0] == cc->alpha2[0] && code2[1] == cc->alpha2[1]) {
            return cc->alpha3;
        }
    }

    return NULL;
}


static ngx_int_t
ngx_http_geoip_mmdb_lookup(ngx_http_request_t *r, MMDB_s *mmdb,
    const char **path, MMDB_entry_data_s *entry_data)
{
    int                     err;
    struct sockaddr        *sa;
    MMDB_lookup_result_s    result;
    ngx_http_geoip_conf_t  *gcf;

    if (path == NULL) {
        return NGX_DECLINED;
    }

    gcf = ngx_http_get_module_main_conf(r, ngx_http_geoip_module);

    sa = ngx_http_geoip_sockaddr(r, gcf);

    switch (sa->sa_family) {

    case AF_INET:
#if (NGX_HAVE_INET6)
    case AF_INET6:
#endif
        break;

    default:
        return NGX_DECLINED;
    }

    result = MMDB_lookup_sockaddr(mmdb, sa, &err);

    if (err != MMDB_SUCCESS) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                      "MMDB_lookup_sockaddr() failed: %s", MMDB_strerror(err));
        return NGX_DECLINED;
    }

    if (!result.found_entry) {
        return NGX_DECLINED;
    }

    if (MMDB_aget_value(&result.entry, entry_data, path) != MMDB_SUCCESS
        || !entry_data->has_data)
    {
        return NGX_DECLINED;
    }

    return NGX_OK;
}


static ngx_int_t
ngx_http_geoip_mmdb_str(ngx_http_request_t *r, MMDB_s *mmdb,
    const char **path, ngx_http_variable_value_t *v)
{
    u_char             *p;
    MMDB_entry_data_s   entry_data;

    if (ngx_http_geoip_mmdb_lookup(r, mmdb, path, &entry_data) != NGX_OK
        || entry_data.type != MMDB_DATA_TYPE_UTF8_STRING)
    {
        v->not_found = 1;
        return NGX_OK;
    }

    p = ngx_pnalloc(r->pool, entry_data.data_size);
    if (p == NULL) {
        return NGX_ERROR;
    }

    ngx_memcpy(p, entry_data.utf8_string, entry_data.data_size);

    v->len = entry_data.data_size;
    v->valid = 1;
    v->no_cacheable = 0;
    v->not_found = 0;
    v->data = p;

    return NGX_OK;
}


static ngx_int_t
ngx_http_geoip_mmdb_code3(ngx_http_request_t *r, MMDB_s *mmdb,
    ngx_http_variable_value_t *v)
{
    const char         *code3;
    MMDB_entry_data_s   entry_data;

    if (ngx_http_geoip_mmdb_lookup(r, mmdb, ngx_http_geoip_mmdb_country_code,
                                   &entry_data)
        != NGX_OK
        || entry_data.type != MMDB_DATA_TYPE_UTF8_STRING
        || entry_data.data_size != 2)
    {
        v->not_found = 1;
        return NGX_OK;
    }

    code3 = ngx_http_geoip_code3(entry_data.utf8_string);

    if (code3 == NULL) {
        v->not_found = 1;
        return NGX_OK;
    }

    v->len = 3;
    v->valid = 1;
    v->no_cacheable = 0;
    v->not_found = 0;
    v->data = (u_char *) code3;

    return NGX_OK;
}


static ngx_int_t
ngx_http_geoip_mmdb_float(ngx_http_request_t *r, MMDB_s *mmdb,
    const char **path, ngx_http_variable_value_t *v)
{
    double              val;
    MMDB_entry_data_s   entry_data;

    if (ngx_http_geoip_mmdb_lookup(r, mmdb, path, &entry_data) != NGX_OK) {
        v->not_found = 1;
        return NGX_OK;
    }

    switch (entry_data.type) {

    case MMDB_DATA_TYPE_DOUBLE:
        val = entry_data.double_value;
        break;

    case MMDB_DATA_TYPE_FLOAT:
        val = entry_data.float_value;
        break;

    default:
        v->not_found = 1;
        return NGX_OK;
    }

    v->data = ngx_pnalloc(r->pool, NGX_INT64_LEN + 5);
    if (v->data == NULL) {
        return NGX_ERROR;
    }

    v->len = ngx_sprintf(v->data, "%.4f", val) - v->data;
    v->valid = 1;
    v->no_cacheable = 0;
    v->not_found = 0;

    return NGX_OK;
}


static ngx_int_t
ngx_http_geoip_mmdb_int(ngx_http_request_t *r, MMDB_s *mmdb,
    const char **path, ngx_http_variable_value_t *v)
{
    int64_t             val;
    MMDB_entry_data_s   entry_data;

    if (ngx_http_geoip_mmdb_lookup(r, mmdb, path, &entry_data) != NGX_OK) {
        v->not_found = 1;
        return NGX_OK;
    }

    switch (entry_data.type) {

    case MMDB_DATA_TYPE_UINT16:
        val = entry_data.uint16;
        break;

    case MMDB_DATA_TYPE_UINT32:
        val = entry_data.uint32;
        break;

    case MMDB_DATA_TYPE_INT32:
        val = entry_data.int32;
        break;

    default:
        v->not_found = 1;
        return NGX_OK;
    }

    v->data = ngx_pnalloc(r->pool, NGX_INT64_LEN);
    if (v->data == NULL) {
        return NGX_ERROR;
    }

    v->len = ngx_sprintf(v->data, "%L", val) - v->data;
    v->valid = 1;
    v->no_cacheable = 0;
    v->not_found = 0;

    return NGX_OK;
}


static ngx_int_t
ngx_http_geoip_mmdb_open(ngx_conf_t *cf, ngx_str_t *name, MMDB_s **db)
{
    int              status;
    MMDB_s          *mmdb;
    ngx_file_info_t  fi;

    if (ngx_file_info(name->data, &fi) == NGX_FILE_ERROR) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, ngx_errno,
                           ngx_file_info_n " \"%V\" failed", name);
        return NGX_ERROR;
    }

    mmdb = ngx_palloc(cf->pool, sizeof(MMDB_s));
    if (mmdb == NULL) {
        return NGX_ERROR;
    }

    status = MMDB_open((char *) name->data, MMDB_MODE_MMAP, mmdb);

    if (status == MMDB_SUCCESS) {
        *db = mmdb;
        return NGX_OK;
    }

#if (NGX_HAVE_LIBGEOIP)

    /* presumably a legacy GeoIP database, let the GeoIP library try it */

    if (status == MMDB_INVALID_METADATA_ERROR) {
        return NGX_DECLINED;
    }

#endif

    ngx_conf_log_error(NGX_LOG_EMERG, cf, 0, "MMDB_open(\"%V\") failed: %s",
                       name, MMDB_strerror(status));

    return NGX_ERROR;
}


static char *
ngx_http_geoip_mmdb_charset(ngx_conf_t *cf)
{
    ngx_str_t  *value;

    value = cf->args->elts;

    /* the MaxMind DB databases are always in UTF-8 */

    if (cf->args->nelts == 3 && ngx_strcmp(value[2].data, "utf8") != 0) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                           "invalid parameter \"%V\"", &value[2]);
        return NGX_CONF_ERROR;
    }

    return NGX_CONF_OK;
}

#endif


static ngx_int_t
ngx_http_geoip_add_variables(ngx_conf_t *cf)
{
    ngx_http_variable_t  *var, *v;

    for (v = ngx_http_geoip_vars; v->name.len; v++) {
        var = ngx_http_add_variable(cf, &v->name, v->flags);
        if (var == NULL) {
            return NGX_ERROR;
        }

        var->get_handler = v->get_handler;
        var->data = v->data;
    }

    return NGX_OK;
}


static void *
ngx_http_geoip_create_conf(ngx_conf_t *cf)
{
    ngx_pool_cleanup_t     *cln;
    ngx_http_geoip_conf_t  *conf;

    conf = ngx_pcalloc(cf->pool, sizeof(ngx_http_geoip_conf_t));
    if (conf == NULL) {
        return NULL;
    }

    conf->proxy_recursive = NGX_CONF_UNSET;

    cln = ngx_pool_cleanup_add(cf->pool, 0);
    if (cln == NULL) {
        return NULL;
    }

    cln->handler = ngx_http_geoip_cleanup;
    cln->data = conf;

    return conf;
}


static char *
ngx_http_geoip_init_conf(ngx_conf_t *cf, void *conf)
{
    ngx_http_geoip_conf_t  *gcf = conf;

    ngx_conf_init_value(gcf->proxy_recursive, 0);

#if (NGX_HAVE_LIBGEOIP)

    if (gcf->country || gcf->org || gcf->city) {
        ngx_conf_log_error(NGX_LOG_WARN, cf, 0,
                           "the legacy GeoIP databases reached End-of-Life "
                           "in May 2022 and are no longer updated, consider "
                           "migrating to the MaxMind DB (MMDB) databases");
    }

#endif

    return NGX_CONF_OK;
}


static char *
ngx_http_geoip_country(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    ngx_http_geoip_conf_t  *gcf = conf;

    ngx_str_t  *value;

#if (NGX_HAVE_LIBGEOIP)
    if (gcf->country) {
        return "is duplicate";
    }
#endif
#if (NGX_HAVE_MAXMINDDB)
    if (gcf->country_mmdb) {
        return "is duplicate";
    }
#endif

    value = cf->args->elts;

#if (NGX_HAVE_MAXMINDDB)

    switch (ngx_http_geoip_mmdb_open(cf, &value[1], &gcf->country_mmdb)) {

    case NGX_OK:
        return ngx_http_geoip_mmdb_charset(cf);

    case NGX_ERROR:
        return NGX_CONF_ERROR;

    default:                    /* NGX_DECLINED, not a MaxMind DB database */
        break;
    }

#endif

#if (NGX_HAVE_LIBGEOIP)

    gcf->country = GeoIP_open((char *) value[1].data, GEOIP_MEMORY_CACHE);

    if (gcf->country == NULL) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                           "GeoIP_open(\"%V\") failed", &value[1]);

        return NGX_CONF_ERROR;
    }

    if (cf->args->nelts == 3) {
        if (ngx_strcmp(value[2].data, "utf8") == 0) {
            GeoIP_set_charset(gcf->country, GEOIP_CHARSET_UTF8);

        } else {
            ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                               "invalid parameter \"%V\"", &value[2]);
            return NGX_CONF_ERROR;
        }
    }

    switch (gcf->country->databaseType) {

    case GEOIP_COUNTRY_EDITION:

        return NGX_CONF_OK;

#if (NGX_HAVE_GEOIP_V6)
    case GEOIP_COUNTRY_EDITION_V6:

        gcf->country_v6 = 1;
        return NGX_CONF_OK;
#endif

    default:
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                           "invalid GeoIP database \"%V\" type:%d",
                           &value[1], gcf->country->databaseType);
        return NGX_CONF_ERROR;
    }

#else

    ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                       "\"%V\" is not a MaxMind DB database", &value[1]);

    return NGX_CONF_ERROR;

#endif
}


static char *
ngx_http_geoip_org(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    ngx_http_geoip_conf_t  *gcf = conf;

    ngx_str_t  *value;

#if (NGX_HAVE_LIBGEOIP)
    if (gcf->org) {
        return "is duplicate";
    }
#endif
#if (NGX_HAVE_MAXMINDDB)
    if (gcf->org_mmdb) {
        return "is duplicate";
    }
#endif

    value = cf->args->elts;

#if (NGX_HAVE_MAXMINDDB)

    switch (ngx_http_geoip_mmdb_open(cf, &value[1], &gcf->org_mmdb)) {

    case NGX_OK:
        return ngx_http_geoip_mmdb_charset(cf);

    case NGX_ERROR:
        return NGX_CONF_ERROR;

    default:                    /* NGX_DECLINED, not a MaxMind DB database */
        break;
    }

#endif

#if (NGX_HAVE_LIBGEOIP)

    gcf->org = GeoIP_open((char *) value[1].data, GEOIP_MEMORY_CACHE);

    if (gcf->org == NULL) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                           "GeoIP_open(\"%V\") failed", &value[1]);

        return NGX_CONF_ERROR;
    }

    if (cf->args->nelts == 3) {
        if (ngx_strcmp(value[2].data, "utf8") == 0) {
            GeoIP_set_charset(gcf->org, GEOIP_CHARSET_UTF8);

        } else {
            ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                               "invalid parameter \"%V\"", &value[2]);
            return NGX_CONF_ERROR;
        }
    }

    switch (gcf->org->databaseType) {

    case GEOIP_ISP_EDITION:
    case GEOIP_ORG_EDITION:
    case GEOIP_DOMAIN_EDITION:
    case GEOIP_ASNUM_EDITION:

        return NGX_CONF_OK;

#if (NGX_HAVE_GEOIP_V6)
    case GEOIP_ISP_EDITION_V6:
    case GEOIP_ORG_EDITION_V6:
    case GEOIP_DOMAIN_EDITION_V6:
    case GEOIP_ASNUM_EDITION_V6:

        gcf->org_v6 = 1;
        return NGX_CONF_OK;
#endif

    default:
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                           "invalid GeoIP database \"%V\" type:%d",
                           &value[1], gcf->org->databaseType);
        return NGX_CONF_ERROR;
    }

#else

    ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                       "\"%V\" is not a MaxMind DB database", &value[1]);

    return NGX_CONF_ERROR;

#endif
}


static char *
ngx_http_geoip_city(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    ngx_http_geoip_conf_t  *gcf = conf;

    ngx_str_t  *value;

#if (NGX_HAVE_LIBGEOIP)
    if (gcf->city) {
        return "is duplicate";
    }
#endif
#if (NGX_HAVE_MAXMINDDB)
    if (gcf->city_mmdb) {
        return "is duplicate";
    }
#endif

    value = cf->args->elts;

#if (NGX_HAVE_MAXMINDDB)

    switch (ngx_http_geoip_mmdb_open(cf, &value[1], &gcf->city_mmdb)) {

    case NGX_OK:
        return ngx_http_geoip_mmdb_charset(cf);

    case NGX_ERROR:
        return NGX_CONF_ERROR;

    default:                    /* NGX_DECLINED, not a MaxMind DB database */
        break;
    }

#endif

#if (NGX_HAVE_LIBGEOIP)

    gcf->city = GeoIP_open((char *) value[1].data, GEOIP_MEMORY_CACHE);

    if (gcf->city == NULL) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                           "GeoIP_open(\"%V\") failed", &value[1]);

        return NGX_CONF_ERROR;
    }

    if (cf->args->nelts == 3) {
        if (ngx_strcmp(value[2].data, "utf8") == 0) {
            GeoIP_set_charset(gcf->city, GEOIP_CHARSET_UTF8);

        } else {
            ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                               "invalid parameter \"%V\"", &value[2]);
            return NGX_CONF_ERROR;
        }
    }

    switch (gcf->city->databaseType) {

    case GEOIP_CITY_EDITION_REV0:
    case GEOIP_CITY_EDITION_REV1:

        return NGX_CONF_OK;

#if (NGX_HAVE_GEOIP_V6)
    case GEOIP_CITY_EDITION_REV0_V6:
    case GEOIP_CITY_EDITION_REV1_V6:

        gcf->city_v6 = 1;
        return NGX_CONF_OK;
#endif

    default:
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                           "invalid GeoIP City database \"%V\" type:%d",
                           &value[1], gcf->city->databaseType);
        return NGX_CONF_ERROR;
    }

#else

    ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                       "\"%V\" is not a MaxMind DB database", &value[1]);

    return NGX_CONF_ERROR;

#endif
}


static char *
ngx_http_geoip_proxy(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    ngx_http_geoip_conf_t  *gcf = conf;

    ngx_str_t   *value;
    ngx_cidr_t  cidr, *c;

    value = cf->args->elts;

    if (ngx_http_geoip_cidr_value(cf, &value[1], &cidr) != NGX_OK) {
        return NGX_CONF_ERROR;
    }

    if (gcf->proxies == NULL) {
        gcf->proxies = ngx_array_create(cf->pool, 4, sizeof(ngx_cidr_t));
        if (gcf->proxies == NULL) {
            return NGX_CONF_ERROR;
        }
    }

    c = ngx_array_push(gcf->proxies);
    if (c == NULL) {
        return NGX_CONF_ERROR;
    }

    *c = cidr;

    return NGX_CONF_OK;
}

static ngx_int_t
ngx_http_geoip_cidr_value(ngx_conf_t *cf, ngx_str_t *net, ngx_cidr_t *cidr)
{
    ngx_int_t  rc;

    if (ngx_strcmp(net->data, "255.255.255.255") == 0) {
        cidr->family = AF_INET;
        cidr->u.in.addr = 0xffffffff;
        cidr->u.in.mask = 0xffffffff;

        return NGX_OK;
    }

    rc = ngx_ptocidr(net, cidr);

    if (rc == NGX_ERROR) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0, "invalid network \"%V\"", net);
        return NGX_ERROR;
    }

    if (rc == NGX_DONE) {
        ngx_conf_log_error(NGX_LOG_WARN, cf, 0,
                           "low address bits of %V are meaningless", net);
    }

    return NGX_OK;
}


static void
ngx_http_geoip_cleanup(void *data)
{
    ngx_http_geoip_conf_t  *gcf = data;

#if (NGX_HAVE_LIBGEOIP)

    if (gcf->country) {
        GeoIP_delete(gcf->country);
    }

    if (gcf->org) {
        GeoIP_delete(gcf->org);
    }

    if (gcf->city) {
        GeoIP_delete(gcf->city);
    }

#endif

#if (NGX_HAVE_MAXMINDDB)

    if (gcf->country_mmdb) {
        MMDB_close(gcf->country_mmdb);
    }

    if (gcf->org_mmdb) {
        MMDB_close(gcf->org_mmdb);
    }

    if (gcf->city_mmdb) {
        MMDB_close(gcf->city_mmdb);
    }

#endif
}
