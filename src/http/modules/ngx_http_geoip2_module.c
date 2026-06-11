
/*
 * Copyright (C) Nitin Swami
 * Copyright (C) Nginx, Inc.
 */


#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>

#include <maxminddb.h>


typedef struct {
    MMDB_s         country;
    MMDB_s         org;
    MMDB_s         city;
    ngx_uint_t     country_loaded;
    ngx_uint_t     org_loaded;
    ngx_uint_t     city_loaded;
    ngx_array_t   *proxies;    /* array of ngx_cidr_t */
    ngx_flag_t     proxy_recursive;
} ngx_http_geoip2_conf_t;


typedef struct {
    const char   *alpha2;
    const char   *alpha3;
} ngx_http_geoip2_ccode_t;


static ngx_int_t ngx_http_geoip2_country_variable(ngx_http_request_t *r,
    ngx_http_variable_value_t *v, uintptr_t data);
static ngx_int_t ngx_http_geoip2_org_variable(ngx_http_request_t *r,
    ngx_http_variable_value_t *v, uintptr_t data);
static ngx_int_t ngx_http_geoip2_city_variable(ngx_http_request_t *r,
    ngx_http_variable_value_t *v, uintptr_t data);
static ngx_int_t ngx_http_geoip2_region_name_variable(ngx_http_request_t *r,
    ngx_http_variable_value_t *v, uintptr_t data);
static ngx_int_t ngx_http_geoip2_city_float_variable(ngx_http_request_t *r,
    ngx_http_variable_value_t *v, uintptr_t data);
static ngx_int_t ngx_http_geoip2_city_int_variable(ngx_http_request_t *r,
    ngx_http_variable_value_t *v, uintptr_t data);
static ngx_int_t ngx_http_geoip2_country_code3_variable(ngx_http_request_t *r,
    ngx_http_variable_value_t *v, uintptr_t data);
static ngx_int_t ngx_http_geoip2_area_code_variable(ngx_http_request_t *r,
    ngx_http_variable_value_t *v, uintptr_t data);

static struct sockaddr *ngx_http_geoip2_addr(ngx_http_request_t *r,
    ngx_http_geoip2_conf_t *gcf);
static ngx_int_t ngx_http_geoip2_lookup(ngx_http_request_t *r,
    MMDB_s *mmdb, struct sockaddr *sa, const char **path,
    MMDB_entry_data_s *entry_data);

static ngx_int_t ngx_http_geoip2_add_variables(ngx_conf_t *cf);
static void *ngx_http_geoip2_create_conf(ngx_conf_t *cf);
static char *ngx_http_geoip2_init_conf(ngx_conf_t *cf, void *conf);
static char *ngx_http_geoip2_country(ngx_conf_t *cf, ngx_command_t *cmd,
    void *conf);
static char *ngx_http_geoip2_org(ngx_conf_t *cf, ngx_command_t *cmd,
    void *conf);
static char *ngx_http_geoip2_city(ngx_conf_t *cf, ngx_command_t *cmd,
    void *conf);
static char *ngx_http_geoip2_proxy(ngx_conf_t *cf, ngx_command_t *cmd,
    void *conf);
static ngx_int_t ngx_http_geoip2_cidr_value(ngx_conf_t *cf, ngx_str_t *net,
    ngx_cidr_t *cidr);
static void ngx_http_geoip2_cleanup(void *data);


static const char *ngx_http_geoip2_country_code3_from_code(const char *code2);


/*
 * MMDB path arrays for variable lookups.
 * Each is a NULL-terminated array of strings.
 */

static const char  *ngx_http_geoip2_path_country_code[] = {
    "country", "iso_code", NULL
};

static const char  *ngx_http_geoip2_path_country_name[] = {
    "country", "names", "en", NULL
};

static const char  *ngx_http_geoip2_path_org[] = {
    "autonomous_system_organization", NULL
};

static const char  *ngx_http_geoip2_path_continent_code[] = {
    "continent", "code", NULL
};

static const char  *ngx_http_geoip2_path_region[] = {
    "subdivisions", "0", "iso_code", NULL
};

static const char  *ngx_http_geoip2_path_region_name[] = {
    "subdivisions", "0", "names", "en", NULL
};

static const char  *ngx_http_geoip2_path_city[] = {
    "city", "names", "en", NULL
};

static const char  *ngx_http_geoip2_path_postal_code[] = {
    "postal", "code", NULL
};

static const char  *ngx_http_geoip2_path_latitude[] = {
    "location", "latitude", NULL
};

static const char  *ngx_http_geoip2_path_longitude[] = {
    "location", "longitude", NULL
};

static const char  *ngx_http_geoip2_path_dma_code[] = {
    "location", "metro_code", NULL
};


/*
 * Variable definitions using $geoip2_* prefix.
 *
 * The 'data' field encodes which database to use:
 *   0 = country database
 *   1 = city database
 *   2 = org database
 * This is used by the variable handlers to select gcf->country/city/org.
 */

#define NGX_HTTP_GEOIP2_DB_COUNTRY  0
#define NGX_HTTP_GEOIP2_DB_CITY     1
#define NGX_HTTP_GEOIP2_DB_ORG      2


static ngx_command_t  ngx_http_geoip2_commands[] = {

    { ngx_string("geoip2_country"),
      NGX_HTTP_MAIN_CONF|NGX_CONF_TAKE1,
      ngx_http_geoip2_country,
      NGX_HTTP_MAIN_CONF_OFFSET,
      0,
      NULL },

    { ngx_string("geoip2_org"),
      NGX_HTTP_MAIN_CONF|NGX_CONF_TAKE1,
      ngx_http_geoip2_org,
      NGX_HTTP_MAIN_CONF_OFFSET,
      0,
      NULL },

    { ngx_string("geoip2_city"),
      NGX_HTTP_MAIN_CONF|NGX_CONF_TAKE1,
      ngx_http_geoip2_city,
      NGX_HTTP_MAIN_CONF_OFFSET,
      0,
      NULL },

    { ngx_string("geoip2_proxy"),
      NGX_HTTP_MAIN_CONF|NGX_CONF_TAKE1,
      ngx_http_geoip2_proxy,
      NGX_HTTP_MAIN_CONF_OFFSET,
      0,
      NULL },

    { ngx_string("geoip2_proxy_recursive"),
      NGX_HTTP_MAIN_CONF|NGX_CONF_FLAG,
      ngx_conf_set_flag_slot,
      NGX_HTTP_MAIN_CONF_OFFSET,
      offsetof(ngx_http_geoip2_conf_t, proxy_recursive),
      NULL },

      ngx_null_command
};


static ngx_http_module_t  ngx_http_geoip2_module_ctx = {
    ngx_http_geoip2_add_variables,         /* preconfiguration */
    NULL,                                  /* postconfiguration */

    ngx_http_geoip2_create_conf,           /* create main configuration */
    ngx_http_geoip2_init_conf,             /* init main configuration */

    NULL,                                  /* create server configuration */
    NULL,                                  /* merge server configuration */

    NULL,                                  /* create location configuration */
    NULL                                   /* merge location configuration */
};


ngx_module_t  ngx_http_geoip2_module = {
    NGX_MODULE_V1,
    &ngx_http_geoip2_module_ctx,           /* module context */
    ngx_http_geoip2_commands,              /* module directives */
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


static ngx_http_variable_t  ngx_http_geoip2_vars[] = {

    { ngx_string("geoip2_country_code"), NULL,
      ngx_http_geoip2_country_variable,
      (uintptr_t) ngx_http_geoip2_path_country_code, 0, 0 },

    { ngx_string("geoip2_country_code3"), NULL,
      ngx_http_geoip2_country_code3_variable,
      0, 0, 0 },

    { ngx_string("geoip2_country_name"), NULL,
      ngx_http_geoip2_country_variable,
      (uintptr_t) ngx_http_geoip2_path_country_name, 0, 0 },

    { ngx_string("geoip2_org"), NULL,
      ngx_http_geoip2_org_variable,
      (uintptr_t) ngx_http_geoip2_path_org, 0, 0 },

    { ngx_string("geoip2_city_continent_code"), NULL,
      ngx_http_geoip2_city_variable,
      (uintptr_t) ngx_http_geoip2_path_continent_code, 0, 0 },

    { ngx_string("geoip2_city_country_code"), NULL,
      ngx_http_geoip2_city_variable,
      (uintptr_t) ngx_http_geoip2_path_country_code, 0, 0 },

    { ngx_string("geoip2_city_country_code3"), NULL,
      ngx_http_geoip2_country_code3_variable,
      NGX_HTTP_GEOIP2_DB_CITY, 0, 0 },

    { ngx_string("geoip2_city_country_name"), NULL,
      ngx_http_geoip2_city_variable,
      (uintptr_t) ngx_http_geoip2_path_country_name, 0, 0 },

    { ngx_string("geoip2_region"), NULL,
      ngx_http_geoip2_city_variable,
      (uintptr_t) ngx_http_geoip2_path_region, 0, 0 },

    { ngx_string("geoip2_region_name"), NULL,
      ngx_http_geoip2_region_name_variable,
      (uintptr_t) ngx_http_geoip2_path_region_name, 0, 0 },

    { ngx_string("geoip2_city"), NULL,
      ngx_http_geoip2_city_variable,
      (uintptr_t) ngx_http_geoip2_path_city, 0, 0 },

    { ngx_string("geoip2_postal_code"), NULL,
      ngx_http_geoip2_city_variable,
      (uintptr_t) ngx_http_geoip2_path_postal_code, 0, 0 },

    { ngx_string("geoip2_latitude"), NULL,
      ngx_http_geoip2_city_float_variable,
      (uintptr_t) ngx_http_geoip2_path_latitude, 0, 0 },

    { ngx_string("geoip2_longitude"), NULL,
      ngx_http_geoip2_city_float_variable,
      (uintptr_t) ngx_http_geoip2_path_longitude, 0, 0 },

    { ngx_string("geoip2_dma_code"), NULL,
      ngx_http_geoip2_city_int_variable,
      (uintptr_t) ngx_http_geoip2_path_dma_code, 0, 0 },

    { ngx_string("geoip2_area_code"), NULL,
      ngx_http_geoip2_area_code_variable,
      0, 0, 0 },

      ngx_http_null_variable
};


/* ISO 3166-1 alpha-2 to alpha-3 lookup table */

static ngx_http_geoip2_ccode_t  ngx_http_geoip2_country_codes[] = {
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
ngx_http_geoip2_country_code3_from_code(const char *code2)
{
    ngx_http_geoip2_ccode_t  *cc;

    for (cc = ngx_http_geoip2_country_codes; cc->alpha2 != NULL; cc++) {
        if (code2[0] == cc->alpha2[0] && code2[1] == cc->alpha2[1]) {
            return cc->alpha3;
        }
    }

    return NULL;
}


static struct sockaddr *
ngx_http_geoip2_addr(ngx_http_request_t *r, ngx_http_geoip2_conf_t *gcf)
{
    ngx_addr_t           addr;
    ngx_table_elt_t     *xfwd;

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


static ngx_int_t
ngx_http_geoip2_lookup(ngx_http_request_t *r, MMDB_s *mmdb,
    struct sockaddr *sa, const char **path, MMDB_entry_data_s *entry_data)
{
    int                     mmdb_error;
    MMDB_lookup_result_s    result;

    if (sa->sa_family != AF_INET && sa->sa_family != AF_INET6) {
        return NGX_DECLINED;
    }

    result = MMDB_lookup_sockaddr(mmdb, sa, &mmdb_error);

    if (mmdb_error != MMDB_SUCCESS) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                      "MMDB_lookup_sockaddr() failed: %s",
                      MMDB_strerror(mmdb_error));
        return NGX_ERROR;
    }

    if (!result.found_entry) {
        return NGX_DECLINED;
    }

    mmdb_error = MMDB_aget_value(&result.entry, entry_data, path);

    if (mmdb_error != MMDB_SUCCESS) {
        return NGX_DECLINED;
    }

    if (!entry_data->has_data) {
        return NGX_DECLINED;
    }

    return NGX_OK;
}


static ngx_int_t
ngx_http_geoip2_country_variable(ngx_http_request_t *r,
    ngx_http_variable_value_t *v, uintptr_t data)
{
    const char              **path = (const char **) data;
    ngx_http_geoip2_conf_t   *gcf;
    MMDB_entry_data_s         entry_data;
    struct sockaddr          *sa;
    u_char                   *p;

    gcf = ngx_http_get_module_main_conf(r, ngx_http_geoip2_module);

    if (gcf->country_loaded == 0) {
        goto not_found;
    }

    sa = ngx_http_geoip2_addr(r, gcf);

    if (ngx_http_geoip2_lookup(r, &gcf->country, sa, path,
                                &entry_data) != NGX_OK)
    {
        goto not_found;
    }

    if (entry_data.type != MMDB_DATA_TYPE_UTF8_STRING) {
        goto not_found;
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

not_found:

    v->not_found = 1;

    return NGX_OK;
}


static ngx_int_t
ngx_http_geoip2_org_variable(ngx_http_request_t *r,
    ngx_http_variable_value_t *v, uintptr_t data)
{
    const char              **path = (const char **) data;
    ngx_http_geoip2_conf_t   *gcf;
    MMDB_entry_data_s         entry_data;
    struct sockaddr          *sa;
    u_char                   *p;

    gcf = ngx_http_get_module_main_conf(r, ngx_http_geoip2_module);

    if (gcf->org_loaded == 0) {
        goto not_found;
    }

    sa = ngx_http_geoip2_addr(r, gcf);

    if (ngx_http_geoip2_lookup(r, &gcf->org, sa, path,
                                &entry_data) != NGX_OK)
    {
        goto not_found;
    }

    if (entry_data.type != MMDB_DATA_TYPE_UTF8_STRING) {
        goto not_found;
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

not_found:

    v->not_found = 1;

    return NGX_OK;
}


static ngx_int_t
ngx_http_geoip2_city_variable(ngx_http_request_t *r,
    ngx_http_variable_value_t *v, uintptr_t data)
{
    const char              **path = (const char **) data;
    ngx_http_geoip2_conf_t   *gcf;
    MMDB_entry_data_s         entry_data;
    struct sockaddr          *sa;
    u_char                   *p;

    gcf = ngx_http_get_module_main_conf(r, ngx_http_geoip2_module);

    if (gcf->city_loaded == 0) {
        goto not_found;
    }

    sa = ngx_http_geoip2_addr(r, gcf);

    if (ngx_http_geoip2_lookup(r, &gcf->city, sa, path,
                                &entry_data) != NGX_OK)
    {
        goto not_found;
    }

    if (entry_data.type != MMDB_DATA_TYPE_UTF8_STRING) {
        goto not_found;
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

not_found:

    v->not_found = 1;

    return NGX_OK;
}


static ngx_int_t
ngx_http_geoip2_region_name_variable(ngx_http_request_t *r,
    ngx_http_variable_value_t *v, uintptr_t data)
{
    const char              **path = (const char **) data;
    ngx_http_geoip2_conf_t   *gcf;
    MMDB_entry_data_s         entry_data;
    struct sockaddr          *sa;
    u_char                   *p;

    gcf = ngx_http_get_module_main_conf(r, ngx_http_geoip2_module);

    if (gcf->city_loaded == 0) {
        goto not_found;
    }

    sa = ngx_http_geoip2_addr(r, gcf);

    if (ngx_http_geoip2_lookup(r, &gcf->city, sa, path,
                                &entry_data) != NGX_OK)
    {
        goto not_found;
    }

    if (entry_data.type != MMDB_DATA_TYPE_UTF8_STRING) {
        goto not_found;
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

not_found:

    v->not_found = 1;

    return NGX_OK;
}


static ngx_int_t
ngx_http_geoip2_city_float_variable(ngx_http_request_t *r,
    ngx_http_variable_value_t *v, uintptr_t data)
{
    const char              **path = (const char **) data;
    ngx_http_geoip2_conf_t   *gcf;
    MMDB_entry_data_s         entry_data;
    struct sockaddr          *sa;
    double                    val;
    u_char                   *p;

    gcf = ngx_http_get_module_main_conf(r, ngx_http_geoip2_module);

    if (gcf->city_loaded == 0) {
        v->not_found = 1;
        return NGX_OK;
    }

    sa = ngx_http_geoip2_addr(r, gcf);

    if (ngx_http_geoip2_lookup(r, &gcf->city, sa, path,
                                &entry_data) != NGX_OK)
    {
        v->not_found = 1;
        return NGX_OK;
    }

    if (entry_data.type == MMDB_DATA_TYPE_DOUBLE) {
        val = entry_data.double_value;

    } else if (entry_data.type == MMDB_DATA_TYPE_FLOAT) {
        val = (double) entry_data.float_value;

    } else {
        v->not_found = 1;
        return NGX_OK;
    }

    p = ngx_pnalloc(r->pool, NGX_INT64_LEN + 5);
    if (p == NULL) {
        return NGX_ERROR;
    }

    v->len = ngx_snprintf(p, NGX_INT64_LEN + 5, "%.4f", val) - p;
    v->valid = 1;
    v->no_cacheable = 0;
    v->not_found = 0;
    v->data = p;

    return NGX_OK;
}


static ngx_int_t
ngx_http_geoip2_city_int_variable(ngx_http_request_t *r,
    ngx_http_variable_value_t *v, uintptr_t data)
{
    const char              **path = (const char **) data;
    ngx_http_geoip2_conf_t   *gcf;
    MMDB_entry_data_s         entry_data;
    struct sockaddr          *sa;
    u_char                   *p;

    gcf = ngx_http_get_module_main_conf(r, ngx_http_geoip2_module);

    if (gcf->city_loaded == 0) {
        v->not_found = 1;
        return NGX_OK;
    }

    sa = ngx_http_geoip2_addr(r, gcf);

    if (ngx_http_geoip2_lookup(r, &gcf->city, sa, path,
                                &entry_data) != NGX_OK)
    {
        v->not_found = 1;
        return NGX_OK;
    }

    p = ngx_pnalloc(r->pool, NGX_INT64_LEN);
    if (p == NULL) {
        return NGX_ERROR;
    }

    if (entry_data.type == MMDB_DATA_TYPE_UINT16) {
        v->len = ngx_sprintf(p, "%ud", (ngx_uint_t) entry_data.uint16) - p;

    } else if (entry_data.type == MMDB_DATA_TYPE_UINT32) {
        v->len = ngx_sprintf(p, "%uD", (uint32_t) entry_data.uint32) - p;

    } else if (entry_data.type == MMDB_DATA_TYPE_INT32) {
        v->len = ngx_sprintf(p, "%d", entry_data.int32) - p;

    } else {
        v->not_found = 1;
        return NGX_OK;
    }

    v->valid = 1;
    v->no_cacheable = 0;
    v->not_found = 0;
    v->data = p;

    return NGX_OK;
}


static ngx_int_t
ngx_http_geoip2_country_code3_variable(ngx_http_request_t *r,
    ngx_http_variable_value_t *v, uintptr_t data)
{
    ngx_http_geoip2_conf_t   *gcf;
    MMDB_entry_data_s         entry_data;
    MMDB_s                   *mmdb;
    struct sockaddr          *sa;
    const char               *code3;
    u_char                   *p;
    char                      code2[3];

    gcf = ngx_http_get_module_main_conf(r, ngx_http_geoip2_module);

    /*
     * For city_country_code3, use city database (data == DB_CITY);
     * for country_code3, use country database (data == 0).
     */
    if (data == NGX_HTTP_GEOIP2_DB_CITY) {
        if (gcf->city_loaded == 0) {
            goto not_found;
        }
        mmdb = &gcf->city;

    } else {
        if (gcf->country_loaded == 0) {
            goto not_found;
        }
        mmdb = &gcf->country;
    }

    sa = ngx_http_geoip2_addr(r, gcf);

    if (ngx_http_geoip2_lookup(r, mmdb, sa,
                                ngx_http_geoip2_path_country_code,
                                &entry_data) != NGX_OK)
    {
        goto not_found;
    }

    if (entry_data.type != MMDB_DATA_TYPE_UTF8_STRING
        || entry_data.data_size != 2)
    {
        goto not_found;
    }

    code2[0] = entry_data.utf8_string[0];
    code2[1] = entry_data.utf8_string[1];
    code2[2] = '\0';

    code3 = ngx_http_geoip2_country_code3_from_code(code2);
    if (code3 == NULL) {
        goto not_found;
    }

    p = ngx_pnalloc(r->pool, 3);
    if (p == NULL) {
        return NGX_ERROR;
    }

    ngx_memcpy(p, code3, 3);

    v->len = 3;
    v->valid = 1;
    v->no_cacheable = 0;
    v->not_found = 0;
    v->data = p;

    return NGX_OK;

not_found:

    v->not_found = 1;

    return NGX_OK;
}


static ngx_int_t
ngx_http_geoip2_area_code_variable(ngx_http_request_t *r,
    ngx_http_variable_value_t *v, uintptr_t data)
{
    /* area_code is not available in GeoIP2 databases, always empty */

    v->len = 0;
    v->valid = 1;
    v->no_cacheable = 0;
    v->not_found = 0;
    v->data = (u_char *) "";

    return NGX_OK;
}


static ngx_int_t
ngx_http_geoip2_add_variables(ngx_conf_t *cf)
{
    ngx_http_variable_t  *var, *v;

    for (v = ngx_http_geoip2_vars; v->name.len; v++) {
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
ngx_http_geoip2_create_conf(ngx_conf_t *cf)
{
    ngx_pool_cleanup_t      *cln;
    ngx_http_geoip2_conf_t  *conf;

    conf = ngx_pcalloc(cf->pool, sizeof(ngx_http_geoip2_conf_t));
    if (conf == NULL) {
        return NULL;
    }

    conf->proxy_recursive = NGX_CONF_UNSET;

    cln = ngx_pool_cleanup_add(cf->pool, 0);
    if (cln == NULL) {
        return NULL;
    }

    cln->handler = ngx_http_geoip2_cleanup;
    cln->data = conf;

    return conf;
}


static char *
ngx_http_geoip2_init_conf(ngx_conf_t *cf, void *conf)
{
    ngx_http_geoip2_conf_t  *gcf = conf;

    ngx_conf_init_value(gcf->proxy_recursive, 0);

    return NGX_CONF_OK;
}


static char *
ngx_http_geoip2_country(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    ngx_http_geoip2_conf_t  *gcf = conf;

    ngx_str_t  *value;
    int         status;

    if (gcf->country_loaded != 0) {
        return "is duplicate";
    }

    value = cf->args->elts;

    status = MMDB_open((char *) value[1].data, MMDB_MODE_MMAP, &gcf->country);

    if (status != MMDB_SUCCESS) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                           "MMDB_open(\"%V\") failed: %s",
                           &value[1], MMDB_strerror(status));
        return NGX_CONF_ERROR;
    }

    gcf->country_loaded = 1;

    return NGX_CONF_OK;
}


static char *
ngx_http_geoip2_org(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    ngx_http_geoip2_conf_t  *gcf = conf;

    ngx_str_t  *value;
    int         status;

    if (gcf->org_loaded != 0) {
        return "is duplicate";
    }

    value = cf->args->elts;

    status = MMDB_open((char *) value[1].data, MMDB_MODE_MMAP, &gcf->org);

    if (status != MMDB_SUCCESS) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                           "MMDB_open(\"%V\") failed: %s",
                           &value[1], MMDB_strerror(status));
        return NGX_CONF_ERROR;
    }

    gcf->org_loaded = 1;

    return NGX_CONF_OK;
}


static char *
ngx_http_geoip2_city(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    ngx_http_geoip2_conf_t  *gcf = conf;

    ngx_str_t  *value;
    int         status;

    if (gcf->city_loaded != 0) {
        return "is duplicate";
    }

    value = cf->args->elts;

    status = MMDB_open((char *) value[1].data, MMDB_MODE_MMAP, &gcf->city);

    if (status != MMDB_SUCCESS) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                           "MMDB_open(\"%V\") failed: %s",
                           &value[1], MMDB_strerror(status));
        return NGX_CONF_ERROR;
    }

    gcf->city_loaded = 1;

    return NGX_CONF_OK;
}


static char *
ngx_http_geoip2_proxy(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    ngx_http_geoip2_conf_t  *gcf = conf;

    ngx_str_t   *value;
    ngx_cidr_t   cidr, *c;

    value = cf->args->elts;

    if (ngx_http_geoip2_cidr_value(cf, &value[1], &cidr) != NGX_OK) {
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
ngx_http_geoip2_cidr_value(ngx_conf_t *cf, ngx_str_t *net, ngx_cidr_t *cidr)
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
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                           "invalid network \"%V\"", net);
        return NGX_ERROR;
    }

    if (rc == NGX_DONE) {
        ngx_conf_log_error(NGX_LOG_WARN, cf, 0,
                           "low address bits of %V are meaningless", net);
    }

    return NGX_OK;
}


static void
ngx_http_geoip2_cleanup(void *data)
{
    ngx_http_geoip2_conf_t  *gcf = data;

    if (gcf->country_loaded != 0) {
        MMDB_close(&gcf->country);
    }

    if (gcf->org_loaded != 0) {
        MMDB_close(&gcf->org);
    }

    if (gcf->city_loaded != 0) {
        MMDB_close(&gcf->city);
    }
}
