
#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_hunk.h>
#include <ngx_event_write.h>
#include <ngx_http.h>
#include <ngx_http_config.h>


static ngx_command_t ngx_http_ssi_filter_commands[];

static void *ngx_http_ssi_filter_create_conf(ngx_pool_t *pool);

ngx_http_module_t  ngx_http_ssi_filter_module = {
    NGX_HTTP_MODULE,
    NULL,                                  /* create server config */
    ngx_http_ssi_filter_create_conf,       /* create location config */
    ngx_http_ssi_filter_commands,          /* module directives */
    NULL,                                  /* init module */
    NULL                                   /* init output body filter */
};


static ngx_command_t ngx_http_ssi_filter_commands[] = {

    {"ssi", ngx_conf_set_flag_slot,
     offsetof(ngx_http_ssi_filter_conf_t, on),
     NGX_HTTP_LOC_CONF, NGX_CONF_FLAG, 
     "enable ssi filter"},

    {NULL}

};


int ngx_http_ssi_filter(ngx_http_request_t *r, ngx_chain_t *in)
{
    ngx_chain_t  *ch, **prev, *chain;
    ngx_http_ssi_filter_ctx_t  *ctx;
    ngx_http_ssi_filter_conf_t *conf;

    ctx = (ngx_http_ssi_filter_ctx_t *)
                              ngx_get_module_ctx(r->main ? r->main : r,
                                                 ngx_http_ssi_filter_module);
    if (ctx == NULL) {
        ngx_http_create_ctx(r, ctx,
                            ngx_http_ssi_filter_module,
                            sizeof(ngx_http_ssi_filter_ctx_t));

        ctx->state = &ssi_start;
    }

    state = ctx->state;
    length = ctx->length;

    ch = in;
    p = ch->hunk->pos.mem; 

    rc = ngx_http_ssi_parse(r, ctx, in);
    if (rc == NGX_SSI_FOUND) {
    }

}


static int ngx_http_ssi_parse(ngx_http_request_t *r,
                              ngx_http_ssi_filter_ctx_t *ctx, ngx_chain_t *in)
{
    state = ctx->state;
    length = ctx->length;

    for ( ;; ) {

        if (state == ssi_start_state) {
            for (/* void */ ; p < ch->hunk->last.mem; p++) {
                if (*p == '<') {
                    state = ssi_exclam_state;
                    length = 1;
                    break;
                }
            }
        }

        for (/* void */ ;
             p < ch->hunk->last.mem
                 && (state > ssi_start_state && state < ssi_command_state)
             p++)
        {
            switch (state) {

            case ssi_exclam_state:
                switch (*p) {

                case '!':
                    state = ssi_dash1_state;
                    length = 2;
                    break;

                case '<':
                    state = ssi_exclam_state;
                    length = 1;
                    break;

                default:
                    state = ssi_start_state;
                    length = 0;
                    break;
                }

                break;

            case ssi_dash1_state:
                switch (*p) {

                case '-':
                    state = ssi_dash2_state;
                    length = 3;
                    break;

                case '<':
                    state = ssi_exclam_state;
                    length = 1;
                    break;

                default:
                    state = ssi_start_state;
                    length = 0;
                    break;
                }

                break;

            case ssi_dash2_state:
                switch (*p) {

                case '-':
                    state = ssi_sharp_state;
                    length = 4;
                    break;

                case '<':
                    state = ssi_exclam_state;
                    length = 1;
                    break;

                default:
                    state = ssi_start_state;
                    length = 0;
                    break;
                }

                break;

            case ssi_sharp_state:
                switch (*p) {

                case '#':
                    ctx->state = ssi_command_state;
                    ctx->length = 5;
                    return NGX_SSI_FOUND;

                case '<':
                    state = ssi_exclam_state;
                    length = 1;
                    break;

                default:
                    state = ssi_start_state;
                    length = 0;
                    break;
                }

                break;
            }
        }

        if (state > ssi_start_state) {
            ngx_add_hunk_to_chain(ch->hunk);
        }

        ch = ch->next;
        if (ch == NULL) {
            ctx->state = state;
            break;
        }

        p = ch->hunk->pos.mem; 
    }

        if (state > ssi_start_state)
            if (ngx_http_ssi_dup_hunk(r, ch->hunk) == NGX_ERROR)
                return NGX_ERROR;

}


static ngx_http_ssi_dup_hunk(ngx_http_request_t *r, ngx_hunk_t *hunk);
{
    new dup_hunk
    set dup_hunk
    ngx_add_hunk_to_chain dup_hunk

    ngx_test_null(ssi_hunk, ngx_push_array);
    ssi_hunk->ssi_hunk = dup_hunk;
    ssi_hunk->hunk = hunk;
    ssi_hunk->pos = NULL;
}





























static void *ngx_http_ssi_filter_create_conf(ngx_pool_t *pool)
{
    ngx_http_ssi_filter_conf_t *conf;

    ngx_test_null(conf,
                  ngx_palloc(pool, sizeof(ngx_http_ssi_filter_conf_t)),
                  NULL);

    conf->buffer_output = NGX_CONF_UNSET;

    return conf;
}
