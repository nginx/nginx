
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

    if (in == NULL)
        return next_filter;

    ctx = (ngx_http_ssi_filter_ctx_t *)
                             ngx_get_module_ctx(r, ngx_http_ssi_filter_module);
    if (ctx == NULL) {
        ngx_http_create_ctx(r, ctx,
                            ngx_http_ssi_filter_module,
                            sizeof(ngx_http_ssi_filter_ctx_t));

        ctx->state = &ssi_start;
        ctx->handler = ngx_http_ssi_find_start;
    }

    ch = in;
    ctx->start = ctx->pos = ch->hunk->pos.mem; 

    for ( ;; ) {
        if (ctx->handler(r, ctx, ch) == NGX_ERROR)
            return NGX_ERROR;

        if (ctx->pos + ctx->length == ch->hunk->last.mem) {
            ch = ch->next;
            if (ch == NULL)
                break;

            ctx->start = ctx->pos = ch->hunk->pos.mem; 
        }
    }
}



static int ngx_http_ssi_find_start(ngx_http_request_t *r,
                                   ngx_http_ssi_filter_ctx_t *ctx,
                                   ngx_chain_t *ch)
{
    ngx_http_ssi_parse(r, ctx, ch->hunk);

    if (ctx->state == ssi_command_state
        || (ctx->length > 0 && ch->next == NULL)
        || ctx->hunk_with_ssi)
    {
        ngx_test_null(h, ngx_palloc(r->pool, sizeof(ngx_hunk_t)), NGX_ERROR);
#if !(HAVE_OFFSET_EQUAL_PTR)
        h->pos.file = h->last.file = 0;
#endif
        h->pre_start = h->start = h->pos.mem = ctx->start;
        h->post_end = h->end = h->last.mem = ctx->pos;
        h->type = NGX_HUNK_TEMP;
        h->tag = 0;
        h->file = NULL;

        ngx_add_hunk_to_chain(ctx->last, h, r->pool, NGX_ERROR);

        ngx_test_null(ssi_hunk, ngx_push_array(ctx->ssi_hunks), NGX_ERROR);
        ssi_hunk->ssi_hunk = h;
        ssi_hunk->hunk = ch->hunk;
        ssi_hunk->pos = NULL;
    }

    if (ctx->state == ssi_command_state)
        ctx->handler = ngx_http_ssi_find_command;
    }

    return NGX_OK;
}


static int ngx_http_ssi_find_command(ngx_http_request_t *r,
                                      ngx_http_ssi_filter_ctx_t *ctx,
                                       ngx_chain_t *ch)
{
    ngx_http_ssi_parse_command(r, ctx, ch->hunk);
}


static char ssi_start[] = "<!--#";

static char ssi_include[] = "include";

static ssi_parser_t ssi_pre_command_state[] = {
    { 1, (char *) ' ', ssi_pre_command_state, NULL },

    { 7, "include", ssi_command_state, ssi_include_state },

    { 4, "random", ssi_command_state, NULL },
    { 0, NULL, ssi_error_state }
};

static ssi_parser_t ssi_include_state[] = {
    { 1, (char *) ' ', ssi_include_state, NULL },
    { 7, "virtual", ssi_equal_state, offsetof(ssi_include_t, virtual) },
    { 0, NULL, ssi_error_state }
};

static ssi_parser_t ssi_equal_state[] = {
    { 1, (char *) ' ', ssi_equal_state, NULL },
    { 1, (char *) '=', ssi_param_state, NULL },
};

static char ssi_echo[] = "echo";

static void ngx_http_ssi_parse(ngx_http_request_t *r,
                               ngx_http_ssi_filter_ctx_t *ctx,
                               ngx_hunk_t *hunk)


    for ( ;; ) {

        for (/* void */ ; p < ch->hunk->last.mem; p++) {

            switch (state) {

            case ssi_start_state:

                /* tight loop */
                while (p < ch->hunk->last.mem) {
                    if (*p++ == '<') {
                        state = ssi_comment_state;
                        length = 1;
                        break;
                    }
                }

                /* fall through */

            case ssi_comment_state:

                if (*p == ssi_start[length]) {
                    length++;

                } else {
                    length = 0;
                    flush = 1;
                    state = ssi_start_state;
                }

                if (length < 6)
                    continue;

                state = ssi_space_before_command_state;

                /* fall through */

            case ssi_space_before_command_state:

                if (*p == ' ' || *p == '\t' || *p == CR || *p == LF)
                     continue;

                state = ssi_command_state;

                /* fall through */

            case ssi_choose_command_state:

                for (i = 0; ctx->name[i].len; i++) {
                    if (*p == ctx->name[i].name[0]) {
                        state = choos[i].state;
                    }
                }

            case ssi_command_state:
                if (*p == ssi_include[n];
                    n++;

                break;

            }
        }

            if (length == 6
                || (length > 0 && ch->next == NULL)
                || hunk_with_ssi) {

                if (ctx->saved > 0 && flush) {
                    add saved
                    ctx->saved = 0;
                }

                for (c = ctx->in; c != hunk; c = c->next) {
                    ngx_add_hunk_to_chain(ctx->last, c->hunk,
                                          r->pool, NGX_ERROR);
                }

                add duped;
                push duped_hunk, hunk, NULL;

                n = length - (hunk->last.mem - pos);
                for (c = hunk; c; c->next) {
                    if (n > c->hunk->last.mem - c->hunk->pos.mem) {
                        n -= c->hunk->last.mem - c->hunk->pos.mem;
                        push NULL, c->hunk, NULL;
                    }
                }

                ctx->in = c;
            }
        }

    } else {

        for (/* void */ ; p < ch->hunk->last.mem; p++) {
            if (*p == ' ' || *p == '\t' || *p == CR || *P == LF)
                continue;

            ctx->state = ssi_command_state;
            break;
        }

        if (

    }
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
