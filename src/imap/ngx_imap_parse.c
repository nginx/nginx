
/*
 * Copyright (C) Igor Sysoev
 */


#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_event.h>
#include <ngx_imap.h>


ngx_int_t ngx_pop3_parse_command(ngx_imap_session_t *s)
{
    u_char      ch, *p, *c;
    ngx_str_t  *arg;
    enum {
        sw_start = 0,
        sw_spaces_before_argument,
        sw_argument,
        sw_almost_done,
        sw_done
    } state;

    state = s->state;
    p = s->buffer->pos;

    while (p < s->buffer->last && state < sw_done) {
        ch = *p++;

        switch (state) {

        /* POP3 command */

        case sw_start:
            if (ch == ' ' || ch == CR || ch == LF) {
                c = s->buffer->start;

                if (p - 1 - c == 4) {

                    if (c[0] == 'U' && c[1] == 'S'
                        && c[2] == 'E' && c[3] == 'R')
                    {
                        s->command = NGX_POP3_USER;

                    } else if (c[0] == 'P' && c[1] == 'A'
                               && c[2] == 'S' && c[3] == 'S')
                    {
                        s->command = NGX_POP3_PASS;

                    } else if (c[0] == 'Q' && c[1] == 'U'
                               && c[2] == 'I' && c[3] == 'T')
                    {
                        s->command = NGX_POP3_QUIT;

#if 0
                    } else if (c[0] == 'N' && c[1] == 'O'
                               && c[2] == 'O' && c[3] == 'P')
                    {
                        s->command = NGX_POP3_NOOP;
#endif

                    } else {
                        s->state = sw_start;
                        return NGX_IMAP_PARSE_INVALID_COMMAND;
                    }

                } else {
                    s->state = sw_start;
                    return NGX_IMAP_PARSE_INVALID_COMMAND;
                }

                switch (ch) {
                case ' ':
                    state = sw_spaces_before_argument;
                    break;
                case CR:
                    state = sw_almost_done;
                    break;
                case LF:
                    state = sw_done;
                    break;
                }
                break;
            }

            if (ch < 'A' || ch > 'Z') {
                s->state = sw_start;
                return NGX_IMAP_PARSE_INVALID_COMMAND;
            }

            break;

        /* the spaces before the argument */
        case sw_spaces_before_argument:
            switch (ch) {
            case ' ':
                break;
            case CR:
                state = sw_almost_done;
                s->arg_end = p - 1;
                break;
            case LF:
                state = sw_done;
                s->arg_end = p - 1;
                break;
            default:
                if (s->args.nelts > 2) {
                    s->state = sw_start;
                    return NGX_IMAP_PARSE_INVALID_COMMAND;
                }

                state = sw_argument;
                s->arg_start = p - 1;
                break;
            }
            break;

        /* the argument */
        case sw_argument:
            switch (ch) {
            case ' ':
            case CR:
            case LF:
                if (!(arg = ngx_array_push(&s->args))) {
                    return NGX_ERROR;
                }
                arg->len = p - 1 - s->arg_start;
                arg->data = s->arg_start;
                s->arg_start = NULL;

                switch (ch) {
                case ' ':
                    state = sw_spaces_before_argument;
                    break;
                case CR:
                    state = sw_almost_done;
                    break;
                case LF:
                    state = sw_done;
                    break;
                }
                break;

            default:
                break;
            }
            break;

        /* end of request line */
        case sw_almost_done:
            switch (ch) {
            case LF:
                state = sw_done;
                break;
            default:
                s->state = sw_start;
                return NGX_IMAP_PARSE_INVALID_COMMAND;
            }
            break;

        /* suppress warning */
        case sw_done:
            break;
        }
    }

    s->buffer->pos = p;

    if (state == sw_done) {
        if (s->arg_start) {
            if (!(arg = ngx_array_push(&s->args))) {
                return NGX_ERROR;
            }
            arg->len = s->arg_end - s->arg_start;
            arg->data = s->arg_start;
            s->arg_start = NULL;
        }

        s->state = sw_start;
        return NGX_OK;

    } else {
        s->state = state;
        return NGX_AGAIN;
    }
}
