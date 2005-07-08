
/*
 * Copyright (C) Igor Sysoev
 */


#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_event.h>
#include <ngx_imap.h>


ngx_int_t ngx_imap_parse_command(ngx_imap_session_t *s)
{
    u_char      ch, *p, *c;
    ngx_str_t  *arg;
    enum {
        sw_start = 0,
        sw_spaces_before_command,
        sw_command,
        sw_spaces_before_argument,
        sw_argument,
        sw_literal,
        sw_start_literal_argument,
        sw_literal_argument,
        sw_end_literal_argument,
        sw_almost_done
    } state;

    state = s->state;

    for (p = s->buffer->pos; p < s->buffer->last; p++) {
        ch = *p;

        switch (state) {

        /* IMAP tag */
        case sw_start:
            switch (ch) {
            case ' ':
                s->tag.len = p - s->buffer->start + 1;
                s->tag.data = s->buffer->start;
                state = sw_spaces_before_command;
                break;
            case CR:
                s->state = sw_start;
                return NGX_IMAP_PARSE_INVALID_COMMAND;
            case LF:
                s->state = sw_start;
                return NGX_IMAP_PARSE_INVALID_COMMAND;
            }
            break;

        case sw_spaces_before_command:
            switch (ch) {
            case ' ':
                break;
            case CR:
                s->state = sw_start;
                return NGX_IMAP_PARSE_INVALID_COMMAND;
            case LF:
                s->state = sw_start;
                return NGX_IMAP_PARSE_INVALID_COMMAND;
            default:
                s->cmd_start = p;
                state = sw_command;
                break;
            }
            break;

        case sw_command:
            if (ch == ' ' || ch == CR || ch == LF) {

                c = s->cmd_start;

                switch (p - c) {

                case 4:
                    if ((c[0] == 'N' || c[0] == 'n')
                        && (c[1] == 'O'|| c[1] == 'o')
                        && (c[2] == 'O'|| c[2] == 'o')
                        && (c[3] == 'P'|| c[3] == 'p'))
                    {
                        s->command = NGX_IMAP_NOOP;

                    } else {
                        goto invalid;
                    }
                    break;

                case 5:
                    if ((c[0] == 'L'|| c[0] == 'l')
                        && (c[1] == 'O'|| c[1] == 'o')
                        && (c[2] == 'G'|| c[2] == 'g')
                        && (c[3] == 'I'|| c[3] == 'i')
                        && (c[4] == 'N'|| c[4] == 'n'))
                    {
                        s->command = NGX_IMAP_LOGIN;

                    } else {
                        goto invalid;
                    }
                    break;

                case 6:
                    if ((c[0] == 'L'|| c[0] == 'l')
                        && (c[1] == 'O'|| c[1] == 'o')
                        && (c[2] == 'G'|| c[2] == 'g')
                        && (c[3] == 'O'|| c[3] == 'o')
                        && (c[4] == 'U'|| c[4] == 'u')
                        && (c[5] == 'T'|| c[5] == 't'))
                    {
                        s->command = NGX_IMAP_LOGOUT;

                    } else {
                        goto invalid;
                    }
                    break;

                case 10:
                    if ((c[0] == 'C'|| c[0] == 'c')
                        && (c[1] == 'A'|| c[1] == 'a')
                        && (c[2] == 'P'|| c[2] == 'p')
                        && (c[3] == 'A'|| c[3] == 'a')
                        && (c[4] == 'B'|| c[4] == 'b')
                        && (c[5] == 'I'|| c[5] == 'i')
                        && (c[6] == 'L'|| c[6] == 'l')
                        && (c[7] == 'I'|| c[7] == 'i')
                        && (c[8] == 'T'|| c[8] == 't')
                        && (c[9] == 'Y'|| c[9] == 'y'))
                    {
                        s->command = NGX_IMAP_CAPABILITY;

                    } else {
                        goto invalid;
                    }
                    break;

                default:
                    goto invalid;
                }

                switch (ch) {
                case ' ':
                    state = sw_spaces_before_argument;
                    break;
                case CR:
                    state = sw_almost_done;
                    break;
                case LF:
                    goto done;
                }
                break;
            }

            if ((ch < 'A' || ch > 'Z') && (ch < 'a' || ch > 'z')) {
                goto invalid;
            }

            break;

        case sw_spaces_before_argument:
            switch (ch) {
            case ' ':
                break;
            case CR:
                state = sw_almost_done;
                s->arg_end = p;
                break;
            case LF:
                s->arg_end = p;
                goto done;
            case '"':
                if (s->args.nelts <= 2) {
                    s->quoted = 1;
                    s->arg_start = p + 1;
                    state = sw_argument;
                    break;
                }
                goto invalid;
            case '{':
                if (s->args.nelts <= 2) {
                    state = sw_literal;
                    break;
                }
                goto invalid;
            default:
                if (s->args.nelts <= 2) {
                    s->arg_start = p;
                    state = sw_argument;
                    break;
                }
                goto invalid;
            }
            break;

        case sw_argument:
            switch (ch) {
            case '"':
                if (!s->quoted) {
                    break;
                }
                s->quoted = 0;
                /* fall through */
            case ' ':
            case CR:
            case LF:
                arg = ngx_array_push(&s->args);
                if (arg == NULL) {
                    return NGX_ERROR;
                }
                arg->len = p - s->arg_start;
                arg->data = s->arg_start;
                s->arg_start = NULL;

                switch (ch) {
                case '"':
                case ' ':
                    state = sw_spaces_before_argument;
                    break;
                case CR:
                    state = sw_almost_done;
                    break;
                case LF:
                    goto done;
                }
                break;
            }
            break;

        case sw_literal:
            if (ch >= '0' && ch <= '9') {
                s->literal_len = s->literal_len * 10 + (ch - '0');
                break;
            }
            if (ch == '}') {
                state = sw_start_literal_argument;
                break;
            }
            goto invalid;

        case sw_start_literal_argument:
            switch (ch) {
            case CR:
                break;
            case LF:
                s->buffer->pos = p + 1;
                s->arg_start = p + 1;
                s->state = sw_literal_argument;
                return NGX_IMAP_NEXT;
            }
            goto invalid;

        case sw_literal_argument:
            if (--s->literal_len) {
                break;
            }

            arg = ngx_array_push(&s->args);
            if (arg == NULL) {
                return NGX_ERROR;
            }
            arg->len = p + 1 - s->arg_start;
            arg->data = s->arg_start;
            s->arg_start = NULL;
            state = sw_end_literal_argument;

            break;

        case sw_end_literal_argument:
            switch (ch) {
            case '{':
                if (s->args.nelts <= 2) {
                    state = sw_literal;
                    break;
                }
                goto invalid;
            case CR:
                state = sw_almost_done;
                break;
            case LF:
                goto done;
            default:
                goto invalid;
            }
            break;

        case sw_almost_done:
            switch (ch) {
            case LF:
                goto done;
            default:
                goto invalid;
            }
        }
    }

    s->buffer->pos = p;
    s->state = state;

    return NGX_AGAIN;

done:

    s->buffer->pos = p + 1;

    if (s->arg_start) {
        arg = ngx_array_push(&s->args);
        if (arg == NULL) {
            return NGX_ERROR;
        }
        arg->len = s->arg_end - s->arg_start;
        arg->data = s->arg_start;
        s->arg_start = NULL;
        s->cmd_start = NULL;
        s->quoted = 0;
        s->literal_len = 0;
    }

    s->state = sw_start;

    return NGX_OK;

invalid:

    s->state = sw_start;
    s->quoted = 0;
    s->literal_len = 0;

    return NGX_IMAP_PARSE_INVALID_COMMAND;
}


ngx_int_t ngx_pop3_parse_command(ngx_imap_session_t *s)
{
    u_char      ch, *p, *c, c0, c1, c2, c3;
    ngx_str_t  *arg;
    enum {
        sw_start = 0,
        sw_spaces_before_argument,
        sw_argument,
        sw_almost_done
    } state;

    state = s->state;

    for (p = s->buffer->pos; p < s->buffer->last; p++) {
        ch = *p;

        switch (state) {

        /* POP3 command */
        case sw_start:
            if (ch == ' ' || ch == CR || ch == LF) {
                c = s->buffer->start;

                if (p - c == 4) {

                    c0 = ngx_toupper(c[0]);
                    c1 = ngx_toupper(c[1]);
                    c2 = ngx_toupper(c[2]);
                    c3 = ngx_toupper(c[3]);

                    if (c0 == 'U' && c1 == 'S' && c2 == 'E' && c3 == 'R')
                    {
                        s->command = NGX_POP3_USER;

                    } else if (c0 == 'P' && c1 == 'A' && c2 == 'S' && c3 == 'S')
                    {
                        s->command = NGX_POP3_PASS;

                    } else if (c0 == 'Q' && c1 == 'U' && c2 == 'I' && c3 == 'T')
                    {
                        s->command = NGX_POP3_QUIT;

                    } else if (c0 == 'C' && c1 == 'A' && c2 == 'P' && c3 == 'A')
                    {
                        s->command = NGX_POP3_CAPA;

                    } else if (c0 == 'N' && c1 == 'O' && c2 == 'O' && c3 == 'P')
                    {
                        s->command = NGX_POP3_NOOP;

                    } else {
                        goto invalid;
                    }

                } else {
                    goto invalid;
                }

                switch (ch) {
                case ' ':
                    state = sw_spaces_before_argument;
                    break;
                case CR:
                    state = sw_almost_done;
                    break;
                case LF:
                    goto done;
                }
                break;
            }

            if ((ch < 'A' || ch > 'Z') && (ch < 'a' || ch > 'z')) {
                goto invalid;
            }

            break;

        case sw_spaces_before_argument:
            switch (ch) {
            case ' ':
                break;
            case CR:
                state = sw_almost_done;
                s->arg_end = p;
                break;
            case LF:
                s->arg_end = p;
                goto done;
            default:
                if (s->args.nelts <= 2) {
                    state = sw_argument;
                    s->arg_start = p;
                    break;
                }
                goto invalid;
            }
            break;

        case sw_argument:
            switch (ch) {
            case ' ':
            case CR:
            case LF:
                arg = ngx_array_push(&s->args);
                if (arg == NULL) {
                    return NGX_ERROR;
                }
                arg->len = p - s->arg_start;
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
                    goto done;
                }
                break;

            default:
                break;
            }
            break;

        case sw_almost_done:
            switch (ch) {
            case LF:
                goto done;
            default:
                goto invalid;
            }
        }
    }

    s->buffer->pos = p;
    s->state = state;

    return NGX_AGAIN;

done:

    s->buffer->pos = p + 1;

    if (s->arg_start) {
        arg = ngx_array_push(&s->args);
        if (arg == NULL) {
            return NGX_ERROR;
        }
        arg->len = s->arg_end - s->arg_start;
        arg->data = s->arg_start;
        s->arg_start = NULL;
    }

    s->state = sw_start;

    return NGX_OK;

invalid:

    s->state = sw_start;

    return NGX_IMAP_PARSE_INVALID_COMMAND;
}
