
/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) Nginx, Inc.
 */


#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_event.h>
#include <ngx_mail.h>
#include <ngx_mail_pop3_module.h>
#include <ngx_mail_imap_module.h>
#include <ngx_mail_smtp_module.h>


ngx_int_t
ngx_mail_pop3_parse_command(ngx_mail_session_t *s)
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

                    } else if (c0 == 'A' && c1 == 'P' && c2 == 'O' && c3 == 'P')
                    {
                        s->command = NGX_POP3_APOP;

                    } else if (c0 == 'Q' && c1 == 'U' && c2 == 'I' && c3 == 'T')
                    {
                        s->command = NGX_POP3_QUIT;

                    } else if (c0 == 'C' && c1 == 'A' && c2 == 'P' && c3 == 'A')
                    {
                        s->command = NGX_POP3_CAPA;

                    } else if (c0 == 'A' && c1 == 'U' && c2 == 'T' && c3 == 'H')
                    {
                        s->command = NGX_POP3_AUTH;

                    } else if (c0 == 'N' && c1 == 'O' && c2 == 'O' && c3 == 'P')
                    {
                        s->command = NGX_POP3_NOOP;
#if (NGX_MAIL_SSL)
                    } else if (c0 == 'S' && c1 == 'T' && c2 == 'L' && c3 == 'S')
                    {
                        s->command = NGX_POP3_STLS;
#endif
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

                /*
                 * the space should be considered as part of the at username
                 * or password, but not of argument in other commands
                 */

                if (s->command == NGX_POP3_USER
                    || s->command == NGX_POP3_PASS)
                {
                    break;
                }

                /* fall through */

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

    s->state = (s->command != NGX_POP3_AUTH) ? sw_start : sw_argument;

    return NGX_OK;

invalid:

    s->state = sw_start;
    s->arg_start = NULL;

    return NGX_MAIL_PARSE_INVALID_COMMAND;
}


ngx_int_t
ngx_mail_imap_parse_command(ngx_mail_session_t *s)
{
    u_char      ch, *p, *c;
    ngx_str_t  *arg;
    enum {
        sw_start = 0,
        sw_spaces_before_command,
        sw_command,
        sw_spaces_before_argument,
        sw_argument,
        sw_backslash,
        sw_literal,
        sw_no_sync_literal_argument,
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
                return NGX_MAIL_PARSE_INVALID_COMMAND;
            case LF:
                s->state = sw_start;
                return NGX_MAIL_PARSE_INVALID_COMMAND;
            }
            break;

        case sw_spaces_before_command:
            switch (ch) {
            case ' ':
                break;
            case CR:
                s->state = sw_start;
                return NGX_MAIL_PARSE_INVALID_COMMAND;
            case LF:
                s->state = sw_start;
                return NGX_MAIL_PARSE_INVALID_COMMAND;
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

#if (NGX_MAIL_SSL)
                case 8:
                    if ((c[0] == 'S'|| c[0] == 's')
                        && (c[1] == 'T'|| c[1] == 't')
                        && (c[2] == 'A'|| c[2] == 'a')
                        && (c[3] == 'R'|| c[3] == 'r')
                        && (c[4] == 'T'|| c[4] == 't')
                        && (c[5] == 'T'|| c[5] == 't')
                        && (c[6] == 'L'|| c[6] == 'l')
                        && (c[7] == 'S'|| c[7] == 's'))
                    {
                        s->command = NGX_IMAP_STARTTLS;

                    } else {
                        goto invalid;
                    }
                    break;
#endif

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

                case 12:
                    if ((c[0] == 'A'|| c[0] == 'a')
                        && (c[1] == 'U'|| c[1] == 'u')
                        && (c[2] == 'T'|| c[2] == 't')
                        && (c[3] == 'H'|| c[3] == 'h')
                        && (c[4] == 'E'|| c[4] == 'e')
                        && (c[5] == 'N'|| c[5] == 'n')
                        && (c[6] == 'T'|| c[6] == 't')
                        && (c[7] == 'I'|| c[7] == 'i')
                        && (c[8] == 'C'|| c[8] == 'c')
                        && (c[9] == 'A'|| c[9] == 'a')
                        && (c[10] == 'T'|| c[10] == 't')
                        && (c[11] == 'E'|| c[11] == 'e'))
                    {
                        s->command = NGX_IMAP_AUTHENTICATE;

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
            if (ch == ' ' && s->quoted) {
                break;
            }

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
            case '\\':
                if (s->quoted) {
                    s->backslash = 1;
                    state = sw_backslash;
                }
                break;
            }
            break;

        case sw_backslash:
            switch (ch) {
            case CR:
            case LF:
                goto invalid;
            default:
                state = sw_argument;
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
            if (ch == '+') {
                state = sw_no_sync_literal_argument;
                break;
            }
            goto invalid;

        case sw_no_sync_literal_argument:
            if (ch == '}') {
                s->no_sync_literal = 1;
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
                if (s->no_sync_literal == 0) {
                    s->state = sw_literal_argument;
                    return NGX_IMAP_NEXT;
                }
                state = sw_literal_argument;
                s->no_sync_literal = 0;
                break;
            default:
                goto invalid;
            }
            break;

        case sw_literal_argument:
            if (s->literal_len && --s->literal_len) {
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
                state = sw_spaces_before_argument;
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
        s->cmd_start = NULL;
        s->quoted = 0;
        s->no_sync_literal = 0;
        s->literal_len = 0;
    }

    s->state = (s->command != NGX_IMAP_AUTHENTICATE) ? sw_start : sw_argument;

    return NGX_OK;

invalid:

    s->state = sw_start;
    s->quoted = 0;
    s->no_sync_literal = 0;
    s->literal_len = 0;

    return NGX_MAIL_PARSE_INVALID_COMMAND;
}


ngx_int_t
ngx_mail_smtp_parse_command(ngx_mail_session_t *s)
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

        /* SMTP command */
        case sw_start:
            if (ch == ' ' || ch == CR || ch == LF) {
                c = s->buffer->start;

                if (p - c == 4) {

                    c0 = ngx_toupper(c[0]);
                    c1 = ngx_toupper(c[1]);
                    c2 = ngx_toupper(c[2]);
                    c3 = ngx_toupper(c[3]);

                    if (c0 == 'H' && c1 == 'E' && c2 == 'L' && c3 == 'O')
                    {
                        s->command = NGX_SMTP_HELO;

                    } else if (c0 == 'E' && c1 == 'H' && c2 == 'L' && c3 == 'O')
                    {
                        s->command = NGX_SMTP_EHLO;

                    } else if (c0 == 'Q' && c1 == 'U' && c2 == 'I' && c3 == 'T')
                    {
                        s->command = NGX_SMTP_QUIT;

                    } else if (c0 == 'A' && c1 == 'U' && c2 == 'T' && c3 == 'H')
                    {
                        s->command = NGX_SMTP_AUTH;

                    } else if (c0 == 'N' && c1 == 'O' && c2 == 'O' && c3 == 'P')
                    {
                        s->command = NGX_SMTP_NOOP;

                    } else if (c0 == 'M' && c1 == 'A' && c2 == 'I' && c3 == 'L')
                    {
                        s->command = NGX_SMTP_MAIL;

                    } else if (c0 == 'R' && c1 == 'S' && c2 == 'E' && c3 == 'T')
                    {
                        s->command = NGX_SMTP_RSET;

                    } else if (c0 == 'R' && c1 == 'C' && c2 == 'P' && c3 == 'T')
                    {
                        s->command = NGX_SMTP_RCPT;

                    } else if (c0 == 'V' && c1 == 'R' && c2 == 'F' && c3 == 'Y')
                    {
                        s->command = NGX_SMTP_VRFY;

                    } else if (c0 == 'E' && c1 == 'X' && c2 == 'P' && c3 == 'N')
                    {
                        s->command = NGX_SMTP_EXPN;

                    } else if (c0 == 'H' && c1 == 'E' && c2 == 'L' && c3 == 'P')
                    {
                        s->command = NGX_SMTP_HELP;

                    } else {
                        goto invalid;
                    }
#if (NGX_MAIL_SSL)
                } else if (p - c == 8) {

                    if ((c[0] == 'S'|| c[0] == 's')
                        && (c[1] == 'T'|| c[1] == 't')
                        && (c[2] == 'A'|| c[2] == 'a')
                        && (c[3] == 'R'|| c[3] == 'r')
                        && (c[4] == 'T'|| c[4] == 't')
                        && (c[5] == 'T'|| c[5] == 't')
                        && (c[6] == 'L'|| c[6] == 'l')
                        && (c[7] == 'S'|| c[7] == 's'))
                    {
                        s->command = NGX_SMTP_STARTTLS;

                    } else {
                        goto invalid;
                    }
#endif
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
                if (s->args.nelts <= 10) {
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

    s->state = (s->command != NGX_SMTP_AUTH) ? sw_start : sw_argument;

    return NGX_OK;

invalid:

    s->state = sw_start;
    s->arg_start = NULL;

    return NGX_MAIL_PARSE_INVALID_COMMAND;
}


ngx_int_t
ngx_mail_auth_parse(ngx_mail_session_t *s, ngx_connection_t *c)
{
    ngx_str_t                 *arg;

#if (NGX_MAIL_SSL)
    if (ngx_mail_starttls_only(s, c)) {
        return NGX_MAIL_PARSE_INVALID_COMMAND;
    }
#endif

    if (s->args.nelts == 0) {
        return NGX_MAIL_PARSE_INVALID_COMMAND;
    }

    arg = s->args.elts;

    if (arg[0].len == 5) {

        if (ngx_strncasecmp(arg[0].data, (u_char *) "LOGIN", 5) == 0) {

            if (s->args.nelts == 1) {
                return NGX_MAIL_AUTH_LOGIN;
            }

            if (s->args.nelts == 2) {
                return NGX_MAIL_AUTH_LOGIN_USERNAME;
            }

            return NGX_MAIL_PARSE_INVALID_COMMAND;
        }

        if (ngx_strncasecmp(arg[0].data, (u_char *) "PLAIN", 5) == 0) {

            if (s->args.nelts == 1) {
                return NGX_MAIL_AUTH_PLAIN;
            }

            if (s->args.nelts == 2) {
                return ngx_mail_auth_plain(s, c, 1);
            }
        }

        return NGX_MAIL_PARSE_INVALID_COMMAND;
    }

    if (arg[0].len == 8) {

        if (s->args.nelts != 1) {
            return NGX_MAIL_PARSE_INVALID_COMMAND;
        }

        if (ngx_strncasecmp(arg[0].data, (u_char *) "CRAM-MD5", 8) == 0) {
            return NGX_MAIL_AUTH_CRAM_MD5;
        }
    }

    return NGX_MAIL_PARSE_INVALID_COMMAND;
}
