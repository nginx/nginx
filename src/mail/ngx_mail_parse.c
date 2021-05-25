
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


static ngx_int_t ngx_mail_imap_parse_id_params(ngx_mail_session_t *s, u_char *p);

typedef enum {
        swi_start = 0,
        swi_spaces_before_command,
        swi_command,
        swi_spaces_before_argument,
        swi_argument,
        swi_backslash,
        swi_literal,
        swi_no_sync_literal_argument,
        swi_start_literal_argument,
        swi_literal_argument,
        swi_end_literal_argument,
        swi_almost_done,
        swi_begin_idparams = 15,
        swi_end_idparams,
        swi_done_idparams,
        swi_almost_done_idparams,
        swi_begin_idfield,
        swi_id_n,
        swi_id_ni,
        swi_id_nil,
        swi_idfield,
        swi_idfield_len,
        swi_idfield_len_plus,
        swi_begin_idfield_l,
        swi_idfield_l,
        swi_SP_before_idvalue,
        swi_X_before_idfield,
        swi_begin_idvalue,
        swi_idvalue,
        swi_idvalue_n,
        swi_idvalue_ni,
        swi_idvalue_nil,
        swi_idvalue_len,
        swi_idvalue_len_plus,
        swi_begin_idvalue_l,
        swi_idvalue_l,
} ngx_imap_parse_state_e;

typedef enum {
    swp_start = 0,
    swp_spaces_before_argument,
    swp_argument,
    swp_almost_done
} ngx_pop3_parse_state_e;

typedef enum {
    sws_start = 0,
    sws_command,
    sws_spaces_before_argument,
    sws_argument,
    sws_almost_done,
    sws_invalid
} ngx_smtp_parse_state_e;

inline void ngx_mail_set_imap_parse_state_start(ngx_mail_session_t * s) {
    s->state = swi_start;
}

inline void ngx_mail_set_pop3_parse_state_start(ngx_mail_session_t * s) {
    s->state = swp_start;
}

inline void ngx_mail_set_smtp_parse_state_start(ngx_mail_session_t * s) {
    s->state = sws_start;
}

inline void ngx_mail_set_imap_parse_state_argument(ngx_mail_session_t * s) {
    s->state = swi_argument;
}

inline void ngx_mail_set_pop3_parse_state_argument(ngx_mail_session_t * s) {
    s->state = swp_argument;
}

inline void ngx_mail_set_smtp_parse_state_argument(ngx_mail_session_t * s) {
    s->state = sws_argument;
}

inline void ngx_mail_reset_parse_buffer(ngx_mail_session_t * s) {
    s->buffer->pos = s->buffer->start;
    s->buffer->last = s->buffer->start;
}


ngx_int_t
ngx_mail_pop3_parse_command(ngx_mail_session_t *s)
{
    u_char      ch, *p, *c, c0, c1, c2, c3;
    ngx_str_t  *arg;

    ngx_pop3_parse_state_e state = s->state;

    for (p = s->buffer->pos; p < s->buffer->last; p++) {
        ch = *p;

        switch (state) {

        /* POP3 command */
        case swp_start:
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
                    state = swp_spaces_before_argument;
                    break;
                case CR:
                    state = swp_almost_done;
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

        case swp_spaces_before_argument:
            switch (ch) {
            case ' ':
                break;
            case CR:
                state = swp_almost_done;
                s->arg_end = p;
                break;
            case LF:
                s->arg_end = p;
                goto done;
            default:
                if (s->args.nelts <= 2) {
                    state = swp_argument;
                    s->arg_start = p;
                    break;
                }
                goto invalid;
            }
            break;

        case swp_argument:
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
                    state = swp_spaces_before_argument;
                    break;
                case CR:
                    state = swp_almost_done;
                    break;
                case LF:
                    goto done;
                }
                break;

            default:
                break;
            }
            break;

        case swp_almost_done:
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

    return NGX_OK;

invalid:

    s->state = swp_start;
    s->arg_start = NULL;

    return NGX_MAIL_PARSE_INVALID_COMMAND;
}


ngx_int_t
ngx_mail_imap_parse_command(ngx_mail_session_t *s)
{
    u_char      ch, *p, *c;
    ngx_int_t   rc;
    ngx_str_t  *arg;
    p = NULL; /* for avoid warning */
    ngx_imap_parse_state_e state = s->state;

    if(state >= swi_begin_idparams) { /* beyond the states handled in ID parse function */
        rc = ngx_mail_imap_parse_id_params(s, s->buffer->pos);
        switch (rc) {
        case NGX_OK:
             goto done;
        case NGX_MAIL_PARSE_INVALID_COMMAND:
             goto invalid;
        default: /* NGX_ERROR, NGX_AGAIN or NGX_IMAP_NEXT */
             return rc;
        }
    }

    for (p = s->buffer->pos; p < s->buffer->last; p++) {
        ch = *p;

        switch (state) {

        /* IMAP tag */
        case swi_start:
            switch (ch) {
            case ' ':
                s->tag.len = p - s->buffer->start;
                s->tag.data = s->buffer->start;
                state = swi_spaces_before_command;
                s->eargs = 0;
                break;
            case CR: /* walk through */
            case LF: /* walk through */
            case '\x0':
                s->tag.len = p - s->buffer->start;
                s->tag.data = s->buffer->start;
                s->state = swi_start;
                return NGX_MAIL_PARSE_INVALID_COMMAND;
            }
            break;

        case swi_spaces_before_command:
            switch (ch) {
            case ' ':
                break;
            case CR:
                s->state = swi_start;
                return NGX_MAIL_PARSE_INVALID_COMMAND;
            case LF:
                s->state = swi_start;
                return NGX_MAIL_PARSE_INVALID_COMMAND;
            case '\x0':
                s->state = swi_start;
                return NGX_MAIL_PARSE_INVALID_COMMAND;
            default:
                s->cmd_start = p;
                state = swi_command;
                break;
            }
            break;

        case swi_command:
            if (ch == ' ' || ch == CR || ch == LF) {

                c = s->cmd_start;

                switch (p - c) {

                case 2:
                    if ((c[0] == 'I' || c[0] == 'i')
                        && (c[1] == 'D' || c[1] == 'd'))
                    {
                        s->command = NGX_IMAP_ID;
                        /* RFC 2971 */
                        ngx_int_t rc;
                        s->state = swi_begin_idparams;
                        p++; //move to the next character
                        rc = ngx_mail_imap_parse_id_params(s, p);
                        switch (rc) {
                        case NGX_OK:
                            goto done;
                        case NGX_MAIL_PARSE_INVALID_COMMAND:
                            goto invalid;
                        default: /* NGX_ERROR or NGX_IMAP_NEXT */
                            return rc;
                        }
                    } else {
                        goto invalid;
                    }
                    break;

                case 4:
                    if ((c[0] == 'N' || c[0] == 'n')
                        && (c[1] == 'O'|| c[1] == 'o')
                        && (c[2] == 'O'|| c[2] == 'o')
                        && (c[3] == 'P'|| c[3] == 'p'))
                    {
                        s->command = NGX_IMAP_NOOP;
                        s->eargs = 0;
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
                        s->eargs = 2;
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
                        s->eargs = 0;
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
                        s->eargs = 0;
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
                        s->eargs = 0;
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
                        if (ch != ' ') {
                            goto invalid;
                        } else {
                            s->command = NGX_IMAP_AUTHENTICATE;
                            s->eargs = 1;
                        }

                    } else {
                        goto invalid;
                    }
                    break;

                default:
                    goto invalid;
                }

                switch (ch) {
                case ' ':
                    if (s->command == NGX_IMAP_CAPABILITY) {
                        goto invalid;
                    }
                    state = swi_spaces_before_argument;
                    break;
                case CR:
                    state = swi_almost_done;
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

        case swi_spaces_before_argument:
            switch (ch) {
            case ' ':
                break;
            case CR:
                if (s->args.nelts == 0) {
                    goto invalid; //no argument
                }
                state = swi_almost_done;
                s->arg_end = p;
                break;
            case LF:
                if ( s->args.nelts == 0) {
                    goto invalid; // no argument
                }
                s->arg_end = p;
                goto done;
            case '"':
                if (s->args.nelts <= s->eargs) {
                    s->quoted = 1;
                    s->arg_start = p + 1;
                    state = swi_argument;
                    break;
                }
                goto invalid;
            case '{':
                if (s->args.nelts <= s->eargs) {
                    state = swi_literal;
                    break;
                }
                goto invalid;
            default:
                if (s->args.nelts <= s->eargs) {
                    s->arg_start = p;
                    state = swi_argument;
                    break;
                }
                goto invalid;
            }
            break;

        case swi_argument:
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
                    state = swi_spaces_before_argument;
                    break;
                case CR:
                    state = swi_almost_done;
                    break;
                case LF:
                    goto done;
                }
                break;
            case '\\':
                if (s->quoted) {
                    s->backslash = 1;
                    state = swi_backslash;
                }
                break;
            }
            break;

        case swi_backslash:
            switch (ch) {
            case CR:
            case LF:
                goto invalid;
            // (RFC3501)
            // a backslash may only escape another backslash, or a double quote
            case '\\':
            case '"':
                state = swi_argument;
                break;
            default:
                goto invalid;
            }
            break;

        case swi_literal:
            if (ch >= '0' && ch <= '9') {
                s->literal_len = s->literal_len * 10 + (ch - '0');
                break;
            }
            if (ch == '}') {
                state = swi_start_literal_argument;
                break;
            }
            if (ch == '+') {
                state = swi_no_sync_literal_argument;
                break;
            }
            goto invalid;

        case swi_no_sync_literal_argument:
            if (ch == '}') {
                s->no_sync_literal = 1;
                state = swi_start_literal_argument;
                break;
            }
            goto invalid;

        case swi_start_literal_argument:
            switch (ch) {
            case CR:
                break;
            case LF:
                s->buffer->pos = p + 1;
                s->arg_start = p + 1;
                if (s->no_sync_literal == 0) {
                    s->state = swi_literal_argument;
                    return NGX_IMAP_NEXT;
                }
                state = swi_literal_argument;
                s->no_sync_literal = 0;
                break;
            default:
                goto invalid;
            }
            break;

        case swi_literal_argument:
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
            state = swi_end_literal_argument;

            break;

        case swi_end_literal_argument:
            switch (ch) {
            case '{':
                if (s->args.nelts <= s->eargs) {
                    state = swi_literal;
                    break;
                }
                goto invalid;
            case CR:
                state = swi_almost_done;
                break;
            case LF:
                goto done;
            default:
                state = swi_spaces_before_argument;
                break;
            }
            break;

        case swi_almost_done:
            switch (ch) {
            case LF:
                goto done;
            default:
                goto invalid;
            }
        default:
            break; /* for avoid warning only */
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

    return NGX_OK;

invalid:

    s->state = swi_start;
    s->quoted = 0;
    s->no_sync_literal = 0;
    s->literal_len = 0;

    return NGX_MAIL_PARSE_INVALID_COMMAND;
}


static ngx_int_t
ngx_mail_imap_parse_id_params(ngx_mail_session_t *s, u_char *p)
{
    u_char ch;
    ngx_imap_parse_state_e state;
    ngx_str_t *arg;
    state = s->state;

    for (; p < s->buffer->last; p++) {
        ch = *p;
        switch(state) {
        case swi_begin_idparams:
            switch (ch) {
                case '(':
                    state = swi_begin_idfield;
                    break;
                case 'n':
                case 'N':
                    state = swi_id_n;
                    break;
                default:
                    ngx_log_debug1 (NGX_LOG_DEBUG_MAIL, s->connection->log, 0,
                        "swi_begin_idparams: expected (/n/N, got '%c'", ch);
                    return NGX_MAIL_PARSE_INVALID_COMMAND;
            }
            break;

        case swi_end_idparams:
            switch (ch)
            {
                case ')':
                    state = swi_done_idparams;
                    break;
                default:
                    ngx_log_debug1 (NGX_LOG_DEBUG_MAIL, s->connection->log, 0,
                        "swi_end_idparams: expected ), got '%c'", ch);
                    return NGX_MAIL_PARSE_INVALID_COMMAND;
            }

            break;

        case swi_done_idparams:
            switch (ch)
            {
                case CR:
                    state = swi_almost_done;
                    break;
                case LF:
                    return NGX_OK;
                default:
                    ngx_log_debug1 (NGX_LOG_DEBUG_MAIL, s->connection->log, 0,
                        "swi_done_idparams: expected CR/LF, got '%c'", ch);
                    return NGX_MAIL_PARSE_INVALID_COMMAND;
            }
            break;

        case swi_id_n:
            switch (ch) {
                case 'i':
                case 'I':
                    state = swi_id_ni;
                    break;
                default:
                    ngx_log_debug1 (NGX_LOG_DEBUG_MAIL, s->connection->log, 0,
                        "swi_id_n: expected i/I, got '%c'", ch);
                    return NGX_MAIL_PARSE_INVALID_COMMAND;
            }
            break;

        case swi_id_ni:
            switch (ch) {
                case 'l':
                case 'L':
                    state = swi_id_nil;
                    break;
                default:
                    ngx_log_debug1 (NGX_LOG_DEBUG_MAIL, s->connection->log, 0,
                        "swi_id_ni: expected l/L, got '%c'", ch);
                    return NGX_MAIL_PARSE_INVALID_COMMAND;
            }
            break;

        case swi_id_nil:
            switch (ch) {
                case CR:
                    state = swi_almost_done;
                    break;
                case LF:
                    return NGX_OK;
                default:
                    return NGX_MAIL_PARSE_INVALID_COMMAND;
            }
            break;

        case swi_begin_idfield:
            switch (ch) {
                case '{':
                    s->literal_len = 0;
                    state = swi_idfield_len;
                    break;
                case '"':
                    s->quoted = 1;
                    s->backslash = 0;
                    s->arg_start = p+1;
                    state = swi_idfield;
                    break;
                default:
                    ngx_log_debug1 (NGX_LOG_DEBUG_MAIL, s->connection->log, 0,
                        "swi_begin_idfield: expected \"/{, got '%c'", ch);
                     return NGX_MAIL_PARSE_INVALID_COMMAND;
            }
            break;

        case swi_idfield_len:
            if (ch >= '0' && ch <= '9') {
                s->literal_len = s->literal_len * 10 + (ch - '0');
                break;
            }
            if (ch == '+') {
                state = swi_idfield_len_plus;   /* literalplus stuff */
                break;
            }
            if (ch == '}') {
                s->no_sync_literal = 0;
                state = swi_begin_idfield_l;
                break;
            }
            ngx_log_debug1 (NGX_LOG_DEBUG_MAIL, s->connection->log, 0,
                "swi_idfield_len: expected 0-9/+/}, got '%c'", ch);
            return NGX_MAIL_PARSE_INVALID_COMMAND;

        case swi_idfield_len_plus:
            if (ch == '}') {
                s->no_sync_literal = 1;
                state = swi_begin_idfield_l;
                break;
            }
            ngx_log_debug1 (NGX_LOG_DEBUG_MAIL, s->connection->log, 0,
                "swi_idfield_len_plus: expected }, got '%c'", ch);
            return NGX_MAIL_PARSE_INVALID_COMMAND;

        case swi_begin_idfield_l:
            switch (ch)
            {
                case CR:
                    break;
                case LF:
                    if (s->literal_len) {
                        s->buffer->pos = p + 1;
                        s->arg_start = p + 1;
                        state = swi_idfield_l;
                    } else {
                        s->buffer->pos = p + 1;
                        s->arg_start = NULL;
                        arg = ngx_array_push (&s->args);
                        if (arg == NULL) { return NGX_ERROR; }
                        arg->data = (u_char *)"";
                        arg->len = 0;
                        state = swi_SP_before_idvalue;
                    }
                    if (s->no_sync_literal == 1) {
                        s->no_sync_literal = 0;
                        break;
                    } else {
                        s->state = state;
                        return NGX_IMAP_NEXT;
                    }
                default:
                    ngx_log_debug1 (NGX_LOG_DEBUG_MAIL, s->connection->log, 0,
                        "swi_begin_idfield_l: expected CR/LF, got '%c'", ch);
                    return NGX_MAIL_PARSE_INVALID_COMMAND;
            }
            break;

        case swi_idfield_l:
            if (s->literal_len && --s->literal_len) {
                break;
            }

            arg = ngx_array_push (&s->args);
            if (arg == NULL) {
                return NGX_ERROR;
            }

            arg->len = p + 1 - s->arg_start;
            arg->data = s->arg_start;
            s->arg_start = NULL;
            state = swi_SP_before_idvalue;
            break;

        case swi_idfield:
            switch (ch) {
                case '\\':
                    if (!s->backslash) {
                        s->backslash = 1;
                    } else {
                        if (ch == '\\' && ch == '"')
                            s->backslash = 0;
                        else {
                            ngx_log_debug1 (NGX_LOG_DEBUG_MAIL,
                              s->connection->log, 0,
                              "swi_idfield: \\ escapes non-quoted special '%c'",
                              ch);
                            return NGX_MAIL_PARSE_INVALID_COMMAND;
                        }
                    }
                    break;

                case '"':
                    if (s->backslash) {
                        s->backslash = 0;
                        break;
                    }
                    s->quoted = 0;
                    arg = ngx_array_push(&s->args);
                    if (arg == NULL) {
                        return NGX_ERROR;
                    }

                    arg->len = p - s->arg_start;
                    arg->data = s->arg_start;
                    s->arg_start = NULL;
                    state = swi_SP_before_idvalue;
                    break;

                case CR:
                case LF:
                    ngx_log_debug0 (NGX_LOG_DEBUG_MAIL, s->connection->log, 0,
                        "swi_idfield: CR/LF breaks id field");
                    return NGX_MAIL_PARSE_INVALID_COMMAND;
                default:
                    break;
            }
            break;

        case swi_begin_idvalue:
            switch (ch)
            {
                case '"':
                    s->quoted = 1;
                    s->backslash = 0;
                    s->arg_start = p+1;
                    state = swi_idvalue;
                    break;
                case 'n':
                case 'N':
                    state = swi_idvalue_n;
                    break;
                case '{':
                    s->literal_len = 0;
                    state = swi_idvalue_len;
                    break;
                default:
                    ngx_log_debug1 (NGX_LOG_DEBUG_MAIL, s->connection->log, 0,
                        "swi_begin_idvalue: expected \"/n/N/{, got '%c'", ch);
                    return NGX_MAIL_PARSE_INVALID_COMMAND;
            }
            break;

        case swi_idvalue_len:
            if (ch >= '0' && ch <= '9') {
                s->literal_len = s->literal_len + (ch - '0');
                break;
            }
            if (ch == '+') {
                state = swi_idvalue_len_plus;
                break;
            }
            if (ch == '}') {
                s->no_sync_literal = 0;
                state = swi_begin_idvalue_l;
                break;
            }
            ngx_log_debug1 (NGX_LOG_DEBUG_MAIL, s->connection->log, 0,
                "swi_idvalue_len: expected 0-9/}, got '%c'", ch);
            return NGX_MAIL_PARSE_INVALID_COMMAND;

        case swi_idvalue_len_plus:
            if (ch == '}') {
                s->no_sync_literal = 1;
                state = swi_begin_idvalue_l;
                break;
            }
            ngx_log_debug1 (NGX_LOG_DEBUG_MAIL, s->connection->log, 0,
                "swi_idvalue_len_plus: expected }, got '%c'", ch);
            return NGX_MAIL_PARSE_INVALID_COMMAND;

        case swi_begin_idvalue_l:
            switch (ch)
            {
                case CR:
                    break;
                case LF:
                    if (s->literal_len) {
                        s->buffer->pos = p + 1;
                        s->arg_start = p + 1;
                        state = swi_idvalue_l;
                    } else {
                        s->buffer->pos = p + 1;
                        s->arg_start = NULL;
                        arg = ngx_array_push (&s->args);
                        if (arg == NULL) { return NGX_ERROR; }
                        arg->data = (u_char *)"";
                        arg->len = 0;
                        state = swi_X_before_idfield;
                    }
                    if (s->no_sync_literal == 1) {
                        s->no_sync_literal = 0;
                        break;
                    } else {
                        s->state = state;
                        return NGX_IMAP_NEXT;
                    }
                default:
                    ngx_log_debug1 (NGX_LOG_DEBUG_MAIL, s->connection->log, 0,
                        "swi_begin_idvalue_l: expected CR/LF, got '%c'", ch);
                    return NGX_MAIL_PARSE_INVALID_COMMAND;
            }
            break;

        case swi_idvalue_l:
            if (s->literal_len && --s->literal_len) {
                break;
            }

            arg = ngx_array_push (&s->args);
            if (arg == NULL) {
                return NGX_ERROR;
            }

            arg->len = p + 1 - s->arg_start;
            arg->data = s->arg_start;
            s->arg_start = NULL;
            state = swi_X_before_idfield;
            break;

        case swi_idvalue_n:
            switch (ch)
            {
                case 'i':
                case 'I':
                    state = swi_idvalue_ni;
                    break;
                default:
                    ngx_log_debug1 (NGX_LOG_DEBUG_MAIL, s->connection->log, 0,
                        "swi_idvalue_n: expected i/I, got '%c'", ch);
                    return NGX_MAIL_PARSE_INVALID_COMMAND;
            }
            break;

        case swi_idvalue_ni:
            switch (ch)
            {
                case 'l':
                case 'L':
                    state = swi_idvalue_nil;
                    break;
                default:
                    ngx_log_debug1 (NGX_LOG_DEBUG_MAIL, s->connection->log, 0,
                        "swi_idvalue_ni: expected l/L, got '%c'", ch);
                    return NGX_MAIL_PARSE_INVALID_COMMAND;
            }
            break;

        case swi_idvalue_nil:
            switch (ch)
            {
                case ' ':
                    state = swi_begin_idfield;
                    arg = ngx_array_push (&s->args);
                    if (arg == NULL) {
                        return NGX_ERROR;
                    }
                    arg->data = (u_char *)"";
                    arg->len = 0;
                    break;
                case ')':
                    state = swi_done_idparams;
                    arg = ngx_array_push (&s->args);
                    if (arg == NULL) {
                        return NGX_ERROR;
                    }
                    arg->data = (u_char *)"";
                    arg->len = 0;
                    break;
                default:
                    ngx_log_debug1 (NGX_LOG_DEBUG_MAIL, s->connection->log, 0,
                        "swi_idvalue_nil: expected SP/), got '%c'", ch);
                    return NGX_MAIL_PARSE_INVALID_COMMAND;
            }
            break;

        case swi_SP_before_idvalue:
            switch (ch)
            {
                case ' ':
                    state = swi_begin_idvalue;
                    break;
                default:
                    ngx_log_debug1 (NGX_LOG_DEBUG_MAIL, s->connection->log, 0,
                        "swi_SP_before_idvalue: expected SP, got '%c'", ch);
                    return NGX_MAIL_PARSE_INVALID_COMMAND;
            }
            break;

        case swi_X_before_idfield:
            switch (ch)
            {
                case ' ':
                    state = swi_begin_idfield;
                    break;
                case ')':
                    state = swi_done_idparams;
                    break;
                default:
                    ngx_log_debug1 (NGX_LOG_DEBUG_MAIL, s->connection->log, 0,
                        "swi_X_before_idfield: expected SP/), got '%c'", ch);
                    return NGX_MAIL_PARSE_INVALID_COMMAND;
            }
            break;

        case swi_idvalue:
            switch (ch)
            {
                case '\\':
                    if (!s->backslash) {
                        s->backslash = 1;
                    } else {
                        if (ch == '\\' || ch == '"')
                            s->backslash = 0;
                        else {
                            ngx_log_debug1 (NGX_LOG_DEBUG_MAIL,
                              s->connection->log, 0,
                              "swi_idvalue: \\ escapes non-quoted special '%c'",
                              ch);
                            return NGX_MAIL_PARSE_INVALID_COMMAND;
                        }
                    }
                    break;

                case '"':
                    if (s->backslash)
                    {
                        s->backslash = 0;
                        break;
                    }
                    s->quoted = 0;
                    arg = ngx_array_push (&s->args);
                    if (arg == NULL) {
                        return NGX_ERROR;
                    }

                    arg->len = p - s->arg_start;
                    arg->data = s->arg_start;
                    s->arg_start = NULL;
                    state = swi_X_before_idfield;
                    break;

                case CR:
                case LF:
                    ngx_log_debug0 (NGX_LOG_DEBUG_MAIL, s->connection->log, 0,
                        "swi_idvalue: CR/LF breaks id value");
                    return NGX_MAIL_PARSE_INVALID_COMMAND;
                default:
                    break;
            }
            break;
        case swi_almost_done:
            switch (ch) {
            case LF:
                return NGX_OK;
            default:
                return NGX_MAIL_PARSE_INVALID_COMMAND;
            }

        default:
            break; /* for avoid warning only */
        } /* switch (state) */
    } /* for */

    s->buffer->pos = p;
    s->state = state;

    return NGX_AGAIN;
}


ngx_int_t
ngx_mail_smtp_parse_command(ngx_mail_session_t *s)
{
    u_char      ch, *p, *c, c0, c1, c2, c3;
    ngx_str_t  *arg;

    ngx_smtp_parse_state_e state = s->state;

    for (p = s->buffer->pos; p < s->buffer->last; p++) {
        ch = *p;

        switch (state) {

        /* SMTP command */
        case sws_start:
            s->cmd_start = p;
            state = sws_command;

            /* fall through */

        case sws_command:
            if (ch == ' ' || ch == CR || ch == LF) {
                c = s->cmd_start;

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

                s->cmd.data = s->cmd_start;
                s->cmd.len = p - s->cmd_start;

                switch (ch) {
                case ' ':
                    state = sws_spaces_before_argument;
                    break;
                case CR:
                    state = sws_almost_done;
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

        case sws_invalid:
            goto invalid;

        case sws_spaces_before_argument:
            switch (ch) {
            case ' ':
                break;
            case CR:
                state = sws_almost_done;
                s->arg_end = p;
                break;
            case LF:
                s->arg_end = p;
                goto done;
            default:
                if (s->args.nelts <= 10) {
                    state = sws_argument;
                    s->arg_start = p;
                    break;
                }
                goto invalid;
            }
            break;

        case sws_argument:
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
                    state = sws_spaces_before_argument;
                    break;
                case CR:
                    state = sws_almost_done;
                    break;
                case LF:
                    goto done;
                }
                break;

            default:
                break;
            }
            break;

        case sws_almost_done:
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

    return NGX_OK;

invalid:

    s->state = sws_invalid;
    s->arg_start = NULL;

    /* skip invalid command till LF */

    for (p = s->buffer->pos; p < s->buffer->last; p++) {
        if (*p == LF) {
            s->state = sws_start;
            p++;
            break;
        }
    }

    s->buffer->pos = p;

    return NGX_MAIL_PARSE_INVALID_COMMAND;
}


ngx_int_t
ngx_mail_auth_parse(ngx_mail_session_t *s, ngx_connection_t *c)
{
    ngx_str_t                 *arg;

    if (s->args.nelts == 0) {
        return NGX_MAIL_PARSE_INVALID_COMMAND;
    }

    arg = s->args.elts;

    if (arg[0].len == 5) {

        if (ngx_strncasecmp(arg[0].data, (u_char *) "LOGIN", 5) == 0) {

            if (s->args.nelts == 1) {
                return NGX_MAIL_AUTH_LOGIN;
            }

            if (s->args.nelts == 2) { //initial response
                return NGX_MAIL_AUTH_LOGIN_USERNAME;
            }

            return NGX_MAIL_PARSE_INVALID_COMMAND;
        }

        if (ngx_strncasecmp(arg[0].data, (u_char *) "PLAIN", 5) == 0) {

            if (s->args.nelts == 1) {
                return NGX_MAIL_AUTH_PLAIN;
            }

            if (s->args.nelts == 2) { //initial response
                return NGX_MAIL_AUTH_PLAIN_IR;
            }
        }

        return NGX_MAIL_PARSE_INVALID_COMMAND;
    }

    if (arg[0].len == 6) {
        if (ngx_strncasecmp(arg[0].data, (u_char *) "GSSAPI", 6) == 0 ) {
            if (s->args.nelts == 1) {
                return NGX_MAIL_AUTH_GSSAPI;
            }

            if (s->args.nelts == 2) { //initial response
                return NGX_MAIL_AUTH_GSSAPI_IR;
            }
        } 
       
        return NGX_MAIL_PARSE_INVALID_COMMAND;
    }

    if (arg[0].len == 8) {

        if (ngx_strncasecmp(arg[0].data, (u_char *) "CRAM-MD5", 8) == 0) {

            if (s->args.nelts != 1) {
                return NGX_MAIL_PARSE_INVALID_COMMAND;
            }

            return NGX_MAIL_AUTH_CRAM_MD5;
        }

        if (ngx_strncasecmp(arg[0].data, (u_char *) "EXTERNAL", 8) == 0) {

            if (s->args.nelts == 1) {
                return NGX_MAIL_AUTH_EXTERNAL;
            }

            if (s->args.nelts == 2) {
                return ngx_mail_auth_external(s, c, 1);
            }
        }

        return NGX_MAIL_PARSE_INVALID_COMMAND;
    }

    return NGX_MAIL_PARSE_INVALID_AUTH_MECH;
}
