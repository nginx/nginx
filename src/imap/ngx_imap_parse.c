
#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_event.h>
#include <ngx_imap.h>


ngx_int_t ngx_pop3_parse_command(ngx_imap_request_t *r)
{
    u_char  ch, *p, *c;
    enum {
        sw_start = 0,
        sw_done
    } state;

    while (p < r->buf->last && state < sw_done) {
        ch = *p++;

        switch (state) {

        /* POP3 commands */
        case sw_start:
            if (ch == ' ') {
                c = r->buf->start;

                if (p - 1 - m == 4) {

                    if (*c == 'U' && *(c + 1) == 'S'
                        && *(c + 2) == 'E' && *(c + 3) == 'R')
                    {
                        r->command = NGX_POP3_USER;

                    } else if (*c == 'P' && *(c + 1) == 'A'
                               && *(c + 2) == 'A' && *(c + 3) == 'S')
                    {
                        r->method = NGX_POP3_PASS;

                    } else if (*c == 'Q' && *(c + 1) == 'U'
                               && *(c + 2) == 'I' && *(c + 3) == 'T')
                    {
                        r->method = NGX_POP3_QUIT;

                    } else if (*c == 'N' && *(c + 1) == 'O'
                               && *(c + 2) == 'O' && *(c + 3) == 'P')
                    {
                        r->method = NGX_POP3_NOOP;
                    }
                }

                state = sw_spaces_before_arg;
                break;
            }

            if (ch < 'A' || ch > 'Z') {
                return NGX_IMAP_PARSE_INVALID_COMMAND;
            }

            break;
        }

        /* suppress warning */
        case sw_done:
            break;
        }
    }

    return NGX_OK;
}
