
#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_types.h>
#include <ngx_alloc.h>
#include <ngx_array.h>
#include <ngx_hunk.h>
#include <ngx_connection.h>
#include <ngx_sendv.h>
#include <ngx_sendfile.h>
#include <ngx_event_write.h>


ngx_chain_t *ngx_event_write(ngx_connection_t *c, ngx_chain_t *in, off_t flush)
{
    int           rc, i, last;
    u_int         flags;
    char         *prev;
    off_t         sent;
    ngx_iovec_t  *iov;
    ngx_array_t  *header, *trailer;
    ngx_hunk_t   *file;
    ngx_chain_t  *ch;

    ch = in;
    file = NULL;
    last = 0;

    ngx_test_null(header, ngx_create_array(c->pool, 10, sizeof(ngx_iovec_t)),
                  (ngx_chain_t *) -1);

    ngx_test_null(trailer, ngx_create_array(c->pool, 10, sizeof(ngx_iovec_t)),
                  (ngx_chain_t *) -1);

    do {
        header->nelts = 0;
        trailer->nelts = 0;

        if (ch->hunk->type & NGX_HUNK_IN_MEMORY) {
            prev = NULL;
            iov = NULL;

            while (ch && (ch->hunk->type & NGX_HUNK_IN_MEMORY))
            {
                if (prev == ch->hunk->pos.mem) {
                    iov->ngx_iov_len += ch->hunk->last.mem - ch->hunk->pos.mem;

                } else {
                    ngx_test_null(iov, ngx_push_array(header),
                                  (ngx_chain_t *) -1);
                    iov->ngx_iov_base = ch->hunk->pos.mem;
                    iov->ngx_iov_len = ch->hunk->last.mem - ch->hunk->pos.mem;
                    prev = ch->hunk->last.mem;
                }

                if (ch->hunk->type & NGX_HUNK_LAST) {
                    last = 1;
                }

                ch = ch->next;
            }
        }

        if (ch && (ch->hunk->type & NGX_HUNK_FILE)) {
            file = ch->hunk;
            ch = ch->next;

            if (ch->hunk->type & NGX_HUNK_LAST) {
                last = 1;
            }
        }

#if (HAVE_MAX_SENDFILE_IOVEC)
        if (file && header->nelts > HAVE_MAX_SENDFILE_IOVEC) {
            rc = ngx_sendv(c->fd, (ngx_iovec_t *) header->elts, header->nelts,
                           &sent);
        } else {
#endif
            if (ch && ch->hunk->type & NGX_HUNK_IN_MEMORY) {
                prev = NULL;
                iov = NULL;

                while (ch && (ch->hunk->type & NGX_HUNK_IN_MEMORY)) {

                    if (prev == ch->hunk->pos.mem) {
                        iov->ngx_iov_len +=
                                        ch->hunk->last.mem - ch->hunk->pos.mem;

                    } else {
                        ngx_test_null(iov, ngx_push_array(trailer),
                                      (ngx_chain_t *) -1);
                        iov->ngx_iov_base = ch->hunk->pos.mem;
                        iov->ngx_iov_len =
                                        ch->hunk->last.mem - ch->hunk->pos.mem;
                        prev = ch->hunk->last.mem;
                    }

                    if (ch->hunk->type & NGX_HUNK_LAST) {
                        last = 1;
                    }

                    ch = ch->next;
                }
            }

            if (file) {
                flags = ngx_sendfile_flags;
#if (HAVE_SENDFILE_DISCONNECT)
                if (last && c->close) {
                    flags |= HAVE_SENDFILE_DISCONNECT;
                }
#endif
                rc = ngx_sendfile(c,
                                  (ngx_iovec_t *) header->elts, header->nelts,
                                  file->file->fd, file->pos.file,
                                  (size_t) (file->last.file - file->pos.file),
                                  (ngx_iovec_t *) trailer->elts, trailer->nelts,
                                  &sent, flags);

#if (HAVE_AIO_EVENT) && !(HAVE_IOCP_EVENT)
            } else if (ngx_event_flags & NGX_HAVE_AIO_EVENT) {

                sent = 0;
                rc = NGX_AGAIN;
                iov = (ngx_iovec_t *) header->elts;
                for (i = 0; i < header->nelts; i++) {
                    rc = ngx_event_aio_write(c, iov[i].ngx_iov_base,
                                             iov[i].ngx_iov_len);

                    if (rc > 0) {
                        sent += rc;
                    } else {
                        break;
                    }

                    if (rc < (int) iov->ngx_iov_len) {
                        break;
                    }
                }
#endif
            } else {
                rc = ngx_sendv(c, (ngx_iovec_t *) header->elts, header->nelts);

                sent = rc > 0 ? rc: 0;

#if (NGX_DEBUG_EVENT_WRITE)
                ngx_log_debug(c->log, "sendv: " OFF_FMT _ sent);
#endif
            }
#if (HAVE_MAX_SENDFILE_IOVEC)
        }
#endif
        if (rc == NGX_ERROR)
            return (ngx_chain_t *) NGX_ERROR;

        c->sent += sent;
        flush -= sent;

        for (ch = in; ch; ch = ch->next) {

#if (NGX_DEBUG_EVENT_WRITE)
            ngx_log_debug(c->log, "event write: %x " QX_FMT " " OFF_FMT _
                          ch->hunk->type _
                          ch->hunk->pos.file _
                          ch->hunk->last.file - ch->hunk->pos.file);
#endif

            if (sent >= ch->hunk->last.file - ch->hunk->pos.file) {
                sent -= ch->hunk->last.file - ch->hunk->pos.file;
                ch->hunk->pos.file = ch->hunk->last.file;

#if (NGX_DEBUG_EVENT_WRITE)
                ngx_log_debug(c->log, "event write: " QX_FMT " 0 " OFF_FMT _
                              ch->hunk->pos.file _ sent);
#endif

/*
                if (ch->hunk->type & NGX_HUNK_LAST)
                   break;
*/

                continue;
            }

            ch->hunk->pos.file += sent;

#if (NGX_DEBUG_EVENT_WRITE)
            ngx_log_debug(c->log, "event write: " QX_FMT " " OFF_FMT _
                          ch->hunk->pos.file _
                          ch->hunk->last.file - ch->hunk->pos.file);
#endif

            break;
        }

    /* flush hunks if threaded state */
    } while (c->write->context && flush > 0);

    ngx_destroy_array(trailer);
    ngx_destroy_array(header);

    return ch;
}
