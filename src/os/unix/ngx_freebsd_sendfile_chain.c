
#include <ngx_config.h>

#include <ngx_core.h>
#include <ngx_types.h>
#include <ngx_alloc.h>
#include <ngx_array.h>
#include <ngx_hunk.h>
#include <ngx_connection.h>
#include <ngx_sendv.h>
#include <ngx_sendfile.h>
#include <ngx_freebsd_init.h>


ngx_chain_t *ngx_freebsd_sendfile_chain(ngx_connection_t *c, ngx_chain_t *in)
{
    int              rc;
    char            *prev;
    size_t           hsize, size;
    off_t            sent;
    struct iovec    *iov;
    struct sf_hdtr   hdtr;
    ngx_err_t        err;
    ngx_array_t      header, trailer;
    ngx_hunk_t      *file;
    ngx_chain_t     *ce;

    ce = in;
    file = NULL;
    hsize = 0;

    ngx_init_array(header, c->pool, 10, sizeof(struct iovec), NGX_CHAIN_ERROR);
    ngx_init_array(trailer, c->pool, 10, sizeof(struct iovec), NGX_CHAIN_ERROR);

    /* create the header iovec */
    if (ngx_hunk_in_memory_only(ce->hunk)) {
        prev = NULL;
        iov = NULL;

        /* create the iovec and coalesce the neighbouring chain entries */
        while (ce && ngx_hunk_in_memory_only(ce->hunk)) {

            if (prev == ce->hunk->pos) {
                iov->iov_len += ce->hunk->last - ce->hunk->pos;
                prev = ce->hunk->last;

            } else {
                ngx_test_null(iov, ngx_push_array(&header), NGX_CHAIN_ERROR);
                iov->iov_base = ce->hunk->pos;
                iov->iov_len = ce->hunk->last - ce->hunk->pos;
                prev = ce->hunk->last;
            }

            if (ngx_freebsd_sendfile_nbytes_bug) {
                hsize += ce->hunk->last - ce->hunk->pos;
            }

            ce = ce->next;
        }
    }

    /* TODO: coalesce the neighbouring file hunks */
    if (ce && (ce->hunk->type & NGX_HUNK_FILE)) {
        file = ce->hunk;
        ce = ce->next;
    }

    /* create the trailer iovec */
    if (ce && ngx_hunk_in_memory_only(ce->hunk)) {
        prev = NULL;
        iov = NULL;

        /* create the iovec and coalesce the neighbouring chain entries */
        while (ce && ngx_hunk_in_memory_only(ce->hunk)) {

            if (prev == ce->hunk->pos) {
                iov->iov_len += ce->hunk->last - ce->hunk->pos;
                prev = ce->hunk->last;

            } else {
                ngx_test_null(iov, ngx_push_array(&trailer), NGX_CHAIN_ERROR);
                iov->iov_base = ce->hunk->pos;
                iov->iov_len = ce->hunk->last - ce->hunk->pos;
                prev = ce->hunk->last;
            }

            ce = ce->next;
        }
    }

    if (file) {
        hdtr.headers = (struct iovec *) header.elts;
        hdtr.hdr_cnt = header.nelts;
        hdtr.trailers = (struct iovec *) trailer.elts;
        hdtr.trl_cnt = trailer.nelts;

        rc = sendfile(file->file->fd, c->fd, file->file_pos,
                      (size_t) (file->file_last - file->file_pos) + hsize,
                      &hdtr, &sent, 0);

        if (rc == -1) {
            err = ngx_errno;
            if (err == NGX_EAGAIN || err == NGX_EINTR) {
                ngx_log_error(NGX_LOG_INFO, c->log, err,
                              "sendfile() sent only %qd bytes", sent);

            } else {
                ngx_log_error(NGX_LOG_CRIT, c->log, err, "sendfile() failed");
                return NGX_CHAIN_ERROR;
            }
        }

#if (NGX_DEBUG_WRITE_CHAIN)
        ngx_log_debug(c->log, "sendfile: %d, @%qd %qd:%d" _
                      rc _ file->file_pos _ sent _
                      (size_t) (file->file_last - file->file_pos) + hsize);
#endif

    } else {
        rc = writev(c->fd, (struct iovec *) header.elts, header.nelts);

        if (rc == -1) {
            err = ngx_errno;
            if (err == NGX_EAGAIN) {
                ngx_log_error(NGX_LOG_INFO, c->log, err, "writev() EAGAIN");

            } else if (err == NGX_EINTR) {
                ngx_log_error(NGX_LOG_INFO, c->log, err, "writev() EINTR");

            } else {
                ngx_log_error(NGX_LOG_CRIT, c->log, err, "writev() failed");
                return NGX_CHAIN_ERROR;
            }
        }

        sent = rc > 0 ? rc : 0;
    }

#if (NGX_DEBUG_WRITE_CHAIN)
    ngx_log_debug(c->log, "sendv: %qd" _ sent);
#endif

    c->sent += sent;

    for (ce = in; ce && sent > 0; ce = ce->next) {

        if (ce->hunk->type & NGX_HUNK_IN_MEMORY) {
            size = ce->hunk->last - ce->hunk->pos;
        } else {
            size = ce->hunk->file_last - ce->hunk->file_pos;
        }

        if (sent >= size) {
            sent -= size;

            if (ce->hunk->type & NGX_HUNK_IN_MEMORY) {
                ce->hunk->pos = ce->hunk->last;
            }

            if (ce->hunk->type & NGX_HUNK_FILE) {
                ce->hunk->file_pos = ce->hunk->file_last;
            }

            continue;
        }

        if (ce->hunk->type & NGX_HUNK_IN_MEMORY) {
            ce->hunk->pos += sent;
        }

        if (ce->hunk->type & NGX_HUNK_FILE) {
            ce->hunk->file_pos += sent;
        }

        break;
    }

    ngx_destroy_array(&trailer);
    ngx_destroy_array(&header);

    return ce;
}
