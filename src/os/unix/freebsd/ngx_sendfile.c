
#include <ngx_config.h>

#if (HAVE_FREEBSD_SENDFILE)

#include <ngx_core.h>
#include <ngx_types.h>
#include <ngx_socket.h>
#include <ngx_errno.h>
#include <ngx_log.h>
#include <ngx_connection.h>
#include <ngx_sendv.h>
#include <ngx_sendfile.h>

/*
  CHECK:
       check sent if errno == EINTR then should return right sent.
       EINTR should not occur according to man.
*/


int ngx_sendfile(ngx_connection_t *c,
                 ngx_iovec_t *headers, int hdr_cnt,
                 ngx_fd_t fd, off_t offset, size_t nbytes,
                 ngx_iovec_t *trailers, int trl_cnt,
                 off_t *sent, u_int flags)
{
    int             rc, i;
    ngx_err_t       err;
    struct sf_hdtr  hdtr;

    hdtr.headers = headers;
    hdtr.hdr_cnt = hdr_cnt;
    hdtr.trailers = trailers;
    hdtr.trl_cnt = trl_cnt;

#if (HAVE_FREEBSD_SENDFILE_NBYTES_BUG)
    for (i = 0; i < hdr_cnt; i++) {
        nbytes += headers[i].iov_len;
    }
#endif

    rc = sendfile(fd, c->fd, offset, nbytes, &hdtr, sent, flags);

    if (rc == -1) {
        err = ngx_errno;
        if (err != NGX_EAGAIN && err != NGX_EINTR) {
            ngx_log_error(NGX_LOG_ERR, c->log, err, "sendfile failed");

            return NGX_ERROR;

        } else {
            ngx_log_error(NGX_LOG_INFO, c->log, err,
                          "sendfile sent only %qd bytes", *sent);

            return NGX_AGAIN;
        }
    }

    ngx_log_debug(c->log, "sendfile: %d, @%qd %qd:%d" _
                  rc _ offset _ *sent _ nbytes);

    return NGX_OK;
}

#endif
