
#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_types.h>
#include <ngx_file.h>
#include <ngx_socket.h>
#include <ngx_errno.h>
#include <ngx_log.h>
#include <ngx_sendv.h>
#include <ngx_sendfile.h>

/*
  TODO:
    FreeBSD:
       check sent if errno == EINTR then should return right sent.
*/

#if (HAVE_FREEBSD_SENDFILE)

int ngx_sendfile(ngx_socket_t s,
                 ngx_iovec_t *headers, int hdr_cnt,
                 ngx_fd_t fd, off_t offset, size_t nbytes,
                 ngx_iovec_t *trailers, int trl_cnt,
                 off_t *sent,
                 ngx_log_t *log)
{
    int             rc, i;
    ngx_err_t       err;
    struct sf_hdtr  hdtr;

    hdtr.headers = headers;
    hdtr.hdr_cnt = hdr_cnt;
    hdtr.trailers = trailers;
    hdtr.trl_cnt = trl_cnt;

#if (HAVE_FREEBSD_SENDFILE_NBYTES_BUG)
    for (i = 0; i < hdr_cnt; i++)
        nbytes += headers[i].iov_len;
#endif

    rc = sendfile(fd, s, offset, nbytes, &hdtr, sent, 0);

    if (rc == -1) {
        err = ngx_socket_errno;
        if (err != NGX_EAGAIN && err != NGX_EINTR) {
            ngx_log_error(NGX_LOG_ERR, log, err,
                         "ngx_sendfile: sendfile failed");
            return NGX_ERROR;

        } else {
            ngx_log_error(NGX_LOG_INFO, log, err,
                         "ngx_sendfile: sendfile sent only %qd bytes", *sent);
        }
    }

    ngx_log_debug(log, "ngx_sendfile: %d, @%qd %qd:%d" _
                  rc _ offset _ *sent _ nbytes);

    return NGX_OK;
}

#endif
