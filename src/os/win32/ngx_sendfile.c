
#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_types.h>
#include <ngx_files.h>
#include <ngx_socket.h>
#include <ngx_errno.h>
#include <ngx_log.h>
#include <ngx_sendv.h>
#include <ngx_sendfile.h>

/*
  TODO:
       various flags
       TransmitPackets
*/

#if (HAVE_WIN32_TRANSMITFILE)

int ngx_sendfile(ngx_socket_t s,
                 ngx_iovec_t *headers, int hdr_cnt,
                 ngx_fd_t fd, off_t offset, size_t nbytes,
                 ngx_iovec_t *trailers, int trl_cnt,
                 off_t *sent,
                 ngx_log_t *log)
{
    int                    tfrc, rc;
    ngx_err_t              tf_err, err;
    OVERLAPPED             olp;
    TRANSMIT_FILE_BUFFERS  tfb, *ptfb;

    tf_err = 0;
    err = 0;

    olp.Internal = 0;
    olp.InternalHigh = 0;
    olp.Offset = (DWORD) offset;
    olp.OffsetHigh = (DWORD) (offset >> 32);
    olp.hEvent = NULL;

    if (headers || trailers) {
        tfb.Head = headers->ngx_iov_base;
        tfb.HeadLength = headers->ngx_iov_len;
        tfb.Tail = trailers->ngx_iov_base;
        tfb.TailLength = trailers->ngx_iov_len;
        ptfb = &tfb;

    } else {
        ptfb = NULL;
    }

#if 1
    tfrc = TransmitFile(s, fd, nbytes, 0, &olp, ptfb, 0);
#else
    tfrc = TransmitFile(s, fd, nbytes, 0, NULL, ptfb, 0);
#endif

    if (tfrc == 0)
        tf_err = ngx_socket_errno;

    /* set sent */
#if 0
    rc = WSAGetOverlappedResult(s, &olp, (unsigned long *) sent, 0, NULL);
#else
    *sent = olp.InternalHigh;
    rc = 1;
#endif

    ngx_log_debug(log, "ngx_sendfile: %d, @%I64d %I64d:%d" _
                  tfrc _ offset _ *sent _ nbytes);

    if (rc == 0) {
        err = ngx_socket_errno;
        ngx_log_error(NGX_LOG_ERR, log, err,
                     "ngx_sendfile: WSAGetOverlappedResult failed");
    }

    if (tfrc == 0) {
        if (tf_err != NGX_EAGAIN) {
            ngx_log_error(NGX_LOG_ERR, log, tf_err,
                          "ngx_sendfile: TransmitFile failed");
            return NGX_ERROR;
        }

        ngx_log_error(NGX_LOG_INFO, log, tf_err,
                      "ngx_sendfile: TransmitFile sent only %I64d bytes",
                      *sent);
    }

    if (rc == 0)
        return NGX_ERROR;

    return NGX_OK;
}

#endif
