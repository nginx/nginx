
#include <ngx_config.h>
#include <ngx_types.h>
#include <ngx_errno.h>
#include <ngx_log.h>
#include <ngx_sendv.h>
#include <ngx_sendfile.h>

/*
  TODO:
       various flags
       TransmitPackets
*/

/*
  returns
      0 done
     -1 error
*/

#if (HAVE_WIN32_TRANSMITFILE)

int ngx_sendfile(ngx_socket_t s,
                 ngx_iovec_t *headers, int hdr_cnt,
                 ngx_file_t fd, off_t offset, size_t nbytes,
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

    tfrc = TransmitFile(s, fd, nbytes, 0, &olp, ptfb, 0);

    if (tfrc == 0)
        tf_err = ngx_socket_errno;

    /* set sent */
    rc = WSAGetOverlappedResult(s, &olp, (unsigned long *) sent, 0, NULL);

    ngx_log_debug(log, "ngx_sendfile: %d, @%qd %d:%qd" _
                  tfrc _ offset _ nbytes _ *sent);

    if (rc == 0) {
        err = ngx_socket_errno;
        ngx_log_error(NGX_LOG_ERR, log, err,
                     "ngx_sendfile: WSAGetOverlappedResult failed");
    }

    if (tfrc == 0) {
        if (tf_err != NGX_EAGAIN) {
            ngx_log_error(NGX_LOG_ERR, log, tf_err,
                          "ngx_sendfile: TransmitFile failed");
            return -1;
        }

        ngx_log_error(NGX_LOG_INFO, log, tf_err,
                     "ngx_sendfile: TransmitFile sent only %qd bytes", *sent);
    }

    if (rc == 0)
        return -1;

    return 0;
}

#endif
