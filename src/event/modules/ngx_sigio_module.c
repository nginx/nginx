

int ngx_sigio_add_event(ngx_event_t *ev, int signal)
{
    ngx_connection_t  *c;

    c = (ngx_connection_t *) ev->data;

    if (fcntl(c->fd, F_SETFL, O_RDWR|O_NONBLOCK|O_ASYNC) == -1) {
        ngx_log_error(NGX_LOG_ALERT, ev->log, ngx_errno,
                      "fcntl(O_RDWR|O_NONBLOCK|O_ASYNC) failed");
        return NGX_ERROR;
    }

    if (fcntl(c->fd, F_SETSIG, signal) == -1) {
        ngx_log_error(NGX_LOG_ALERT, ev->log, ngx_errno,
                      "fcntl(F_SETSIG) failed");
        return NGX_ERROR;
    }

    if (fcntl(c->fd, F_SETOWN, pid) == -1) {
        ngx_log_error(NGX_LOG_ALERT, ev->log, ngx_errno,
                      "fcntl(F_SETOWN) failed");
        return NGX_ERROR;
    }

#if (HAVE_ONESIGFD)
    if (fcntl(c->fd, F_SETAUXFL, O_ONESIGFD) == -1) {
        ngx_log_error(NGX_LOG_ALERT, ev->log, ngx_errno,
                      "fcntl(F_SETAUXFL) failed");
        return NGX_ERROR;
    }
#endif

    return NGX_OK;
}

int ngx_sigio_process_events(ngx_log_t *log)
{
    struct siginfo  si;

    for ( ;; ) {
        if (timer) {
            sig = sigtimedwait(&sigio_set, &si, &ts);

            if (sig == -1) {
                ngx_log_error(NGX_LOG_ALERT, ev->log, ngx_errno,
                              "sigtimedwait() failed");
                continue;
            }
        }

        } else {
            sig = sigwaitinfo(&set, &si);

            if (sig == -1) {
                ngx_log_error(NGX_LOG_ALERT, ev->log, ngx_errno,
                              "sigwaitinfo() failed");
            }
        }

        if (sig == rtsig) {
            c = &ngx_connections[si.si_fd];

            if (si.si_band & (POLLERR|POLLHUP|POLLNVAL)) {
                ev = ???;

                if (ev->active) {
                    ev->ready = 1;
                    if (ev->event_handler(ev) == NGX_ERROR) {
                        ev->close_handler(ev);
                    }
                }
            }

            if (si.si_band & (POLLIN)) {
                ev = c->read;

                if (ev->active) {
                    ev->ready = 1;
                    if (ev->event_handler(ev) == NGX_ERROR) {
                        ev->close_handler(ev);
                    }
                }
            }

            if (si.si_band & (POLLOUT)) {
                ev = c->write;

                if (ev->active) {
                    ev->ready = 1;
                    if (ev->event_handler(ev) == NGX_ERROR) {
                        ev->close_handler(ev);
                    }
                }
            }

        } else if (sig == SIGIO) {
            ngx_log_error(NGX_LOG_ALERT, ev->log, ngx_errno,
                          "Signal queue overflowed: "
                          "SIGIO, fd:%d, band:%d", si.si_fd, si.si_band);

            /* flush queue: method #1 (dphttpd) */
            ts.tv_sec = 0;
            ts.tv_nsec = 0;
            while (sigtimedwait(&sigio_set, &si, &ts) > 0);

            /* flush queue: method #2 (dkftpbench) */
            signal(m_signum, SIG_IGN);
            signal(m_signum, SIG_DFL);

            /* do poll */

        } else {
        }
    }
}
