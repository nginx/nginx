#ifndef _NGX_EVENT_H_INCLUDED_
#define _NGX_EVENT_H_INCLUDED_


#include <ngx_config.h>
#include <ngx_core.h>


#define NGX_INVALID_INDEX  0x80000000


#if (HAVE_IOCP)

typedef struct {
    WSAOVERLAPPED    ovlp;
    ngx_event_t     *event;
    int              error;
} ngx_event_ovlp_t;

#endif


struct ngx_event_s {
    void            *data;
    /* TODO rename to handler, move flags to struct start */
    void           (*event_handler)(ngx_event_t *ev);

    void            *context;
    char            *action;

    unsigned int     index;

    /* queue in mutex(), aio_read(), aio_write()  */
    ngx_event_t     *prev;
    ngx_event_t     *next;

    ngx_event_t     *timer_prev;
    ngx_event_t     *timer_next;

    ngx_msec_t       timer_delta;
    ngx_msec_t       timer;

    ngx_log_t       *log;

    /*
     * kqueue only:
     *   accept:     number of sockets that wait to be accepted
     *   read:       bytes to read
     *   write:      available space in buffer
     *
     * otherwise:
     *   accept:     1 if accept many, 0 otherwise
     */
    int              available;

    unsigned         oneshot:1;

    unsigned         write:1;

    /* used to detect the stale events in kqueue, rt signals and epoll */
    unsigned         instance:1;

    /*
     * the event was passed or would be passed to a kernel;
     * in aio mode - operation was posted.
     */
    unsigned         active:1;

    /* the ready event; in aio mode 0 means that no operation can be posted */
    unsigned         ready:1;

    /* aio operation is complete */
    unsigned         complete:1;

    unsigned         eof:1;
    unsigned         error:1;

    unsigned         timedout:1;
    unsigned         timer_set:1;

    unsigned         delayed:1;

    unsigned         read_discarded:1;

    unsigned         ignore_econnreset:1;
    unsigned         unexpected_eof:1;

    unsigned         deferred_accept:1;

    /* TODO: aio_eof and kq_eof can be the single pending_eof */
    /* the pending eof in aio chain operation */
    unsigned         aio_eof:1;

    /* the pending eof reported by kqueue */
    unsigned         kq_eof:1;

#if (WIN32)
    /* setsockopt(SO_UPDATE_ACCEPT_CONTEXT) was succesfull */
    unsigned         accept_context_updated:1;
#endif

#if (HAVE_KQUEUE)
    /* the pending errno reported by kqueue */
    int              kq_errno;
#endif

#if (HAVE_LOWAT_EVENT) /* kqueue's NOTE_LOWAT */
    int              lowat;
#endif


#if (HAVE_AIO)

#if (HAVE_IOCP)
    ngx_event_ovlp_t ovlp;
#else
    struct aiocb     aiocb;
#endif

#endif


#if 0

    /* the threads support */

    /*
     * the event thread context, we store it here
     * if $(CC) does not understand __thread declaration
     * and pthread_getspecific() is too costly
     */

    void            *thr_ctx;

#if (NGX_EVENT_T_PADDING)

    /* event should not cross cache line in SMP */

    int              padding[NGX_EVENT_T_PADDING];
#endif
#endif
};


typedef struct {
    int   (*add)(ngx_event_t *ev, int event, u_int flags);
    int   (*del)(ngx_event_t *ev, int event, u_int flags);

    int   (*enable)(ngx_event_t *ev, int event, u_int flags);
    int   (*disable)(ngx_event_t *ev, int event, u_int flags);

    int   (*add_conn)(ngx_connection_t *c);
    int   (*del_conn)(ngx_connection_t *c);

    int   (*process)(ngx_log_t *log);
    int   (*init)(ngx_cycle_t *cycle);
    void  (*done)(ngx_cycle_t *cycle);
} ngx_event_actions_t;


extern ngx_event_actions_t   ngx_event_actions;


/*
 * The event filter requires to read/write the whole data -
 * select, poll, /dev/poll, kqueue.
 */
#define NGX_USE_LEVEL_EVENT    0x00000001

/*
 * The event filter is deleted after a notification without an additional
 * syscall - select, poll, kqueue.
 */
#define NGX_USE_ONESHOT_EVENT  0x00000002

/*
 *  The event filter notifies only the changes and an initial level - kqueue.
 */
#define NGX_USE_CLEAR_EVENT    0x00000004

/*
 * The event filter has kqueue features - the eof flag, errno,
 * available data, etc
 */
#define NGX_HAVE_KQUEUE_EVENT  0x00000008

/*
 * The event filter supports low water mark - kqueue's NOTE_LOWAT.
 * kqueue in FreeBSD 4.1-4.2 has no NOTE_LOWAT so we need a separate flag.
 */
#define NGX_HAVE_LOWAT_EVENT   0x00000010

/*
 * The event filter notifies only the changes (the edges)
 * but not an initial level - epoll.
 */
#define NGX_USE_EDGE_EVENT     0x00000020

/*
 * No need to add or delete the event filters - rt signals.
 */
#define NGX_USE_SIGIO_EVENT    0x00000040

/*
 * No need to add or delete the event filters - overlapped, aio_read,
 * aioread, io_submit.
 */
#define NGX_USE_AIO_EVENT      0x00000080

/*
 * Need to add socket or handle only once - i/o completion port.
 * It also requires HAVE_AIO_EVENT and NGX_HAVE_AIO_EVENT to be set.
 */
#define NGX_USE_IOCP_EVENT     0x00000100



/*
 * The event filter is deleted before the closing file.
 * Has no meaning for select, poll, epoll.
 *
 * kqueue:     kqueue deletes event filters for file that closed
 *             so we need only to delete filters in user-level batch array
 * /dev/poll:  we need to flush POLLREMOVE event before closing file
 */

#define NGX_CLOSE_EVENT         1


#if (HAVE_KQUEUE)

#define NGX_READ_EVENT     EVFILT_READ
#define NGX_WRITE_EVENT    EVFILT_WRITE

/*
 * NGX_CLOSE_EVENT is the module flag and it would not go into a kernel
 * so we need to choose the value that would not interfere with any existent
 * and future flags.  kqueue has such values - EV_FLAG1, EV_EOF and EV_ERROR.
 * They are reserved and cleared on a kernel entrance.
 */
#undef  NGX_CLOSE_EVENT
#define NGX_CLOSE_EVENT    EV_FLAG1

#define NGX_LEVEL_EVENT    0
#define NGX_ONESHOT_EVENT  EV_ONESHOT
#define NGX_CLEAR_EVENT    EV_CLEAR


#elif (HAVE_POLL)

#define NGX_READ_EVENT     POLLIN
#define NGX_WRITE_EVENT    POLLOUT

#define NGX_LEVEL_EVENT    0
#define NGX_ONESHOT_EVENT  1


#elif (HAVE_DEVPOLL)

#define NGX_READ_EVENT     POLLIN
#define NGX_WRITE_EVENT    POLLOUT

#define NGX_LEVEL_EVENT    0


#else /* select */

#define NGX_READ_EVENT     0
#define NGX_WRITE_EVENT    1

#define NGX_LEVEL_EVENT    0
#define NGX_ONESHOT_EVENT  1

#endif /* HAVE_KQUEUE */


#if (HAVE_IOCP_EVENT)
#define NGX_IOCP_ACCEPT      0
#define NGX_IOCP_IO          1
#endif


#ifndef NGX_CLEAR_EVENT
#define NGX_CLEAR_EVENT    0    /* dummy declaration */
#endif


#define ngx_process_events   ngx_event_actions.process
#define ngx_add_event        ngx_event_actions.add
#define ngx_del_event        ngx_event_actions.del
#define ngx_add_conn         ngx_event_actions.add_conn
#define ngx_del_conn         ngx_event_actions.del_conn

#define ngx_add_timer        ngx_event_add_timer
#define ngx_del_timer        ngx_event_del_timer


#define ngx_recv             ngx_io.recv
#define ngx_recv_chain       ngx_io.recv_chain
#define ngx_write_chain      ngx_io.send_chain



#define NGX_EVENT_MODULE      0x544E5645  /* "EVNT" */
#define NGX_EVENT_CONF        0x00200000


typedef struct {
    int   connections;
    int   timer_queues;
    int   use;
} ngx_event_conf_t;


typedef struct {
    ngx_str_t              *name;

    void                 *(*create_conf)(ngx_cycle_t *cycle);
    char                 *(*init_conf)(ngx_cycle_t *cycle, void *conf);

    ngx_event_actions_t     actions;
} ngx_event_module_t;



extern int                   ngx_event_flags;
extern ngx_module_t          ngx_events_module;
extern ngx_module_t          ngx_event_core_module;


#define ngx_event_get_conf(conf_ctx, module)                                  \
             (*(ngx_get_conf(conf_ctx, ngx_events_module))) [module.ctx_index];



void ngx_event_accept(ngx_event_t *ev);

#if (WIN32)
void ngx_event_acceptex(ngx_event_t *ev);
int ngx_event_post_acceptex(ngx_listening_t *ls, int n);
#endif



#include <ngx_event_timer.h>

#if (WIN32)
#include <ngx_iocp_module.h>
#endif



ngx_inline static int ngx_handle_read_event(ngx_event_t *rev, int close)
{
    if (ngx_event_flags & NGX_USE_CLEAR_EVENT) {

        /* kqueue */

        if (!rev->active && !rev->ready) {
            if (ngx_add_event(rev, NGX_READ_EVENT, NGX_CLEAR_EVENT)
                                                                == NGX_ERROR) {
                return NGX_ERROR;
            }
        }

        return NGX_OK;

    } else if (ngx_event_flags & NGX_USE_LEVEL_EVENT) {

        /* select, poll, /dev/poll */

        if (!rev->active && !rev->ready) {
            if (ngx_add_event(rev, NGX_READ_EVENT, NGX_LEVEL_EVENT)
                                                                == NGX_ERROR) {
                return NGX_ERROR;
            }

            return NGX_OK;
        }

        if (rev->active && (rev->ready || close)) {
            if (ngx_del_event(rev, NGX_READ_EVENT, close ? NGX_CLOSE_EVENT : 0)
                                                                == NGX_ERROR) {
                return NGX_ERROR;
            }

            return NGX_OK;
        }
    }

    /* aio, iocp, epoll, rt signals */

    return NGX_OK;
}


ngx_inline static int ngx_handle_level_read_event(ngx_event_t *rev)
{
    if (ngx_event_flags & NGX_USE_LEVEL_EVENT) {
        if (!rev->active && !rev->ready) {
            if (ngx_add_event(rev, NGX_READ_EVENT, NGX_LEVEL_EVENT)
                                                                == NGX_ERROR) {
                return NGX_ERROR;
            }

            return NGX_OK;
        }

        if (rev->active && rev->ready) {
            if (ngx_del_event(rev, NGX_READ_EVENT, 0) == NGX_ERROR) {
                return NGX_ERROR;
            }

            return NGX_OK;
        }
    }

    return NGX_OK;
}


ngx_inline static int ngx_handle_write_event(ngx_event_t *wev, int lowat)
{
    if (ngx_event_flags & NGX_USE_CLEAR_EVENT) {

        /* kqueue */

#if (HAVE_LOWAT_EVENT) /* kqueue's NOTE_LOWAT */

        if (ngx_event_flags & NGX_HAVE_LOWAT_EVENT) {
            wev->lowat = lowat;
        }

#endif
        if (!wev->active && !wev->ready) {
            if (ngx_add_event(wev, NGX_WRITE_EVENT, NGX_CLEAR_EVENT)
                                                                == NGX_ERROR) {
                return NGX_ERROR;
            }
        }

        return NGX_OK;

    } else if (ngx_event_flags & NGX_USE_LEVEL_EVENT) {

        /* select, poll, /dev/poll */

        if (!wev->active && !wev->ready) {
            if (ngx_add_event(wev, NGX_WRITE_EVENT, NGX_LEVEL_EVENT)
                                                                == NGX_ERROR) {
                return NGX_ERROR;
            }

            return NGX_OK;
        }

        if (wev->active && wev->ready) {
            if (ngx_del_event(wev, NGX_WRITE_EVENT, 0) == NGX_ERROR) {
                return NGX_ERROR;
            }

            return NGX_OK;
        }
    }

    /* aio, iocp, epoll, rt signals */

    return NGX_OK;
}


ngx_inline static int ngx_handle_level_write_event(ngx_event_t *wev)
{
    if (ngx_event_flags & NGX_USE_LEVEL_EVENT) {
        if (!wev->active && !wev->ready) {
            if (ngx_add_event(wev, NGX_WRITE_EVENT, NGX_LEVEL_EVENT)
                                                                == NGX_ERROR) {
                return NGX_ERROR;
            }

            return NGX_OK;
        }

        if (wev->active && wev->ready) {
            if (ngx_del_event(wev, NGX_WRITE_EVENT, 0) == NGX_ERROR) {
                return NGX_ERROR;
            }

            return NGX_OK;
        }
    }

    return NGX_OK;
}


#endif /* _NGX_EVENT_H_INCLUDED_ */
