#ifndef _NGX_EVENT_H_INCLUDED_
#define _NGX_EVENT_H_INCLUDED_


#include <ngx_config.h>
#include <ngx_core.h>


#define NGX_INVALID_INDEX  0xd0d0d0d0


#if (HAVE_IOCP)

typedef struct {
    WSAOVERLAPPED    ovlp;
    ngx_event_t     *event;
    int              error;
} ngx_event_ovlp_t;

#endif


typedef struct {
    ngx_uint_t       lock;

    ngx_event_t     *events;
    ngx_event_t     *last;
} ngx_event_mutex_t;


struct ngx_event_s {
    void            *data;
    /* TODO rename to handler */
    void           (*event_handler)(ngx_event_t *ev);

    u_int            index;

    /* the link of the posted queue or the event mutecies queues */
    ngx_event_t     *next;

    ngx_log_t       *log;

    /*
     * The inline of "ngx_rbtree_t  rbtree;".
     *
     * It allows to pack the rbtree_color and the various event bit flags into
     * the single "int".  We also use "unsigned char" and then "unsigned short"
     * because otherwise MSVC 6.0 uses an additional "int" for the bit flags.
     * We use "char rbtree_color" instead of "unsigned int rbtree_color:1"
     * because it preserves the bits order on the big endian platforms.
     */

    ngx_int_t        rbtree_key;
    void            *rbtree_left;
    void            *rbtree_right;
    void            *rbtree_parent;
    char             rbtree_color;

    unsigned char    oneshot:1;

    unsigned char    write:1;

    /* used to detect the stale events in kqueue, rt signals and epoll */
    unsigned char    instance:1;

    /*
     * the event was passed or would be passed to a kernel;
     * in aio mode - operation was posted.
     */
    unsigned char    active:1;

    unsigned char    disabled:1;

    /* the ready event; in aio mode 0 means that no operation can be posted */
    unsigned char    ready:1;

    /* aio operation is complete */
    unsigned char    complete:1;

    unsigned short   eof:1;
    unsigned short   error:1;

    unsigned short   timedout:1;
    unsigned short   timer_set:1;

    unsigned short   delayed:1;

    unsigned short   read_discarded:1;

    unsigned short   unexpected_eof:1;

    unsigned short   deferred_accept:1;

    /* TODO: aio_eof and kq_eof can be the single pending_eof */
    /* the pending eof in aio chain operation */
    unsigned short   aio_eof:1;

    /* the pending eof reported by kqueue */
    unsigned short   kq_eof:1;

#if (WIN32)
    /* setsockopt(SO_UPDATE_ACCEPT_CONTEXT) was succesfull */
    unsigned short   accept_context_updated:1;
#endif

#if (HAVE_KQUEUE)
    unsigned short   kq_vnode:1;

    /* the pending errno reported by kqueue */
    int              kq_errno;
#endif

    /*
     * kqueue only:
     *   accept:     number of sockets that wait to be accepted
     *   read:       bytes to read when event is ready
     *               or lowat when event is set with NGX_LOWAT_EVENT flag
     *   write:      available space in buffer when event is ready
     *               or lowat when event is set with NGX_LOWAT_EVENT flag
     *
     * otherwise:
     *   accept:     1 if accept many, 0 otherwise
     */

#if (HAVE_KQUEUE)
    int              available;
#else
    unsigned short   available:1;
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
    int   (*del_conn)(ngx_connection_t *c, u_int flags);

    int   (*process)(ngx_log_t *log);
    int   (*init)(ngx_cycle_t *cycle);
    void  (*done)(ngx_cycle_t *cycle);
} ngx_event_actions_t;


extern ngx_event_actions_t   ngx_event_actions;


/*
 * The event filter requires to read/write the whole data -
 * select, poll, /dev/poll, kqueue, epoll.
 */
#define NGX_USE_LEVEL_EVENT    0x00000001

/*
 * The event filter is deleted after a notification without an additional
 * syscall - select, poll, kqueue, epoll.
 */
#define NGX_USE_ONESHOT_EVENT  0x00000002

/*
 * The event filter notifies only the changes and an initial level -
 * kqueue, epoll.
 */
#define NGX_USE_CLEAR_EVENT    0x00000004

/*
 * The event filter has kqueue features - the eof flag, errno,
 * available data, etc.
 */
#define NGX_HAVE_KQUEUE_EVENT  0x00000008

/*
 * The event filter supports low water mark - kqueue's NOTE_LOWAT.
 * kqueue in FreeBSD 4.1-4.2 has no NOTE_LOWAT so we need a separate flag.
 */
#define NGX_HAVE_LOWAT_EVENT   0x00000010

/*
 * The event filter notifies only the changes (the edges)
 * but not an initial level - early epoll patches.
 */
#define NGX_USE_EDGE_EVENT     0x00000020

/*
 * No need to add or delete the event filters - rt signals.
 */
#define NGX_USE_SIGIO_EVENT    0x00000040

/*
 * The alternative event method after the rt signals queue overflow.
 */
#define NGX_OVERFLOW_EVENT     0x00000080

/*
 * No need to add or delete the event filters - overlapped, aio_read,
 * aioread, io_submit.
 */
#define NGX_USE_AIO_EVENT      0x00000100

/*
 * Need to add socket or handle only once - i/o completion port.
 * It also requires HAVE_AIO and NGX_USE_AIO_EVENT to be set.
 */
#define NGX_USE_IOCP_EVENT     0x00000200



/*
 * The event filter is deleted before the closing file.
 * Has no meaning for select, poll, epoll.
 *
 * kqueue:     kqueue deletes event filters for file that closed
 *             so we need only to delete filters in user-level batch array
 * /dev/poll:  we need to flush POLLREMOVE event before closing file
 */

#define NGX_CLOSE_EVENT    1


/* these flags have a meaning only for kqueue */
#define NGX_LOWAT_EVENT    0
#define NGX_DISABLE_EVENT  0
#define NGX_VNODE_EVENT    0


#if (HAVE_KQUEUE)

#define NGX_READ_EVENT     EVFILT_READ
#define NGX_WRITE_EVENT    EVFILT_WRITE

#undef  NGX_VNODE_EVENT
#define NGX_VNODE_EVENT    EVFILT_VNODE

/*
 * NGX_CLOSE_EVENT and NGX_LOWAT_EVENT are the module flags and they would
 * not go into a kernel so we need to choose the value that would not interfere
 * with any existent and future kqueue flags.  kqueue has such values -
 * EV_FLAG1, EV_EOF and EV_ERROR.  They are reserved and cleared on a kernel
 * entrance.
 */
#undef  NGX_CLOSE_EVENT
#define NGX_CLOSE_EVENT    EV_EOF

#undef  NGX_LOWAT_EVENT
#define NGX_LOWAT_EVENT    EV_FLAG1

#define NGX_LEVEL_EVENT    0
#define NGX_ONESHOT_EVENT  EV_ONESHOT
#define NGX_CLEAR_EVENT    EV_CLEAR

#undef  NGX_DISABLE_EVENT
#define NGX_DISABLE_EVENT  EV_DISABLE


#elif (HAVE_DEVPOLL)

#define NGX_READ_EVENT     POLLIN
#define NGX_WRITE_EVENT    POLLOUT

#define NGX_LEVEL_EVENT    0
#define NGX_ONESHOT_EVENT  1


#elif (HAVE_EPOLL)

#define NGX_READ_EVENT     EPOLLIN
#define NGX_WRITE_EVENT    EPOLLOUT

#define NGX_LEVEL_EVENT    0
#define NGX_CLEAR_EVENT    EPOLLET
#define NGX_ONESHOT_EVENT  0x70000000
#if 0
#define NGX_ONESHOT_EVENT  EPOLLONESHOT
#endif


#elif (HAVE_POLL)

#define NGX_READ_EVENT     POLLIN
#define NGX_WRITE_EVENT    POLLOUT

#define NGX_LEVEL_EVENT    0
#define NGX_ONESHOT_EVENT  1


#else /* select */

#define NGX_READ_EVENT     0
#define NGX_WRITE_EVENT    1

#define NGX_LEVEL_EVENT    0
#define NGX_ONESHOT_EVENT  1

#endif /* HAVE_KQUEUE */


#if (HAVE_IOCP)
#define NGX_IOCP_ACCEPT      0
#define NGX_IOCP_IO          1
#define NGX_IOCP_CONNECT     2
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
    int          connections;
    int          use;
    ngx_flag_t   multi_accept;
    char       *name;
} ngx_event_conf_t;


typedef struct {
    ngx_str_t              *name;

    void                 *(*create_conf)(ngx_cycle_t *cycle);
    char                 *(*init_conf)(ngx_cycle_t *cycle, void *conf);

    ngx_event_actions_t     actions;
} ngx_event_module_t;



extern volatile ngx_event_t  *ngx_posted_events;

extern int                    ngx_event_flags;
extern ngx_module_t           ngx_events_module;
extern ngx_module_t           ngx_event_core_module;


#define ngx_event_get_conf(conf_ctx, module)                                  \
             (*(ngx_get_conf(conf_ctx, ngx_events_module))) [module.ctx_index];



void ngx_event_accept(ngx_event_t *ev);

#if (WIN32)
void ngx_event_acceptex(ngx_event_t *ev);
int ngx_event_post_acceptex(ngx_listening_t *ls, int n);
#endif


/* used in ngx_log_debugX() */
#define ngx_event_ident(p)  ((ngx_connection_t *) (p))->fd


#include <ngx_event_timer.h>

#if (WIN32)
#include <ngx_iocp_module.h>
#endif



ngx_inline static int ngx_handle_read_event(ngx_event_t *rev, u_int flags)
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
                                                                  == NGX_ERROR)
            {
                return NGX_ERROR;
            }

            return NGX_OK;
        }

        if (rev->active && (rev->ready || (flags & NGX_CLOSE_EVENT))) {
            if (ngx_del_event(rev, NGX_READ_EVENT, flags) == NGX_ERROR) {
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
                                                                  == NGX_ERROR)
            {
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


ngx_inline static int ngx_handle_write_event(ngx_event_t *wev, u_int flags)
{
    if (ngx_event_flags & NGX_USE_CLEAR_EVENT) {

        /* kqueue */

        if (!wev->active && !wev->ready) {
            if (ngx_add_event(wev, NGX_WRITE_EVENT, NGX_CLEAR_EVENT|flags)
                                                                  == NGX_ERROR)
            {
                return NGX_ERROR;
            }
        }

        return NGX_OK;

    } else if (ngx_event_flags & NGX_USE_LEVEL_EVENT) {

        /* select, poll, /dev/poll */

        if (!wev->active && !wev->ready) {
            if (ngx_add_event(wev, NGX_WRITE_EVENT, NGX_LEVEL_EVENT)
                                                                  == NGX_ERROR)
            {
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
                                                                  == NGX_ERROR)
            {
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
