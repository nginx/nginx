#ifndef _NGX_EVENT_H_INCLUDED_
#define _NGX_EVENT_H_INCLUDED_


#include <ngx_config.h>
#include <ngx_core.h>

#if 0
#include <ngx_types.h>
#include <ngx_time.h>
#include <ngx_socket.h>
#include <ngx_log.h>
#include <ngx_alloc.h>
#include <ngx_array.h>
#include <ngx_conf_file.h>
#endif



/* STUB */
#define NGX_LOWAT   10000

#define NGX_INVALID_INDEX  0x80000000


#if 0
typedef struct ngx_event_s       ngx_event_t;
#endif

#if (HAVE_IOCP)
typedef struct {
    WSAOVERLAPPED    ovlp;
    ngx_event_t     *event;
    int              error;
} ngx_event_ovlp_t;
#endif


struct ngx_event_s {
    void            *data;
    void           (*event_handler)(ngx_event_t *ev);

#if 0
    int            (*close_handler)(ngx_event_t *ev);
#endif
    void            *context;
    char            *action;

    unsigned int     index;

    ngx_event_t     *prev;     /* queue in mutex(), aio_read(), aio_write()  */
    ngx_event_t     *next;     /*                                            */

#if 0
    int            (*timer_handler)(ngx_event_t *ev);
#endif
    ngx_event_t     *timer_prev;
    ngx_event_t     *timer_next;

    ngx_msec_t       timer_delta;
    ngx_msec_t       timer;

    ngx_log_t       *log;

    int              available; /* kqueue only:                              */
                                /*   accept: number of sockets that wait     */
                                /*           to be accepted                  */
                                /*   read:   bytes to read                   */
                                /*   write:  available space in buffer       */
                                /* otherwise:                                */
                                /*   accept: 1 if accept many, 0 otherwise   */

    unsigned         oneshot:1;

#if 0
    unsigned         listening:1;
#endif
    unsigned         write:1;

    unsigned         instance:1;  /* used to detect stale events in kqueue,
                                     rt signals and epoll */

    unsigned         active:1;
    unsigned         ready:1;
    unsigned         timedout:1;
    unsigned         blocked:1;
    unsigned         timer_set:1;
    unsigned         delayed:1;

    unsigned         process:1;
    unsigned         read_discarded:1;

    unsigned         ignore_econnreset:1;
    unsigned         unexpected_eof:1;

#if (HAVE_DEFERRED_ACCEPT)
    unsigned         deferred_accept:1;
#endif

#if (HAVE_KQUEUE)
    unsigned         eof:1;
    int              error;
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
    void            *thr_ctx;   /* event thread context if $(CC) doesn't
                                   understand __thread declaration
                                   and pthread_getspecific() is too costly */

#if (NGX_EVENT_T_PADDING)
    int              padding[NGX_EVENT_T_PADDING];  /* event should not cross
                                                       cache line in SMP */
#endif
#endif
};


#if 1
typedef enum {
    NGX_SELECT_EVENT_N = 0,
#if (HAVE_POLL)
    NGX_POLL_EVENT_N,
#endif
#if (HAVE_DEVPOLL)
    NGX_DEVPOLL_EVENT_N,
#endif
#if (HAVE_KQUEUE)
    NGX_KQUEUE_EVENT_N,
#endif
#if (HAVE_AIO)
    NGX_AIO_EVENT_N,
#endif
#if (HAVE_IOCP)
    NGX_IOCP_EVENT_N,
#endif
    NGX_DUMMY_EVENT_N    /* avoid comma at end of enumerator list */
} ngx_event_type_e ;
#endif


typedef struct {
    int   (*add)(ngx_event_t *ev, int event, u_int flags);
    int   (*del)(ngx_event_t *ev, int event, u_int flags);

    int   (*enable)(ngx_event_t *ev, int event, u_int flags);
    int   (*disable)(ngx_event_t *ev, int event, u_int flags);

    int   (*add_conn)(ngx_connection_t *c);
    int   (*del_conn)(ngx_connection_t *c);

    int   (*process)(ngx_log_t *log);
    int   (*init)(ngx_log_t *log);
    void  (*done)(ngx_log_t *log);
} ngx_event_actions_t;


/* The event filter requires to read/write the whole data -
   select, poll, /dev/poll, kqueue. */
#define NGX_HAVE_LEVEL_EVENT    0x00000001

/* The event filter is deleted after a notification without an additional
   syscall - select, poll, kqueue.  */
#define NGX_HAVE_ONESHOT_EVENT  0x00000002

/* The event filter notifies only the changes and an initial level - kqueue */
#define NGX_HAVE_CLEAR_EVENT    0x00000004

/* The event filter has kqueue features - the eof flag, errno,
   available data, etc */
#define NGX_HAVE_KQUEUE_EVENT   0x00000008

/* The event filter supports low water mark - kqueue's NOTE_LOWAT.
   kqueue in FreeBSD 4.1-4.2 has no NOTE_LOWAT so we need a separate flag */
#define NGX_HAVE_LOWAT_EVENT    0x00000010

/* The event filter notifies only the changes (the edges)
   but not an initial level - epoll */
#define NGX_HAVE_EDGE_EVENT     0x00000020

/* No need to add or delete the event filters - rt signals */
#define NGX_HAVE_SIGIO_EVENT    0x00000040

/* No need to add or delete the event filters - overlapped, aio_read, aioread */
#define NGX_HAVE_AIO_EVENT      0x00000080

/* Need to add socket or handle only once - i/o completion port.
   It also requires HAVE_AIO_EVENT and NGX_HAVE_AIO_EVENT to be set */
#define NGX_HAVE_IOCP_EVENT     0x00000100


#define NGX_USE_LEVEL_EVENT     0x00010000
#define NGX_USE_AIO_EVENT       0x00020000


/* Event filter is deleted before closing file.
   Has no meaning for select, poll, epoll.

   kqueue:     kqueue deletes event filters for file that closed
               so we need only to delete filters in user-level batch array
   /dev/poll:  we need to flush POLLREMOVE event before closing file */

#define NGX_CLOSE_EVENT         1


#if (HAVE_KQUEUE)

#define NGX_READ_EVENT     EVFILT_READ
#define NGX_WRITE_EVENT    EVFILT_WRITE

/* NGX_CLOSE_EVENT is the module flag and it would not go into a kernel
   so we need to choose the value that would not interfere with any existent
   and future flags. kqueue has such values - EV_FLAG1, EV_EOF and EV_ERROR.
   They are reserved and cleared on a kernel entrance */
#undef  NGX_CLOSE_EVENT
#define NGX_CLOSE_EVENT    EV_FLAG1

#define NGX_LEVEL_EVENT    0
#define NGX_ONESHOT_EVENT  EV_ONESHOT
#define NGX_CLEAR_EVENT    EV_CLEAR

#ifndef HAVE_CLEAR_EVENT
#define HAVE_CLEAR_EVENT   1
#endif


#elif (HAVE_POLL) || (HAVE_DEVPOLL)

#define NGX_READ_EVENT     POLLIN
#define NGX_WRITE_EVENT    POLLOUT

#define NGX_LEVEL_EVENT    0
#define NGX_ONESHOT_EVENT  1

#else

#define NGX_READ_EVENT     0
#define NGX_WRITE_EVENT    1

#define NGX_LEVEL_EVENT    0
#define NGX_ONESHOT_EVENT  1

#endif /* HAVE_KQUEUE */

#ifndef NGX_CLEAR_EVENT
#define NGX_CLEAR_EVENT    0    /* dummy */
#endif

#if (USE_KQUEUE)

#define ngx_init_events      ngx_kqueue_init
#define ngx_process_events   ngx_kqueue_process_events
#define ngx_add_event        ngx_kqueue_add_event
#define ngx_del_event        ngx_kqueue_del_event
#if 0
#define ngx_add_timer        ngx_kqueue_add_timer
#else
#define ngx_add_timer        ngx_event_add_timer
#endif
#define ngx_event_recv       ngx_event_recv_core

#else

#define ngx_init_events     (ngx_event_init[ngx_event_type])
#define ngx_process_events   ngx_event_actions.process
#define ngx_add_event        ngx_event_actions.add
#define ngx_del_event        ngx_event_actions.del

#if 0
#define ngx_add_timer        ngx_event_actions.timer
#else
#define ngx_add_timer        ngx_event_add_timer
#endif

#if (HAVE_IOCP_EVENT)
#define ngx_event_recv       ngx_event_wsarecv
#elif (HAVE_AIO_EVENT)
#define ngx_event_recv       ngx_event_aio_read
#else
#define ngx_event_recv       ngx_io.recv
#define ngx_write_chain      ngx_io.send_chain
#endif

#endif

#define ngx_del_timer        ngx_event_del_timer



extern ngx_event_t          *ngx_read_events;
extern ngx_event_t          *ngx_write_events;
extern ngx_connection_t     *ngx_connections;

#if !(USE_KQUEUE)
extern ngx_event_actions_t   ngx_event_actions;
extern ngx_event_type_e      ngx_event_type;
extern int                   ngx_event_flags;
#endif


#if !(HAVE_EPOLL)
#define  ngx_edge_add_event(ev)  NGX_ERROR
#endif


#define NGX_EVENT_MODULE_TYPE 0x544E5645  /* "EVNT" */

#define NGX_EVENT_CONF        0x00200000
#define NGX_EVENT_MODULE      0


typedef struct {
    int   connections;
    int   timer_queues;
    int   use;
} ngx_event_conf_t;


typedef struct {
    int                     index;
    ngx_str_t              *name;

    void                 *(*create_conf)(ngx_pool_t *p);
    char                 *(*init_conf)(ngx_pool_t *p, void *conf);

    ngx_event_actions_t     actions;
} ngx_event_module_t;


extern ngx_module_t        ngx_events_module;
extern ngx_event_module_t  ngx_event_module_ctx;


#define ngx_event_get_conf(module)                                           \
                          (*(ngx_get_conf(ngx_events_module))) [module.index];



void ngx_event_accept(ngx_event_t *ev);


ssize_t ngx_event_recv_core(ngx_connection_t *c, char *buf, size_t size);
int ngx_event_close_connection(ngx_event_t *ev);


int  ngx_pre_thread(ngx_array_t *ls, ngx_pool_t *pool, ngx_log_t *log);
void ngx_worker(ngx_log_t *log);


#include <ngx_event_timer.h>


#endif /* _NGX_EVENT_H_INCLUDED_ */
