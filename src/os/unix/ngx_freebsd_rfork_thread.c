
#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_process.h>
#include <ngx_log.h>
#include <ngx_alloc.h>


extern int   __isthreaded;


typedef int  ngx_tid_t;


static inline int ngx_gettid();


static char        *stacks_start;
static char        *stacks_end;
static size_t       stack_size;
static char        *last_stack;
static int          last_thread;

static ngx_log_t   *log;

static ngx_tid_t   *tids;

static int          red_zone = 4096;


/* the thread-safe errno */

static int   errno0;   /* the main thread's errno */
static int  *errnos;

int *__error()
{
    int  tid;

    tid = ngx_gettid();
    return tid ? &errnos[tid] : &errno0;
}


int ngx_create_thread(ngx_tid_t *tid, int (*func)(void *arg), void *arg)
{
    int         id, err;
    char       *stack_top;

    last_stack += stack_size;
    stack_top = last_stack - red_zone;

    if (stack_top > stacks_end) {
        ngx_log_error(NGX_LOG_CRIT, log, 0, "no more threads allocated");
        return NGX_ERROR;
    }

#if 0
    id = rfork_thread(RFPROC|RFMEM|RFFDG|RFCFDG, stack_top, func, arg);
#elif 1
    id = rfork_thread(RFPROC|RFMEM, stack_top, func, arg);
#else
    id = rfork_thread(RFPROC|RFTHREAD|RFMEM, stack_top, func, arg);
#endif
    err = errno;

    if (id == -1) {
        ngx_log_error(NGX_LOG_ALERT, log, err, "rfork() failed");

    } else {
        *tid = id;
        tids[last_thread++] = id;

        /* allow the spinlock in libc malloc() */
        __isthreaded = 1;
    }

    return err;
}


int ngx_init_thread_env(int n, size_t size, ngx_log_t *lg)
{
    int    len, i;
    char  *usrstack, *zone;

    log = lg;

    /* create the thread stacks */

    len = 4;
    if (sysctlbyname("kern.usrstack", &usrstack, &len, NULL, 0) == -1) {
        ngx_log_error(NGX_LOG_ALERT, log, errno,
                      "sysctlbyname(kern.usrstack) failed");
        return NGX_ERROR;
    }

printf("usrstack: %08X\n", usrstack);
printf("red zone: %08X\n", usrstack - (size + red_zone));

#if 1
    /* red zone */
    zone = mmap(usrstack - (size + red_zone), red_zone,
                PROT_NONE, MAP_ANON, -1, 0);
    if (zone == MAP_FAILED) {
        ngx_log_error(NGX_LOG_ALERT, log, errno,
                      "mmap(%d, PROT_NONE, MAP_ANON) failed", red_zone);
        return NGX_ERROR;
    }
#else
    zone = usrstack - (size + red_zone);
#endif

    last_stack = zone + red_zone;

    for (i = 0; i < n; i++) {
        last_stack -= size + red_zone;
printf("stack: %08X\n", last_stack);
        last_stack = mmap(last_stack, size, PROT_READ|PROT_WRITE,
                          MAP_STACK, -1, 0);
        if (last_stack == MAP_FAILED) {
            ngx_log_error(NGX_LOG_ALERT, log, errno,
                          "mmap(%d, MAP_STACK) failed", size);
            return NGX_ERROR;
        }
    }

    stacks_start = last_stack;
    stack_size = size + red_zone;
    stacks_end = stacks_start + n * stack_size;

    /* create the thread errno array */
    ngx_test_null(errnos, ngx_calloc(n * sizeof(int), log), NGX_ERROR);

    /* create the thread tid array */
    ngx_test_null(tids, ngx_calloc(n * sizeof(ngx_tid_t), log), NGX_ERROR);

    tids[0] = ngx_getpid();
    last_thread = 1;

    return NGX_OK;
}


ngx_tid_t ngx_thread_self()
{
    return tids[ngx_gettid()];
}


static inline int ngx_gettid()
{   
    char  *sp;

    __asm__ ("mov %%esp, %0" : "=q" (sp));

    return (sp > stacks_end) ? 0: ((sp - stacks_start) / stack_size  + 1);
}
