
#include <ngx_config.h>
#include <ngx_core.h>


extern int   __isthreaded;


typedef int  ngx_tid_t;


static inline int ngx_gettid();


static char        *usrstack;
static int          red_zone = 4096;

static size_t       stack_size;
static size_t       usable_stack_size;
static char        *last_stack;

static int          threads;
static int          nthreads;
static ngx_tid_t   *tids;

/* the thread-safe errno */

static int   errno0;   /* the main thread's errno */
static int  *errnos;

int *__error()
{
    int  tid;

    tid = ngx_gettid();

    return tid ? &errnos[tid - 1] : &errno0;
}


int ngx_create_thread(ngx_tid_t *tid, int (*func)(void *arg), void *arg,
                      ngx_log_t *log)
{
    int         id, err;
    char       *stack, *stack_top;

    if (threads >= nthreads) {
        ngx_log_error(NGX_LOG_CRIT, log, 0,
                      "no more than %d threads can be created", nthreads);
        return NGX_ERROR;
    }

    last_stack -= stack_size;
    stack = mmap(last_stack, usable_stack_size, PROT_READ|PROT_WRITE,
                 MAP_STACK, -1, 0);
    if (stack == MAP_FAILED) {
        ngx_log_error(NGX_LOG_ALERT, log, errno,
                      "mmap(%08X:%d, MAP_STACK) thread stack failed",
                      last_stack, usable_stack_size);
        return NGX_ERROR;
    }

    if (stack != last_stack) {
        ngx_log_error(NGX_LOG_ALERT, log, 0, "stack address was changed");
    }

    stack_top = stack + usable_stack_size;

printf("stack: %08X-%08X\n", stack, stack_top);

#if 1
    id = rfork_thread(RFPROC|RFTHREAD|RFMEM, stack_top, func, arg);
#elif 1
    id = rfork_thread(RFPROC|RFMEM, stack_top, func, arg);
#elif 1
    id = rfork_thread(RFFDG|RFCFDG, stack_top, func, arg);
#else
    id = rfork(RFFDG|RFCFDG);
#endif

    err = errno;

    if (id == -1) {
        ngx_log_error(NGX_LOG_ALERT, log, err, "rfork() failed");

    } else {
        *tid = id;
        threads = (usrstack - stack_top) / stack_size;
        tids[threads] = id;

        /* allow the spinlock in libc malloc() */
        __isthreaded = 1;
    }

    return err;
}


int ngx_init_thread_env(int n, size_t size, ngx_log_t *log)
{
    int    len;
    char  *rz, *zone;

    nthreads = n;

    len = 4;
    if (sysctlbyname("kern.usrstack", &usrstack, &len, NULL, 0) == -1) {
        ngx_log_error(NGX_LOG_ALERT, log, errno,
                      "sysctlbyname(kern.usrstack) failed");
        return NGX_ERROR;
    }

printf("usrstack: %08X\n", usrstack);

    /* red zone */
    rz = usrstack - (size + red_zone);

printf("red zone: %08X\n", rz);

    zone = mmap(rz, red_zone, PROT_NONE, MAP_ANON, -1, 0);
    if (zone == MAP_FAILED) {
        ngx_log_error(NGX_LOG_ALERT, log, errno,
                      "mmap(%08X:%d, PROT_NONE, MAP_ANON) red zone failed",
                      rz, red_zone);
        return NGX_ERROR;
    }

    if (zone != rz) {
        ngx_log_error(NGX_LOG_ALERT, log, 0, "red zone address was changed");
    }

    /* create the thread errno array */
    ngx_test_null(errnos, ngx_calloc(n * sizeof(int), log), NGX_ERROR);

    /* create the thread tid array */
    ngx_test_null(tids, ngx_calloc((n + 1) * sizeof(ngx_tid_t), log),
                  NGX_ERROR);

    tids[0] = ngx_getpid();
    threads = 1;

    last_stack = zone + red_zone;
    usable_stack_size = size;
    stack_size = size + red_zone;

    return NGX_OK;
}


ngx_tid_t ngx_thread_self()
{
    int        tid;
    ngx_tid_t  pid;

    tid = ngx_gettid();

    if (tids[tid] == 0) {
        pid = ngx_getpid();
        tids[tid] = pid;
        return pid;
    }

    return tids[tid];
}


static inline int ngx_gettid()
{
    char  *sp;

    if (stack_size == 0) {
        return 0;
    }

    __asm__ ("mov %%esp, %0" : "=q" (sp));

    return (usrstack - sp) / stack_size;
}
