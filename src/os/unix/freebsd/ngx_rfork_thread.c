
#include <ngx_os_thread.h>

char    *ngx_stacks_start;
char    *ngx_stacks_end;
size_t   ngx_stack_size;


/* handle thread-safe errno */
static int   errno0; /* errno for main thread */
static int  *errnos;

int *__error()
{
    ngx_tid_t tid = ngx_gettid();
    return tid ? &(errnos[ngx_gettid()]) : &errno0;
}


int ngx_create_thread(ngx_os_tid_t *tid, void *stack,
                     int (*func)(void *arg), void *arg, ngx_log_t log)
{
    int id, err;

    id = rfork_thread(RFPROC|RFMEM, stack, func, arg);
    err = ngx_errno;

    if (id == -1)
        ngx_log_error(NGX_LOG_ERR, log, err,
                      "ngx_create_os_thread: rfork failed");
    else
        *tid = id;

    return err;
}


int ngx_create_thread_env(int n, size_t size, ngx_log_t log)
{
    char *addr;

    /* create thread stacks */
    addr = mmap(NULL, n * size, PROT_READ|PROT_WRITE, MAP_ANON, -1, NULL);
    if (addr == MAP_FAILED) {
        ngx_log_error(NGX_LOG_ERR, log, ngx_errno,
                      "ngx_create_os_thread_stacks: mmap failed");
        return -1;
    }

    nxg_stacks_start = addr;
    nxg_stacks_end = addr + n * size;
    nxg_stack_size = size;

    /* create thread errno array */
    ngx_test_null(errnos, ngx_calloc(n * sizeof(int)), -1);

    /* create thread tid array */
    ngx_test_null(ngx_os_tids, ngx_calloc(n * sizeof(ngx_os_tid_t)), -1);

    /* allow spinlock in malloc() */
    __isthreaded = 1;

    return 0;
}
