
/*
 * Copyright (C) Igor Sysoev
 */


#include <ngx_config.h>
#include <ngx_core.h>


#if (HAVE_MAP_ANON)

void *ngx_create_shared_memory(size_t size, ngx_log_t *log)
{
    void  *p;

    p = mmap(NULL, size, PROT_READ|PROT_WRITE, MAP_ANON|MAP_SHARED, -1, 0);

    if (p == MAP_FAILED) {
        ngx_log_error(NGX_LOG_ALERT, log, ngx_errno,
                      "mmap(MAP_ANON|MAP_SHARED, " SIZE_T_FMT ") failed",
                      size);
        return NULL;
    }

    return p;
}

#elif (HAVE_MAP_DEVZERO)

void *ngx_create_shared_memory(size_t size, ngx_log_t *log)
{
    void      *p;
    ngx_fd_t   fd;

    fd = open("/dev/zero", O_RDWR);

    if (fd == -1) {
        ngx_log_error(NGX_LOG_ALERT, log, ngx_errno,
                      "open(/dev/zero) failed");
        return NULL;
    }

    p = mmap(NULL, size, PROT_READ|PROT_WRITE, MAP_SHARED, fd, 0);

    if (p == MAP_FAILED) {
        ngx_log_error(NGX_LOG_ALERT, log, ngx_errno,
                      "mmap(/dev/zero, MAP_SHARED, " SIZE_T_FMT ") failed",
                      size);
        p = NULL;
    }

    if (close(fd) == -1) {
        ngx_log_error(NGX_LOG_ALERT, log, ngx_errno, "close() failed");
    }

    return p;
}

#elif (HAVE_SYSVSHM)

#include <sys/ipc.h>
#include <sys/shm.h>


void *ngx_create_shared_memory(size_t size, ngx_log_t *log)
{
    int    id;
    void  *p;

    id = shmget(IPC_PRIVATE, size, (SHM_R|SHM_W|IPC_CREAT));

    if (id == -1) {
        ngx_log_error(NGX_LOG_ALERT, log, ngx_errno,
                      "shmget(" SIZE_T_FMT ") failed", size);
        return NULL;
    }

    ngx_log_debug1(NGX_LOG_DEBUG_CORE, log, 0, "shmget id: %d", id);

    p = shmat(id, NULL, 0);

    if (p == (void *) -1) {
        ngx_log_error(NGX_LOG_ALERT, log, ngx_errno, "shmat() failed");
        p = NULL;
    }

    if (shmctl(id, IPC_RMID, NULL) == -1) {
        ngx_log_error(NGX_LOG_ALERT, log, ngx_errno, "shmctl(IPC_RMID) failed");
        p = NULL;
    }

    return p;
}

#endif
