

#include <ngx_config.h>

#include <ngx_log.h>
#include <ngx_pthread.h>


int ngx_create_os_thread(ngx_os_tid_t *tid, void *stack,
                         ngx_thread_start_routine_t func, void *arg,
                         ngx_log_t log)
{
    int              err;
    pthread_attr_t  *attr;

    attr = NULL;

    err = pthread_create(tid, attr, func, arg);

    if (err != 0) {
        ngx_log_error(NGX_LOG_ERR, log, err, "pthread_create() failed");
        return NGX_ERROR;
    }

    return NGX_OK;
}
