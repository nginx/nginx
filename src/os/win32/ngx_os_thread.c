

#include <ngx_config.h>

#include <ngx_log.h>
#include <ngx_os_thread.h>


int ngx_create_os_thread(ngx_os_tid_t *tid, void *stack,
                         ngx_thread_start_routine_t func, void *arg,
                         ngx_log_t log)
{
    ngx_os_tid_t  id;
    int  dummy;       /* needed in Win9X only, in NT can be NULL */

    id = CreateThread(NULL, stack_size, func, arg, 0, &dummy);

    if (id == NULL) {
        ngx_log_error(NGX_LOG_ERR, log, err, "CreateThread() failed");
        return NGX_ERROR;
    }

    *tid = id;

    return NGX_OK;
}
