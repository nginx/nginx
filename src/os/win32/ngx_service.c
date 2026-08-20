
/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) Nginx, Inc.
 */

#include <ngx_config.h>
#include <ngx_core.h>

#define NGX_SERVICE_CONTROL_SHUTDOWN   128
#define NGX_SERVICE_CONTROL_REOPEN     129
HANDLE  ngx_stop_event; // Defined in src\os\win32\ngx_process_cycle.c

/*
void LpserviceMainFunctiona(
  [in] DWORD dwNumServicesArgs,
  [in] LPSTR *lpServiceArgVectors
)
*/
void WINAPI service_main(DWORD dwNumServicesArgs, LPSTR *lpServiceArgVectors);

/*

DWORD LphandlerFunctionEx(
  [in] DWORD dwControl,
  [in] DWORD dwEventType,
  [in] LPVOID lpEventData,
  [in] LPVOID lpContext
)

*/
DWORD WINAPI service_handler(DWORD control, DWORD  type, void *data, void *ctx);

SERVICE_STATUS_HANDLE  service = 0; // Put this field in ngx_cycle ?

SERVICE_TABLE_ENTRY service_table[] = {
    { "nginx", service_main},
    { NULL, NULL }
};


ngx_int_t
ngx_service()
{
    /* primary thread */
    /* StartServiceCtrlDispatcher() should be called within 30 seconds */

    if (StartServiceCtrlDispatcher(service_table) == 0) {
        ngx_log_error(NGX_LOG_EMERG, ngx_cycle->log, ngx_errno,
                      "StartServiceCtrlDispatcher() failed");
        return NGX_ERROR;
    }
    return NGX_OK;
}


void WINAPI
service_main(DWORD dwNumServicesArgs, LPSTR *lpServiceArgVectors)
{
    SERVICE_STATUS         status;

    /* thread spawned by SCM */
    service = RegisterServiceCtrlHandlerEx("nginx", service_handler, NULL);
    if (service == INVALID_HANDLE_VALUE) {
        ngx_log_error(NGX_LOG_EMERG, ngx_cycle->log, ngx_errno,
                      "RegisterServiceCtrlHandlerEx() failed");
        return;
    }

    /* Use a more generic report_service_status ? */
    status.dwServiceType = SERVICE_WIN32_OWN_PROCESS;
    status.dwCurrentState = SERVICE_START_PENDING;
    status.dwControlsAccepted = SERVICE_ACCEPT_STOP;
    status.dwWin32ExitCode = NO_ERROR;
    status.dwServiceSpecificExitCode = 0;
    status.dwCheckPoint = 1;
    status.dwWaitHint = 2000;

    /* SetServiceStatus() should be called within 80 seconds */
    if (SetServiceStatus(service, &status) == 0) {
        ngx_log_error(NGX_LOG_EMERG, ngx_cycle->log, ngx_errno,
                      "SetServiceStatus() failed");
        return;
    }

    /* init */
    // Do we have any init to wait for ?
    // Init seems preety well advanced when the service thread is created

    status.dwCurrentState = SERVICE_RUNNING;
    status.dwCheckPoint = 0;
    status.dwWaitHint = 0;

    if (SetServiceStatus(service, &status) == 0) {
        ngx_log_error(NGX_LOG_EMERG, ngx_cycle->log, ngx_errno,
                      "SetServiceStatus() failed");
        return;
    }

}

int report_service_stop_status(DWORD dwCurrentState)
{
    SERVICE_STATUS         status;

    status.dwServiceType = SERVICE_WIN32_OWN_PROCESS;
    status.dwCurrentState = dwCurrentState;
    status.dwControlsAccepted = 0;
    status.dwWin32ExitCode = NO_ERROR;
    status.dwServiceSpecificExitCode = 0;
    status.dwCheckPoint = 0;
    status.dwWaitHint = 0;

    /* SetServiceStatus() should be called within 80 seconds */
    if (SetServiceStatus(service, &status) == 0) {
        return 1;
    }
    return 0;
}



DWORD WINAPI
service_handler(DWORD control, DWORD type, void *data, void *ctx)
{
     switch (control) {

    // case SERVICE_CONTROL_INTERROGATE:
    //     status = NGX_IOCP_INTERROGATE;
    //     break;
    //
    case SERVICE_CONTROL_STOP:
        report_service_stop_status(SERVICE_STOP_PENDING);
        if (SetEvent(ngx_stop_event) == 0) {
            ngx_log_error(NGX_LOG_EMERG, ngx_cycle->log, ngx_errno,
                      "SetEvent(ngx_stop_event) failed");
        }
        report_service_stop_status(SERVICE_STOPPED);
        break;
    //
    // case SERVICE_CONTROL_PARAMCHANGE:
    //     status = NGX_IOCP_RECONFIGURE;
    //     break;
    //
    // case NGX_SERVICE_CONTROL_SHUTDOWN:
    //     status = NGX_IOCP_REOPEN;
    //     break;
    //
    // case NGX_SERVICE_CONTROL_REOPEN:
    //     status = NGX_IOCP_REOPEN;
    //     break;

    default:
        return ERROR_CALL_NOT_IMPLEMENTED;
    }
    return NO_ERROR;
}
