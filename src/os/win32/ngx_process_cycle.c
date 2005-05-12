
/*
 * Copyright (C) Igor Sysoev
 */


#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_event.h>
#include <nginx.h>


static void *ngx_worker_thread_cycle(void *data);
static long __stdcall ngx_window_procedure(HWND window, u_int message,
    u_int wparam, long lparam);

#if 0
ngx_pid_t     ngx_new_binary;

sig_atomic_t  ngx_reap;
sig_atomic_t  ngx_timer;

#endif

ngx_uint_t    ngx_process;
ngx_pid_t     ngx_pid;
ngx_uint_t    ngx_threaded;
ngx_uint_t    ngx_inherited;


sig_atomic_t  ngx_terminate;
sig_atomic_t  ngx_quit;
ngx_uint_t    ngx_exiting;

#if 0

sig_atomic_t  ngx_noaccept;
sig_atomic_t  ngx_reconfigure;
sig_atomic_t  ngx_reopen;
sig_atomic_t  ngx_change_binary;

#endif


static HMENU  ngx_menu;


void
ngx_master_process_cycle(ngx_cycle_t *cycle)
{
    ngx_log_error(NGX_LOG_EMERG, cycle->log, 0, "master mode is not supported");

    exit(2);
}


void
ngx_single_process_cycle(ngx_cycle_t *cycle)
{
    int               rc;
    ngx_int_t         i;
    ngx_err_t         err;
    ngx_tid_t         tid;
    MSG               message;
    HWND              window;
    HMENU             menu;
    HICON             icon,tray;
    WNDCLASS          wc;
    HINSTANCE         instance;
    ngx_core_conf_t  *ccf;

    ngx_init_temp_number();

    for (i = 0; ngx_modules[i]; i++) {
        if (ngx_modules[i]->init_process) {
            if (ngx_modules[i]->init_process(cycle) == NGX_ERROR) {
                /* fatal */
                exit(2);
            }
        }
    }


    ccf = (ngx_core_conf_t *) ngx_get_conf(cycle->conf_ctx, ngx_core_module);

    if (ngx_init_threads(ngx_threads_n,
                                   ccf->thread_stack_size, cycle) == NGX_ERROR)
    {     
        /* fatal */
        exit(2);
    }

    err = ngx_thread_key_create(&ngx_core_tls_key);
    if (err != 0) {
        ngx_log_error(NGX_LOG_ALERT, cycle->log, err,
                      ngx_thread_key_create_n " failed");
        /* fatal */
        exit(2);
    }


    instance = GetModuleHandle(NULL);

    icon = LoadIcon(instance, "nginx");
    if (icon == NULL) {
        ngx_log_error(NGX_LOG_EMERG, cycle->log, ngx_errno,
                      "LoadIcon(\"nginx\") failed");
        /* fatal */
        exit(2);
    }

    tray = LoadIcon(instance, "tray");
    if (icon == NULL) {
        ngx_log_error(NGX_LOG_EMERG, cycle->log, ngx_errno,
                      "LoadIcon(\"tray\") failed");
        /* fatal */
        exit(2);
    }

    menu = LoadMenu(instance, "nginx");
    if (menu == NULL) {
        ngx_log_error(NGX_LOG_EMERG, cycle->log, ngx_errno,
                      "LoadMenu() failed");
        /* fatal */
        exit(2);
    }

    ngx_menu = GetSubMenu(menu, 0);
    if (ngx_menu == NULL) {
        ngx_log_error(NGX_LOG_EMERG, cycle->log, ngx_errno,
                      "GetSubMenu() failed");
        /* fatal */
        exit(2);
    }


    wc.style = CS_HREDRAW|CS_VREDRAW; 
    wc.lpfnWndProc = ngx_window_procedure;
    wc.cbClsExtra = 0;
    wc.cbWndExtra = 0;
    wc.hInstance = instance;
    wc.hIcon = icon;
    wc.hCursor = NULL;
    wc.hbrBackground = NULL;
    wc.lpszMenuName =  NULL;
    wc.lpszClassName = "nginx";

    if (RegisterClass(&wc) == 0) {
        ngx_log_error(NGX_LOG_EMERG, cycle->log, ngx_errno,
                      "RegisterClass() failed");
        /* fatal */
        exit(2);
    }


    window = CreateWindow("nginx", "nginx", WS_OVERLAPPEDWINDOW,
                          CW_USEDEFAULT, CW_USEDEFAULT,
                          CW_USEDEFAULT, CW_USEDEFAULT,
                          NULL, NULL, instance, NULL);

    if (window == NULL) {
        ngx_log_error(NGX_LOG_EMERG, cycle->log, ngx_errno,
                      "CreateWindow() failed");
        /* fatal */
        exit(2);
    }


    if (ngx_system_tray_icon(window, NIM_ADD, tray, (u_char *) " nginx")
        != NGX_OK)
    {
        ngx_log_error(NGX_LOG_EMERG, cycle->log, ngx_errno,
                      "Shell_NotifyIcon(NIM_ADD) failed");
        /* fatal */
        exit(2);
    }


    if (ngx_create_thread(&tid, ngx_worker_thread_cycle, NULL, cycle->log) != 0)
    {
        /* fatal */
        exit(2);
    }


    for ( ;; ) {
        rc = GetMessage(&message, NULL, 0, 0);

        if (rc == -1) {
            ngx_log_error(NGX_LOG_ALERT, cycle->log, ngx_errno,
                          "GetMessage() failed");
            continue;
        }

        if (rc == 0) {
            exit(0);
        }

        TranslateMessage(&message);
        DispatchMessage(&message);
    }
}


static void *
ngx_worker_thread_cycle(void *data)
{
    ngx_cycle_t  *cycle;

    cycle = (ngx_cycle_t *) ngx_cycle;

    while (!ngx_quit) {
        ngx_log_debug0(NGX_LOG_DEBUG_EVENT, cycle->log, 0, "worker cycle");

        ngx_process_events(cycle);
    }

    return NULL;
}


static long __stdcall
ngx_window_procedure(HWND window, u_int message, u_int wparam, long lparam)
{
    POINT  mouse;

    switch (message) {

    case NGX_WM_TRAY:
        if (lparam == WM_RBUTTONDOWN) {
            if (GetCursorPos(&mouse) == 0) {
                ngx_log_error(NGX_LOG_ALERT, ngx_cycle->log, ngx_errno,
                              "GetCursorPos() failed");
                return 0;
            }

            if (SetForegroundWindow(window) == 0) {
                ngx_log_error(NGX_LOG_ALERT, ngx_cycle->log, ngx_errno,
                              "SetForegroundWindow() failed");
                return 0;
            }

            if (TrackPopupMenu(ngx_menu, TPM_RIGHTBUTTON,
                               mouse.x, mouse.y, 0, window, NULL) == 0)
            {
                ngx_log_error(NGX_LOG_ALERT, ngx_cycle->log, ngx_errno,
                              "TrackPopupMenu() failed");
                return 0;
            }
        }

        return 0;

    case WM_COMMAND:
        if (wparam == NGX_WM_ABOUT) {
            ngx_message_box("nginx", MB_OK, 0,
                            NGINX_VER CRLF "(C) 2002-2005 Igor Sysoev");
            return 0;
        }

        if (wparam == NGX_WM_EXIT) {
            if (ngx_system_tray_icon(window, NIM_DELETE, NULL, NULL)
                != NGX_OK)
            {
                ngx_log_error(NGX_LOG_ALERT, ngx_cycle->log, ngx_errno,
                              "Shell_NotifyIcon(NIM_DELETE) failed");
            }
        }

        PostQuitMessage(0);

        return 0;

    default:
        return DefWindowProc(window, message, wparam, lparam);
    }
}
