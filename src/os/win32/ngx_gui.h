
/*
 * Copyright (C) Igor Sysoev
 */


#ifndef _NGX_GUI_H_INCLUDED_
#define _NGX_GUI_H_INCLUDED_


#include <ngx_config.h>
#include <ngx_core.h>


#define NGX_WM_TRAY    WM_USER
#define NGX_WM_EXIT    WM_USER + 1
#define NGX_WM_ABOUT   WM_USER + 2


void ngx_message_box(char *title, ngx_uint_t type, ngx_err_t err,
                     const char *fmt, ...);

ngx_int_t ngx_system_tray_icon(HWND window, u_long action,
                               HICON icon, u_char *tip);


#endif /* _NGX_GUI_H_INCLUDED_ */
