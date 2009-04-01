
/*
 * Copyright (C) Igor Sysoev
 */


#include <ngx_config.h>
#include <ngx_core.h>


#define NGX_MAX_TEXT   2048


void __cdecl
ngx_message_box(char *title, ngx_uint_t type, ngx_err_t err,
    const char *fmt, ...)
{
    va_list  args;
    u_char   text[NGX_MAX_TEXT], *p, *last;

    last = text + NGX_MAX_TEXT;

    va_start(args, fmt);
    p = ngx_vsnprintf(text, NGX_MAX_TEXT, fmt, args);
    va_end(args);

    if (err) {

        if (p > last - 50) {

            /* leave a space for an error code */

            p = last - 50;
            *p++ = '.';
            *p++ = '.';
            *p++ = '.';
        }

        p = ngx_snprintf(p, last - p, ((unsigned) err < 0x80000000)
                                           ? " (%d: " : " (%Xd: ", err);
        p = ngx_strerror_r(err, p, last - p);

        if (p < last) {
            *p++ = ')';
        }
    }

    if (p == last) {
        p--;
    }

    *p = '\0';

    MessageBox(NULL, (char *) text, title, type);
}


ngx_int_t
ngx_system_tray_icon(HWND window, u_long action, HICON icon, u_char *tip)
{
    NOTIFYICONDATA  ni;

    ni.cbSize = sizeof(NOTIFYICONDATA);
    ni.hWnd = window;
    ni.uID = 0;
    ni.uFlags = NIF_MESSAGE|NIF_ICON|NIF_TIP;
    ni.uCallbackMessage = NGX_WM_TRAY;
    ni.hIcon = icon;

    if (tip) {
        ngx_cpystrn((u_char *) ni.szTip, tip, 64);
    } else {
        ni.szTip[0] = '\0';
    }

    if (Shell_NotifyIcon(action, &ni) == 0) {
        return NGX_ERROR;
    }

    return NGX_OK;
}
