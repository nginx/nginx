/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) Nginx, Inc.
 */


#include <ngx_config.h>
#include <ngx_core.h>


#define NGX_MAX_ERROR_STR   2048


void ngx_cdecl
ngx_event_log(ngx_err_t err, const char *fmt, ...)
{
    u_char         *p, *last;
    long            types;
    HKEY            key;
    HANDLE          ev;
    va_list         args;
    u_char          text[NGX_MAX_ERROR_STR];
    const char     *msgarg[9];
    static u_char   netmsg[] = "%SystemRoot%\\System32\\netmsg.dll";

    last = text + NGX_MAX_ERROR_STR;
    p = text + GetModuleFileName(NULL, (char *) text, NGX_MAX_ERROR_STR - 50);

    *p++ = ':';
    ngx_linefeed(p);

    va_start(args, fmt);
    p = ngx_vslprintf(p, last, fmt, args);
    va_end(args);

    if (err) {
        p = ngx_log_errno(p, last, err);
    }

    if (p > last - NGX_LINEFEED_SIZE - 1) {
        p = last - NGX_LINEFEED_SIZE - 1;
    }

    ngx_linefeed(p);

    *p = '\0';

    /*
     * we do not log errors here since we use
     * Event Log only to log our own logs open errors
     */

    if (RegCreateKeyEx(HKEY_LOCAL_MACHINE,
           "SYSTEM\\CurrentControlSet\\Services\\EventLog\\Application\\nginx",
           0, NULL, REG_OPTION_NON_VOLATILE, KEY_SET_VALUE, NULL, &key, NULL)
        != 0)
    {
        return;
    }

    if (RegSetValueEx(key, "EventMessageFile", 0, REG_EXPAND_SZ,
                      netmsg, sizeof(netmsg) - 1)
        != 0)
    {
        return;
    }

    types = EVENTLOG_ERROR_TYPE;

    if (RegSetValueEx(key, "TypesSupported", 0, REG_DWORD,
                      (u_char *) &types, sizeof(long))
        != 0)
    {
        return;
    }

    RegCloseKey(key);

    ev = RegisterEventSource(NULL, "nginx");

    msgarg[0] = (char *) text;
    msgarg[1] = NULL;
    msgarg[2] = NULL;
    msgarg[3] = NULL;
    msgarg[4] = NULL;
    msgarg[5] = NULL;
    msgarg[6] = NULL;
    msgarg[7] = NULL;
    msgarg[8] = NULL;

    /*
     * the 3299 event id in netmsg.dll has the generic message format:
     *     "%1 %2 %3 %4 %5 %6 %7 %8 %9"
     */

    ReportEvent(ev, EVENTLOG_ERROR_TYPE, 0, 3299, NULL, 9, 0, msgarg, NULL);

    DeregisterEventSource(ev);
}
