
/*
 * Copyright (C) Igor Sysoev
 */


#ifndef _NGX_SOCKET_H_INCLUDED_
#define _NGX_SOCKET_H_INCLUDED_


#include <ngx_config.h>
#include <ngx_core.h>


#define NGX_WRITE_SHUTDOWN SD_SEND


typedef SOCKET  ngx_socket_t;
typedef int     socklen_t;


#define ngx_socket(af, type, proto, flags)   socket(af, type, proto)

#if 0
#define ngx_socket(af, type, proto, flags)                                    \
            WSASocket(af, type, proto, NULL, 0, flags)
#endif

#define ngx_socket_n        "WSASocket()"

int ngx_nonblocking(ngx_socket_t s);
int ngx_blocking(ngx_socket_t s);

#define ngx_nonblocking_n   "ioctlsocket(FIONBIO)"
#define ngx_blocking_n      "ioctlsocket(!FIONBIO)"

#define ngx_shutdown_socket    shutdown
#define ngx_shutdown_socket_n  "shutdown()"

#define ngx_close_socket    closesocket
#define ngx_close_socket_n  "closesocket()"


#ifndef WSAID_ACCEPTEX

typedef BOOL (PASCAL FAR * LPFN_ACCEPTEX)(
    IN SOCKET sListenSocket,
    IN SOCKET sAcceptSocket,
    IN PVOID lpOutputBuffer,
    IN DWORD dwReceiveDataLength,
    IN DWORD dwLocalAddressLength,
    IN DWORD dwRemoteAddressLength,
    OUT LPDWORD lpdwBytesReceived,
    IN LPOVERLAPPED lpOverlapped
    );

#define WSAID_ACCEPTEX \
        {0xb5367df1,0xcbac,0x11cf,{0x95,0xca,0x00,0x80,0x5f,0x48,0xa1,0x92}}

#endif


#ifndef WSAID_GETACCEPTEXSOCKADDRS

typedef VOID (PASCAL FAR * LPFN_GETACCEPTEXSOCKADDRS)(
    IN PVOID lpOutputBuffer,
    IN DWORD dwReceiveDataLength,
    IN DWORD dwLocalAddressLength,
    IN DWORD dwRemoteAddressLength,
    OUT struct sockaddr **LocalSockaddr,
    OUT LPINT LocalSockaddrLength,
    OUT struct sockaddr **RemoteSockaddr,
    OUT LPINT RemoteSockaddrLength
    );

#define WSAID_GETACCEPTEXSOCKADDRS \
        {0xb5367df2,0xcbac,0x11cf,{0x95,0xca,0x00,0x80,0x5f,0x48,0xa1,0x92}}

#endif


#ifndef LPFN_TRANSMITFILE

typedef BOOL (PASCAL FAR * LPFN_TRANSMITFILE)(
    IN SOCKET hSocket,
    IN HANDLE hFile,
    IN DWORD nNumberOfBytesToWrite,
    IN DWORD nNumberOfBytesPerSend,
    IN LPOVERLAPPED lpOverlapped,
    IN LPTRANSMIT_FILE_BUFFERS lpTransmitBuffers,
    IN DWORD dwReserved
    );

#define WSAID_TRANSMITFILE \
        {0xb5367df0,0xcbac,0x11cf,{0x95,0xca,0x00,0x80,0x5f,0x48,0xa1,0x92}}

#endif


extern LPFN_ACCEPTEX              acceptex;
extern LPFN_GETACCEPTEXSOCKADDRS  getacceptexsockaddrs;
extern LPFN_TRANSMITFILE          transmitfile;


ngx_inline static int ngx_tcp_push(ngx_socket_t s) {
     return 0;
}

#define ngx_tcp_push_n        "tcp_push()"


#endif /* _NGX_SOCKET_H_INCLUDED_ */
