#ifndef _NGX_RECV_H_INCLUDED_
#define _NGX_RECV_H_INCLUDED_


#include <errno.h>

#define ngx_recv(fd, buf, size, flags)  recv(fd, buf, size, flags)


#endif /* _NGX_RECV_H_INCLUDED_ */
