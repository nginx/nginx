#ifndef _NGX_EVENT_WRITE_H_INCLUDED_
#define _NGX_EVENT_WRITE_H_INCLUDED_


#include <ngx_types.h>
#include <ngx_hunk.h>
#include <ngx_connection.h>

ngx_chain_t *ngx_event_write(ngx_connection_t *cn, ngx_chain_t *in,
                             off_t flush);


#endif /* _NGX_EVENT_WRITE_H_INCLUDED_ */
