#ifndef _NGX_PARSE_H_INCLUDED_
#define _NGX_PARSE_H_INCLUDED_


#include <ngx_config.h>
#include <ngx_core.h>


#define NGX_PARSE_LARGE_TIME  -2


int ngx_parse_size(ngx_str_t *line);
int ngx_parse_time(ngx_str_t *line, int sec);


#endif /* _NGX_PARSE_H_INCLUDED_ */
