#ifndef _NGINX_H_INCLUDED_
#define _NGINX_H_INCLUDED_


#define NGINX_VER          "nginx/0.0.3"
#define NGINX_CONF         (u_char *) "nginx.conf"
#define NGINX_PID          "nginx.pid"
#define NGINX_NEWPID_EXT   ".newbin"
#define NGINX_NEWPID       NGINX_PID NGINX_NEWPID_EXT

#define NGINX_VAR          "NGINX"

extern ngx_module_t        ngx_core_module;


#endif /* _NGINX_H_INCLUDED_ */
