#ifndef _NGX_HTTP_CONFIG_COMMAND_H_INCLUDED_
#define _NGX_HTTP_CONFIG_COMMAND_H_INCLUDED_


#define NGX_CONF_TAKE1     0
#define NGX_CONF_ITERATE   0

#define NGX_CONF_UNSET   -1

typedef struct {
    char    *name;
    char  *(*set)();
    int      offset;
    int      zone;
    int      type;
    char    *description;
} ngx_command_t;

char *ngx_conf_set_size_slot(char *conf, int offset, char *value);
char *ngx_conf_set_time_slot(char *conf, int offset, char *value);


#endif _NGX_HTTP_CONFIG_COMMAND_H_INCLUDED_
