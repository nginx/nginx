
#include <ngx_config.h>

char *ngx_conf_set_size_slot(char *conf, int offset, char *value)
{
    int size;

    size = atoi(value);
    if (size < 0)
        return "value must be greater or equal to zero";

    *(int *) (conf + offset) = size;
    return NULL;
}

char *ngx_conf_set_time_slot(char *conf, int offset, char *value)
{
    int size;

    size = atoi(value);
    if (size < 0)
        return "value must be greater or equal to zero";

    *(int *) (conf + offset) = size;
    return NULL;
}
