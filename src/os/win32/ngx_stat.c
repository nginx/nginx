
#include <windows.h>

#include <ngx_stat.h>

int ngx_stat(char *file, ngx_stat_t *sb)
{
    *sb = GetFileAttributes(file);

    if (*sb == INVALID_FILE_ATTRIBUTES) {
        return -1;
    }

    return 0;
}
