
#include <ngx_core.h>
#include <ngx_types.h>
#include <ngx_file.h>

ssize_t ngx_read_file(ngx_file_t *file, char *buf, size_t size, off_t offset)
{
    size_t n;

    if (ReadFile(file->fd, buf, size, &n, NULL) == 0) {
        ngx_log_error(NGX_LOG_ERR, file->log, ngx_errno, "ReadFile() failed");
        return NGX_ERROR;
    }

    return n;
}
