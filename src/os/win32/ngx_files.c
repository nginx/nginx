
#include <ngx_config.h>
#include <ngx_core.h>


ssize_t ngx_read_file(ngx_file_t *file, char *buf, size_t size, off_t offset)
{
    size_t n;

    if (ReadFile(file->fd, buf, size, &n, NULL) == 0) {
        ngx_log_error(NGX_LOG_ERR, file->log, ngx_errno, "ReadFile() failed");
        return NGX_ERROR;
    }

    file->offset += n;

    return n;
}


int ngx_file_append_mode(ngx_fd_t fd)
{
    if (SetFilePointer(fd, 0, NULL, FILE_END) == 0xFFFFFFFF) {
        if (GetLastError() != NO_ERROR) {
            return NGX_ERROR;
        }
    }

    return NGX_OK;
}
