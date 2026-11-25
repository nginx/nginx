
/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) Nginx, Inc.
 */


#include <ngx_config.h>
#include <ngx_core.h>


static char *ngx_linux_cgroup_path(void);
static void ngx_linux_unescape_mount_path(char *path);
static ngx_int_t ngx_linux_cgroup_quota(ngx_int_t ncpu, char *mount,
    char *relative, ngx_int_t mount_id);
static ngx_int_t ngx_linux_mount_id(ngx_fd_t fd);


u_char  ngx_linux_kern_ostype[50];
u_char  ngx_linux_kern_osrelease[50];


static ngx_os_io_t ngx_linux_io = {
    ngx_unix_recv,
    ngx_readv_chain,
    ngx_udp_unix_recv,
    ngx_unix_send,
    ngx_udp_unix_send,
    ngx_udp_unix_sendmsg_chain,
#if (NGX_HAVE_SENDFILE)
    ngx_linux_sendfile_chain,
    NGX_IO_SENDFILE
#else
    ngx_writev_chain,
    0
#endif
};


ngx_int_t
ngx_os_specific_init(ngx_log_t *log)
{
    struct utsname  u;

    if (uname(&u) == -1) {
        ngx_log_error(NGX_LOG_ALERT, log, ngx_errno, "uname() failed");
        return NGX_ERROR;
    }

    (void) ngx_cpystrn(ngx_linux_kern_ostype, (u_char *) u.sysname,
                       sizeof(ngx_linux_kern_ostype));

    (void) ngx_cpystrn(ngx_linux_kern_osrelease, (u_char *) u.release,
                       sizeof(ngx_linux_kern_osrelease));

    ngx_os_io = ngx_linux_io;

    return NGX_OK;
}


void
ngx_os_specific_status(ngx_log_t *log)
{
    ngx_log_error(NGX_LOG_NOTICE, log, 0, "OS: %s %s",
                  ngx_linux_kern_ostype, ngx_linux_kern_osrelease);
}


ngx_int_t
ngx_linux_worker_processes(ngx_int_t ncpu)
{
    char       *cgroup, *line, *fields, *id, *root, *mount, *relative;
    FILE       *file;
    size_t      size, len;
    ngx_int_t   mount_id;

    if (ncpu == 1) {
        return ncpu;
    }

    cgroup = ngx_linux_cgroup_path();
    if (cgroup == NULL) {
        return ncpu;
    }

    file = fopen("/proc/self/mountinfo", "r");
    if (file == NULL) {
        ngx_free(cgroup);
        return ncpu;
    }

    line = NULL;
    size = 0;

    while (ncpu > 1 && getline(&line, &size, file) != -1) {
        if (ngx_strstr(line, " - cgroup2 ") == NULL) {
            continue;
        }

        fields = line;
        id = strsep(&fields, " ");
        (void) strsep(&fields, " ");  /* parent ID */
        (void) strsep(&fields, " ");  /* major:minor */

        root = strsep(&fields, " ");
        mount = strsep(&fields, " ");

        mount_id = ngx_atoi((u_char *) id, ngx_strlen(id));

        if (mount_id == NGX_ERROR || root == NULL || mount == NULL
            || *root != '/' || *mount != '/')
        {
            continue;
        }

        ngx_linux_unescape_mount_path(root);
        ngx_linux_unescape_mount_path(mount);

        /* A cgroup2 mount can expose only a subtree of the hierarchy. */

        len = ngx_strlen(root);

        if (len == 1) {
            relative = cgroup;

        } else {
            if (ngx_strncmp(cgroup, root, len) != 0
                || (cgroup[len] != '/' && cgroup[len] != '\0'))
            {
                continue;
            }

            relative = cgroup + len;
        }

        ncpu = ngx_linux_cgroup_quota(ncpu, mount, relative, mount_id);
    }

    ngx_free(line);
    ngx_free(cgroup);
    fclose(file);

    return ncpu;
}


static char *
ngx_linux_cgroup_path(void)
{
    char     *line, *path;
    FILE     *file;
    size_t    size;
    ssize_t   n;

    file = fopen("/proc/self/cgroup", "r");
    if (file == NULL) {
        return NULL;
    }

    line = NULL;
    size = 0;
    path = NULL;

    while ((n = getline(&line, &size, file)) != -1) {
        if (n < 5 || ngx_strncmp(line, "0::/", 4) != 0) {
            continue;
        }

        if (line[n - 1] != '\n') {
            break;
        }

        line[--n] = '\0';

        /* Outside the current cgroup namespace there is no visible path. */

        if (ngx_strstr(line + 3, "/../") == NULL
            && (n < 6 || ngx_strcmp(line + n - 3, "/..") != 0))
        {
            path = memmove(line, line + 3, n - 2);
        }

        break;
    }

    fclose(file);

    if (path == NULL) {
        ngx_free(line);
    }

    return path;
}


static void
ngx_linux_unescape_mount_path(char *path)
{
    char  *p, *dst;

    for (p = path, dst = path; *p; p++, dst++) {
        if (*p == '\\' && p[1] >= '0' && p[1] <= '3'
            && p[2] >= '0' && p[2] <= '7' && p[3] >= '0' && p[3] <= '7')
        {
            *dst = (char) (((p[1] - '0') << 6) | ((p[2] - '0') << 3)
                           | (p[3] - '0'));
            p += 3;

        } else {
            *dst = *p;
        }
    }

    *dst = '\0';
}


static ngx_int_t
ngx_linux_cgroup_quota(ngx_int_t ncpu, char *mount, char *relative,
    ngx_int_t mount_id)
{
    FILE                *file;
    size_t               len, rel;
    u_char              *root, *end;
    ngx_fd_t             fd;
    unsigned long long   quota, period, limit;
    u_char               path[NGX_MAX_PATH];

    len = ngx_strlen(mount);
    rel = ngx_strlen(relative);

    if (len == 1) {
        len = 0;
    }

    if (rel == 1) {
        rel = 0;
    }

    if (len + sizeof("/cpu.max") > sizeof(path)) {
        return ncpu;
    }

    /* Start with the nearest ancestor if the full path is too long. */

    while (len + rel + sizeof("/cpu.max") > sizeof(path)) {
        while (relative[--rel] != '/') { /* void */ }
    }

    root = ngx_cpymem(path, mount, len);
    end = ngx_cpymem(root, relative, rel);

    for ( ;; ) {
        ngx_memcpy(end, "/cpu.max", sizeof("/cpu.max"));

        fd = ngx_open_file(path, NGX_FILE_RDONLY|NGX_FILE_NONBLOCK,
                           NGX_FILE_OPEN, 0);

        if (fd != NGX_INVALID_FILE) {
            /* A covering mount can hide the cgroup2 mount. */

            if (ngx_linux_mount_id(fd) == mount_id) {
                file = fdopen(fd, "r");

                if (file != NULL) {
                    if (fscanf(file, "%llu %llu", &quota, &period) == 2
                        && quota > 0 && period > 0)
                    {
                        limit = quota / period + (quota % period != 0);

                        if (limit < (unsigned long long) ncpu) {
                            ncpu = (ngx_int_t) limit;
                        }
                    }

                    fclose(file);
                    fd = NGX_INVALID_FILE;
                }
            }

            if (fd != NGX_INVALID_FILE) {
                ngx_close_file(fd);
            }
        }

        if (end == root || ncpu == 1) {
            return ncpu;
        }

        while (*--end != '/') { /* void */ }
    }
}


static ngx_int_t
ngx_linux_mount_id(ngx_fd_t fd)
{
    int      id;
    char     line[64];
    FILE    *file;
    u_char   path[sizeof("/proc/self/fdinfo/") + NGX_INT_T_LEN];

    ngx_sprintf(path, "/proc/self/fdinfo/%d%Z", fd);

    file = fopen((char *) path, "r");
    if (file == NULL) {
        return NGX_ERROR;
    }

    while (fgets(line, sizeof(line), file) != NULL) {
        if (sscanf(line, "mnt_id: %d", &id) == 1) {
            fclose(file);
            return id;
        }
    }

    fclose(file);

    return NGX_ERROR;
}
