
/*
 * Copyright (C) Igor Sysoev
 */


#ifndef _NGX_FILES_H_INCLUDED_
#define _NGX_FILES_H_INCLUDED_


#include <ngx_config.h>
#include <ngx_core.h>


#define NGX_INVALID_FILE         -1
#define NGX_FILE_ERROR           -1



#define ngx_open_file(name, mode, create, access)                            \
    open((const char *) name, mode|create, access)
#define ngx_open_file_n          "open()"

#define NGX_FILE_RDONLY          O_RDONLY
#define NGX_FILE_WRONLY          O_WRONLY
#define NGX_FILE_RDWR            O_RDWR
#define NGX_FILE_CREATE_OR_OPEN  O_CREAT
#define NGX_FILE_OPEN            0
#define NGX_FILE_TRUNCATE        O_TRUNC
#define NGX_FILE_APPEND          O_APPEND

#define NGX_FILE_DEFAULT_ACCESS  0644


#define ngx_close_file           close
#define ngx_close_file_n         "close()"


#define ngx_delete_file(name)    unlink((const char *) name)
#define ngx_delete_file_n        "unlink()"


ngx_fd_t ngx_open_tempfile(u_char *name, ngx_uint_t persistent,
    ngx_uint_t access);
#define ngx_open_tempfile_n      "open()"


ssize_t ngx_read_file(ngx_file_t *file, u_char *buf, size_t size, off_t offset);
#define ngx_read_file_n          "read()"

ssize_t ngx_write_file(ngx_file_t *file, u_char *buf, size_t size,
    off_t offset);

ssize_t ngx_write_chain_to_file(ngx_file_t *file, ngx_chain_t *ce,
    off_t offset, ngx_pool_t *pool);


#define ngx_read_fd              read
#define ngx_read_fd_n            "read()"

#define ngx_write_fd             write
#define ngx_write_fd_n           "write()"

#define ngx_linefeed(p)          *p++ = LF;
#define NGX_LINEFEED_SIZE        1


#define ngx_rename_file(o, n)    rename((const char *) o, (const char *) n)
#define ngx_rename_file_n        "rename()"


#define ngx_change_file_access(n, a) chmod((const char *) n, a)
#define ngx_change_file_access_n "chmod()"


ngx_int_t ngx_set_file_time(u_char *name, ngx_fd_t fd, time_t s);
#define ngx_set_file_time_n      "utimes()"


#define ngx_file_info(file, sb)  stat((const char *) file, sb)
#define ngx_file_info_n          "stat()"

#define ngx_fd_info(fd, sb)      fstat(fd, sb)
#define ngx_fd_info_n            "fstat()"

#define ngx_is_dir(sb)           (S_ISDIR((sb)->st_mode))
#define ngx_is_file(sb)          (S_ISREG((sb)->st_mode))
#define ngx_is_link(sb)          (S_ISLNK((sb)->st_mode))
#define ngx_is_exec(sb)          ((sb)->st_mode & S_IXUSR)
#define ngx_file_access(sb)      ((sb)->st_mode & 0777)
#define ngx_file_size(sb)        (sb)->st_size
#define ngx_file_mtime(sb)       (sb)->st_mtime
#define ngx_file_uniq(sb)        (sb)->st_ino



#define ngx_getcwd(buf, size)    (getcwd(buf, size) != NULL)
#define ngx_getcwd_n             "getcwd()"
#define NGX_MAX_PATH             PATH_MAX

#define NGX_DIR_MASK_LEN         0


ngx_int_t ngx_open_dir(ngx_str_t *name, ngx_dir_t *dir);
#define ngx_open_dir_n           "opendir()"


#define ngx_close_dir(d)         closedir((d)->dir)
#define ngx_close_dir_n          "closedir()"


#define ngx_read_dir(d)                                                      \
    (((d)->de = readdir((d)->dir)) ? NGX_OK : NGX_ERROR)
#define ngx_read_dir_n           "readdir()"


#define ngx_create_dir(name, access) mkdir((const char *) name, access)
#define ngx_create_dir_n         "mkdir()"


#define ngx_delete_dir(name)     rmdir((const char *) name)
#define ngx_delete_dir_n         "rmdir()"


#define ngx_dir_access(a)        (a | (a & 0444) >> 2)


#define ngx_de_name(dir)         ((u_char *) (dir)->de->d_name)
#if (NGX_FREEBSD)
#define ngx_de_namelen(dir)      (dir)->de->d_namlen
#else
#define ngx_de_namelen(dir)      ngx_strlen((dir)->de->d_name)
#endif
#define ngx_de_info(name, dir)   stat((const char *) name, &(dir)->info)
#define ngx_de_info_n            "stat()"
#define ngx_de_link_info(name, dir)  lstat((const char *) name, &(dir)->info)
#define ngx_de_link_info_n       "lstat()"
#define ngx_de_is_dir(dir)       (S_ISDIR((dir)->info.st_mode))
#define ngx_de_is_file(dir)      (S_ISREG((dir)->info.st_mode))
#define ngx_de_is_link(dir)      (S_ISLNK((dir)->info.st_mode))
#define ngx_de_access(dir)       (((dir)->info.st_mode) & 0777)
#define ngx_de_size(dir)         (dir)->info.st_size
#define ngx_de_mtime(dir)        (dir)->info.st_mtime


typedef struct {
    size_t      n;
    glob_t      pglob;
    u_char     *pattern;
    ngx_log_t  *log;
} ngx_glob_t;


ngx_int_t ngx_open_glob(ngx_glob_t *gl);
#define ngx_open_glob_n          "glob()"
ngx_int_t ngx_read_glob(ngx_glob_t *gl, ngx_str_t *name);
void ngx_close_glob(ngx_glob_t *gl);


ngx_err_t ngx_trylock_fd(ngx_fd_t fd);
ngx_err_t ngx_lock_fd(ngx_fd_t fd);
ngx_err_t ngx_unlock_fd(ngx_fd_t fd);

#define ngx_trylock_fd_n         "fcntl(F_SETLK, F_WRLCK)"
#define ngx_lock_fd_n            "fcntl(F_SETLKW, F_WRLCK)"
#define ngx_unlock_fd_n          "fcntl(F_SETLK, F_UNLCK)"


#endif /* _NGX_FILES_H_INCLUDED_ */
