
/*
 * Copyright (C) Nginx, Inc.
 */


#include <ngx_config.h>
#include <ngx_core.h>
#include <poll.h>


#define NGX_CTRL_MAX_FD          64
#define NGX_CTRL_MAX_REQUEST     1024

#define NGX_CTRL_OK              200
#define NGX_CTRL_BAD_REQUEST     400
#define NGX_CTRL_NOT_FOUND       404
#define NGX_CTRL_NOT_ALLOWED     405
#define NGX_CTRL_UNPROCESSABLE   422
#define NGX_CTRL_INTERNAL_ERROR  500

#define NGX_CTRL_GET             1
#define NGX_CTRL_PATCH           2

#define NGX_CTRL_ENV             "NGINX_CTRL"


typedef struct {
    ngx_fd_t      fd;
    ngx_pool_t   *pool;
    ngx_uint_t    index;
    ngx_uint_t    state;

    ngx_str_t     path;
    ngx_uint_t    method;

    ngx_buf_t    *in;
    ngx_chain_t  *out;

    ngx_uint_t    reloaded;
} ngx_control_request_t;


typedef struct {
    ngx_str_t     name;
    ngx_int_t     pid;
    ngx_uint_t    exiting;
} ngx_control_process_t;


static ngx_int_t ngx_control_inherit(void);
static void ngx_control_close(ngx_control_request_t *r);
static void ngx_control_handle_accept(void);
static ngx_int_t ngx_control_handle_read(ngx_control_request_t *r);
static ngx_int_t ngx_control_content(ngx_control_request_t *r);
static char *ngx_control_status_text(ngx_uint_t code);
static ngx_int_t ngx_control_send_response(ngx_control_request_t *r,
    ngx_uint_t code, ngx_buf_t *body);
static ngx_int_t ngx_control_handle_write(ngx_control_request_t *r);

static ngx_int_t ngx_control_api_endpoints(ngx_control_request_t *r,
    const char **paths, ngx_int_t npaths);
static ngx_int_t ngx_control_show_processes(ngx_control_request_t *r);
static ngx_int_t ngx_control_show_version(ngx_control_request_t *r);
static ngx_int_t ngx_control_reload_config(ngx_control_request_t *r);
static ngx_int_t ngx_control_print_config(ngx_control_request_t *r);
static void ngx_control_log_capture(ngx_log_t *log, ngx_uint_t l,
    u_char *buf, size_t len);

static ngx_int_t ngx_control_parse_request_line(ngx_control_request_t *r);
static ngx_int_t ngx_control_send_json(ngx_control_request_t *r, ngx_int_t code,
    ngx_data_item_t *obj);


static ngx_control_request_t  ngx_control_requests[NGX_CTRL_MAX_FD];
static struct pollfd          ngx_control_pollfd[NGX_CTRL_MAX_FD];
static ngx_uint_t             ngx_control_pollfd_n;
static char                   ngx_control_unix_path[NGX_UNIX_ADDRSTRLEN];
static ngx_uint_t             ngx_control_inherited;
ngx_uint_t                    ngx_control_api_enabled;


static ngx_str_t  ngx_control_version = ngx_string(NGINX_VERSION);

#ifdef NGX_BUILD
static ngx_str_t  ngx_control_build = ngx_string(NGX_BUILD);
#else
static ngx_str_t  ngx_control_build;
#endif

static ngx_data_decl_t  ngx_control_process_fields[] = {

    { ngx_string("name"),
      ngx_data_struct_str_handler,
      offsetof(ngx_control_process_t, name) },

    { ngx_string("pid"),
      ngx_data_struct_int_handler,
      offsetof(ngx_control_process_t, pid) },

    { ngx_string("exiting"),
      ngx_data_struct_boolean_handler,
      offsetof(ngx_control_process_t, exiting) },

      ngx_data_null_decl
};

static ngx_data_decl_t  ngx_control_status_fields[] = {

    { ngx_string("version"),
      ngx_data_string_handler,
      (uintptr_t) &ngx_control_version },

    { ngx_string("build"),
      ngx_data_string_handler,
      (uintptr_t) &ngx_control_build },

      ngx_data_null_decl
};

static ngx_data_decl_t  ngx_control_config_fields[] = {
    { ngx_string("name"),
      ngx_data_struct_str_handler,
      offsetof(ngx_keyval_t, key) },

    { ngx_string("content"),
      ngx_data_struct_str_handler,
      offsetof(ngx_keyval_t, value) },

      ngx_data_null_decl
};


ngx_int_t
ngx_control_init(u_char *addr)
{
    int        reuseaddr;
    ngx_fd_t   fd;
    ngx_url_t  u;

    if (addr == NULL) {
        return NGX_OK;
    }

    ngx_memzero(&u, sizeof(ngx_url_t));

    u.url.data = addr;
    u.url.len = ngx_strlen(addr);
    u.listen = 1;

    if (ngx_parse_url(ngx_cycle->pool, &u) != NGX_OK) {
        if (u.err) {
            ngx_log_error(NGX_LOG_EMERG, ngx_cycle->log, 0,
                          "control: %s in \"%V\"", u.err, &u.url);
        }

        return NGX_ERROR;
    }

#if (NGX_HAVE_UNIX_DOMAIN)
    if (u.family == AF_UNIX) {
        ngx_memcpy(ngx_control_unix_path, u.host.data, u.host.len);

    } else if (u.no_port || u.last_port) {
        ngx_log_error(NGX_LOG_EMERG, ngx_cycle->log, 0,
                      "control: invalid port in \"%V\"", &u.url);
        return NGX_ERROR;
    }
#else
    if (u.no_port || u.last_port) {
        ngx_log_error(NGX_LOG_EMERG, ngx_cycle->log, 0,
                      "control: invalid port in \"%V\"", &u.url);
        return NGX_ERROR;
    }
#endif

    if (ngx_control_inherit() == NGX_OK) {
        ngx_control_inherited = 1;
        return NGX_OK;
    }

    fd = ngx_socket(u.family, SOCK_STREAM, 0);

    if (fd == -1) {
        ngx_log_error(NGX_LOG_EMERG, ngx_cycle->log, ngx_socket_errno,
                      "control: " ngx_socket_n " failed");
        return NGX_ERROR;
    }

    if (fcntl(fd, F_SETFL, O_ASYNC|O_NONBLOCK) == -1) {
        ngx_log_error(NGX_LOG_EMERG, ngx_cycle->log, ngx_socket_errno,
                      "control: fcntl(O_ASYNC|O_NONBLOCK) failed");
        ngx_close_socket(fd);
        return NGX_ERROR;
    }

    if (fcntl(fd, F_SETOWN, ngx_pid) == -1) {
        ngx_log_error(NGX_LOG_EMERG, ngx_cycle->log, ngx_socket_errno,
                      "control: fcntl(F_SETOWN) failed");
        ngx_close_socket(fd);
        return NGX_ERROR;
    }

    reuseaddr = 1;

    if (setsockopt(fd, SOL_SOCKET, SO_REUSEADDR,
                   (const void *) &reuseaddr, sizeof(int))
        == -1)
    {
        ngx_log_error(NGX_LOG_EMERG, ngx_cycle->log, ngx_socket_errno,
                      "control: setsockopt(SO_REUSEADDR) failed");
        ngx_close_socket(fd);
        return NGX_ERROR;
    }

    if (bind(fd, &u.sockaddr.sockaddr, u.socklen) == -1) {
        ngx_log_error(NGX_LOG_EMERG, ngx_cycle->log, ngx_socket_errno,
                      "control: bind() failed");
        ngx_close_socket(fd);
        return NGX_ERROR;
    }

#if (NGX_HAVE_UNIX_DOMAIN)
    if (u.family == AF_UNIX) {
        if (chmod(ngx_control_unix_path, S_IRUSR|S_IWUSR) == -1) {
            ngx_log_error(NGX_LOG_EMERG, ngx_cycle->log, ngx_errno,
                          "control: chmod() failed");
            ngx_close_socket(fd);
            return NGX_ERROR;
        }
    }
#endif

    if (listen(fd, NGX_LISTEN_BACKLOG) == -1) {
        ngx_log_error(NGX_LOG_EMERG, ngx_cycle->log, ngx_socket_errno,
                      "control: listen() failed");
        ngx_close_socket(fd);
        return NGX_ERROR;
    }

    ngx_control_pollfd[0].fd = fd;
    ngx_control_pollfd[0].events = POLLIN;
    ngx_control_pollfd_n = 1;

    return NGX_OK;
}


void
ngx_control_uninit(void)
{
    ngx_control_close_sockets();

    if (ngx_control_unix_path[0] && ngx_new_binary == 0
        && (!ngx_control_inherited || ngx_getppid() != ngx_parent))
    {
        if (ngx_delete_file(ngx_control_unix_path) == NGX_FILE_ERROR) {
            ngx_log_error(NGX_LOG_EMERG, ngx_cycle->log, ngx_errno,
                         ngx_delete_file_n " %s failed", ngx_control_unix_path);
        }
    }
}


void
ngx_control_close_sockets(void)
{
    ngx_uint_t  i;

    for (i = 0; i < ngx_control_pollfd_n; i++) {
        ngx_close_socket(ngx_control_pollfd[i].fd);
    }
}


char *
ngx_control_handoff(void)
{
    static u_char  env[sizeof(NGX_CTRL_ENV) + NGX_INT32_LEN + 1];

    if (ngx_control_pollfd_n == 0) {
        return NULL;
    }

    ngx_sprintf(env, NGX_CTRL_ENV "=%d%Z", ngx_control_pollfd[0].fd);

    return (char *) env;
}


void
ngx_control_reown(void)
{
    if (ngx_control_pollfd_n == 0) {
        return;
    }

    if (fcntl(ngx_control_pollfd[0].fd, F_SETOWN, ngx_pid) == -1) {
        ngx_log_error(NGX_LOG_ALERT, ngx_cycle->log, ngx_socket_errno,
                      "control: fcntl(F_SETOWN) failed");
    }
}


ngx_int_t
ngx_control_handle_events(void)
{
    int                     ready, revents;
    ngx_uint_t              i, reloaded;
    struct pollfd          *pfd;
    ngx_control_request_t  *r;

    ngx_log_debug0(NGX_LOG_DEBUG_EVENT, ngx_cycle->log, 0,
                   "control: handle events");

    ready = poll(ngx_control_pollfd, ngx_control_pollfd_n, 0);

    if (ready <= 0) {
        if (ready == -1 && ngx_errno != NGX_EINTR) {
            ngx_log_error(NGX_LOG_ALERT, ngx_cycle->log, ngx_errno,
                          "control: poll() failed");
            return NGX_ERROR;
        }

        return NGX_OK;
    }

    reloaded = 0;

    for (i = 0; i < ngx_control_pollfd_n; /* void */) {

        r = &ngx_control_requests[i];
        pfd = &ngx_control_pollfd[i];
        revents = pfd->revents;

        ngx_log_debug4(NGX_LOG_DEBUG_EVENT, ngx_cycle->log, 0,
                       "control: i:%ui fd:%d e:%d re:%d",
                       i, pfd->fd, pfd->events, pfd->revents);

        if (i) {
            r->pool->log = ngx_cycle->log;
        }

        if ((revents & (POLLERR|POLLHUP|POLLNVAL)) && i != 0) {
            ngx_control_close(r);
            continue;
        }

        if (revents & POLLIN) {
            if (i == 0) {
                ngx_control_handle_accept();
                i++;
                continue;
            }

            if (ngx_control_handle_read(r) != NGX_AGAIN) {
                reloaded |= r->reloaded;
                ngx_control_close(r);
                continue;
            }

            reloaded |= r->reloaded;
        }

        if (revents & POLLOUT) {
            if (ngx_control_handle_write(r) != NGX_AGAIN) {
                ngx_control_close(r);
                continue;
            }
        }

        i++;
    }

    return reloaded ? NGX_DONE : NGX_OK;
}


static ngx_int_t
ngx_control_inherit(void)
{
    u_char    *env;
    ngx_fd_t   fd;

    env = (u_char *) getenv(NGX_CTRL_ENV);
    if (env == NULL) {
        return NGX_DECLINED;
    }

    fd = ngx_atoi(env, ngx_strlen(env));
    if (fd == NGX_ERROR) {
        ngx_log_error(NGX_LOG_ALERT, ngx_cycle->log, 0,
                      "control: invalid " NGX_CTRL_ENV " value \"%s\"", env);
        return NGX_ERROR;
    }

    if (fcntl(fd, F_SETOWN, ngx_pid) == -1) {
        ngx_log_error(NGX_LOG_ALERT, ngx_cycle->log, ngx_socket_errno,
                      "control: fcntl(F_SETOWN) failed");
        ngx_close_socket(fd);
        return NGX_ERROR;
    }

    ngx_control_pollfd[0].fd = fd;
    ngx_control_pollfd[0].events = POLLIN;
    ngx_control_pollfd_n = 1;

    return NGX_OK;
}


static void
ngx_control_close(ngx_control_request_t *r)
{
    ngx_uint_t  i;

    i = r->index;

    ngx_close_socket(r->fd);

    ngx_destroy_pool(r->pool);

    if (i + 1 < ngx_control_pollfd_n) {
        ngx_memmove(&ngx_control_pollfd[i], &ngx_control_pollfd[i + 1],
                    (ngx_control_pollfd_n - (i + 1)) * sizeof(struct pollfd));
        ngx_memmove(&ngx_control_requests[i], &ngx_control_requests[i + 1],
            (ngx_control_pollfd_n - (i + 1)) * sizeof(ngx_control_request_t));

        for (/* void */; i < ngx_control_pollfd_n - 1; i++) {
            ngx_control_requests[i].index--;
        }
    }

    ngx_control_pollfd_n--;
}


static void
ngx_control_handle_accept(void)
{
    ngx_fd_t                fd;
    ngx_err_t               err;
    struct pollfd          *pfd;
    ngx_control_request_t  *r;

    for ( ;; ) {
        fd = accept(ngx_control_pollfd[0].fd, NULL, NULL);

        if (fd == -1) {
            err = ngx_socket_errno;

            if (err == NGX_EAGAIN) {
                return;
            }

            ngx_log_error(NGX_LOG_ERR, ngx_cycle->log, err,
                          "control: accept() failed");

            if (err == NGX_ECONNABORTED) {
                continue;
            }

            return;
        }

        if (ngx_control_pollfd_n == NGX_CTRL_MAX_FD) {
            ngx_log_error(NGX_LOG_WARN, ngx_cycle->log, 0,
                          "control: too many client connections");
            /* close the oldest connection */
            r = &ngx_control_requests[1];
            r->pool->log = ngx_cycle->log;
            ngx_control_close(r);
        }

        r = &ngx_control_requests[ngx_control_pollfd_n];
        ngx_memzero(r, sizeof(ngx_control_request_t));
        r->fd = fd;

        ngx_log_debug1(NGX_LOG_DEBUG_EVENT, ngx_cycle->log, 0,
                       "control accept fd:%d", r->fd);

        if (fcntl(r->fd, F_SETFD, FD_CLOEXEC) == -1) {
            ngx_log_error(NGX_LOG_ERR, ngx_cycle->log, 0,
                          "control: fcntl(FD_CLOEXEC) failed");
            ngx_close_socket(r->fd);
            continue;
        }

        if (fcntl(r->fd, F_SETFL, O_ASYNC|O_NONBLOCK) == -1) {
            ngx_log_error(NGX_LOG_ERR, ngx_cycle->log, 0,
                          "control: fcntl(O_ASYNC|O_NONBLOCK) failed");
            ngx_close_socket(r->fd);
            continue;
        }

        if (fcntl(r->fd, F_SETOWN, ngx_pid) == -1) {
            ngx_log_error(NGX_LOG_ERR, ngx_cycle->log, 0,
                          "control: fcntl(F_SETOWN) failed");
            ngx_close_socket(r->fd);
            continue;
        }

        pfd = &ngx_control_pollfd[ngx_control_pollfd_n];
        ngx_memzero(pfd, sizeof(struct pollfd));
        pfd->fd = r->fd;
        pfd->events = POLLIN;
        pfd->revents = POLLIN;

        r->pool = ngx_create_pool(NGX_DEFAULT_POOL_SIZE, ngx_cycle->log);
        if (r->pool == NULL) {
            ngx_close_socket(r->fd);
            continue;
        }

        r->in = ngx_create_temp_buf(r->pool, NGX_CTRL_MAX_REQUEST);
        if (r->in == NULL) {
            ngx_destroy_pool(r->pool);
            ngx_close_socket(r->fd);
            continue;
        }

        r->index = ngx_control_pollfd_n++;
    }
}


static ngx_int_t
ngx_control_handle_read(ngx_control_request_t *r)
{
    ssize_t     n;
    ngx_buf_t  *b;

    ngx_log_debug1(NGX_LOG_DEBUG_EVENT, ngx_cycle->log, 0,
                   "control: read fd:%d", r->fd);

    b = r->in;

    if (b->last == b->end) {
        ngx_log_error(NGX_LOG_ERR, ngx_cycle->log, 0,
                      "control: request too large");
        return NGX_ERROR;
    }

    n = recv(r->fd, b->last, b->end - b->last, 0);

    if (n < 0) {
        if (ngx_errno == NGX_EAGAIN) {
            return NGX_AGAIN;
        }

        ngx_log_error(NGX_LOG_ERR, ngx_cycle->log, ngx_socket_errno,
                      "control: recv() failed");
        return NGX_ERROR;
    }

    if (n == 0) {
        return NGX_DONE;
    }

    b->last += n;

    switch (ngx_control_parse_request_line(r)) {

    case NGX_AGAIN:
        return NGX_AGAIN;

    case NGX_DECLINED:
        ngx_log_error(NGX_LOG_ERR, ngx_cycle->log, 0,
                      "control: failed to parse request");
        ngx_control_pollfd[r->index].events &= ~POLLIN;
        return ngx_control_send_response(r, NGX_CTRL_BAD_REQUEST, NULL);

    case NGX_DONE:
        ngx_control_pollfd[r->index].events &= ~POLLIN;
        return ngx_control_content(r);

    default:
        ngx_control_pollfd[r->index].events &= ~POLLIN;
        return NGX_ERROR;
    }
}


static ngx_int_t
ngx_control_content(ngx_control_request_t *r)
{
    u_char  *p;
    size_t   len;

    static const char  *root_endpoints[] = { "1" };
    static const char  *api_endpoints[] = { "control", "nginx" };
    static const char  *control_endpoints[] = { "processes", "config" };

    p = r->path.data;
    len = r->path.len;

    if (len > 1 && p[len - 1] == '/') {
        r->path.len = --len;
    }

    /* the path always starts with "/" */

    switch (len) {
    case 1:
        if (r->method != NGX_CTRL_GET) {
            return ngx_control_send_response(r, NGX_CTRL_NOT_ALLOWED, NULL);
        }

        return ngx_control_api_endpoints(r, root_endpoints, 1);

    case 2:
        if (ngx_strncmp(p, "/1", len) == 0) {
            if (r->method != NGX_CTRL_GET) {
                return ngx_control_send_response(r, NGX_CTRL_NOT_ALLOWED, NULL);
            }

            return ngx_control_api_endpoints(r, api_endpoints, 2);
        }

        break;

    case 8:
        if (ngx_strncmp(p, "/1/nginx", len) == 0) {
            if (r->method != NGX_CTRL_GET) {
                return ngx_control_send_response(r, NGX_CTRL_NOT_ALLOWED, NULL);
            }

            return ngx_control_show_version(r);
        }

        break;

    case 10:
        if (ngx_strncmp(p, "/1/control", len) == 0) {
            if (r->method != NGX_CTRL_GET) {
                return ngx_control_send_response(r, NGX_CTRL_NOT_ALLOWED, NULL);
            }

            return ngx_control_api_endpoints(r, control_endpoints, 2);
        }

        break;

    case 17:
        if (ngx_strncmp(p, "/1/control/config", len) == 0) {
            if (r->method == NGX_CTRL_PATCH) {
                return ngx_control_reload_config(r);
            }

            if (r->method == NGX_CTRL_GET) {
                return ngx_control_print_config(r);
            }

            return ngx_control_send_response(r, NGX_CTRL_NOT_ALLOWED, NULL);
        }

        break;

    case 20:
        if (ngx_strncmp(p, "/1/control/processes", len) == 0) {
            if (r->method != NGX_CTRL_GET) {
                return ngx_control_send_response(r, NGX_CTRL_NOT_ALLOWED, NULL);
            }

            return ngx_control_show_processes(r);
        }

        break;
    }

    return ngx_control_send_response(r, NGX_CTRL_NOT_FOUND, NULL);
}


static char *
ngx_control_status_text(ngx_uint_t code)
{
    switch (code) {
    case NGX_CTRL_OK:
        return "OK";
    case NGX_CTRL_BAD_REQUEST:
        return "Bad Request";
    case NGX_CTRL_NOT_FOUND:
        return "Not Found";
    case NGX_CTRL_NOT_ALLOWED:
        return "Not Allowed";
    case NGX_CTRL_UNPROCESSABLE:
        return "Unprocessable Entity";
    case NGX_CTRL_INTERNAL_ERROR:
        return "Internal Server Error";
    default:
        return "";
    }
}


static ngx_int_t
ngx_control_send_response(ngx_control_request_t *r, ngx_uint_t code,
    ngx_buf_t *body)
{
    char         *status;
    ngx_uint_t    n;
    ngx_chain_t  *c;

    const char  response_fmt[] =
        "HTTP/1.1 %03ui %s\r\n"
        "Server: " NGINX_VER "\r\n"
        "Connection: close\r\n"
        "Content-Type: application/json\r\n"
        "Content-Length: %ui\r\n"
        "\r\n";

    c = ngx_alloc_chain_link(r->pool);
    if (c == NULL) {
        return NGX_ERROR;
    }

    status = ngx_control_status_text(code);

    c->buf = ngx_create_temp_buf(r->pool,
                sizeof(response_fmt) + 2 * NGX_INT_T_LEN + ngx_strlen(status));
    if (c->buf == NULL) {
        return NGX_ERROR;
    }

    c->next = NULL;

    n = body ? body->last - body->pos : 0;

    c->buf->last = ngx_sprintf(c->buf->pos, response_fmt, code, status, n);

    if (body) {
        c->next = ngx_alloc_chain_link(r->pool);
        if (c->next == NULL) {
            return NGX_ERROR;
        }

        c->next->buf = body;
        c->next->next = NULL;
    }

    r->out = c;

    return ngx_control_handle_write(r);
}


static ngx_int_t
ngx_control_handle_write(ngx_control_request_t *r)
{
    ssize_t       n;
    ngx_buf_t    *b;
    ngx_chain_t  *c;

    for (c = r->out; c != NULL; c = c->next) {
        b = c->buf;

        while (b && b->pos < b->last) {
            n = send(r->fd, b->pos, b->last - b->pos, 0);

            if (n <= 0) {
                if (n == -1 && ngx_errno == NGX_EAGAIN) {
                    ngx_control_pollfd[r->index].events |= POLLOUT;
                    return NGX_AGAIN;
                }

                ngx_log_error(NGX_LOG_ERR, ngx_cycle->log, ngx_socket_errno,
                              "control: send() failed");
                return NGX_ERROR;
            }

            b->pos += n;

            ngx_log_debug1(NGX_LOG_DEBUG_EVENT, ngx_cycle->log, 0,
                           "control: wrote %i bytes", n);
        }
    }

    return NGX_DONE;
}


static ngx_int_t
ngx_control_send_json(ngx_control_request_t *r, ngx_int_t code,
    ngx_data_item_t *obj)
{
    ngx_buf_t  *b;

    b = ngx_json_render(r->pool, obj);
    if (b == NULL) {
        return NGX_ERROR;
    }

    return ngx_control_send_response(r, code, b);
}


static ngx_int_t
ngx_control_api_endpoints(ngx_control_request_t *r, const char **paths,
    ngx_int_t npaths)
{
    ngx_int_t         i;
    ngx_str_t         p;
    ngx_data_item_t  *json, *path;

    if (r->method != NGX_CTRL_GET) {
        return ngx_control_send_response(r, NGX_CTRL_NOT_ALLOWED, NULL);
    }

    json = ngx_data_new_list(r->pool);
    if (json == NULL) {
        return NGX_ERROR;
    }

    for (i = 0; i < npaths; i++) {
        p.data = (u_char *) paths[i];
        p.len = ngx_strlen(paths[i]);

        path = ngx_data_string_handler((uintptr_t) &p, r->pool, NULL);
        if (path == NULL) {
            return NGX_ERROR;
        }

        ngx_data_add_item(json, NULL, path);
    }

    return ngx_control_send_json(r, NGX_CTRL_OK, (ngx_data_item_t *) json);
}


static ngx_int_t
ngx_control_show_processes(ngx_control_request_t *r)
{
    ngx_int_t               i;
    ngx_data_item_t        *process_list, *obj;
    ngx_control_process_t   process;

    process_list = ngx_data_new_list(r->pool);
    if (process_list == NULL) {
        return NGX_ERROR;
    }

    for (i = 0; i < ngx_last_process; i++) {
        if (ngx_processes[i].pid == -1) {
            continue;
        }

        process.name.data = (u_char *) ngx_processes[i].name;
        process.name.len = ngx_strlen(process.name.data);
        process.pid = ngx_processes[i].pid;
        process.exiting = ngx_processes[i].exiting;

        obj = ngx_data_obj_handler((uintptr_t) ngx_control_process_fields,
                                   r->pool, &process);
        if (obj == NULL) {
            return NGX_ERROR;
        }

        ngx_data_add_item(process_list, NULL, obj);
    }

    return ngx_control_send_json(r, NGX_CTRL_OK, process_list);
}


static ngx_int_t
ngx_control_show_version(ngx_control_request_t *r)
{
    ngx_data_item_t  *resp;

    resp = ngx_data_obj_handler((uintptr_t) ngx_control_status_fields, r->pool,
                                NULL);
    if (resp == NULL) {
        return NGX_ERROR;
    }

    return ngx_control_send_json(r, NGX_CTRL_OK, resp);
}


static ngx_int_t
ngx_control_print_config(ngx_control_request_t *r)
{
    ngx_uint_t        i;
    ngx_keyval_t      item;
    ngx_data_item_t  *list, *obj;
    ngx_conf_dump_t  *dump;

    list = ngx_data_new_list(r->pool);
    if (list == NULL) {
        return NGX_ERROR;
    }

    dump = ngx_cycle->config_dump.elts;

    for (i = 0; i < ngx_cycle->config_dump.nelts; i++) {

        item.key = dump[i].name;
        item.value.data = dump[i].buffer->pos;
        item.value.len = dump[i].buffer->last - dump[i].buffer->pos;

        obj = ngx_data_obj_handler((uintptr_t) ngx_control_config_fields,
                                   r->pool, &item);
        if (obj == NULL) {
            return NGX_ERROR;
        }

        ngx_data_add_item(list, NULL, obj);
    }

    return ngx_control_send_json(r, NGX_CTRL_OK, list);
}


static ngx_data_item_t *
ngx_control_json_logs(ngx_array_t *logs)
{
    ngx_str_t        *l;
    ngx_uint_t        i;
    ngx_data_item_t  *obj, *log_list, *log;

    static ngx_str_t  logs_field = ngx_string("logs");

    obj = ngx_data_new_object(logs->pool);
    if (obj == NULL) {
        return NULL;
    }

    log_list = ngx_data_new_list(logs->pool);
    if (log_list == NULL) {
        return NULL;
    }

    l = logs->elts;
    for (i = 0; i < logs->nelts; i++) {
        log = ngx_data_string_handler((uintptr_t) &l[i], logs->pool, NULL);
        if (log == NULL) {
            return NULL;
        }

        ngx_data_add_item(log_list, NULL, log);
    }

    ngx_data_add_item(obj, &logs_field, log_list);

    return obj;
}


static ngx_int_t
ngx_control_reload_config(ngx_control_request_t *r)
{
    ngx_int_t         status;
    ngx_log_t         log, *tmp;
    ngx_cycle_t      *cycle;
    ngx_array_t       log_store;
    ngx_data_item_t  *obj;

    status = NGX_CTRL_OK;

    if (ngx_array_init(&log_store, r->pool, 3, sizeof(ngx_str_t)) != NGX_OK) {
        return NGX_ERROR;
    }

    ngx_memzero(&log, sizeof(ngx_log_t));
    log.wdata = &log_store;
    log.writer = ngx_control_log_capture;
    log.log_level = NGX_LOG_DEBUG;

    tmp = ngx_cycle->log;
    log.next = tmp;
    ngx_cycle->log = &log;
    cycle = ngx_init_cycle((ngx_cycle_t *) ngx_cycle);

    if (cycle == NULL) {
        status = NGX_CTRL_UNPROCESSABLE;
        ngx_cycle->log = tmp;

    } else {
        ngx_cycle = cycle;
        r->reloaded = 1;
        r->pool->log = ngx_cycle->log;
    }

    obj = ngx_control_json_logs(&log_store);
    if (obj == NULL) {
        return NGX_ERROR;
    }

    return ngx_control_send_json(r, status, obj);
}


static void
ngx_control_log_capture(ngx_log_t *log, ngx_uint_t lvl, u_char *buf, size_t len)
{
    u_char       *log_data;
    ngx_str_t    *log_str;
    ngx_array_t  *store;

    if (lvl > NGX_LOG_WARN) {
        return;
    }

    store = log->wdata;

    log_data = ngx_pnalloc(store->pool, len);
    if (log_data == NULL) {
        return;
    }

    log_str = ngx_array_push(store);
    if (log_str == NULL) {
        return;
    }

    ngx_memcpy(log_data, buf, len);

    log_str->data = log_data;
    log_str->len = len;
}


static ngx_int_t
ngx_control_parse_request_line(ngx_control_request_t *r)
{
    static uint32_t  usual[] = {
        0x00000000, /* 0000 0000 0000 0000  0000 0000 0000 0000 */
                    /* ?>=< ;:98 7654 3210  /.-, +*)( '&%$ #"!  */
        0x7fff37d6, /* 0111 1111 1111 1111  0011 0111 1101 0110 */
                    /* _^]\ [ZYX WVUT SRQP  ONML KJIH GFED CBA@ */
        0xffffffff, /* 1111 1111 1111 1111  1111 1111 1111 1111 */
                    /*  ~}| {zyx wvut srqp  onml kjih gfed cba` */
        0x7fffffff, /* 0111 1111 1111 1111  1111 1111 1111 1111 */
        0xffffffff, /* 1111 1111 1111 1111  1111 1111 1111 1111 */
        0xffffffff, /* 1111 1111 1111 1111  1111 1111 1111 1111 */
        0xffffffff, /* 1111 1111 1111 1111  1111 1111 1111 1111 */
        0xffffffff  /* 1111 1111 1111 1111  1111 1111 1111 1111 */
    };

    u_char      c, ch, *p;
    ngx_buf_t  *b;
    enum {
        sw_start = 0,
        sw_method,
        sw_spaces_before_uri,
        sw_schema,
        sw_schema_slash,
        sw_schema_slash_slash,
        sw_spaces_before_host,
        sw_host_start,
        sw_host,
        sw_host_end,
        sw_host_ip_literal,
        sw_port_start,
        sw_port,
        sw_uri,
        sw_http_,
        sw_http_H,
        sw_http_HT,
        sw_http_HTT,
        sw_http_HTTP,
        sw_first_major_digit,
        sw_major_digit,
        sw_first_minor_digit,
        sw_minor_digit,
        sw_almost_done
    } state;

    b = r->in;
    state = r->state;

    for (p = b->pos; p < b->last; p++) {
        ch = *p;

        switch (state) {
        /* HTTP methods: GET, PATCH */
        case sw_start:
            if ((ch < 'A' || ch > 'Z') && ch != '_' && ch != '-') {
                return NGX_DECLINED;
            }

            state = sw_method;

            break;

        case sw_method:
            if (ch == ' ') {
                state = sw_spaces_before_uri;

                switch (p - b->start) {
                case 3:
                    if (ngx_strncmp(b->start, "GET", 3) == 0) {
                        r->method = NGX_CTRL_GET;
                        break;
                    }
                    break;

                case 5:
                    if (ngx_strncmp(b->start, "PATCH", 5) == 0) {
                        r->method = NGX_CTRL_PATCH;
                        break;
                    }
                    break;
                }

                break;
            }

            if ((ch < 'A' || ch > 'Z') && ch != '_' && ch != '-') {
                return NGX_DECLINED;
            }

            break;

        /* space* before URI */
        case sw_spaces_before_uri:
            if (ch == '/') {
                r->path.data = p;
                state = sw_uri;
                break;
            }

            c = (u_char) (ch | 0x20);
            if (c >= 'a' && c <= 'z') {
                state = sw_schema;
                break;
            }

            if (ch != ' ') {
                return NGX_DECLINED;
            }

            break;

        case sw_schema:
            c = (u_char) (ch | 0x20);
            if (c >= 'a' && c <= 'z') {
                break;
            }

            if ((ch >= '0' && ch <= '9') || ch == '+' || ch == '-' || ch == '.')
            {
                break;
            }

            if (ch != ':') {
                return NGX_DECLINED;
            }

            state = sw_schema_slash;
            break;

        case sw_schema_slash:
            if (ch != '/') {
                return NGX_DECLINED;
            }

            state = sw_schema_slash_slash;
            break;

        case sw_schema_slash_slash:
            if (ch != '/') {
                return NGX_DECLINED;
            }

            state = sw_host_start;
            break;

        case sw_spaces_before_host:
            if (ch == ' ') {
                break;
            }
            /* fall through */

        case sw_host_start:
            if (ch == '[') {
                state = sw_host_ip_literal;
                break;
            }

            state = sw_host;
            /* fall through */

        case sw_host:
            c = (u_char) (ch | 0x20);
            if (c >= 'a' && c <= 'z') {
                break;
            }

            if ((ch >= '0' && ch <= '9') || ch == '.' || ch == '-') {
                break;
            }
            /* fall through */

        case sw_host_end:
            if (ch == ':') {
                state = sw_port_start;
                break;
            }

            /* if we supported CONNECT verb we would need to decline here */

            switch (ch) {
            case '/':
                r->path.data = p;
                state = sw_uri;
                break;
            /* empty path cases */
            case '?':
                ngx_str_set(&r->path, "/");
                state = sw_uri;
                break;
            case ' ':
                ngx_str_set(&r->path, "/");
                state = sw_http_;
                break;
            }
            break;

        case sw_host_ip_literal:
            if (ch >= '0' && ch <= '9') {
                break;
            }

            c = (u_char) (ch | 0x20);
            if (c >= 'a' && c <= 'z') {
                break;
            }

            switch (ch) {
            case ':':
                break;
            case ']':
                state = sw_host_end;
                break;
            case '-':
            case '.':
            case '_':
            case '~':
                /* unreserved */
                break;
            case '!':
            case '$':
            case '&':
            case '\'':
            case '(':
            case ')':
            case '*':
            case '+':
            case ',':
            case ';':
            case '=':
                /* sub-delims */
                break;
            default:
                return NGX_DECLINED;
            }
            break;

        case sw_port_start:
            state = sw_port;

            if (ch >= '0' && ch <= '9') {
                break;
            }

            /* if we supported CONNECT verb we would need to decline here */

            /* fall through */

        case sw_port:
            if (ch >= '0' && ch <= '9') {
                break;
            }

            switch (ch) {
            case '/':
                r->path.data = p;
                state = sw_uri;
                break;
            /* empty path cases */
            case '?':
                ngx_str_set(&r->path, "/");
                state = sw_uri;
                break;
            case ' ':
                ngx_str_set(&r->path, "/");
                state = sw_http_;
                break;
            default:
                return NGX_DECLINED;
            }
            break;

        /* URI */
        case sw_uri:
            if (usual[ch >> 5] & (1U << (ch & 0x1f))) {
                break;
            }

            switch (ch) {
            case ' ':
                state = sw_http_;
                /* fall through */
            case '?':
                if (r->path.len == 0) {
                    r->path.len = p - r->path.data;
                }
                break;

            case '.':
            case '%':
            case '#':
            case '+':
            case 0x7f:
                return NGX_DECLINED;
            default:
                if (ch < 0x20) {
                    return NGX_DECLINED;
                }
                break;
            }
            break;

        /* space+ after URI */
        case sw_http_:
            switch (ch) {
            case ' ':
                break;
            case 'H':
                state = sw_http_H;
                break;
            default:
                return NGX_DECLINED;
            }
            break;

        case sw_http_H:
            switch (ch) {
            case 'T':
                state = sw_http_HT;
                break;
            default:
                return NGX_DECLINED;
            }
            break;

        case sw_http_HT:
            switch (ch) {
            case 'T':
                state = sw_http_HTT;
                break;
            default:
                return NGX_DECLINED;
            }
            break;

        case sw_http_HTT:
            switch (ch) {
            case 'P':
                state = sw_http_HTTP;
                break;
            default:
                return NGX_DECLINED;
            }
            break;

        case sw_http_HTTP:
            switch (ch) {
            case '/':
                state = sw_first_major_digit;
                break;
            default:
                return NGX_DECLINED;
            }
            break;

        /* first digit of major HTTP version */
        case sw_first_major_digit:
            if (ch != '1') {
                return NGX_DECLINED;
            }

            state = sw_major_digit;
            break;

        /* major HTTP version or dot */
        case sw_major_digit:
            if (ch == '.') {
                state = sw_first_minor_digit;
                break;
            } else {
                /* major versions other than 1 are not supported */
                return NGX_DECLINED;
            }

        /* first digit of minor HTTP version */
        case sw_first_minor_digit:
            if (ch != '0' && ch != '1') {
                return NGX_DECLINED;
            }

            state = sw_minor_digit;
            break;

        /* minor HTTP version or end of request line */
        case sw_minor_digit:
            if (ch == CR) {
                state = sw_almost_done;
                break;

            } else if (ch == LF) {
                goto done;

            } else {
                /* support only 1.1 or 1.0 */
                return NGX_DECLINED;
            }

        /* end of request line */
        case sw_almost_done:
            switch (ch) {
            case LF:
                goto done;
            default:
                return NGX_DECLINED;
            }
        }
    }

    b->pos = p;
    r->state = state;

    return NGX_AGAIN;

done:
    b->pos = p + 1;
    r->state = sw_start;

    return NGX_DONE;
}
