
#include <nginx.h>

#include <ngx_config.h>
#include <ngx_string.h>
#include <ngx_log.h>
#include <ngx_alloc.h>
#include <ngx_server.h>
#include <ngx_connection.h>
#include <ngx_listen.h>

/*
#include <ngx_http.h>
*/


#if !(WIN32)
static int ngx_options(int argc, char *const *argv);
#endif

char *ngx_root = "/home/is/work/xml/xml/html";

int ngx_http_init_connection(void *data);


int ngx_max_conn = 512;
struct sockaddr_in ngx_addr = {0, AF_INET, 0, 0, 0};
int ngx_backlog = 0;

ngx_pool_t   ngx_pool;
ngx_log_t    ngx_log;
ngx_server_t ngx_server;


int main(int argc, char *const *argv)
{
    char addr_text[22];
    ngx_socket_t s;
    ngx_listen_t ls;
    int            reuseaddr = 1;
#if (WIN32)
    WSADATA      wsd;
    unsigned long  nb = 1;
#endif


    ngx_log.log_level = NGX_LOG_DEBUG;
    ngx_pool.log = &ngx_log;
    ngx_addr.sin_port = htons(8000);
    ngx_addr.sin_family = AF_INET;

#if !(WIN32)
    if (ngx_options(argc, argv) == -1)
        ngx_log_error(NGX_LOG_EMERG, (&ngx_log), 0, "invalid argument");
#endif

    ngx_log_debug((&ngx_log), "%d, %s:%d" _ ngx_max_conn _
                 inet_ntoa(ngx_addr.sin_addr) _ ntohs(ngx_addr.sin_port));

#if (WIN32)
    if (WSAStartup(MAKEWORD(2,2), &wsd) != 0)
        ngx_log_error(NGX_LOG_EMERG, (&ngx_log), ngx_socket_errno,
                      "WSAStartup failed");
#endif

    /* for each listening socket */
    s = socket(AF_INET, SOCK_STREAM, 0);
    if (s == -1)
        ngx_log_error(NGX_LOG_EMERG, &(ngx_log), ngx_socket_errno,
                      "socket failed");

    if (setsockopt(s, SOL_SOCKET, SO_REUSEADDR,
                   (const void *) &reuseaddr, sizeof(int)) == -1)
        ngx_log_error(NGX_LOG_EMERG, &(ngx_log), ngx_socket_errno,
                     "setsockopt (SO_REUSEADDR) failed");

#if (WIN32)
    if (ioctlsocket(s, FIONBIO, &nb) == -1)
        ngx_log_error(NGX_LOG_EMERG, &(ngx_log), ngx_socket_errno,
                     "ioctlsocket (FIONBIO) failed");
#else
    if (fcntl(s, F_SETFL, O_NONBLOCK) == -1)
        ngx_log_error(NGX_LOG_EMERG, &(ngx_log), ngx_socket_errno,
                     "fcntl (O_NONBLOCK) failed");
#endif

    ngx_snprintf(ngx_cpystrn(addr_text, inet_ntoa(ngx_addr.sin_addr), 16),
                 7, ":%d", ntohs(ngx_addr.sin_port));

    if (bind(s, (struct sockaddr *) &ngx_addr,
             sizeof(struct sockaddr_in)) == -1)
        ngx_log_error(NGX_LOG_EMERG, &(ngx_log), ngx_socket_errno,
                     "bind to %s failed", addr_text);

    if (listen(s, ngx_backlog) == -1)
        ngx_log_error(NGX_LOG_EMERG, &(ngx_log), ngx_socket_errno,
                     "listen to %s failed", addr_text);

    ngx_server.buff_size = 1024;
    ngx_server.handler = ngx_http_init_connection;

    /* daemon */

    ls.fd = s;
    ls.server = &ngx_server;
    ls.log = &ngx_log;

    /* fork */

    ngx_worker(&ls, 1, &ngx_pool, &ngx_log);
}

#if !(WIN32)
extern char *optarg;

static int ngx_options(int argc, char *const *argv)
{
    char ch, *pos;
    int port;

    while ((ch = getopt(argc, argv, "l:c:")) != -1) {
        switch (ch) {
        case 'l':
            if (pos = strchr(optarg, ':')) {
                *(pos) = '\0';
                if ((port = atoi(pos + 1)) <= 0)
                    return -1;
                ngx_addr.sin_port = htons(port);
            }

            if ((ngx_addr.sin_addr.s_addr = inet_addr(optarg)) == INADDR_NONE)
                return -1;
            break;

        case 'c':
            if ((ngx_max_conn = atoi(optarg)) <= 0)
                return -1;
            break;

        case '?':
        default:
            return -1;
        }

    }

    return 0;
}
#endif
