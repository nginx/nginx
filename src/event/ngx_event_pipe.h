#ifndef _NGX_EVENT_PIPE_H_INCLUDED_
#define _NGX_EVENT_PIPE_H_INCLUDED_


#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_event.h>


typedef struct ngx_event_pipe_s  ngx_event_pipe_t;

typedef int (*ngx_event_pipe_input_filter_pt)(ngx_event_pipe_t *p,
                                              ngx_hunk_t *hunk);
typedef int (*ngx_event_pipe_output_filter_pt)(void *data, ngx_chain_t *chain);


struct ngx_event_pipe_s {
    ngx_chain_t       *free_raw_hunks;
    ngx_chain_t       *in;
    ngx_chain_t      **last_in;

    ngx_chain_t       *out;
    ngx_chain_t      **last_out;

    ngx_chain_t       *free;
    ngx_chain_t       *busy;

    /*
     * the input filter i.e. that moves HTTP/1.1 chunks
     * from the raw hunks to an incoming chain
     */

    ngx_event_pipe_input_filter_pt    input_filter;
    void                              *input_ctx;

    ngx_event_pipe_output_filter_pt   output_filter;
    void                              *output_ctx;

    unsigned           read:1;
    unsigned           cachable:1;
    unsigned           single_buf:1;
    unsigned           free_bufs:1;
    unsigned           upstream_done:1;
    unsigned           upstream_error:1;
    unsigned           upstream_eof:1;
    unsigned           upstream_blocked:1;
    unsigned           downstream_done:1;
    unsigned           downstream_error:1;
    unsigned           cyclic_temp_file:1;

    int                hunks;
    ngx_bufs_t         bufs;
    ngx_hunk_tag_t     tag;

    size_t             busy_size;

    off_t              read_length;

    off_t              max_temp_file_size;
    int                temp_file_write_size;

    ngx_connection_t  *upstream;
    ngx_connection_t  *downstream;

    ngx_msec_t         read_timeout;
    ngx_msec_t         send_timeout;
    ssize_t            send_lowat;

    ngx_pool_t        *pool;
    ngx_log_t         *log;

    ngx_chain_t       *preread_hunks;
    int                preread_size;

    ngx_temp_file_t   *temp_file;

    /* STUB */ int     num;
};


int ngx_event_pipe(ngx_event_pipe_t *p, int do_write);
int ngx_event_pipe_copy_input_filter(ngx_event_pipe_t *p, ngx_hunk_t *hunk);


#endif /* _NGX_EVENT_PIPE_H_INCLUDED_ */
