#ifndef _NGX_CYCLE_H_INCLUDED_
#define _NGX_CYCLE_H_INCLUDED_


#include <ngx_config.h>
#include <ngx_core.h>


struct ngx_cycle_s {
    void           ****conf_ctx;
    ngx_pool_t        *pool;
    ngx_log_t         *log;
    ngx_array_t        listening;
    ngx_array_t        open_files;
    ngx_array_t        pathes;

    int                connection_n;
    ngx_connection_t  *connections;
    ngx_event_t       *read_events;
    ngx_event_t       *write_events;

    ngx_cycle_t       *old_cycle;

    ngx_str_t          conf_file;
};


ngx_cycle_t *ngx_init_cycle(ngx_cycle_t *old_cycle);
void ngx_reopen_files(ngx_cycle_t *cycle, uid_t user);


extern volatile ngx_cycle_t  *ngx_cycle;
extern ngx_array_t            ngx_old_cycles;


#endif /* _NGX_CYCLE_H_INCLUDED_ */
