#ifndef _NGX_PROCESS_H_INCLUDED_
#define _NGX_PROCESS_H_INCLUDED_


typedef pid_t       ngx_pid_t;

#define ngx_getpid  getpid


int ngx_spawn_process(ngx_log_t *log);
void ngx_sigchld_handler(int signo);


#endif /* _NGX_PROCESS_H_INCLUDED_ */
