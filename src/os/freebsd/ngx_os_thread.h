#ifndef _NGX_OS_THREAD_H_INCLUDED_
#define _NGX_OS_THREAD_H_INCLUDED_


typedef int  ngx_os_tid_t;
typedef int  ngx_tid_t;


extern char   *ngx_stacks_start;
extern char   *ngx_stacks_end;
extern size_t  ngx_stack_size;


static inline ngx_tid_t ngx_gettid()
{   
    char *sp;

    __asm__ ("mov %%esp,%0" : "=r" (sp));
    return (sp > ngx_stacks_end) ? 0:
           (sp - ngx_stacks_start) / ngx_stack_size + 1;
}


#endif /* _NGX_OS_THREAD_H_INCLUDED_ */
