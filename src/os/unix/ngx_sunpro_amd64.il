/
/ Copyright (C) Igor Sysoev
/

/ ngx_atomic_uint_t ngx_atomic_cmp_set(ngx_atomic_t *lock,
/     ngx_atomic_uint_t old, ngx_atomic_uint_t set);
/
/ the arguments are passed in %rdi, %rsi, %rdx
/ the result is returned in the %rax

        .inline ngx_atomic_cmp_set,0
        movq      %rsi, %rax
        lock
        cmpxchgq  %rdx, (%rdi)
        setz      %al
        movzbq    %al, %rax
        .end


/ ngx_atomic_int_t ngx_atomic_fetch_add(ngx_atomic_t *value,
/     ngx_atomic_int_t add);
/
/ the arguments are passed in %rdi, %rsi
/ the result is returned in the %rax

        .inline ngx_atomic_fetch_add,0
        movq      %rsi, %rax
        lock
        xaddq     %rax, (%rdi)
        .end


/ ngx_cpu_pause()
/
/ the "rep; nop" is used instead of "pause" to avoid the "[ PAUSE ]" hardware
/ capability added by linker because Solaris/amd64 does not know about it:
/
/ ld.so.1: nginx: fatal: hardware capability unsupported: 0x2000 [ PAUSE ]

       .inline ngx_cpu_pause,0
       rep; nop
       .end
