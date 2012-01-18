/
/ Copyright (C) Igor Sysoev
/ Copyright (C) Nginx, Inc.
/


/  "casa   [%o2] 0x80, %o1, %o0"  and
/  "casxa  [%o2] 0x80, %o1, %o0"  do the following:
/
/       if ([%o2] == %o1) {
/           swap(%o0, [%o2]);
/       } else {
/           %o0 = [%o2];
/       }


/ ngx_atomic_uint_t ngx_casa(ngx_atomic_uint_t set, ngx_atomic_uint_t old,
/      ngx_atomic_t *lock);
/
/ the arguments are passed in the %o0, %o1, %o2
/ the result is returned in the %o0

        .inline ngx_casa,0
        casa    [%o2] 0x80, %o1, %o0
        .end


/ ngx_atomic_uint_t ngx_casxa(ngx_atomic_uint_t set, ngx_atomic_uint_t old,
/      ngx_atomic_t *lock);
/
/ the arguments are passed in the %o0, %o1, %o2
/ the result is returned in the %o0

        .inline ngx_casxa,0
        casxa   [%o2] 0x80, %o1, %o0
        .end
