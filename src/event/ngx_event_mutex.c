
spinlock_max depend on CPU number and mutex type.
    1 CPU               1
    ngx_malloc_mutex    1000 ?


int ngx_event_mutex_trylock(ngx_mutex_t *mtx)
{
    for(i = mtx->spinlock_max; i; i--)
        if (trylock(mtx->lock))
            return 1;

    return 0;
}
