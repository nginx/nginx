
/*
 * Copyright (C) Igor Sysoev
 */


#include <ngx_config.h>
#include <ngx_core.h>


static ngx_int_t ngx_radix32tree_delete_node(ngx_radix_tree_t *tree,
    uint32_t key, uint32_t mask, ngx_radix_node_t **pnode, uint32_t bit);
void ngx_radix32tree_compress_node(ngx_radix_tree_t *tree,
    ngx_radix_node_t *node);
static void *ngx_radix_alloc(ngx_radix_tree_t *tree);


ngx_radix_tree_t *
ngx_radix_tree_create(ngx_pool_t *pool, ngx_int_t preallocate)
{
    uint32_t           key, mask, inc;
    ngx_radix_tree_t  *tree;

    tree = ngx_palloc(pool, sizeof(ngx_radix_tree_t));
    if (tree == NULL) {
        return NULL;
    }

    tree->pool = pool;
    tree->free = NULL;
    tree->start = NULL;
    tree->size = 0;
    tree->count = 0;

    tree->root = ngx_radix_alloc(tree);
    if (tree->root == NULL) {
        return NULL;
    }

    tree->root->right = NULL;
    tree->root->left = NULL;
    tree->root->skip = 0;
    tree->root->value = NGX_RADIX_NO_VALUE;

    if (preallocate == 0) {
        return tree;
    }

    /*
     * Preallocation of first nodes : 0, 1, 00, 01, 10, 11, 000, 001, etc.
     * increases TLB hits even if for first lookup iterations.
     * On 32-bit platforms the 7 preallocated bits takes continuous 4K,
     * 8 - 8K, 9 - 16K, etc.  On 64-bit platforms the 6 preallocated bits
     * takes continuous 4K, 7 - 8K, 8 - 16K, etc.  There is no sense to
     * to preallocate more than one page, because further preallocation
     * distributes the only bit per page.  Instead, a random insertion
     * may distribute several bits per page.
     *
     * Thus, by default we preallocate maximum
     *     6 bits on amd64 (64-bit platform and 4K pages)
     *     7 bits on i386 (32-bit platform and 4K pages)
     *     7 bits on sparc64 in 64-bit mode (8K pages)
     *     8 bits on sparc64 in 32-bit mode (8K pages)
     */

    if (preallocate == -1) {
        switch (ngx_pagesize / sizeof(ngx_radix_tree_t)) {

        /* amd64 */
        case 128:
            preallocate = 6;
            break;

        /* i386, sparc64 */
        case 256:
            preallocate = 7;
            break;

        /* sparc64 in 32-bit mode */
        default:
            preallocate = 8;
        }
    }

    mask = 0;
    inc = 0x80000000;

    while (preallocate--) {

        key = 0;
        mask >>= 1;
        mask |= 0x80000000;

        do {
            if (ngx_radix32tree_insert(tree, key, mask, NGX_RADIX_NO_VALUE)
                != NGX_OK)
            {
                return NULL;
            }

            key += inc;

        } while (key);

        inc >>= 1;
    }

    return tree;
}


ngx_int_t
ngx_radix32tree_insert(ngx_radix_tree_t *tree, uint32_t key, uint32_t mask,
    uintptr_t value)
{
    uint32_t           bit;
    ngx_radix_node_t  *node, *next;

    bit = 0x80000000;

    node = tree->root;
    next = tree->root;

    while (bit & mask) {
        if (key & bit) {
            next = node->right;

        } else {
            next = node->left;
        }

        if (next == NULL) {
            break;
        }

        bit >>= 1;
        node = next;
    }

    if (next) {
        if (node->value != NGX_RADIX_NO_VALUE) {
            return NGX_BUSY;
        }

        node->value = value;
        return NGX_OK;
    }

    while (bit & mask) {
        next = ngx_radix_alloc(tree);
        if (next == NULL) {
            return NGX_ERROR;
        }

        next->right = NULL;
        next->left = NULL;
        next->skip = 0;
        next->value = NGX_RADIX_NO_VALUE;

        if (key & bit) {
            node->right = next;

        } else {
            node->left = next;
        }

        bit >>= 1;
        node = next;
    }

    node->value = value;

    return NGX_OK;
}


ngx_int_t
ngx_radix32tree_delete(ngx_radix_tree_t *tree, uint32_t key, uint32_t mask)
{
    return ngx_radix32tree_delete_node(tree, key, mask, &tree->root,
                                       0x80000000);
}


static ngx_int_t
ngx_radix32tree_delete_node(ngx_radix_tree_t *tree, uint32_t key, uint32_t mask,
    ngx_radix_node_t **pnode, uint32_t bit)
{
    ngx_radix_node_t  *node;

    node = *pnode;

    if (node == NULL) {
        return NGX_ERROR;
    }

    if ((bit & mask) == 0) {

        if (node->right || node->left) {

            if (node->value != NGX_RADIX_NO_VALUE) {
                node->value = NGX_RADIX_NO_VALUE;
                return NGX_OK;
            }

            return NGX_ERROR;

        } else {
            node->right = tree->free;
            tree->free = node;
            tree->count--;

            *pnode = NULL;
        }

        return NGX_OK;
    }

    if (ngx_radix32tree_delete_node(tree, key, mask,
                                    (key & bit) ? &node->right : &node->left,
                                    bit >> 1)
        != NGX_OK)
    {
        return NGX_ERROR;
    }

    if (node->right || node->left) {
        return NGX_OK;
    }

    if (node->value != NGX_RADIX_NO_VALUE) {
        return NGX_OK;
    }

    node->right = tree->free;
    tree->free = node;
    tree->count--;

    *pnode = NULL;

    return NGX_OK;
}


void
ngx_radix32tree_compress(ngx_radix_tree_t *tree)
{
    if (tree->root) {
        ngx_radix32tree_compress_node(tree, tree->root);
    }
}


void
ngx_radix32tree_compress_node(ngx_radix_tree_t *tree, ngx_radix_node_t *node)
{
    uintptr_t          skip;
    ngx_radix_node_t  *n;

    if (node->right) {

        skip = 0;

        for (n = node->right;
             n->right && n->left == NULL && n->value == NGX_RADIX_NO_VALUE;
             n = node->right)
        {
            node->right = n->right;

            n->right = tree->free;
            tree->free = n;
            tree->count--;

            skip++;
        }

        node->right->skip = skip;

        ngx_radix32tree_compress_node(tree, node->right);
    }

    if (node->left) {

        skip = 0;

        for (n = node->left;
             n->left && n->right == NULL && n->value == NGX_RADIX_NO_VALUE;
             n = node->left)
        {
            node->left = n->left;

            n->right = tree->free;
            tree->free = n;
            tree->count--;

            skip++;
        }

        node->left->skip = skip;

        ngx_radix32tree_compress_node(tree, node->left);
    }
}


uintptr_t
ngx_radix32tree_find(ngx_radix_tree_t *tree, uint32_t key)
{
    uint32_t           bit, test;
    uintptr_t          value, skip;
    ngx_radix_node_t  *node;

    value = NGX_RADIX_NO_VALUE;
    node = tree->root;

    if (node == NULL) {
        return NGX_RADIX_NO_VALUE;
    }

    bit = 0x80000000;

    for ( ;; ) {

        if (node->value != NGX_RADIX_NO_VALUE) {
            value = node->value;
        }

        if (key & bit) {
            node = node->right;
            test = 0;

        } else {
            node = node->left;
            test = bit >> 1;
        }

        if (node == NULL) {
            return value;
        }

        bit >>= 1;

        for (skip = node->skip; skip; skip--) {

            if ((key & bit) == test) {
                return value;
            }

            bit >>= 1;
            test >>= 1;
        }
    }
}


static void *
ngx_radix_alloc(ngx_radix_tree_t *tree)
{
    char  *p;

    if (tree->free) {
        p = (char *) tree->free;
        tree->free = tree->free->right;
        tree->count++;
        return p;
    }

    if (tree->size < sizeof(ngx_radix_node_t)) {
        tree->start = ngx_pmemalign(tree->pool, ngx_pagesize, ngx_pagesize);
        if (tree->start == NULL) {
            return NULL;
        }

        tree->size = ngx_pagesize;
    }

    p = tree->start;
    tree->start += sizeof(ngx_radix_node_t);
    tree->size -= sizeof(ngx_radix_node_t);
    tree->count++;

    return p;
}
