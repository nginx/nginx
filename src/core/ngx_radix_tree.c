
/*
 * Copyright (C) Igor Sysoev
 */


#include <ngx_config.h>
#include <ngx_core.h>


static void *ngx_radix_alloc(ngx_radix_tree_t *tree);


ngx_radix_tree_t *ngx_radix_tree_create(ngx_pool_t *pool)
{
    ngx_radix_tree_t  *tree;

    if (!(tree = ngx_palloc(pool, sizeof(ngx_radix_tree_t)))) {
        return NULL;
    }

    tree->pool = pool;
    tree->free = NULL;
    tree->start = NULL;
    tree->size = 0;

    if (!(tree->root = ngx_radix_alloc(tree))) {
        return NULL;
    }

    tree->root->right = NULL;
    tree->root->left = NULL;
    tree->root->parent = NULL;
    tree->root->value = NGX_RADIX_NO_VALUE;

    return tree;
}


ngx_int_t ngx_radix32tree_insert(ngx_radix_tree_t *tree,
                                 uint32_t key, uint32_t mask, uintptr_t value)
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
        if (!(next = ngx_radix_alloc(tree))) {
            return NGX_ERROR;
        }

        next->right = NULL;
        next->left = NULL;
        next->parent = node;
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


ngx_int_t ngx_radix32tree_delete(ngx_radix_tree_t *tree,
                                 uint32_t key, uint32_t mask)
{
    uint32_t           bit;
    ngx_radix_node_t  *node;

    bit = 0x80000000;
    node = tree->root;

    while (node && (bit & mask)) {
        if (key & bit) {
            node = node->right;

        } else {
            node = node->left;
        }

        bit >>= 1;
    }

    if (node == NULL) {
        return NGX_ERROR;
    }

    if (node->right || node->left) {
        if (node->value != NGX_RADIX_NO_VALUE) {
            node->value = NGX_RADIX_NO_VALUE;
            return NGX_OK;
        }

        return NGX_ERROR;
    }

    for ( ;; ) {
        if (node->parent->right == node) {
            node->parent->right = NULL;
        } else {
            node->parent->left = NULL;
        }

        node->right = tree->free;
        tree->free = node;

        node = node->parent;

        if (node->right
            || node->left
            || node->value != NGX_RADIX_NO_VALUE
            || node->parent == NULL)
        {
            break;
        }
    }

    return NGX_OK;
}


uintptr_t ngx_radix32tree_find(ngx_radix_tree_t *tree, uint32_t key)
{
    uint32_t           bit;
    uintptr_t          value;
    ngx_radix_node_t  *node;

    bit = 0x80000000;
    value = NGX_RADIX_NO_VALUE;
    node = tree->root;

    while (node) {
        if (node->value != NGX_RADIX_NO_VALUE) {
            value = node->value;
        }

        if (key & bit) {
            node = node->right;

        } else {
            node = node->left;
        }

        bit >>= 1;
    }

    return value;
}


static void *ngx_radix_alloc(ngx_radix_tree_t *tree)
{
    char  *p;

    if (tree->free) {
        p = (char *) tree->free;
        tree->free = tree->free->right;
        return p;
    }

    if (tree->size < sizeof(ngx_radix_node_t)) {
        if (!(tree->start = ngx_palloc(tree->pool, ngx_pagesize))) {
            return NULL;
        }

        tree->size = ngx_pagesize;
    }

    p = tree->start;
    tree->start += sizeof(ngx_radix_node_t);
    tree->size -= sizeof(ngx_radix_node_t);

    return p;
}
