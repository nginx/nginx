
/*
 * Copyright (C) Igor Sysoev
 */


#include <ngx_config.h>
#include <ngx_core.h>


static void *ngx_radix_alloc(ngx_radix_tree_t *tree, size_t size);


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

    if (!(tree->root = ngx_radix_alloc(tree, sizeof(ngx_radix_node_t)))) {
        return NULL;
    }

    tree->root->value = (uintptr_t) 0;
    tree->root->right = NULL;
    tree->root->left = NULL;
    tree->root->parent = NULL;

    return tree;
}


ngx_int_t ngx_radix32tree_insert(ngx_radix_tree_t *tree,
                                 uint32_t key, uint32_t mask, uintptr_t value)
{
    uint32_t           bit;
    ngx_radix_node_t  *node, *next;

    bit = 0x80000000;
    node = tree->root;
    next = NULL;

    while (bit & mask) {
        if (key & bit) {
            next = node->right;

        } else {
            next = node->left;
        }

        bit >>= 1;

        if (next == NULL) {
            break;
        }

        node = next;
    }

    if (next) {
        if (node->value) {
            return NGX_BUSY;
        }

        node->value = value;
        return NGX_OK;
    }

    while (bit & mask) {
        if (!(next = ngx_radix_alloc(tree, sizeof(ngx_radix_node_t)))) {
            return NGX_ERROR;
        }

        next->value = value;
        next->right = NULL;
        next->left = NULL;
        next->parent = node;

        if (key & bit) {
            node->right = next;

        } else {
            node->left = next;
        }

        bit >>= 1;
        node = next;
    }

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
        node->value = (uintptr_t) 0;
        return NGX_OK;
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

        if (node->right || node->left || node->value || node->parent == NULL) {
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
    value = (uintptr_t) 0;
    node = tree->root;

    while (node) {
        if (node->value) {
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


static void *ngx_radix_alloc(ngx_radix_tree_t *tree, size_t size)
{
    char  *p;

    if (tree->free) {
        p = (char *) tree->free;
        tree->free = tree->free->right;
        return p;
    }

    if (tree->size < size) {
        if (!(tree->start = ngx_palloc(tree->pool, ngx_pagesize))) {
            return NULL;
        }

        tree->size = ngx_pagesize;
    }

    p = tree->start;
    tree->start += size;
    tree->size -= size;

    return p;
}
