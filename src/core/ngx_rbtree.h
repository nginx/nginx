#ifndef _NGX_RBTREE_H_INCLUDED_
#define _NGX_RBTREE_H_INCLUDED_


#include <ngx_config.h>
#include <ngx_core.h>


typedef struct ngx_rbtree_s  ngx_rbtree_t;

struct ngx_rbtree_s {
   ngx_int_t       key;
   ngx_rbtree_t   *left;
   ngx_rbtree_t   *right;
   ngx_rbtree_t   *parent;
   char            color;
};

extern ngx_rbtree_t  sentinel;


void ngx_rbtree_insert(ngx_rbtree_t **root, ngx_rbtree_t *node);
void ngx_rbtree_delete(ngx_rbtree_t **root, ngx_rbtree_t *node);


ngx_inline static ngx_rbtree_t *ngx_rbtree_min(ngx_rbtree_t *root)
{
   while (root->left != &sentinel) {
       root = root->left;
   }

   return root;
}


#endif /* _NGX_RBTREE_H_INCLUDED_ */
