
#include <ngx_config.h>
#include <ngx_core.h>


/*
 * The code is based on the algorithm described in the "Introduction
 * to Algorithms" by Cormen, Leiserson and Rivest.
 */

#define ngx_rbt_red(node)           ((uintptr_t) (node)->data |= 1)
#define ngx_rbt_black(node)         ((uintptr_t) (node)->data &= ~1)
#define ngx_rbt_is_red(node)        ((uintptr_t) (node)->data & 1)
#define ngx_rbt_is_black(node)      (!ngx_rbt_is_red(node))
#define ngx_rbt_copy_color(n1, n2)                                            \
                         ((uintptr_t) (n1)->data |= (uintptr_t) (n2)->data & 1)


ngx_inline void ngx_rbtree_left_rotate(ngx_rbtree_t **root, ngx_rbtree_t *node);
ngx_inline void ngx_rbtree_right_rotate(ngx_rbtree_t **root,
                                        ngx_rbtree_t *node);

ngx_rbtree_t  sentinel;


void ngx_rbtree_insert(ngx_rbtree_t **root, ngx_rbtree_t *node)
{
    ngx_rbtree_t  *temp;

    /* a binary tree insert */

    if (*root == &sentinel) {
        node->parent = &sentinel;
        node->left = &sentinel;
        node->right = &sentinel;
        ngx_rbt_black(node);
        *root = node;

        return;
    }

    temp = *root;

    for ( ;; ) {
        if (node->key < temp->key) {
            if (temp->left == &sentinel) {
                temp->left = node;
                break;
            }

            temp = temp->left;
            continue;
        }

        if (temp->right == &sentinel) {
            temp->right = node;
            break;
        }

        temp = temp->right;
        continue;
    }

    node->parent = temp;
    node->left = &sentinel;
    node->right = &sentinel;


    /* re-balance tree */

    ngx_rbt_red(node);

    while (node->parent && ngx_rbt_is_red(node->parent)) {

        if (node->parent == node->parent->parent->left) {
            temp = node->parent->parent->right;

            if (ngx_rbt_is_red(temp)) {
                ngx_rbt_black(node->parent);
                ngx_rbt_black(temp);
                ngx_rbt_red(node->parent->parent);
                node = node->parent->parent;

            } else {
                if (node == node->parent->right) {
                    node = node->parent;
                    ngx_rbtree_left_rotate(root, node);
                }

                ngx_rbt_black(node->parent);
                ngx_rbt_red(node->parent->parent);
                ngx_rbtree_right_rotate(root, node->parent->parent);
            }

        } else {
            temp = node->parent->parent->left;

            if (ngx_rbt_is_red(temp)) {
                ngx_rbt_black(node->parent);
                ngx_rbt_black(temp);
                ngx_rbt_red(node->parent->parent);
                node = node->parent->parent;

            } else {
                if (node == node->parent->left) {
                    node = node->parent;
                    ngx_rbtree_right_rotate(root, node);
                }

                ngx_rbt_black(node->parent);
                ngx_rbt_red(node->parent->parent);
                ngx_rbtree_left_rotate(root, node->parent->parent);
            }
        }

    }

    ngx_rbt_black(*root);
}


void ngx_rbtree_delete(ngx_rbtree_t **root, ngx_rbtree_t *node)
{
    ngx_rbtree_t  *subst, *temp, *w;

    /* a binary tree delete */

    if (node->left == &sentinel || node->right == &sentinel) {
        subst = node;

    } else {

        /* find a node successor */

        if (node->right == &sentinel) {
            temp = node;
            subst = node->parent;

            while (subst != &sentinel && temp == subst->right) {
                 temp = subst;
                 subst = subst->parent;
            }

        } else {
            subst = ngx_rbtree_min(node->right);
        }
    }

    if (subst->left != &sentinel) {
        temp = subst->left;
    } else {
        temp = subst->right;
    }

    temp->parent = subst->parent;

    if (subst->parent == &sentinel) {
        *root = temp;

    } else if (subst == subst->parent->left) {
        subst->parent->left = temp;

    } else {
        subst->parent->right = temp;
    }

    if (subst != node) {
        node->key = subst->key;
        node->data = subst->data;
    }

    if (ngx_rbt_is_red(subst)) {
        return;
    }

    /* a delete fixup */

    while (temp->parent != &sentinel && ngx_rbt_is_black(temp)) {
        if (temp == temp->parent->left) {
            w = temp->parent->right;

            if (ngx_rbt_is_red(w)) {
                ngx_rbt_black(w);
                ngx_rbt_red(temp->parent);
                ngx_rbtree_left_rotate(root, temp->parent);
                w = temp->parent->right;
            }

            if (ngx_rbt_is_black(w->left) && ngx_rbt_is_black(w->right)) {
                ngx_rbt_red(w);
                temp = temp->parent;

            } else {
                if (ngx_rbt_is_black(w->right)) {
                    ngx_rbt_black(w->left);
                    ngx_rbt_red(w);
                    ngx_rbtree_right_rotate(root, w);
                    w = temp->parent->right;
                }

                ngx_rbt_copy_color(w, temp->parent);
                ngx_rbt_black(temp->parent);
                ngx_rbt_black(w->right);
                ngx_rbtree_left_rotate(root, temp->parent);
                temp = *root;
            }

        } else {
            w = temp->parent->left;

            if (ngx_rbt_is_red(w)) {
                ngx_rbt_black(w);
                ngx_rbt_red(temp->parent);
                ngx_rbtree_right_rotate(root, temp->parent);
                w = temp->parent->left;
            }

            if (ngx_rbt_is_black(w->right) && ngx_rbt_is_black(w->left)) {
                ngx_rbt_red(w);
                temp = temp->parent;

            } else {
                if (ngx_rbt_is_black(w->left)) {
                    ngx_rbt_black(w->right);
                    ngx_rbt_red(w);
                    ngx_rbtree_left_rotate(root, w);
                    w = temp->parent->left;
                }

                ngx_rbt_copy_color(w, temp->parent);
                ngx_rbt_black(temp->parent);
                ngx_rbt_black(w->left);
                ngx_rbtree_right_rotate(root, temp->parent);
                temp = *root;
            }
        }
    }

    ngx_rbt_black(temp);
}


ngx_inline void ngx_rbtree_left_rotate(ngx_rbtree_t **root, ngx_rbtree_t *node)
{
    ngx_rbtree_t  *temp;

    temp = node->right;
    node->right = temp->left;

    if (temp->left != &sentinel) {
        temp->left->parent = node;
    }

    temp->parent = node->parent;

    if (node->parent == &sentinel) {
        *root = temp;

    } else if (node == node->parent->left) {
        node->parent->left = temp;

    } else {
        node->parent->right = temp;
    }

    temp->left = node;
    node->parent = temp;
}


ngx_inline void ngx_rbtree_right_rotate(ngx_rbtree_t **root, ngx_rbtree_t *node)
{
    ngx_rbtree_t  *temp;

    temp = node->left;
    node->left = temp->right;

    if (temp->right != &sentinel) {
        temp->right->parent = node;
    }

    temp->parent = node->parent;

    if (node->parent == &sentinel) {
        *root = temp;

    } else if (node == node->parent->right) {
        node->parent->right = temp;

    } else {
        node->parent->left = temp;
    }

    temp->right = node;
    node->parent = temp;
}
