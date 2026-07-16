
/*
 * Copyright (C) Nginx, Inc.
 */


#include <ngx_config.h>
#include <ngx_core.h>


typedef ssize_t   (*ngx_json_length_pt)(ngx_data_item_t *item);
typedef u_char   *(*ngx_json_encode_pt)(u_char *p, ngx_data_item_t *item);


typedef struct {
    ngx_json_length_pt        length;
    ngx_json_encode_pt        encode;
} ngx_json_encode_t;


static ssize_t ngx_json_obj_length(ngx_data_item_t *item);
static ssize_t ngx_json_list_length(ngx_data_item_t *item);
static ssize_t ngx_json_string_length(ngx_data_item_t *item);
static ssize_t ngx_json_integer_length(ngx_data_item_t *item);
static ssize_t ngx_json_boolean_length(ngx_data_item_t *item);
static ssize_t ngx_json_null_length(ngx_data_item_t *item);

static u_char *ngx_json_obj_encode(u_char *p, ngx_data_item_t *item);
static u_char *ngx_json_list_encode(u_char *p, ngx_data_item_t *item);
static u_char *ngx_json_string_encode(u_char *p, ngx_data_item_t *item);
static u_char *ngx_json_integer_encode(u_char *p, ngx_data_item_t *item);
static u_char *ngx_json_boolean_encode(u_char *p, ngx_data_item_t *item);
static u_char *ngx_json_null_encode(u_char *p, ngx_data_item_t *item);


static ngx_json_encode_t  ngx_json_encode[] = {

    /* NGX_DATA_OBJECT_TYPE */
    { ngx_json_obj_length,
      ngx_json_obj_encode },

    /* NGX_DATA_LIST_TYPE */
    { ngx_json_list_length,
      ngx_json_list_encode },

    /* NGX_DATA_STRING_TYPE */
    { ngx_json_string_length,
      ngx_json_string_encode },

    /* NGX_DATA_INTEGER_TYPE */
    { ngx_json_integer_length,
      ngx_json_integer_encode },

    /* NGX_DATA_BOOLEAN_TYPE */
    { ngx_json_boolean_length,
      ngx_json_boolean_encode },

    /* NGX_DATA_NULL_TYPE */
    { ngx_json_null_length,
      ngx_json_null_encode },
};


ngx_buf_t *
ngx_json_render(ngx_pool_t *pool, ngx_data_item_t *item)
{
    size_t      length;
    ngx_buf_t  *buf;

    length = ngx_json_encode[item->type].length(item);
    if (length == (size_t) NGX_ERROR) {
        return NULL;
    }

    buf = ngx_create_temp_buf(pool, length);
    if (buf == NULL) {
        return NULL;
    }

    buf->last = ngx_json_encode[item->type].encode(buf->last, item);

    return buf;
}


static ssize_t
ngx_json_obj_length(ngx_data_item_t *item)
{
    size_t            len, total;
    ngx_data_obj_t   *obj;
    ngx_data_item_t  *i;

    obj = &item->data.object;
    total = sizeof("{}") - 1;
    i = obj->item;

    if (i) {
        for ( ;; ) {
            len = sizeof("\"\":") - 1 + i->name.len
                  + ngx_escape_json(NULL, i->name.data, i->name.len);

            if (total > NGX_MAX_SIZE_T_VALUE - len) {
                return NGX_ERROR;
            }

            total += len;

            len = ngx_json_encode[i->type].length(i);
            if (len == (size_t) NGX_ERROR) {
                return NGX_ERROR;
            }

            if (total > NGX_MAX_SIZE_T_VALUE - len) {
                return NGX_ERROR;
            }

            total += len;

            i = i->next;

            if (i == NULL) {
                break;
            }

            if (total > NGX_MAX_SIZE_T_VALUE - (sizeof(",") - 1)) {
                return NGX_ERROR;
            }

            total += sizeof(",") - 1;
        }
    }

    return total;
}


static u_char *
ngx_json_obj_encode(u_char *p, ngx_data_item_t *item)
{
    ngx_data_obj_t   *obj;
    ngx_data_item_t  *i;

    obj = &item->data.object;
    i = obj->item;

    *p++ = '{';

    if (i) {
        for ( ;; ) {
            *p++ = '"';

            p = (u_char *) ngx_escape_json(p, i->name.data, i->name.len);

            *p++ = '"';
            *p++ = ':';

            p = ngx_json_encode[i->type].encode(p, i);

            i = i->next;

            if (i == NULL) {
                break;
            }

            *p++ = ',';
        }
    }

    *p++ = '}';

    return p;
}


static ssize_t
ngx_json_list_length(ngx_data_item_t *item)
{
    size_t            len, total;
    ngx_data_obj_t   *obj;
    ngx_data_item_t  *i;

    obj = &item->data.object;
    total = sizeof("[]") - 1;
    i = obj->item;

    if (i) {
        for ( ;; ) {
            len = ngx_json_encode[i->type].length(i);
            if (len == (size_t) NGX_ERROR) {
                return NGX_ERROR;
            }

            if (total > NGX_MAX_SIZE_T_VALUE - len) {
                return NGX_ERROR;
            }

            total += len;

            i = i->next;

            if (i == NULL) {
                break;
            }

            if (total > NGX_MAX_SIZE_T_VALUE - (sizeof(",") - 1)) {
                return NGX_ERROR;
            }

            total += sizeof(",") - 1;
        }
    }

    return total;
}


static u_char *
ngx_json_list_encode(u_char *p, ngx_data_item_t *item)
{
    ngx_data_obj_t   *obj;
    ngx_data_item_t  *i;

    obj = &item->data.object;
    i = obj->item;

    *p++ = '[';

    if (i) {
        for ( ;; ) {
            p = ngx_json_encode[i->type].encode(p, i);

            i = i->next;

            if (i == NULL) {
                break;
            }

            *p++ = ',';
        }
    }

    *p++ = ']';

    return p;
}


static ssize_t
ngx_json_string_length(ngx_data_item_t *item)
{
    ngx_str_t  *str;

    str = &item->data.string;

    return sizeof("\"\"") - 1 + str->len
           + ngx_escape_json(NULL, str->data, str->len);
}


static u_char *
ngx_json_string_encode(u_char *p, ngx_data_item_t *item)
{
    ngx_str_t  *str;

    str = &item->data.string;

    *p++ = '"';

    p = (u_char *) ngx_escape_json(p, str->data, str->len);

    *p++ = '"';

    return p;
}


static ssize_t
ngx_json_integer_length(ngx_data_item_t *item)
{
    return NGX_INT64_LEN;
}


static u_char *
ngx_json_integer_encode(u_char *p, ngx_data_item_t *item)
{
    return ngx_sprintf(p, "%L", item->data.integer);
}


static ssize_t
ngx_json_boolean_length(ngx_data_item_t *item)
{
    return sizeof("false") - 1;
}


static u_char *
ngx_json_boolean_encode(u_char *p, ngx_data_item_t *item)
{
    return item->data.boolean ? ngx_cpymem(p, "true", 4)
                              : ngx_cpymem(p, "false", 5);
}


static ssize_t
ngx_json_null_length(ngx_data_item_t *item)
{
    return sizeof("null") - 1;
}


static u_char *
ngx_json_null_encode(u_char *p, ngx_data_item_t *item)
{
    return ngx_cpymem(p, "null", 4);
}
