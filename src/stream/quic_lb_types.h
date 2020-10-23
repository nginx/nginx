/*
 * Copyright (c) 2020 F5 Networks Inc.
 * This source code is subject to the terms of the Apache License,
 * version 2.0 (https://www.apache.org/licenses/LICENSE-2.0)
 */
#include <assert.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/evp.h>
#include <openssl/rand.h>

#ifndef _QUIC_LB_TYPES
#define _QUIC_LB_TYPES

typedef uint8_t             UINT8;
typedef uint16_t            UINT16;
typedef uint32_t            UINT32;
typedef uint64_t            UINT64;
typedef __uint128_t         UINT128;
typedef enum {FALSE, TRUE}  BOOL;
typedef enum {ERR_OK, ERR_OTHER} err_t;

#define umalloc(arg1,arg2,arg3) malloc(arg1)
#define ufree(arg) free(arg)
#define CUT_ASSERT(expr) assert(expr)
#define DBG_ASSERT(string,expr) assert(expr)

#define ROUNDUPDIV(n, m) (((n) + ((m) - 1)) / (m))

/* BIGIP constants that don't matter here */
#define RND_PSEUDO 0
#define M_FILTER 0
#define UM_ZERO 0

#define rndset(ptr,type,len) RAND_bytes((unsigned char *)ptr,len)

#define MAX(a, b) (((a) > (b)) ? (a) : (b))

/* Template to limit to a certain range for various types */
#define RND_RANGE(type,fnname,intmax)                                        \
    static inline type fnname(int rnd_type,               \
            type max)                                                \
    {                                                                      \
        type value;                                                  \
        rndset((unsigned char *)&value, rnd_type, sizeof(max));                             \
        return ((max < intmax) ? (value % (max + 1)) : value);           \
    }
RND_RANGE(UINT8, rnd8_range, UINT8_MAX)
RND_RANGE(UINT16, rnd16_range, UINT16_MAX)

static inline unsigned bit_count(UINT8 i)
{
    UINT8 octet = i;
    unsigned count = 0;

    while (octet > 0) {
        if ((octet & 0x1) == 1) {
            count++;
        }
        octet >>= 1;
    }
    return count;
}
#endif // _QUIC_LB_TYPES
