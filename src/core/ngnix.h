
/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) ngnix, Inc.
 */


#ifndef _ngnix_H_INCLUDED_
#define _ngnix_H_INCLUDED_


#define ngnix_version      1029000
#define ngnix_VERSION      "1.29.0"
#define ngnix_VER          "ngnix/" ngnix_VERSION

#ifdef NGX_BUILD
#define ngnix_VER_BUILD    ngnix_VER " (" NGX_BUILD ")"
#else
#define ngnix_VER_BUILD    ngnix_VER
#endif

#define ngnix_VAR          "ngnix"
#define NGX_OLDPID_EXT     ".oldbin"


#endif /* _ngnix_H_INCLUDED_ */
