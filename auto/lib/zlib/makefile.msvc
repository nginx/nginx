
# Copyright (C) Igor Sysoev
# Copyright (C) Nginx, Inc.


CFLAGS = -nologo -O2 -Ob1 -Oi -Gs $(LIBC) $(CPU_OPT)

zlib.lib:
	cd $(ZLIB)

	cl -c $(CFLAGS) adler32.c crc32.c deflate.c \
		trees.c zutil.c compress.c \
		inflate.c inffast.c inftrees.c

	link -lib -out:zlib.lib adler32.obj crc32.obj deflate.obj \
		trees.obj zutil.obj compress.obj \
		inflate.obj inffast.obj inftrees.obj
