
/*
 * Copyright (C) Igor Sysoev
 */


#include <sys/syscall.h>
#include <machine/asm.h>

/*
 * rfork_thread(3) - rfork_thread(flags, stack, func, arg);
 */

#define	KERNCALL	int $0x80

ENTRY(rfork_thread)
	push	%ebp
	mov	%esp, %ebp
	push	%esi

	mov	12(%ebp), %esi	# the thread stack address

	sub	$4, %esi
	mov	20(%ebp), %eax	# the thread argument
	mov	%eax, (%esi)

	sub	$4, %esi
	mov	16(%ebp), %eax	# the thread start address
	mov	%eax, (%esi)

	push	8(%ebp)		# rfork(2) flags
	push	$0
	mov	$SYS_rfork, %eax
	KERNCALL
	jc	error

	cmp	$0, %edx
	jne	child

parent:
	add	$8, %esp
	pop	%esi
	leave
	ret

child:
	mov	%esi, %esp
	pop	%eax
	call	*%eax		# call a thread start address ...
	add	$4, %esp

	push	%eax
	push	$0
	mov	$SYS_exit, %eax	# ... and exit(2) after a thread would return
	KERNCALL

error:
	add	$8, %esp
	pop	%esi
	leave
	PIC_PROLOGUE

	/* libc's cerror: jmp  PIC_PLT(HIDENAME(cerror)) */

	push	%eax
	call	PIC_PLT(CNAME(__error))
	pop	%ecx
	PIC_EPILOGUE
	mov	%ecx, (%eax)
	mov	$-1, %eax
	mov	$-1, %edx
	ret
