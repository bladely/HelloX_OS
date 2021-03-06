/*
 * Copyright (c) 1987, 1993
 *	The Regents of the University of California.  All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 4. Neither the name of the University nor the names of its contributors
 *    may be used to endorse or promote products derived from this software
 *    without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE REGENTS AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE REGENTS OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 *
 *	@(#)malloc.h	8.5 (Berkeley) 5/3/95
 *           src/sys/sys/malloc.h,v 1.77 2004/07/19 06:21:26 green Exp $
 */

#ifndef _SYS_MALLOC_H_
#define	_SYS_MALLOC_H_
#include "bsdsys.h"
#include "kqueue.h"

#define	MINALLOCSIZE	UMA_SMALLEST_UNIT

/*
 * flags to malloc.
 */
#define	M_NOWAIT	0x0001		/* do not block */
#define	M_WAITOK	0x0002		/* ok to block */
#define	M_ZERO		0x0100		/* bzero the allocation */
#define	M_NOVM		0x0200		/* don't ask VM for pages */
#define	M_USE_RESERVE	0x0400		/* can alloc out of reserve memory */

#define	M_MAGIC		877983977	/* time when first defined :-) */

struct malloc_type {
	struct malloc_type *ks_next;	/* next in list */
	u_long 	ks_memuse;	/* total memory held in bytes */
	u_long	ks_size;	/* sizes of this thing that are allocated */
	u_long	ks_inuse;	/* # of packets of this type currently in use */
	int64_t ks_calls;	/* total packets of this type ever allocated */
	u_long	ks_maxused;	/* maximum number ever used */
	u_long	ks_magic;	/* if it's not magic, don't touch it */
	const char *ks_shortdesc;	/* short description */
};
#define	MALLOC_DEFINE(type, shortdesc, longdesc) \
	struct malloc_type type[1]= { \
		{ NULL, 0, 0, 0, 0, 0, M_MAGIC, shortdesc } \
	}; 



#define	MALLOC_DECLARE(type) \
	extern struct malloc_type type[1]

MALLOC_DECLARE(M_CACHE);
MALLOC_DECLARE(M_DEVBUF);
MALLOC_DECLARE(M_TEMP);

MALLOC_DECLARE(M_IFADDR);
MALLOC_DECLARE(M_IFMADDR);
/*
 * Deprecated macro versions of not-quite-malloc() and free().
 */
#define	MALLOC(space, cast, size, type, flags) \
	((space) = (cast)malloc((u_long)(size)))
#define	FREE(addr, type) free(addr)

/*
 * XXX this should be declared in <sys/uio.h>, but that tends to fail
 * because <sys/uio.h> is included in a header before the source file
 * has a chance to include <sys/malloc.h> to get MALLOC_DECLARE() defined.
 */
MALLOC_DECLARE(M_IOV);

extern struct mtx malloc_mtx;

/* XXX struct malloc_type is unused for contig*(). */
/*
void	contigfree(void *addr, unsigned long size, struct malloc_type *type);
void	*contigmalloc(unsigned long size, struct malloc_type *type, int flags,
	    vm_paddr_t low, vm_paddr_t high, unsigned long alignment,
	    unsigned long boundary);
	    */
void	malloc_init(void *);
int	malloc_last_fail(void);
void	malloc_type_allocated(struct malloc_type *type, unsigned long size);
void	malloc_type_freed(struct malloc_type *type, unsigned long size);
void	malloc_uninit(void *);
//void	*realloc(void *addr, unsigned long size, struct malloc_type *type,
//	    int flags);
void	*reallocf(void *addr, unsigned long size, struct malloc_type *type,
	    int flags);

__inline void *
contigmalloc(
	unsigned long size,	/* should be size_t here and for malloc() */
	struct malloc_type *type,
	int flags,
	vm_paddr_t low,
	vm_paddr_t high,
	unsigned long alignment,
	unsigned long boundary)
{
	return malloc(size);
}

__inline void
contigfree(void *addr, unsigned long size, struct malloc_type *type)
{
	free(addr);	
}

#endif /* !_SYS_MALLOC_H_ */
