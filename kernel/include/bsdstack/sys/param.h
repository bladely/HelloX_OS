/*-
 * Copyright (c) 1982, 1986, 1989, 1993
 *	The Regents of the University of California.  All rights reserved.
 * (c) UNIX System Laboratories, Inc.
 * All or some portions of this file are derived from material licensed
 * to the University of California by American Telephone and Telegraph
 * Co. or Unix System Laboratories, Inc. and are reproduced herein with
 * the permission of UNIX System Laboratories, Inc.
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
 *	@(#)param.h	8.3 (Berkeley) 4/4/95
 *           src/sys/sys/param.h,v 1.209.2.4 2004/10/03 17:04:41 mlaier Exp $
 */

#ifndef _SYS_PARAM_H_
#define _SYS_PARAM_H_

#include <bsdsys.h>

#define	BSD	199506		/* System version (year & month). */
#define BSD4_3	1
#define BSD4_4	1

/* 
 * If you bump the version for any reason, you should update the documentation
 * there.
 * Currently this lives here:
 *
 *	doc/en_US.ISO8859-1/books/porters-handbook/book.sgml
 *
 * scheme is:  <major><two digit minor><0 if release branch, otherwise 1>xx
 */

/*
 * Machine-independent constants (some used in following include files).
 * Redefined constants are from POSIX 1003.1 limits file.
 *
 * MAXCOMLEN should be >= sizeof(ac_comm) (see <acct.h>)
 * MAXLOGNAME should be == UT_NAMESIZE+1 (see <utmp.h>)
 */
#include <syslimits.h>

#define	MAXCOMLEN	19		/* max command name remembered */
#define	MAXINTERP	32		/* max interpreter file name length */
#define	MAXLOGNAME	17		/* max login name length (incl. NUL) */
#define	MAXUPRC		CHILD_MAX	/* max simultaneous processes */
#define	NCARGS		ARG_MAX		/* max bytes for an exec function */
#define	NGROUPS		NGROUPS_MAX	/* max number groups */
#define	NOFILE		OPEN_MAX	/* max open files per process */
#define	NOGROUP		65535		/* marker for empty group set member */
#define MAXHOSTNAMELEN	256		/* max hostname size */
#define SPECNAMELEN	63		/* max length of devicename */


//#define	FALSE	0
//#define	TRUE	1

/*
 * Round p (pointer or byte index) up to a correctly-aligned value
 * for all data types (int, long, ...).   The result is unsigned int
 * and must be cast to any desired pointer type.
 */
#ifndef _ALIGNBYTES
#define _ALIGNBYTES	(sizeof(int) - 1)
#endif
#ifndef _ALIGN
#define _ALIGN(p)	(((unsigned)(p) + _ALIGNBYTES) & ~_ALIGNBYTES)
#endif
/* Machine type dependent parameters. */
#ifndef MACHINE
#define MACHINE		"i386"
#endif
#ifndef MACHINE_ARCH
#define	MACHINE_ARCH	"i386"
#endif
#define MID_MACHINE	MID_I386

#ifdef SMP
#define MAXCPU		16
#else
#define MAXCPU		1
#endif /* SMP */

#define ALIGNBYTES	_ALIGNBYTES
#define ALIGN(p)	_ALIGN(p)


typedef __uint32_t pd_entry_t;

typedef __uint32_t pt_entry_t;

#define	PTESHIFT	(2)
#define	PDESHIFT	(2)


#define PAGE_SHIFT	12		/* LOG2(PAGE_SIZE) */
#define PAGE_SIZE	(1<<PAGE_SHIFT)	/* bytes/page */
#define PAGE_MASK	(PAGE_SIZE-1)
#define NPTEPG		(PAGE_SIZE/(sizeof (pt_entry_t)))

#ifdef PAE
#define NPGPTD		4
#define PDRSHIFT	21		/* LOG2(NBPDR) */
#else
#define NPGPTD		1
#define PDRSHIFT	22		/* LOG2(NBPDR) */
#endif

#define NBPTD		(NPGPTD<<PAGE_SHIFT)
#define NPDEPTD		(NBPTD/(sizeof (pd_entry_t)))
#define NPDEPG		(PAGE_SIZE/(sizeof (pd_entry_t)))
#define NBPDR		(1<<PDRSHIFT)	/* bytes/page dir */
#define PDRMASK		(NBPDR-1)

#define IOPAGES	2		/* pages of i/o permission bitmap */

#ifndef KSTACK_PAGES
#define KSTACK_PAGES 2		/* Includes pcb! */
#endif
#define KSTACK_GUARD_PAGES 1	/* pages of kstack guard; 0 disables */
#define UAREA_PAGES 1		/* holds struct user WITHOUT PCB (see def.) */

/*
 * Ceiling on amount of swblock kva space, can be changed via
 * the kern.maxswzone /boot/loader.conf variable.
 */
#ifndef VM_SWZONE_SIZE_MAX
#define VM_SWZONE_SIZE_MAX	(32 * 1024 * 1024)
#endif

/*
 * Ceiling on size of buffer cache (really only effects write queueing,
 * the VM page cache is not effected), can be changed via
 * the kern.maxbcache /boot/loader.conf variable.
 */
#ifndef VM_BCACHE_SIZE_MAX
#define VM_BCACHE_SIZE_MAX	(200 * 1024 * 1024)
#endif

/*
 * Mach derived conversion macros
 */
#define trunc_page(x)		((x) & ~PAGE_MASK)
#define round_page(x)		(((x) + PAGE_MASK) & ~PAGE_MASK)
#define trunc_4mpage(x)		((x) & ~PDRMASK)
#define round_4mpage(x)		((((x)) + PDRMASK) & ~PDRMASK)

#define atop(x)			((x) >> PAGE_SHIFT)
#define ptoa(x)			((x) << PAGE_SHIFT)

#define i386_btop(x)		((x) >> PAGE_SHIFT)
#define i386_ptob(x)		((x) << PAGE_SHIFT)

#define	pgtok(x)		((x) * (PAGE_SIZE / 1024))
#ifndef _KERNEL
#include <limits.h>
#endif

#ifndef _NO_NAMESPACE_POLLUTION

#ifndef DEV_BSHIFT
#define	DEV_BSHIFT	9		/* log2(DEV_BSIZE) */
#endif
#define	DEV_BSIZE	(1<<DEV_BSHIFT)

#ifndef BLKDEV_IOSIZE
#define BLKDEV_IOSIZE  PAGE_SIZE	/* default block device I/O size */
#endif
#ifndef DFLTPHYS
#define DFLTPHYS	(64 * 1024)	/* default max raw I/O transfer size */
#endif
#ifndef MAXPHYS
#define MAXPHYS		(128 * 1024)	/* max raw I/O transfer size */
#endif
#ifndef MAXDUMPPGS
#define MAXDUMPPGS	(DFLTPHYS/PAGE_SIZE)
#endif

/*
 * Constants related to network buffer management.
 * MCLBYTES must be no larger than PAGE_SIZE.
 */
#ifndef	MSIZE
#define MSIZE		256		/* size of an mbuf */
#endif	/* MSIZE */

#ifndef	MCLSHIFT
#define MCLSHIFT	11		/* convert bytes to mbuf clusters */
#endif	/* MCLSHIFT */

#define MCLBYTES	(1 << MCLSHIFT)	/* size of an mbuf cluster */

#define	MJUMPAGESIZE	PAGE_SIZE	/* jumbo cluster 4k */
#define	MJUM9BYTES	(9 * 1024)	/* jumbo cluster 9k */
#define	MJUM16BYTES	(16 * 1024)	/* jumbo cluster 16k */

/*
 * Some macros for units conversion
 */

/* clicks to bytes */
#ifndef ctob
#define ctob(x)	((x)<<PAGE_SHIFT)
#endif

/* bytes to clicks */
#ifndef btoc
#define btoc(x)	(((vm_offset_t)(x)+PAGE_MASK)>>PAGE_SHIFT)
#endif

/*
 * btodb() is messy and perhaps slow because `bytes' may be an off_t.  We
 * want to shift an unsigned type to avoid sign extension and we don't
 * want to widen `bytes' unnecessarily.  Assume that the result fits in
 * a daddr_t.
 */
#ifndef btodb
#define btodb(bytes)	 		/* calculates (bytes / DEV_BSIZE) */ \
	(sizeof (bytes) > sizeof(long) \
	 ? (daddr_t)((unsigned long long)(bytes) >> DEV_BSHIFT) \
	 : (daddr_t)((unsigned long)(bytes) >> DEV_BSHIFT))
#endif

#ifndef dbtob
#define dbtob(db)			/* calculates (db * DEV_BSIZE) */ \
	((off_t)(db) << DEV_BSHIFT)
#endif

#endif /* _NO_NAMESPACE_POLLUTION */

#define	PRIMASK	0x0ff
#define	PCATCH	0x100		/* OR'd with pri for tsleep to check signals */
#define	PDROP	0x200	/* OR'd with pri to stop re-entry of interlock mutex */

#define	NZERO	0		/* default "nice" */

#define	NBBY	8		/* number of bits in a byte */
#define	NBPW	sizeof(int)	/* number of bytes per word (integer) */

#define	CMASK	022		/* default file mask: S_IWGRP|S_IWOTH */

#define	NODEV	(dev_t)(-1)	/* non-existent device */

#define	CBLOCK	128		/* Clist block size, must be a power of 2. */
#define CBQSIZE	(CBLOCK/NBBY)	/* Quote bytes/cblock - can do better. */
				/* Data chars/clist. */
#define	CBSIZE	(CBLOCK - sizeof(struct cblock *) - CBQSIZE)
#define	CROUND	(CBLOCK - 1)	/* Clist rounding. */

/*
 * File system parameters and macros.
 *
 * MAXBSIZE -	Filesystems are made out of blocks of at most MAXBSIZE bytes
 *		per block.  MAXBSIZE may be made larger without effecting
 *		any existing filesystems as long as it does not exceed MAXPHYS,
 *		and may be made smaller at the risk of not being able to use
 *		filesystems which require a block size exceeding MAXBSIZE.
 *
 * BKVASIZE -	Nominal buffer space per buffer, in bytes.  BKVASIZE is the
 *		minimum KVM memory reservation the kernel is willing to make.
 *		Filesystems can of course request smaller chunks.  Actual 
 *		backing memory uses a chunk size of a page (PAGE_SIZE).
 *
 *		If you make BKVASIZE too small you risk seriously fragmenting
 *		the buffer KVM map which may slow things down a bit.  If you
 *		make it too big the kernel will not be able to optimally use 
 *		the KVM memory reserved for the buffer cache and will wind 
 *		up with too-few buffers.
 *
 *		The default is 16384, roughly 2x the block size used by a
 *		normal UFS filesystem.
 */
#define MAXBSIZE	65536	/* must be power of 2 */
#define BKVASIZE	16384	/* must be power of 2 */
#define BKVAMASK	(BKVASIZE-1)

/*
 * MAXPATHLEN defines the longest permissible path length after expanding
 * symbolic links. It is used to allocate a temporary buffer from the buffer
 * pool in which to do the name expansion, hence should be a power of two,
 * and must be less than or equal to MAXBSIZE.  MAXSYMLINKS defines the
 * maximum number of symbolic links that may be expanded in a path name.
 * It should be set high enough to allow all legitimate uses, but halt
 * infinite loops reasonably quickly.
 */
#define	MAXPATHLEN	PATH_MAX
#define MAXSYMLINKS	32

/* Bit map related macros. */
#define	setbit(a,i)	((a)[(i)/NBBY] |= 1<<((i)%NBBY))
#define	clrbit(a,i)	((a)[(i)/NBBY] &= ~(1<<((i)%NBBY)))
#define	isset(a,i)	((a)[(i)/NBBY] & (1<<((i)%NBBY)))
#define	isclr(a,i)	(((a)[(i)/NBBY] & (1<<((i)%NBBY))) == 0)

/* Macros for counting and rounding. */
#ifndef howmany
#define	howmany(x, y)	(((x)+((y)-1))/(y))
#endif
#define	rounddown(x, y)	(((x)/(y))*(y))
#define	roundup(x, y)	((((x)+((y)-1))/(y))*(y))  /* to any y */
#define	roundup2(x, y)	(((x)+((y)-1))&(~((y)-1))) /* if y is powers of two */
#define powerof2(x)	((((x)-1)&(x))==0)

/* Macros for min/max. */
#define	MIN(a,b) (((a)<(b))?(a):(b))
#define	MAX(a,b) (((a)>(b))?(a):(b))

#ifdef _KERNEL
/*
 * Basic byte order function prototypes for non-inline functions.
 */
#ifndef _BYTEORDER_PROTOTYPED
#define	_BYTEORDER_PROTOTYPED
__BEGIN_DECLS
__uint32_t	 htonl(__uint32_t);
__uint16_t	 htons(__uint16_t);
__uint32_t	 ntohl(__uint32_t);
__uint16_t	 ntohs(__uint16_t);
__END_DECLS
#endif

#ifndef lint
#ifndef _BYTEORDER_FUNC_DEFINED
#define	_BYTEORDER_FUNC_DEFINED
#define	htonl(x)	__htonl(x)
#define	htons(x)	__htons(x)
#define	ntohl(x)	__ntohl(x)
#define	ntohs(x)	__ntohs(x)
#endif /* !_BYTEORDER_FUNC_DEFINED */
#endif /* lint */
#endif /* _KERNEL */

/*
 * Constants for setting the parameters of the kernel memory allocator.
 *
 * 2 ** MINBUCKET is the smallest unit of memory that will be
 * allocated. It must be at least large enough to hold a pointer.
 *
 * Units of memory less or equal to MAXALLOCSAVE will permanently
 * allocate physical memory; requests for these size pieces of
 * memory are quite fast. Allocations greater than MAXALLOCSAVE must
 * always allocate and free physical memory; requests for these
 * size allocations should be done infrequently as they will be slow.
 *
 * Constraints: PAGE_SIZE <= MAXALLOCSAVE <= 2 ** (MINBUCKET + 14), and
 * MAXALLOCSIZE must be a power of two.
 */
#if defined(__alpha__) || defined(__ia64__) || defined(__sparc64__)
#define MINBUCKET	5		/* 5 => min allocation of 32 bytes */
#else
#define MINBUCKET	4		/* 4 => min allocation of 16 bytes */
#endif
#define MAXALLOCSAVE	(2 * PAGE_SIZE)

/*
 * Scale factor for scaled integers used to count %cpu time and load avgs.
 *
 * The number of CPU `tick's that map to a unique `%age' can be expressed
 * by the formula (1 / (2 ^ (FSHIFT - 11))).  The maximum load average that
 * can be calculated (assuming 32 bits) can be closely approximated using
 * the formula (2 ^ (2 * (16 - FSHIFT))) for (FSHIFT < 15).
 *
 * For the scheduler to maintain a 1:1 mapping of CPU `tick' to `%age',
 * FSHIFT must be at least 11; this gives us a maximum load avg of ~1024.
 */
#define	FSHIFT	11		/* bits to right of fixed binary point */
#define FSCALE	(1<<FSHIFT)

#define dbtoc(db)			/* calculates devblks to pages */ \
	((db + (ctodb(1) - 1)) >> (PAGE_SHIFT - DEV_BSHIFT))
 
#define ctodb(db)			/* calculates pages to devblks */ \
	((db) << (PAGE_SHIFT - DEV_BSHIFT))

#ifndef HZ
#ifdef __amd64__
#define	HZ 1024
#else
#define	HZ 100
#endif
#endif
#define	NPROC (20 + 16 * maxusers)
#ifndef NBUF
#define NBUF 0
#endif
#ifndef MAXFILES
#define	MAXFILES (maxproc * 2)
#endif

int	hz;
int	tick;
int	maxusers;			/* base tunable */
int	maxproc;			/* maximum # of processes */
int	maxprocperuid;			/* max # of procs per user */
int	maxfiles;			/* sys. wide open files limit */
int	maxfilesperproc;		/* per-proc open files limit */
int	ncallout;			/* maximum # of timer events */
int	nbuf;
int	nswbuf;
int	maxswzone;			/* max swmeta KVA storage */
int	maxbcache;			/* max buffer cache KVA storage */
int	maxpipekva;			/* Limit on pipe KVA */
u_quad_t	maxtsiz;			/* max text size */
u_quad_t	dfldsiz;			/* initial data size limit */
u_quad_t	maxdsiz;			/* max data size */
u_quad_t	dflssiz;			/* initial stack size limit */
u_quad_t	maxssiz;			/* max stack size */
u_quad_t	sgrowsiz;			/* amount to grow stack */


//copy from vmparam.h
/*
 * Machine dependent constants for 386.
 */

#define VM_PROT_READ_IS_EXEC	/* if you can read -- then you can exec */

/*
 * Virtual memory related constants, all in bytes
 */
#define	MAXTSIZ		(128UL*1024*1024)	/* max text size */
#ifndef DFLDSIZ
#define	DFLDSIZ		(128UL*1024*1024)	/* initial data size limit */
#endif
#ifndef MAXDSIZ
#define	MAXDSIZ		(512UL*1024*1024)	/* max data size */
#endif
#ifndef	DFLSSIZ
#define	DFLSSIZ		(8UL*1024*1024)		/* initial stack size limit */
#endif
#ifndef	MAXSSIZ
#define	MAXSSIZ		(64UL*1024*1024)	/* max stack size */
#endif
#ifndef SGROWSIZ
#define SGROWSIZ	(128UL*1024)		/* amount to grow stack */
#endif

#define USRTEXT		(1*PAGE_SIZE)		/* base of user text XXX bogus */

/*
 * The time for a process to be blocked before being very swappable.
 * This is a number of seconds which the system takes as being a non-trivial
 * amount of real time.  You probably shouldn't change this;
 * it is used in subtle ways (fractions and multiples of it are, that is, like
 * half of a ``long time'', almost a long time, etc.)
 * It is related to human patience and other factors which don't really
 * change over time.
 */
#define	MAXSLP 		20


/*
 * Kernel physical load address.
 */
#ifndef KERNLOAD
#define	KERNLOAD		(1 << PDRSHIFT)
#endif

/*
 * Virtual addresses of things.  Derived from the page directory and
 * page table indexes from pmap.h for precision.
 * Because of the page that is both a PD and PT, it looks a little
 * messy at times, but hey, we'll do anything to save a page :-)
 */

#define VM_MAX_KERNEL_ADDRESS	VADDR(KPTDI+NKPDE-1, NPTEPG-1)
#define VM_MIN_KERNEL_ADDRESS	VADDR(PTDPTDI, PTDPTDI)

#define	KERNBASE		VADDR(KPTDI, 0)

#define UPT_MAX_ADDRESS		VADDR(PTDPTDI, PTDPTDI)
#define UPT_MIN_ADDRESS		VADDR(PTDPTDI, 0)

#define VM_MAXUSER_ADDRESS	VADDR(PTDPTDI, 0)

#define USRSTACK		VM_MAXUSER_ADDRESS

#define VM_MAX_ADDRESS		VADDR(PTDPTDI, PTDPTDI)
#define VM_MIN_ADDRESS		((vm_offset_t)0)

/* virtual sizes (bytes) for various kernel submaps */
#ifndef VM_KMEM_SIZE
#define VM_KMEM_SIZE		(12 * 1024 * 1024)
#endif

/*
 * How many physical pages per KVA page allocated.
 * min(max(VM_KMEM_SIZE, Physical memory/VM_KMEM_SIZE_SCALE), VM_KMEM_SIZE_MAX)
 * is the total KVA space allocated for kmem_map.
 */
#ifndef VM_KMEM_SIZE_SCALE
#define	VM_KMEM_SIZE_SCALE	(3)
#endif

/*
 * Ceiling on amount of kmem_map kva space.
 */
#ifndef VM_KMEM_SIZE_MAX
#define	VM_KMEM_SIZE_MAX	(320 * 1024 * 1024)
#endif

/* initial pagein size of beginning of executable file */
#ifndef VM_INITIAL_PAGEIN
#define	VM_INITIAL_PAGEIN	16
#endif



#define MAXUSERS 2



#endif	/* _SYS_PARAM_H_ */
