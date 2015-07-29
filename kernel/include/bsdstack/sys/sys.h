#ifndef __SYS_H__
#define __SYS_H__
#include "stdafx.h"
#include "error.h"
#include "stdio.h"
#include "stdlib.h"
#include "string.h"
//#include "stdarg.h"
#define __BSD_VISIBLE 1

#define KASSERT
typedef unsigned long u_long;
typedef unsigned int u_int;
typedef unsigned short u_short;
typedef unsigned int intptr_t;

typedef char * caddr_t;
typedef	const char *	c_caddr_t;	/* core address, pointer to const */
typedef	volatile char *v_caddr_t;	/* core address, pointer to volatile */

typedef unsigned __int64 u_quad_t;

typedef	signed char		__int8_t;
typedef	unsigned char		__uint8_t;
typedef	short			__int16_t;
typedef	unsigned short		__uint16_t;
typedef	int			__int32_t;
typedef	unsigned int		__uint32_t;
typedef unsigned __int64 __uint64_t;
typedef	__uint32_t	__vm_paddr_t;
typedef	__vm_paddr_t	vm_paddr_t;
/*
 * Standard type definitions.
 */
typedef	__int32_t	__clockid_t;	/* clock_gettime()... */
typedef	__uint32_t	__fflags_t;	/* file flags */
typedef	__uint64_t	__fsblkcnt_t;
typedef	__uint64_t	__fsfilcnt_t;
typedef	__uint32_t	__gid_t;
typedef	__int64	__id_t;		/* can hold a gid_t, pid_t, or uid_t */
typedef	__uint32_t	__ino_t;	/* inode number */
typedef	long		__key_t;	/* IPC key (for Sys V IPC) */
typedef	__int32_t	__lwpid_t;	/* Thread ID (a.k.a. LWP) */
typedef	__uint16_t	__mode_t;	/* permissions */
typedef	int		__nl_item;
typedef	__uint16_t	__nlink_t;	/* link count */
typedef	__int64	__off_t;	/* file offset */ 
typedef	__int32_t	__pid_t;	/* process [group] */
typedef	__int64	__rlim_t;	/* resource limit (XXX not unsigned) */
typedef	__uint8_t	__sa_family_t;
typedef	__uint32_t	__socklen_t;
typedef	long		__suseconds_t;	/* microseconds (signed) */
typedef	__int32_t	__timer_t;	/* timer_gettime()... */
typedef	__uint32_t	__uid_t;
typedef	unsigned int	__useconds_t;	/* microseconds (unsigned) */
typedef __uint8_t	u_int8_t;	/* unsigned integrals (deprecated) */
typedef __uint16_t	u_int16_t;
typedef __uint32_t	u_int32_t;
typedef	__uint32_t	__size_t;		/* sizeof() */
//typedef	__uint32_t	intptr_t;
typedef	__size_t	size_t;
typedef	unsigned char	u_char;
typedef	unsigned short	u_short;
typedef	unsigned int	u_int;
typedef	unsigned long	u_long;

typedef	unsigned short	ushort;		/* Sys V compatibility */
typedef	unsigned int	uint;		/* Sys V compatibility */

typedef u_int16_t n_short;		/* short as received from the net */
typedef u_int32_t n_long;		/* long as received from the net */

typedef	u_int32_t n_time;		/* ms since 00:00 GMT, byte rev */
//typedef __int32_t time_t;
/*
 * Unusual type definitions.
 */
/*
 * rune_t is declared to be an ``int'' instead of the more natural
 * ``unsigned long'' or ``long''.  Two things are happening here.  It is not
 * unsigned so that EOF (-1) can be naturally assigned to it and used.  Also,
 * it looks like 10646 will be a 31 bit standard.  This means that if your
 * ints cannot hold 32 bits, you will be in trouble.  The reason an int was
 * chosen over a long is that the is*() and to*() routines take ints (says
 * ANSI C), but they use __ct_rune_t instead of int.
 *
 * NOTE: rune_t is not covered by ANSI nor other standards, and should not
 * be instantiated outside of lib/libc/locale.  Use wchar_t.  wchar_t and
 * rune_t must be the same type.  Also, wint_t must be no narrower than
 * wchar_t, and should be able to hold all members of the largest
 * character set plus one extra value (WEOF), and must be at least 16 bits.
 */
typedef	int		__ct_rune_t;	/* arg type for ctype funcs */
typedef	__ct_rune_t	__rune_t;	/* rune_t (see above) */

typedef	__uint32_t	__dev_t;	/* device number */

typedef	__uint32_t	__fixpt_t;	/* fixed point number */
typedef	__uint32_t	__vm_offset_t;
typedef	unsigned __int64	__vm_ooffset_t;
typedef	__uint64_t	__vm_pindex_t;
typedef	__uint32_t	__vm_size_t;

typedef	__vm_offset_t	vm_offset_t;
typedef	__vm_ooffset_t	vm_ooffset_t;
typedef	__vm_paddr_t	vm_paddr_t;
typedef	__vm_pindex_t	vm_pindex_t;
typedef	__vm_size_t	vm_size_t;
typedef	__uint64_t	u_quad_t;	/* quads (deprecated) */
typedef	__uint64_t	quad_t;
typedef	quad_t *	qaddr_t;
#ifndef _INT32_T_DECLARED
typedef	__int32_t		int32_t;
#define	_INT32_T_DECLARED
#endif

#define mtx_unlock(m)
#define mtx_lock(m)


struct ucred {
	char *buf;
};
//struct thread{
//	char *buf;
//};
struct mtx
{
	char *buf;
};
#define offsetof(t,m) (size_t)((&((t *)0L)->m))
#define	bcopy(a,b,c)	memcpy(b,a,c)
#define	bzero(a,c)	memset(a,0,c)
#define copyin(dst, src, len)  bcopy(dst, src, len)
#define copyout(dst, src, len)  bcopy(dst, src, len)
#define	tsleep(chan, pri, wmesg, timo)	msleep(chan, NULL, pri, wmesg, timo)

#define	DTYPE_VNODE	1	/* file */
#define	DTYPE_SOCKET	2	/* communications endpoint */
#define	DTYPE_PIPE	3	/* pipe */
#define	DTYPE_FIFO	4	/* fifo (named pipe) */
#define	DTYPE_KQUEUE	5	/* event queue */
#define	DTYPE_CRYPTO	6	/* crypto */


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

/* Stubs for obsolete functions that used to be for interrupt  management */
static __inline void		spl0(void)		{ return; }
static __inline int	splbio(void)		{ return 0; }
static __inline __uint32_t	splcam(void)		{ return 0; }
static __inline __uint32_t	splclock(void)		{ return 0; }
static __inline __uint32_t	splhigh(void)		{ return 0; }
static __inline __uint32_t	splimp(void)		{ return 0; }
static __inline __uint32_t	splnet(void)		{ return 0; }
static __inline __uint32_t	splsoftcam(void)	{ return 0; }
static __inline __uint32_t	splsoftclock(void)	{ return 0; }
static __inline __uint32_t	splsofttty(void)	{ return 0; }
static __inline __uint32_t	splsoftvm(void)		{ return 0; }
static __inline __uint32_t	splsofttq(void)		{ return 0; }
static __inline __uint32_t	splstatclock(void)	{ return 0; }
static __inline __uint32_t	spltty(void)		{ return 0; }
static __inline __uint32_t	splvm(void)		{ return 0; }
static __inline void		splx(__uint32_t a)	{ return; }


#ifndef _GID_T_DECLARED
typedef	__gid_t		gid_t;		/* group id */
#define	_GID_T_DECLARED
#endif

#ifndef _UID_T_DECLARED
//typedef	__uid_t		uid_t;		/* user id */
#define	_UID_T_DECLARED
#endif


#define _LITTLE_ENDIAN 1234
#define _BIG_ENDIAN    3421
#define _BYTE_ORDER _LITTLE_ENDIAN
#define LITTLE_ENDIAN 1234
#define BIG_ENDIAN    3421
#define BYTE_ORDER LITTLE_ENDIAN



#define panic _hx_printf


#define	TUNABLE_INT_FETCH(path, var)

#define		UID_ROOT	0
#define		UID_BIN		3
#define		UID_UUCP	66

#define		GID_WHEEL	0
#define		GID_KMEM	2
#define		GID_OPERATOR	5
#define		GID_BIN		7
#define		GID_GAMES	13
#define		GID_DIALER	68
#include "atomic.h"

#if _BYTE_ORDER == _LITTLE_ENDIAN
#define	htobe16(x)	bswap16((x))
#define	htobe32(x)	bswap32((x))
#define	htobe64(x)	bswap64((x))
#define	htole16(x)	((uint16_t)(x))
#define	htole32(x)	((uint32_t)(x))
#define	htole64(x)	((__uint64_t)(x))

#define	be16toh(x)	bswap16((x))
#define	be32toh(x)	bswap32((x))
#define	be64toh(x)	bswap64((x))
#define	le16toh(x)	((uint16_t)(x))
#define	le32toh(x)	((uint32_t)(x))
#define	le64toh(x)	((__uint64_t)(x))
#else /* _BYTE_ORDER != _LITTLE_ENDIAN */
#define	htobe16(x)	((uint16_t)(x))
#define	htobe32(x)	((uint32_t)(x))
#define	htobe64(x)	((__uint64_t)(x))
#define	htole16(x)	bswap16((x))
#define	htole32(x)	bswap32((x))
#define	htole64(x)	bswap64((x))

#define	be16toh(x)	((uint16_t)(x))
#define	be32toh(x)	((uint32_t)(x))
#define	be64toh(x)	((__uint64_t)(x))
#define	le16toh(x)	bswap16((x))
#define	le32toh(x)	bswap32((x))
#define	le64toh(x)	bswap64((x))
#endif /* _BYTE_ORDER == _LITTLE_ENDIAN */

#define	HASH_NOWAIT	0x00000001
#define	HASH_WAITOK	0x00000002

#define INET
int __inline min(int a, int b)
{
	return a < b ? a : b;
}
int __inline max(int a, int b)
{
	return a > b ? a : b;
}

typedef	__int64 intmax_t;
typedef	__uint64_t	uintmax_t;
typedef	__uint32_t uintptr_t;
typedef	__uint32_t	ptrdiff_t;
/*
 * Bus address and size types
 */
#ifdef PAE
typedef __uint64_t bus_addr_t;
#else
typedef __uint32_t bus_addr_t;
#endif
typedef __uint32_t bus_size_t;

/*
 * Access methods for bus resources and address space.
 */
typedef	int bus_space_tag_t;
typedef	u_int bus_space_handle_t;
/*
 * min()/max() macros that also do
 * strict type-checking.. See the
 * "unnecessary" pointer comparison.
 */
//#define min(x,y) ({ \
// typeid(x) _x = (x); \
// typeid(y) _y = (y); \
// (void) (&_x == &_y);  \
// _x < _y ? _x : _y; })
//#define max(x,y) ({ \
// typeid(x) _x = (x); \
// typeid(y) _y = (y); \
// (void) (&_x == &_y);  \
// _x > _y ? _x : _y; })
#endif
