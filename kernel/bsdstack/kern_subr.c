#include "bsdsys.h"
#include "uio.h"
#include "stdio.h"
#include "libkern.h"
#include "sysproto.h"
#include "domain.h"
#include "mbuf.h"
#include "protosw.h"
#include "socket.h"
#include "socketvar.h"
#include "uma.h"
#include "kmalloc.h"
#include "ktime.h"
#include "bsdif.h"
#include "in_pcb.h"
#include "in_var.h"
#include "tcp_var.h"
#include "tcp_fsm.h"
#include "bsdip.h"
#include "kroute.h"
#include "tcp_ip.h"
#include "netisr.h"
typedef	const void	*cvp;
typedef	const unsigned char	*ustring;
typedef unsigned long	ul;
typedef const unsigned long	*culp;


int
uiomove(void *cp, int n, struct uio *uio)
{
	struct iovec *iov;
	u_int cnt;
	int error = 0;
	
	KASSERT(uio->uio_rw == UIO_READ || uio->uio_rw == UIO_WRITE,
		("uiomove: mode"));
	while (n > 0 && uio->uio_resid) {
		iov = uio->uio_iov;
		cnt = iov->iov_len;
		if (cnt == 0) {
			uio->uio_iov++;
			uio->uio_iovcnt--;
			continue;
		}
		if (cnt > n)
			cnt = n;
		
		switch (uio->uio_segflg) {
			
		case UIO_USERSPACE:
			//if (ticks - PCPU_GET(switchticks) >= hogticks)
			//	uio_yield();
			if (uio->uio_rw == UIO_READ)
				error = copyout(cp, iov->iov_base, cnt);
			else
				error = copyin(iov->iov_base, cp, cnt);
			if (error)
				goto out;
			break;
			
		case UIO_SYSSPACE:
			if (uio->uio_rw == UIO_READ)
				bcopy(cp, iov->iov_base, cnt);
			else
				bcopy(iov->iov_base, cp, cnt);
			break;
		case UIO_NOCOPY:
			break;
		}
		iov->iov_base = (char *)iov->iov_base + cnt;
		iov->iov_len -= cnt;
		uio->uio_resid -= cnt;
		uio->uio_offset += cnt;
		cp = (char *)cp + cnt;
		n -= cnt;
	}
out:
	return (error);
}

int
copyiniov(struct iovec *iovp, u_int iovcnt, struct iovec **iov, int error)
{
	u_int iovlen;
	
	*iov = NULL;
	if (iovcnt > UIO_MAXIOV)
		return (error);
	iovlen = iovcnt * sizeof (struct iovec);
	*iov = malloc(iovlen);
	error = copyin(iovp, *iov, iovlen);
	//if (error) {LUOYU 
	//	free(*iov);
	//	*iov = NULL;
	//}
	return (0);
}

char *
index(p, ch)
const char *p;
int ch;
{
	union {
		const char *cp;
		char *p;
	} u;
	
	u.cp = p;
	for (;; ++u.p) {
		if (*u.p == ch)
			return(u.p);
		if (*u.p == '\0')
			return(NULL);
	}
	/* NOTREACHED */
}

/*
* bcmp -- vax cmpc3 instruction
*/
int
bcmp(b1, b2, length)
const void *b1, *b2;
register size_t length;
{
#if BYTE_ORDER == LITTLE_ENDIAN
/*
* The following code is endian specific.  Changing it from
* little-endian to big-endian is fairly trivial, but making
* it do both is more difficult.
*
* Note that this code will reference the entire longword which
* includes the final byte to compare.  I don't believe this is
* a problem since AFAIK, objects are not protected at smaller
* than longword boundaries.
	*/
	int	shl, shr, len = length;
	ustring	p1 = b1, p2 = b2;
	ul	va, vb;
	
	if (len == 0)
		return (0);
	
		/*
		* align p1 to a longword boundary
	*/
	while ((long)p1 & (sizeof(long) - 1)) {
		if (*p1++ != *p2++)
			return (1);
		if (--len <= 0)
			return (0);
	}
	
	/*
	* align p2 to longword boundary and calculate the shift required to
	* align p1 and p2
	*/
	shr = (long)p2 & (sizeof(long) - 1);
	if (shr != 0) {
		p2 -= shr;			/* p2 now longword aligned */
		shr <<= 3;			/* offset in bits */
		shl = (sizeof(long) << 3) - shr;
		
		va = *(culp)p2;
		p2 += sizeof(long);
		
		while ((len -= sizeof(long)) >= 0) {
			vb = *(culp)p2;
			p2 += sizeof(long);
			if (*(culp)p1 != (va >> shr | vb << shl))
				return (1);
			p1 += sizeof(long);
			va = vb;
		}
		/*
		* At this point, len is between -sizeof(long) and -1,
		* representing 0 .. sizeof(long)-1 bytes remaining.
		*/
		if (!(len += sizeof(long)))
			return (0);
		
		len <<= 3;		/* remaining length in bits */
						/*
						* The following is similar to the `if' condition
						* inside the above while loop.  The ?: is necessary
						* to avoid accessing the longword after the longword
						* containing the last byte to be compared.
		*/
		return ((((va >> shr | ((shl < len) ? *(culp)p2 << shl : 0)) ^
			*(culp)p1) & ((1L << len) - 1)) != 0);
	} else {
		/* p1 and p2 have common alignment so no shifting needed */
		while ((len -= sizeof(long)) >= 0) {
			if (*(culp)p1 != *(culp)p2)
				return (1);
			p1 += sizeof(long);
			p2 += sizeof(long);
		}
		
		/*
		* At this point, len is between -sizeof(long) and -1,
		* representing 0 .. sizeof(long)-1 bytes remaining.
		*/
		if (!(len += sizeof(long)))
			return (0);
		
		return (((*(culp)p1 ^ *(culp)p2)
			& ((1L << (len << 3)) - 1)) != 0);
	}
#else
	const char *p1, *p2;
	
	if (length == 0)
		return(0);
	p1 = b1;
	p2 = b2;
	do
	if (*p1++ != *p2++)
		break;
	while (--length);
	return(length);
#endif
}

/*
* Checksum routine for Internet Protocol family headers.
*
* This routine is very heavily used in the network
* code and should be modified for each CPU to be as fast as possible.
*
* This implementation is 386 version.
*/

#undef	ADDCARRY
#define ADDCARRY(x)     if ((x) > 0xffff) (x) -= 0xffff
#if !defined(__GNUC__) || defined(__INTEL_COMPILER)
/* non gcc parts stolen from sys/alpha/alpha/in_cksum.c */
#define REDUCE32							  \
    {									  \
	q_util.q = sum;							  \
	sum = q_util.s[0] + q_util.s[1] + q_util.s[2] + q_util.s[3];	  \
}
#define REDUCE16							  \
    {									  \
	q_util.q = sum;							  \
	l_util.l = q_util.s[0] + q_util.s[1] + q_util.s[2] + q_util.s[3]; \
	sum = l_util.s[0] + l_util.s[1];				  \
	ADDCARRY(sum);							  \
}
#endif
#define REDUCE          {sum = (sum & 0xffff) + (sum >> 16); ADDCARRY(sum);}

static const u_int32_t in_masks[] = {
	/*0 bytes*/ /*1 byte*/	/*2 bytes*/ /*3 bytes*/
	0x00000000, 0x000000FF, 0x0000FFFF, 0x00FFFFFF,	/* offset 0 */
		0x00000000, 0x0000FF00, 0x00FFFF00, 0xFFFFFF00,	/* offset 1 */
		0x00000000, 0x00FF0000, 0xFFFF0000, 0xFFFF0000,	/* offset 2 */
		0x00000000, 0xFF000000, 0xFF000000, 0xFF000000,	/* offset 3 */
};

union l_util {
	u_int16_t s[2];
	u_int32_t l;
};
union q_util {
	u_int16_t s[4];
	u_int32_t l[2];
	__uint64_t q;
};

static __uint64_t
in_cksumdata(const u_int32_t *lw, int len)
{
	__uint64_t sum = 0;
	__uint64_t prefilled;
	int offset;
	union q_util q_util;
	
	if ((3 & (long) lw) == 0 && len == 20) {
		sum = (__uint64_t) lw[0] + lw[1] + lw[2] + lw[3] + lw[4];
		REDUCE32;
		return sum;
	}
	
	if ((offset = 3 & (long) lw) != 0) {
		const u_int32_t *masks = in_masks + (offset << 2);
		lw = (u_int32_t *) (((long) lw) - offset);
		sum = *lw++ & masks[len >= 3 ? 3 : len];
		len -= 4 - offset;
		if (len <= 0) {
			REDUCE32;
			return sum;
		}
	}
	/*
	* access prefilling to start load of next cache line.
	* then add current cache line
	* save result of prefilling for loop iteration.
	*/
	prefilled = lw[0];
	while ((len -= 32) >= 4) {
		__uint64_t prefilling = lw[8];
		sum += prefilled + lw[1] + lw[2] + lw[3]
			+ lw[4] + lw[5] + lw[6] + lw[7];
		lw += 8;
		prefilled = prefilling;
	}
	if (len >= 0) {
		sum += prefilled + lw[1] + lw[2] + lw[3]
			+ lw[4] + lw[5] + lw[6] + lw[7];
		lw += 8;
	} else {
		len += 32;
	}
	while ((len -= 16) >= 0) {
		sum += (__uint64_t) lw[0] + lw[1] + lw[2] + lw[3];
		lw += 4;
	}
	len += 16;
	while ((len -= 4) >= 0) {
		sum += (__uint64_t) *lw++;
	}
	len += 4;
	if (len > 0)
		sum += (__uint64_t) (in_masks[len] & *lw);
	REDUCE32;
	return sum;
}

u_short
in_addword(u_short a, u_short b)
{
	__uint64_t sum = a + b;
	
	ADDCARRY(sum);
	return (sum);
}

u_short
in_pseudo(u_int32_t a, u_int32_t b, u_int32_t c)
{
	__uint64_t sum;
	union q_util q_util;
	union l_util l_util;
	
	sum = (__uint64_t) a + b + c;
	REDUCE16;
	return (sum);
}

u_short
in_cksum_skip(struct mbuf *m, int len, int skip)
{
	__uint64_t sum = 0;
	int mlen = 0;
	int clen = 0;
	caddr_t addr;
	union q_util q_util;
	union l_util l_util;
	
	len -= skip;
	for (; skip && m; m = m->m_next) {
		if (m->m_len > skip) {
			mlen = m->m_len - skip;
			addr = mtod(m, caddr_t) + skip;
			goto skip_start;
		} else {
			skip -= m->m_len;
		}
	}
	
	for (; m && len; m = m->m_next) {
		if (m->m_len == 0)
			continue;
		mlen = m->m_len;
		addr = mtod(m, caddr_t);
skip_start:
		if (len < mlen)
			mlen = len;
		if ((clen ^ (long) addr) & 1)
			sum += in_cksumdata((const u_int32_t *)addr, mlen) << 8;
		else
			sum += in_cksumdata((const u_int32_t *)addr, mlen);
		
		clen += mlen;
		len -= mlen;
	}
	REDUCE16;
	return (~sum & 0xffff);
}

u_int in_cksum_hdr(const struct ip *ip)
{
    __uint64_t sum = in_cksumdata((const u_int32_t *)ip, sizeof(struct ip));
    union q_util q_util;
    union l_util l_util;
	
    REDUCE16;
    return (~sum & 0xffff);
}

/*
* General routine to allocate a hash table.
*/
void *
hashinit(int elements, struct malloc_type *type, u_long *hashmask)
{
	long hashsize;
	LIST_HEAD(generic, generic) *hashtbl;
	int i;
	
	//if (elements <= 0)
	//	panic("hashinit: bad elements");
	for (hashsize = 1; hashsize <= elements; hashsize <<= 1)
		continue;
	hashsize >>= 1;
	hashtbl = malloc((u_long)hashsize * sizeof(*hashtbl));
	for (i = 0; i < hashsize; i++)
		LIST_INIT(&hashtbl[i]);
	*hashmask = hashsize - 1;
	return (hashtbl);
}

int
copyinstrfrom(const void *  src, void *  dst, size_t len,
			  size_t *  copied, int seg)
{
	int error = 0;
	
	switch (seg) {
	case UIO_USERSPACE:
		//error = copyinstr(src, dst, len, copied);LUOYU
		break;
	case UIO_SYSSPACE:
		//error = copystr(src, dst, len, copied);
		break;
	default:
		//panic("copyinstrfrom: bad seg %d\n", seg);
		break;
	}
	return (error);
}
int
copyinstr(const void *  src, void *  dst, size_t len,
		  size_t *  copied)
{
	int error = 0;
	
	//TO DO memcpy
	return (error);
}

/*
 * General routine to allocate a hash table with control of memory flags.
 */
void *
hashinit_flags(int elements, /*struct malloc_type *type, */u_long *hashmask,
    int flags)
{
	long hashsize;
	LIST_HEAD(generic, generic) *hashtbl;
	int i;

	if (elements <= 0)
		panic("hashinit: bad elements");

	/* Exactly one of HASH_WAITOK and HASH_NOWAIT must be set. */
	KASSERT((flags & HASH_WAITOK) ^ (flags & HASH_NOWAIT),
	    ("Bad flags (0x%x) passed to hashinit_flags", flags));

	for (hashsize = 1; hashsize <= elements; hashsize <<= 1)
		continue;
	hashsize >>= 1;

	if (flags & HASH_NOWAIT)
		hashtbl = malloc((u_long)hashsize * sizeof(*hashtbl));
	else
		hashtbl = malloc((u_long)hashsize * sizeof(*hashtbl));

	if (hashtbl != NULL) {
		for (i = 0; i < hashsize; i++)
			LIST_INIT(&hashtbl[i]);
		*hashmask = hashsize - 1;
	}
	return (hashtbl);
}

void
hashdestroy(void *vhashtbl, /*struct malloc_type *type,*/ u_long hashmask)
{
	LIST_HEAD(generic, generic) *hashtbl, *hp;

	hashtbl = vhashtbl;
	for (hp = hashtbl; hp <= &hashtbl[hashmask]; hp++)
		if (!LIST_EMPTY(hp))
			panic("hashdestroy: hash not empty");
	free(hashtbl);
}

