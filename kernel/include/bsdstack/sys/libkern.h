/*-
 * Copyright (c) 1992, 1993
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
 *	@(#)libkern.h	8.1 (Berkeley) 6/10/93
 *           src/sys/sys/libkern.h,v 1.46 2004/07/15 23:58:23 glebius Exp $
 */

#ifndef _SYS_LIBKERN_H_
#define	_SYS_LIBKERN_H_

#include <sys.h>
#include <kin.h>

/* BCD conversions. */
extern u_char const	bcd2bin_data[];
extern u_char const	bin2bcd_data[];
extern char const	hex2ascii_data[];
uint32_t arc4random(void);
void	 arc4rand(void *ptr, u_int len, int reseed);

#define	bcd2bin(bcd)	(bcd2bin_data[bcd])
#define	bin2bcd(bin)	(bin2bcd_data[bin])
#define	hex2ascii(hex)	(hex2ascii_data[hex])

static __inline int imax(int a, int b) { return (a > b ? a : b); }
static __inline int imin(int a, int b) { return (a < b ? a : b); }
static __inline long lmax(long a, long b) { return (a > b ? a : b); }
static __inline long lmin(long a, long b) { return (a < b ? a : b); }
//static __inline __uint32_t max(__uint32_t a, __uint32_t b) { return (a > b ? a : b); }
//static __inline __uint32_t min(__uint32_t a, __uint32_t b) { return (a < b ? a : b); }
static __inline quad_t qmax(quad_t a, quad_t b) { return (a > b ? a : b); }
static __inline quad_t qmin(quad_t a, quad_t b) { return (a < b ? a : b); }
static __inline u_long ulmax(u_long a, u_long b) { return (a > b ? a : b); }
static __inline u_long ulmin(u_long a, u_long b) { return (a < b ? a : b); }

static __inline int abs(int a) { return (a < 0 ? -a : a); }
static __inline long labs(long a) { return (a < 0 ? -a : a); }
//static __inline quad_t qabs(quad_t a) { return (a < 0 ? -a : a); }
char	*index(const char *, int);

/* Prototypes for non-quad routines. */

int	 bcmp(const void *, const void *, size_t);



static __inline int
memcmp(const void *b1, const void *b2, size_t len)
{
	return (bcmp(b1, b2, len));
}


/* fnmatch() return values. */
#define	FNM_NOMATCH	1	/* Match failed. */

/* fnmatch() flags. */
#define	FNM_NOESCAPE	0x01	/* Disable backslash escaping. */
#define	FNM_PATHNAME	0x02	/* Slash must be matched by slash. */
#define	FNM_PERIOD	0x04	/* Period must be matched by period. */
#define	FNM_LEADING_DIR	0x08	/* Ignore /<tail> after Imatch. */
#define	FNM_CASEFOLD	0x10	/* Case insensitive search. */
#define	FNM_IGNORECASE	FNM_CASEFOLD
#define	FNM_FILE_NAME	FNM_PATHNAME

#define bsd_isspace(c)	((c) == ' ' || ((c) >= '\t' && (c) <= '\r'))
#define bsd_isascii(c)	(((c) & ~0x7f) == 0)
#define bsd_isupper(c)	((c) >= 'A' && (c) <= 'Z')
#define bsd_islower(c)	((c) >= 'a' && (c) <= 'z')
#define bsd_isalpha(c)	(bsd_isupper(c) || bsd_islower(c))
#define bsd_isdigit(c)	((c) >= '0' && (c) <= '9')
#define bsd_isxdigit(c)	(bsd_isdigit(c) \
			  || ((c) >= 'A' && (c) <= 'F') \
			  || ((c) >= 'a' && (c) <= 'f'))
#define bsd_isprint(c)	((c) >= ' ' && (c) <= '~')

#define bsd_toupper(c)	((c) - 0x20 * (((c) >= 'a') && ((c) <= 'z')))
#define bsd_tolower(c)	((c) + 0x20 * (((c) >= 'A') && ((c) <= 'Z')))

#define bsd_in_cksum(m, len)	in_cksum_skip(m, len, 0)


/*
 * priorities/facilities are encoded into a single 32-bit quantity, where the
 * bottom 3 bits are the priority (0-7) and the top 28 bits are the facility
 * (0-big number).  Both the priorities and the facilities map roughly
 * one-to-one to strings in the syslogd(8) source code.  This mapping is
 * included in this file.
 *
 * priorities (these are ordered)
 */
#define	LOG_EMERG	0	/* system is unusable */
#define	LOG_ALERT	1	/* action must be taken immediately */
#define	LOG_CRIT	2	/* critical conditions */
#define	LOG_ERR		3	/* error conditions */
#define	LOG_WARNING	4	/* warning conditions */
#define	LOG_NOTICE	5	/* normal but significant condition */
#define	LOG_INFO	6	/* informational */
#define	LOG_DEBUG	7	/* debug-level messages */

#define	LOG_PRIMASK	0x07	/* mask to extract priority part (internal) */
				/* extract priority */
#define	LOG_PRI(p)	((p) & LOG_PRIMASK)
#define	LOG_MAKEPRI(fac, pri)	((fac) | (pri))

#endif /* !_SYS_LIBKERN_H_ */
