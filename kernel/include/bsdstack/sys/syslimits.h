/*
 * Copyright (c) 1988, 1993
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
 *	@(#)syslimits.h	8.1 (Berkeley) 6/2/93
 *           src/sys/sys/syslimits.h,v 1.18 2004/04/07 04:19:49 imp Exp $
 */

#ifndef _SYS_SYSLIMITS_H_
#define _SYS_SYSLIMITS_H_

#if !defined(_KERNEL) && !defined(_LIMITS_H_) && !defined(_SYS_PARAM_H_)
#if defined(__GNUC__) || defined(__INTEL_COMPILER)
#warning "No user-serviceable parts inside."
#endif
#endif

#if 0  /* SHOULD NOT SUPPORT IN USUAL TIME */  
#define LSB_EXTENDS
#endif

/*
 * Do not add any new variables here.  (See the comment at the end of
 * the file for why.)
 */
#ifdef LSB_EXTENDS
#define	ARG_MAX		 	131072	/* max bytes for an exec function */
#else
#define	ARG_MAX			65536	/* max bytes for an exec function */
#endif
#ifndef CHILD_MAX
#define	CHILD_MAX		   40	/* max simultaneous processes */
#endif
#define	LINK_MAX		32767	/* max file link count */
#define	MAX_CANON		  255	/* max bytes in term canon input line */
#define	MAX_INPUT		  255	/* max bytes in terminal input */
#define	NAME_MAX		  255	/* max bytes in a file name */
#ifdef LSB_EXTENDS
#define	NGROUPS_MAX		   33	/* max supplemental group id's */
#else
#define	NGROUPS_MAX		   16	/* max supplemental group id's */
#endif
#ifndef OPEN_MAX
#define	OPEN_MAX		   64	/* max open files per process */
#endif
#ifdef LSB_EXTENDS
#define	PATH_MAX		 4096	/* max bytes in pathname */
#define	PIPE_BUF		 4096	/* max bytes for atomic pipe writes */
#else
#define	PATH_MAX		 1024	/* max bytes in pathname */
#define	PIPE_BUF		  512	/* max bytes for atomic pipe writes */
#endif
#define	IOV_MAX			 1024	/* max elements in i/o vector */

/*
 * We leave the following values undefined to force applications to either
 * assume conservative values or call sysconf() to get the current value.
 *
 * HOST_NAME_MAX
 *
 * (We should do this for most of the values currently defined here,
 * but many programs are not prepared to deal with this yet.)
 */
#endif
