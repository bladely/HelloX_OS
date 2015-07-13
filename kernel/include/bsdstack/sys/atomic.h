/*-
 * Copyright (c) 1998 Doug Rabson
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 *
 *           src/sys/i386/include/atomic.h,v 1.32 2004/03/12 21:45:29 trhodes Exp $
 */
#ifndef _MACHINE_ATOMIC_H_
#define _MACHINE_ATOMIC_H_

/*
 * Various simple arithmetic on memory which is atomic in the presence
 * of interrupts and multiple processors.
 *
 * atomic_set_char(P, V)	(*(u_char*)(P) |= (V))
 * atomic_clear_char(P, V)	(*(u_char*)(P) &= ~(V))
 * atomic_add_char(P, V)	(*(u_char*)(P) += (V))
 * atomic_subtract_char(P, V)	(*(u_char*)(P) -= (V))
 *
 * atomic_set_short(P, V)	(*(u_short*)(P) |= (V))
 * atomic_clear_short(P, V)	(*(u_short*)(P) &= ~(V))
 * atomic_add_short(P, V)	(*(u_short*)(P) += (V))
 * atomic_subtract_short(P, V)	(*(u_short*)(P) -= (V))
 *
 * atomic_set_int(P, V)		(*(u_int*)(P) |= (V))
 * atomic_clear_int(P, V)	(*(u_int*)(P) &= ~(V))
 * atomic_add_int(P, V)		(*(u_int*)(P) += (V))
 * atomic_subtract_int(P, V)	(*(u_int*)(P) -= (V))
 * atomic_readandclear_int(P)	(return  *(u_int*)P; *(u_int*)P = 0;)
 *
 * atomic_set_long(P, V)	(*(u_long*)(P) |= (V))
 * atomic_clear_long(P, V)	(*(u_long*)(P) &= ~(V))
 * atomic_add_long(P, V)	(*(u_long*)(P) += (V))
 * atomic_subtract_long(P, V)	(*(u_long*)(P) -= (V))
 * atomic_readandclear_long(P)	(return  *(u_long*)P; *(u_long*)P = 0;)
 */

/*
 * The above functions are expanded inline in the statically-linked
 * kernel.  Lock prefixes are generated if an SMP kernel is being
 * built.
 *
 * Kernel modules call real functions which are built into the kernel.
 * This allows kernel modules to be portable between UP and SMP systems.
 */


#undef ATOMIC_ASM
#undef ATOMIC_STORE_LOAD

#define	atomic_set_acq_char		atomic_set_char
#define	atomic_set_rel_char		atomic_set_char
#define	atomic_clear_acq_char		atomic_clear_char
#define	atomic_clear_rel_char		atomic_clear_char
#define	atomic_add_acq_char		atomic_add_char
#define	atomic_add_rel_char		atomic_add_char
#define	atomic_subtract_acq_char	atomic_subtract_char
#define	atomic_subtract_rel_char	atomic_subtract_char

#define	atomic_set_acq_short		atomic_set_short
#define	atomic_set_rel_short		atomic_set_short
#define	atomic_clear_acq_short		atomic_clear_short
#define	atomic_clear_rel_short		atomic_clear_short
#define	atomic_add_acq_short		atomic_add_short
#define	atomic_add_rel_short		atomic_add_short
#define	atomic_subtract_acq_short	atomic_subtract_short
#define	atomic_subtract_rel_short	atomic_subtract_short

#define	atomic_set_acq_int		atomic_set_int
#define	atomic_set_rel_int		atomic_set_int
#define	atomic_clear_acq_int		atomic_clear_int
#define	atomic_clear_rel_int		atomic_clear_int
#define	atomic_add_acq_int		atomic_add_int
#define	atomic_add_rel_int		atomic_add_int
#define	atomic_subtract_acq_int		atomic_subtract_int
#define	atomic_subtract_rel_int		atomic_subtract_int
#define atomic_cmpset_acq_int		atomic_cmpset_int
#define atomic_cmpset_rel_int		atomic_cmpset_int

#define	atomic_set_acq_long		atomic_set_long
#define	atomic_set_rel_long		atomic_set_long
#define	atomic_clear_acq_long		atomic_clear_long
#define	atomic_clear_rel_long		atomic_clear_long
#define	atomic_add_acq_long		atomic_add_long
#define	atomic_add_rel_long		atomic_add_long
#define	atomic_subtract_acq_long	atomic_subtract_long
#define	atomic_subtract_rel_long	atomic_subtract_long
#define	atomic_cmpset_long		atomic_cmpset_int
#define	atomic_cmpset_acq_long		atomic_cmpset_acq_int
#define	atomic_cmpset_rel_long		atomic_cmpset_rel_int

#define atomic_cmpset_acq_ptr		atomic_cmpset_ptr
#define atomic_cmpset_rel_ptr		atomic_cmpset_ptr

#define	atomic_set_8		atomic_set_char
#define	atomic_set_acq_8	atomic_set_acq_char
#define	atomic_set_rel_8	atomic_set_rel_char
#define	atomic_clear_8		atomic_clear_char
#define	atomic_clear_acq_8	atomic_clear_acq_char
#define	atomic_clear_rel_8	atomic_clear_rel_char
#define	atomic_add_8		atomic_add_char
#define	atomic_add_acq_8	atomic_add_acq_char
#define	atomic_add_rel_8	atomic_add_rel_char
#define	atomic_subtract_8	atomic_subtract_char
#define	atomic_subtract_acq_8	atomic_subtract_acq_char
#define	atomic_subtract_rel_8	atomic_subtract_rel_char
#define	atomic_load_acq_8	atomic_load_acq_char
#define	atomic_store_rel_8	atomic_store_rel_char

#define	atomic_set_16		atomic_set_short
#define	atomic_set_acq_16	atomic_set_acq_short
#define	atomic_set_rel_16	atomic_set_rel_short
#define	atomic_clear_16		atomic_clear_short
#define	atomic_clear_acq_16	atomic_clear_acq_short
#define	atomic_clear_rel_16	atomic_clear_rel_short
#define	atomic_add_16		atomic_add_short
#define	atomic_add_acq_16	atomic_add_acq_short
#define	atomic_add_rel_16	atomic_add_rel_short
#define	atomic_subtract_16	atomic_subtract_short
#define	atomic_subtract_acq_16	atomic_subtract_acq_short
#define	atomic_subtract_rel_16	atomic_subtract_rel_short
#define	atomic_load_acq_16	atomic_load_acq_short
#define	atomic_store_rel_16	atomic_store_rel_short

#define	atomic_set_32		atomic_set_int
#define	atomic_set_acq_32	atomic_set_acq_int
#define	atomic_set_rel_32	atomic_set_rel_int
#define	atomic_clear_32		atomic_clear_int
#define	atomic_clear_acq_32	atomic_clear_acq_int
#define	atomic_clear_rel_32	atomic_clear_rel_int
#define	atomic_add_32		atomic_add_int
#define	atomic_add_acq_32	atomic_add_acq_int
#define	atomic_add_rel_32	atomic_add_rel_int
#define	atomic_subtract_32	atomic_subtract_int
#define	atomic_subtract_acq_32	atomic_subtract_acq_int
#define	atomic_subtract_rel_32	atomic_subtract_rel_int
#define	atomic_load_acq_32	atomic_load_acq_int
#define	atomic_store_rel_32	atomic_store_rel_int
#define	atomic_cmpset_32	atomic_cmpset_int
#define	atomic_cmpset_acq_32	atomic_cmpset_acq_int
#define	atomic_cmpset_rel_32	atomic_cmpset_rel_int
#define	atomic_readandclear_32	atomic_readandclear_int

static __inline u_int
atomic_readandclear_int(volatile u_int *addr)
{
	u_int result;

	result = *addr;
	*addr = 0;

	return (result);
}

static __inline u_long
atomic_readandclear_long(volatile u_long *addr)
{
	u_long result;

   result = *addr;
	*addr = 0;
	return (result);
}
static __inline int
atomic_cmpset_int(volatile u_int *dst, u_int exp, u_int src)
{
	int res = exp;
	//TO DO by myself
	*dst = src;
	return (1);
}

#endif /* ! _MACHINE_ATOMIC_H_ */
