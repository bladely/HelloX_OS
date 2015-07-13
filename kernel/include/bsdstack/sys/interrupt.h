/*
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice unmodified, this list of conditions, and the following
 *    disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR ``AS IS'' AND ANY EXPRESS OR
 * IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES
 * OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED.
 * IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY DIRECT, INDIRECT,
 * INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT
 * NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF
 * THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 *
 *           src/sys/sys/interrupt.h,v 1.28 2004/07/02 20:21:43 jhb Exp $
 */

#ifndef _SYS_INTERRUPT_H_
#define _SYS_INTERRUPT_H_

#include <sys.h>
#include <param.h>
/**
 * @brief Interrupt type bits.
 * 
 * These flags are used both by newbus interrupt
 * registration (nexus.c) and also in struct intrec, which defines
 * interrupt properties.
 *
 * XXX We should probably revisit this and remove the vestiges of the
 * spls implicit in names like INTR_TYPE_TTY. In the meantime, don't
 * confuse things by renaming them (Grog, 18 July 2000).
 *
 * We define this in terms of bits because some devices may belong
 * to multiple classes (and therefore need to be included in
 * multiple interrupt masks, which is what this really serves to
 * indicate. Buses which do interrupt remapping will want to
 * change their type to reflect what sort of devices are underneath.
 */
enum intr_type {
	INTR_TYPE_TTY = 1,
	INTR_TYPE_BIO = 2,
	INTR_TYPE_NET = 4,
	INTR_TYPE_CAM = 8,
	INTR_TYPE_MISC = 16,
	INTR_TYPE_CLK = 32,
	INTR_TYPE_AV = 64,
	INTR_FAST = 128,
	INTR_EXCL = 256,		/* exclusive interrupt */
	INTR_MPSAFE = 512,		/* this interrupt is SMP safe */
	INTR_ENTROPY = 1024		/* this interrupt provides entropy */
};

enum intr_trigger {
	INTR_TRIGGER_CONFORM = 0,
	INTR_TRIGGER_EDGE = 1,
	INTR_TRIGGER_LEVEL = 2
};

enum intr_polarity {
	INTR_POLARITY_CONFORM = 0,
	INTR_POLARITY_HIGH = 1,
	INTR_POLARITY_LOW = 2
};

/*
 * Describe a hardware interrupt handler.
 *
 * Multiple interrupt handlers for a specific vector can be chained
 * together.
 */
struct intrhand {
	//driver_intr_t	*ih_handler;	/* Handler function. */
	void		*ih_argument;	/* Argument to pass to handler. */
	int		 ih_flags;
	const char	*ih_name;	/* Name of handler. */
	struct ithd	*ih_ithread;	/* Ithread we are connected to. */
	int		 ih_need;	/* Needs service. */
	//TAILQ_ENTRY(intrhand) ih_next;	/* Next handler for this vector. */
	struct {							
		struct intrhand *tqe_next;	/* next element */			
		struct intrhand **tqe_prev;	/* address of previous next element */
	}ih_next;

	u_char		 ih_pri;	/* Priority of this handler. */
};

/* Interrupt handle flags kept in ih_flags */
#define	IH_FAST		0x00000001	/* Fast interrupt. */
#define	IH_EXCLUSIVE	0x00000002	/* Exclusive interrupt. */
#define	IH_ENTROPY	0x00000004	/* Device is a good entropy source. */
#define	IH_DEAD		0x00000008	/* Handler should be removed. */
#define	IH_MPSAFE	0x80000000	/* Handler does not need Giant. */

typedef	__uint32_t		uintptr_t;

/*
 * Describe an interrupt thread.  There is one of these per interrupt vector.
 * Note that this actually describes an interrupt source.  There may or may
 * not be an actual kernel thread attached to a given source.
 */
struct ithd {
	struct	mtx it_lock;
	struct	thread *it_td;		/* Interrupt process. */
	//LIST_ENTRY(ithd) it_list;	/* All interrupt threads. */
	struct {								\
		struct ithd *le_next;	/* next element */			\
		struct ithd **le_prev;	/* address of previous next element */	\
	}it_list;
	//TAILQ_HEAD(, intrhand) it_handlers; /* Interrupt handlers. */
	struct	ithd *it_interrupted;	/* Who we interrupted. */
	void	(*it_disable)(uintptr_t); /* Enable interrupt source. */
	void	(*it_enable)(uintptr_t); /* Disable interrupt source. */
	void	*it_md;			/* Hook for MD interrupt code. */
	int	it_flags;		/* Interrupt-specific flags. */
	int	it_need;		/* Needs service. */
	uintptr_t it_vector;
	char	it_name[MAXCOMLEN + 1];
};

/* Interrupt thread flags kept in it_flags */
#define	IT_SOFT		0x000001	/* Software interrupt. */
#define	IT_ENTROPY	0x000002	/* Interrupt is an entropy source. */
#define	IT_DEAD		0x000004	/* Thread is waiting to exit. */

/* Flags to pass to sched_swi. */
#define	SWI_DELAY	0x2

/*
 * Software interrupt numbers in priority order.  The priority determines
 * the priority of the corresponding interrupt thread.
 */
#define	SWI_TTY		0
#define	SWI_NET		1
#define	SWI_CAMNET	2
#define	SWI_CAMBIO	3
#define	SWI_VM		4
#define	SWI_CLOCK	5
#define	SWI_TQ_FAST	6
#define	SWI_TQ		6
#define	SWI_TQ_GIANT	6

void	swi_sched(void *cookie, int flags);

#endif
