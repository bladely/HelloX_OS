/*-
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
 *           src/sys/sys/_timeval.h,v 1.1 2002/12/31 04:08:41 mike Exp $
 */

#ifndef _SYS__TIMEVAL_H_
#define _SYS__TIMEVAL_H_

#include <bsdsys.h>
#include <uio.h>
#ifndef _SUSECONDS_T_DECLARED
typedef	__suseconds_t	suseconds_t;
#define	_SUSECONDS_T_DECLARED
#endif

#ifndef _TIME_T_DECLARED
//typedef	__time_t	time_t;
#define	_TIME_T_DECLARED
#endif


#ifndef _TIME_T_DECLARED
#define	_TIME_T_DECLARED
#endif
extern int ticks;
/*
 * Structure returned by gettimeofday(2) system call, and used in other calls.
 */
struct timeval {
	long		tv_sec;		/* seconds (XXX should be time_t) */
	suseconds_t	tv_usec;	/* and microseconds */
};
extern __uint32_t time_second;
extern __uint32_t	time_uptime;

struct timezone {
	int	tz_minuteswest;	/* minutes west of Greenwich */
	int	tz_dsttime;	/* type of dst correction */
};
typedef long     time_t;
struct timespec {
	time_t	tv_sec;		/* seconds */
	long	tv_nsec;	/* and nanoseconds */
};

#if __BSD_VISIBLE
#define	TIMEVAL_TO_TIMESPEC(tv, ts)					\
	do {								\
		(ts)->tv_sec = (tv)->tv_sec;				\
		(ts)->tv_nsec = (tv)->tv_usec * 1000;			\
	} while (0)
#define	TIMESPEC_TO_TIMEVAL(tv, ts)					\
	do {								\
		(tv)->tv_sec = (ts)->tv_sec;				\
		(tv)->tv_usec = (ts)->tv_nsec / 1000;			\
	} while (0)

#endif /* __BSD_VISIBLE */

struct bintime {
	time_t	sec;
	__uint64_t frac;
};

typedef u_int timecounter_get_t(struct timecounter *);
typedef void timecounter_pps_t(struct timecounter *);

struct timecounter {
	timecounter_get_t	*tc_get_timecount;
		/*
		 * This function reads the counter.  It is not required to
		 * mask any unimplemented bits out, as long as they are
		 * constant.
		 */
	timecounter_pps_t	*tc_poll_pps;
		/*
		 * This function is optional.  It will be called whenever the
		 * timecounter is rewound, and is intended to check for PPS
		 * events.  Normal hardware does not need it but timecounters
		 * which latch PPS in hardware (like sys/pci/xrpu.c) do.
		 */
	u_int 			tc_counter_mask;
		/* This mask should mask off any unimplemented bits. */
	__uint64_t		tc_frequency;
		/* Frequency of the counter in Hz. */
	char			*tc_name;
		/* Name of the timecounter. */
	int			tc_quality;
		/*
		 * Used to determine if this timecounter is better than
		 * another timecounter higher means better.  Negative
		 * means "only use at explicit request".
		 */

	void			*tc_priv;
		/* Pointer to the timecounter's private parts. */
	struct timecounter	*tc_next;
		/* Pointer to the next timecounter. */
};

struct timehands {
	/* These fields must be initialized by the driver. */
	struct timecounter	*th_counter;
	int64_t			th_adjustment;
	uint64_t		th_scale;
	u_int	 		th_offset_count;
	struct bintime		th_offset;
	struct timeval		th_microtime;
	struct timespec		th_nanotime;
	/* Fields not to be copied in tc_windup start with th_generation. */
	volatile u_int		th_generation;
	struct timehands	*th_next;
};

#define	DST_NONE	0	/* not on dst */
#define	DST_USA		1	/* USA style dst */
#define	DST_AUST	2	/* Australian style dst */
#define	DST_WET		3	/* Western European dst */
#define	DST_MET		4	/* Middle European dst */
#define	DST_EET		5	/* Eastern European dst */
#define	DST_CAN		6	/* Canada */


/* Operations on timevals. */

#define	timevalclear(tvp)		((tvp)->tv_sec = (tvp)->tv_usec = 0)
#define	timevalisset(tvp)		((tvp)->tv_sec || (tvp)->tv_usec)
#define	timevalcmp(tvp, uvp, cmp)					\
	(((tvp)->tv_sec == (uvp)->tv_sec) ?				\
	    ((tvp)->tv_usec cmp (uvp)->tv_usec) :			\
	    ((tvp)->tv_sec cmp (uvp)->tv_sec))

void	binuptime(struct bintime *bt);

void	bintime(struct bintime *bt);

void	getmicrouptime(struct timeval *tvp);

void	getmicrotime(struct timeval *tvp);

/* Other functions */
int	itimerfix(struct timeval *tv);
int	ppsratecheck(struct timeval *, int *, int);
void	timevaladd(struct timeval *t1, const struct timeval *t2);
void	timevalsub(struct timeval *t1, const struct timeval *t2);
int	tvtohz(struct timeval *tv);

#if __BSD_VISIBLE


static  void
bintime_addx(struct bintime *bt, __uint64_t x)
{
	__uint64_t u;

	u = bt->frac;
	bt->frac += x;
	if (u > bt->frac)
		bt->sec++;
}

static  void
bintime_add(struct bintime *bt, const struct bintime *bt2)
{
	__uint64_t u;

	u = bt->frac;
	bt->frac += bt2->frac;
	if (u > bt->frac)
		bt->sec++;
	bt->sec += bt2->sec;
}

static  void
bintime_sub(struct bintime *bt, const struct bintime *bt2)
{
	__uint64_t u;

	u = bt->frac;
	bt->frac -= bt2->frac;
	if (u < bt->frac)
		bt->sec--;
	bt->sec -= bt2->sec;
}

/*-
 * Background information:
 *
 * When converting between timestamps on parallel timescales of differing
 * resolutions it is historical and scientific practice to round down rather
 * than doing 4/5 rounding.
 *
 *   The date changes at midnight, not at noon.
 *
 *   Even at 15:59:59.999999999 it's not four'o'clock.
 *
 *   time_second ticks after N.999999999 not after N.4999999999
 */

static  void
bintime2timespec(const struct bintime *bt, struct timespec *ts)
{

	ts->tv_sec = bt->sec;
	ts->tv_nsec = (long)((__uint64_t)1000000000 * (__uint32_t)(bt->frac >> 32)) >> 32;
}

static  void
timespec2bintime(const struct timespec *ts, struct bintime *bt)
{

	bt->sec = ts->tv_sec;
	/* 18446744073 = int(2^64 / 1000000000) */
	bt->frac = ts->tv_nsec * (__uint64_t)18446744073; 
}

static  void
bintime2timeval(const struct bintime *bt, struct timeval *tv)
{

	tv->tv_sec = bt->sec;
	tv->tv_usec = (long)((__uint64_t)1000000 * (__uint32_t)(bt->frac >> 32)) >> 32;
}

static  void
timeval2bintime(const struct timeval *tv, struct bintime *bt)
{

	bt->sec = tv->tv_sec;
	/* 18446744073709 = int(2^64 / 1000000) */
	bt->frac = tv->tv_usec * (__uint64_t)18446744073709;
}
#endif /* __BSD_VISIBLE */

struct tm {
	int	tm_sec;		/* seconds after the minute [0-60] */
	int	tm_min;		/* minutes after the hour [0-59] */
	int	tm_hour;	/* hours since midnight [0-23] */
	int	tm_mday;	/* day of the month [1-31] */
	int	tm_mon;		/* months since January [0-11] */
	int	tm_year;	/* years since 1900 */
	int	tm_wday;	/* days since Sunday [0-6] */
	int	tm_yday;	/* days since January 1 [0-365] */
	int	tm_isdst;	/* Daylight Savings Time flag */
	long	tm_gmtoff;	/* offset from UTC in seconds */
	char	*tm_zone;	/* timezone abbreviation */
};

#endif /* !_SYS__TIMEVAL_H_ */
