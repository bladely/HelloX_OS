#include "ktime.h"
#include "callout.h"
#include "socketvar.h"

struct callout *callout;
struct callout_list callfree;
int callwheelsize, callwheelbits, callwheelmask;
//struct callout_tailq *callwheel;
struct callout_list *callwheel;
int softticks;			/* Like ticks, but for softclock(). */
struct mtx callout_lock;

extern int	ticks;

/*-
* Locked by callout_lock:
*   curr_callout    - If a callout is in progress, it is curr_callout.
*                     If curr_callout is non-NULL, threads waiting on
*                     callout_wait will be woken up as soon as the 
*                     relevant callout completes.
*   wakeup_ctr      - Incremented every time a thread wants to wait
*                     for a callout to complete.  Modified only when
*                     curr_callout is non-NULL.
*   wakeup_needed   - If a thread is waiting on callout_wait, then
*                     wakeup_needed is nonzero.  Increased only when
*                     cutt_callout is non-NULL.
*/
static struct callout *curr_callout;
static int wakeup_ctr;
static int wakeup_needed;
static struct callout *nextsoftcheck;	/* Next callout to be checked. */

/*-
* Locked by callout_wait_lock:
*   callout_wait    - If wakeup_needed is set, callout_wait will be
*                     triggered after the current callout finishes.
*   wakeup_done_ctr - Set to the current value of wakeup_ctr after
*                     callout_wait is triggered.
*/
static struct mtx callout_wait_lock;
// static struct cv callout_wait;
static int wakeup_done_ctr;
static void	timevalfix(struct timeval *);

/*
 * The callout mechanism is based on the work of Adam M. Costello and 
 * George Varghese, published in a technical report entitled "Redesigning
 * the BSD Callout and Timer Facilities" and modified slightly for inclusion
 * used in this implementation was published by G. Varghese and T. Lauck in
 * the paper "Hashed and Hierarchical Timing Wheels: Data Structures for
 * the Efficient Implementation of a Timer Facility" in the Proceedings of
 * the 11th ACM Annual Symposium on Operating Systems Principles,
 * Austin, Texas Nov 1987.
 */

/*
 * Software (low priority) clock interrupt.
 * Run periodic events from timeout queue.
 */
void
softclock(void *dummy)
{
	struct callout *c;
	struct callout_tailq *bucket;
	int curticks;
	int steps;	/* #steps since we last allowed interrupts */
	int depth;
	int mpcalls;
	int gcalls;
	int wakeup_cookie;

#ifndef MAX_SOFTCLOCK_STEPS
#define MAX_SOFTCLOCK_STEPS 100 /* Maximum allowed value of steps. */
#endif /* MAX_SOFTCLOCK_STEPS */

	mpcalls = 0;
	gcalls = 0;
	depth = 0;
	steps = 0;
	ticks++;
	//while (softticks != ticks) {
		softticks++;
		/*
		 * softticks may be modified by hard clock, so cache
		 * it while we work on a given bucket.
		 */
		curticks = softticks;
		//bucket = &callwheel[curticks & callwheelmask];
		c = SLIST_FIRST(callwheel);
		
		while (c) {
			//depth++;
			//if (curticks %10 == 0)
			   //printf("c_time = %d curticks %d\n", (int)c->c_time, curticks);
			if (c->c_time != curticks) {
				if (c->c_time < curticks)
					SLIST_REMOVE(callwheel, c, callout, c_links.sle);
				c = SLIST_NEXT(c, c_links.sle);
// 				++steps;
// 				if (steps >= MAX_SOFTCLOCK_STEPS) {
// 					//nextsoftcheck = c;
// 					//c = nextsoftcheck;
// 					steps = 0;
// 				}
			} else {
				void (*c_func)(void *);
				void *c_arg;
				int c_flags;

				nextsoftcheck = SLIST_NEXT(c, c_links.sle);
				SLIST_REMOVE(callwheel, c, callout, c_links.sle);
				c_func = c->c_func;
				c_arg = c->c_arg;
				c_flags = c->c_flags;
				c->c_func = NULL;
				if (c->c_flags & CALLOUT_LOCAL_ALLOC) {
					c->c_flags = CALLOUT_LOCAL_ALLOC;
					SLIST_INSERT_HEAD(&callfree, c,
							  c_links.sle);
				} else {
					c->c_flags =
					    (c->c_flags & ~CALLOUT_PENDING);
				}
				curr_callout = c;
				mtx_unlock_spin(&callout_lock);
				//printf("softclock call func %d\n", c);
				c_func(c_arg);
				
				curr_callout = NULL;
				
				steps = 0;
				c = nextsoftcheck;
			}
		}
	//}
	nextsoftcheck = NULL;
	mtx_unlock_spin(&callout_lock);
}

/*
 * kern_timeout_callwheel_alloc() - kernel low level callwheel initialization 
 *
 *	This code is called very early in the kernel initialization sequence,
 *	and may be called more then once.
 */
caddr_t
kern_timeout_callwheel_alloc(caddr_t v)
{
	/*
	 * Calculate callout wheel size
	 */
	for (callwheelsize = 1, callwheelbits = 0;
	     callwheelsize < ncallout;
	     callwheelsize <<= 1, ++callwheelbits)
		;
	callwheelmask = callwheelsize - 1;
   /* TMD ʲô�ƾ������� ���Ҳ���һСʱ ����һ��Ҫע��callout ��struct callout������*/
	callout = (struct callout *)malloc(sizeof(struct callout) * ncallout);
	//v = (caddr_t)(callout + ncallout);
	callwheel = (struct callout_list *)malloc(sizeof(struct callout_list));
	//v = (caddr_t)(callwheel + callwheelsize);
	return(v);
}

/*
 * kern_timeout_callwheel_init() - initialize previously reserved callwheel
 *				   space.
 *
 *	This code is called just once, after the space reserved for the
 *	callout wheel has been finalized.
 */
void
kern_timeout_callwheel_init(void)
{
	int i;

	SLIST_INIT(&callfree);
	for (i = 0; i < ncallout; i++) {
		callout_init(&callout[i], 0);
		callout[i].c_flags = CALLOUT_LOCAL_ALLOC;
		SLIST_INSERT_HEAD(&callfree, &callout[i], c_links.sle);
	}
	//for (i = 0; i < callwheelsize; i++) {
		SLIST_INIT(callwheel); //Only one time
	//}
// 	mtx_init(&callout_lock, "callout", NULL, MTX_SPIN | MTX_RECURSE);
// #ifdef DIAGNOSTIC
// 	mtx_init(&dont_sleep_in_callout, "dont_sleep_in_callout", NULL, MTX_DEF);
// #endif
// 	mtx_init(&callout_wait_lock, "callout_wait_lock", NULL, MTX_DEF);
// 	cv_init(&callout_wait, "callout_wait");
}

void
callout_init(c, mpsafe)
	struct	callout *c;
	int mpsafe;
{
	bzero(c, sizeof *c);
	if (mpsafe)
		c->c_flags |= CALLOUT_MPSAFE;
}

/*
 * timeout --
 *	Execute a function after a specified length of time.
 *
 * untimeout --
 *	Cancel previous timeout function call.
 *
 * callout_handle_init --
 *	Initialize a handle so that using it with untimeout is benign.
 *
 *	See AT&T BCI Driver Reference Manual for specification.  This
 *	implementation differs from that one in that although an 
 *	identification value is returned from timeout, the original
 *	arguments to timeout as well as the identifier are used to
 *	identify entries for untimeout.
 */
struct callout_handle
timeout(ftn, arg, to_ticks)
	timeout_t *ftn;
	void *arg;
	int to_ticks;
{
	struct callout *new;
	struct callout_handle handle;

	//mtx_lock_spin(&callout_lock);

	/* Fill in the next free callout structure. */
	new = SLIST_FIRST(&callfree);
	if (new == NULL)
		/* XXX Attempt to malloc first */
		panic("timeout table full");
	SLIST_REMOVE_HEAD(&callfree, c_links.sle);
	
	callout_reset(new, to_ticks, ftn, arg);

	handle.callout = new;
	//mtx_unlock_spin(&callout_lock);
	return (handle);
}


/*
* New interface; clients allocate their own callout structures.
*
* callout_reset() - establish or change a timeout
* callout_stop() - disestablish a timeout
* callout_init() - initialize a callout structure so that it can
*	safely be passed to callout_reset() and callout_stop()
*
* <sys/callout.h> defines three convenience macros:
*
* callout_active() - returns truth if callout has not been serviced
* callout_pending() - returns truth if callout is still waiting for timeout
* callout_deactivate() - marks the callout as having been serviced
*/
void
callout_reset(c, to_ticks, ftn, arg)
struct	callout *c;
int	to_ticks;
void	(*ftn)(void *);
void	*arg;
{
	/*
	* We could unlock callout_lock here and lock it again before the
	* TAILQ_INSERT_TAIL, but there's no point since doing this setup
	* doesn't take much time.
	*/
	if (to_ticks <= 0)
		to_ticks = 1;
	if (c->c_flags & CALLOUT_PENDING) {
		if (nextsoftcheck == c) {
			nextsoftcheck = SLIST_NEXT(c, c_links.sle);
		}
		SLIST_REMOVE(callwheel, c, callout, c_links.sle);
		
			/*
			* Part of the normal "stop a pending callout" process
			* is to clear the CALLOUT_ACTIVE and CALLOUT_PENDING
			* flags.  We're not going to bother doing that here,
			* because we're going to be setting those flags ten lines
			* after this point, and we're holding callout_lock
			* between now and then.
		*/
	}
	c->c_arg = arg;
	c->c_flags |= (CALLOUT_ACTIVE | CALLOUT_PENDING);
	c->c_func = ftn;
	c->c_time = ticks + to_ticks/10;//LUOYU:����������10����Ϊ���ǵĶ�ʱ����100msתһ��
	SLIST_INSERT_HEAD(callwheel, c, c_links.sle);//LUOYU
	//printf("callout_reset to_ticks %d\n", to_ticks);
}

int
_callout_stop_safe(c, safe)
	struct	callout *c;
	int	safe;
{
	int wakeup_cookie;
   struct	callout *tmp;
	mtx_lock_spin(&callout_lock);
	/*
	 * Don't attempt to delete a callout that's not on the queue.
	 */
	if (!(c->c_flags & CALLOUT_PENDING)) {
		c->c_flags &= ~CALLOUT_ACTIVE;
		if (c == curr_callout && safe) {
			/* We need to wait until the callout is finished. */
			wakeup_needed = 1;
			wakeup_cookie = wakeup_ctr++;
			mtx_unlock_spin(&callout_lock);
			mtx_lock(&callout_wait_lock);

		} else
			mtx_unlock_spin(&callout_lock);
		return (0);
	}
	c->c_flags &= ~(CALLOUT_ACTIVE | CALLOUT_PENDING);

	if (nextsoftcheck == c) {
		nextsoftcheck = SLIST_NEXT(c, c_links.sle);
	}
   SLIST_REMOVE(callwheel, c, callout, c_links.sle);
   c->c_func = NULL;

	if (c->c_flags & CALLOUT_LOCAL_ALLOC) {
		SLIST_INSERT_HEAD(&callfree, c, c_links.sle);
	}
	mtx_unlock_spin(&callout_lock);
	return (1);
}
//copy from kern_time.c
/*
 * Add and subtract routines for timevals.
 * N.B.: subtract routine doesn't deal with
 * results which are before the beginning,
 * it just gets very confused in this case.
 * Caveat emptor.
 */
void
timevaladd(struct timeval *t1, const struct timeval *t2)
{

	t1->tv_sec += t2->tv_sec;
	t1->tv_usec += t2->tv_usec;
	timevalfix(t1);
}

void
timevalsub(struct timeval *t1, const struct timeval *t2)
{

	t1->tv_sec -= t2->tv_sec;
	t1->tv_usec -= t2->tv_usec;
	timevalfix(t1);
}

static void
timevalfix(struct timeval *t1)
{

	if (t1->tv_usec < 0) {
		t1->tv_sec--;
		t1->tv_usec += 1000000;
	}
	if (t1->tv_usec >= 1000000) {
		t1->tv_sec++;
		t1->tv_usec -= 1000000;
	}
}

/*
 * Compute number of ticks in the specified amount of time.
 */
int
tvtohz(tv)
	struct timeval *tv;
{
	register unsigned long ticks;
	register long sec, usec;

	/*
	 * If the number of usecs in the whole seconds part of the time
	 * difference fits in a long, then the total number of usecs will
	 * fit in an unsigned long.  Compute the total and convert it to
	 * ticks, rounding up and adding 1 to allow for the current tick
	 * to expire.  Rounding also depends on unsigned long arithmetic
	 * to avoid overflow.
	 *
	 * Otherwise, if the number of ticks in the whole seconds part of
	 * the time difference fits in a long, then convert the parts to
	 * ticks separately and add, using similar rounding methods and
	 * overflow avoidance.  This method would work in the previous
	 * case but it is slightly slower and assumes that hz is integral.
	 *
	 * Otherwise, round the time difference down to the maximum
	 * representable value.
	 *
	 * If ints have 32 bits, then the maximum value for any timeout in
	 * 10ms ticks is 248 days.
	 */
	sec = tv->tv_sec;
	usec = tv->tv_usec;
	if (usec < 0) {
		sec--;
		usec += 1000000;
	}
	if (sec < 0) {
#ifdef DIAGNOSTIC
		if (usec > 0) {
			sec++;
			usec -= 1000000;
		}
		printf("tvotohz: negative time difference %ld sec %ld usec\n",
		       sec, usec);
#endif
		ticks = 1;
	} else if (sec <= LONG_MAX / 1000000)
		ticks = (sec * 1000000 + (unsigned long)usec + (tick - 1))
			/ tick + 1;
	else if (sec <= LONG_MAX / hz)
		ticks = sec * hz
			+ ((unsigned long)usec + (tick - 1)) / tick + 1;
	else
		ticks = LONG_MAX;
	if (ticks > INT_MAX)
		ticks = INT_MAX;
	return ((int)ticks);
}

/*
 * Check that a proposed value to load into the .it_value or
 * .it_interval part of an interval timer is acceptable, and
 * fix it to have at least minimal value (i.e. if it is less
 * than the resolution of the clock, round it up.)
 */
int
itimerfix(struct timeval *tv)
{

	if (tv->tv_sec < 0 || tv->tv_sec > 100000000 ||
	    tv->tv_usec < 0 || tv->tv_usec >= 1000000)
		return (EINVAL);
	if (tv->tv_sec == 0 && tv->tv_usec != 0 && tv->tv_usec < tick)
		tv->tv_usec = tick;
	return (0);
}
