#include "sys.h"
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
#include "kin.h"
#include "in_pcb.h"
#include "in_var.h"
#include "if_var.h"
#include "sockio.h"
#include "kroute.h"
#include "ktime.h"
#include "netisr.h"
#include "ip.h"
static void	doselwakeup(struct selinfo *, int);

//#define ADDCARRY(x)  (x > 65535 ? x -= 65535 : x)
//#define REDUCE {l_util.l = sum; sum = l_util.s[0] + l_util.s[1]; ADDCARRY(sum);}


/*
* Implement a dummy timecounter which we can use until we get a real one
* in the air.  This allows the console and other early stuff to use
* time services.
*/

static u_int
dummy_get_timecount(struct timecounter *tc)
{
	static u_int now;
	
	return (++now);
}

static struct timecounter dummy_timecounter = {
	dummy_get_timecount, 0, ~0u, 1000000, "dummy", -1000000
};
extern struct timehands th0;
static struct timehands th9 = { NULL, 0, 0, 0, {0, 0}, {0, 0}, {0, 0}, 0, &th0};
static struct timehands th8 = { NULL, 0, 0, 0, {0, 0}, {0, 0}, {0, 0}, 0, &th9};
static struct timehands th7 = { NULL, 0, 0, 0, {0, 0}, {0, 0}, {0, 0}, 0, &th8};
static struct timehands th6 = { NULL, 0, 0, 0, {0, 0}, {0, 0}, {0, 0}, 0, &th7};
static struct timehands th5 = { NULL, 0, 0, 0, {0, 0}, {0, 0}, {0, 0}, 0, &th6};
static struct timehands th4 = { NULL, 0, 0, 0, {0, 0}, {0, 0}, {0, 0}, 0, &th5};
static struct timehands th3 = { NULL, 0, 0, 0, {0, 0}, {0, 0}, {0, 0}, 0, &th4};
static struct timehands th2 = { NULL, 0, 0, 0, {0, 0}, {0, 0}, {0, 0}, 0, &th3};
static struct timehands th1 = { NULL, 0, 0, 0, {0, 0}, {0, 0}, {0, 0}, 0, &th2};
static struct timehands th0 = {
	&dummy_timecounter,
		0,
		(__uint64_t)-1 / 1000000,
		0,
	{1, 0},
	{0, 0},
	{0, 0},
	1,
	&th1
};
static struct bintime boottimebin;

static u_int nbinuptime;
static u_int nbintime;

struct timehands *volatile timehands = &th0;
struct timecounter *timecounter = &dummy_timecounter;
static struct timecounter *timecounters = &dummy_timecounter;

//copy from bcd.c
/* This is actually used with radix [2..36] */
char const hex2ascii_data[] = "0123456789abcdefghijklmnopqrstuvwxyz";

u_char const bcd2bin_data[] = {
	0,  1,  2,  3,  4,  5,  6,  7,  8,  9, 0, 0, 0, 0, 0, 0,
		10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 0, 0, 0, 0, 0, 0,
		20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 0, 0, 0, 0, 0, 0,
		30, 31, 32, 33, 34, 35, 36, 37, 38, 39, 0, 0, 0, 0, 0, 0,
		40, 41, 42, 43, 44, 45, 46, 47, 48, 49, 0, 0, 0, 0, 0, 0,
		50, 51, 52, 53, 54, 55, 56, 57, 58, 59, 0, 0, 0, 0, 0, 0,
		60, 61, 62, 63, 64, 65, 66, 67, 68, 69, 0, 0, 0, 0, 0, 0,
		70, 71, 72, 73, 74, 75, 76, 77, 78, 79, 0, 0, 0, 0, 0, 0,
		80, 81, 82, 83, 84, 85, 86, 87, 88, 89, 0, 0, 0, 0, 0, 0,
		90, 91, 92, 93, 94, 95, 96, 97, 98, 99
};

u_char const bin2bcd_data[] = {
	0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09,
		0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19,
		0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27, 0x28, 0x29,
		0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x39,
		0x40, 0x41, 0x42, 0x43, 0x44, 0x45, 0x46, 0x47, 0x48, 0x49,
		0x50, 0x51, 0x52, 0x53, 0x54, 0x55, 0x56, 0x57, 0x58, 0x59,
		0x60, 0x61, 0x62, 0x63, 0x64, 0x65, 0x66, 0x67, 0x68, 0x69,
		0x70, 0x71, 0x72, 0x73, 0x74, 0x75, 0x76, 0x77, 0x78, 0x79,
		0x80, 0x81, 0x82, 0x83, 0x84, 0x85, 0x86, 0x87, 0x88, 0x89,
		0x90, 0x91, 0x92, 0x93, 0x94, 0x95, 0x96, 0x97, 0x98, 0x99
};

#define REDUCE          {sum = (sum & 0xffff) + (sum >> 16); ADDCARRY(sum);}

static const u_int32_t in_masks[] = {
	/*0 bytes*/ /*1 byte*/	/*2 bytes*/ /*3 bytes*/
	0x00000000, 0x000000FF, 0x0000FFFF, 0x00FFFFFF,	/* offset 0 */
		0x00000000, 0x0000FF00, 0x00FFFF00, 0xFFFFFF00,	/* offset 1 */
		0x00000000, 0x00FF0000, 0xFFFF0000, 0xFFFF0000,	/* offset 2 */
		0x00000000, 0xFF000000, 0xFF000000, 0xFF000000,	/* offset 3 */
};

/*
* Free a cred structure.
* Throws away space when ref count gets to 0.
* MPSAFE
*/
void
crfree(struct ucred *cr)
{
#if 0
	struct mtx *mtxp = cr->cr_mtxp;
	
	mtx_lock(mtxp);
	KASSERT(cr->cr_ref > 0, ("bad ucred refcount: %d", cr->cr_ref));
	if (--cr->cr_ref == 0) {
		mtx_unlock(mtxp);
		/*
		* Some callers of crget(), such as nfs_statfs(),
		* allocate a temporary credential, but don't
		* allocate a uidinfo structure.
		*/
		if (cr->cr_uidinfo != NULL)
			uifree(cr->cr_uidinfo);
		if (cr->cr_ruidinfo != NULL)
			uifree(cr->cr_ruidinfo);
			/*
			* Free a prison, if any.
		*/
		if (jailed(cr))
			prison_free(cr->cr_prison);
#ifdef MAC
		mac_destroy_cred(cr);
#endif
		FREE(cr, M_CRED);
	} else {
		mtx_unlock(mtxp);
	}
#endif
}

/*
* Drop the reference count on the the socket and XXX release the SX lock in
* the future.  The last reference closes the socket.
*/
void
fputsock(struct socket *so)
{
	
	ACCEPT_LOCK();
	SOCK_LOCK(so);
	sorele(so);
}

#define	SLEEPQ_TYPE		0x0ff		/* Mask of sleep queue types. */
#define	SLEEPQ_MSLEEP		0x00		/* Used by msleep/wakeup. */
#define	SLEEPQ_CONDVAR		0x01		/* Used for a cv. */
#define	SLEEPQ_INTERRUPTIBLE	0x100		/* Sleep is interruptible. */

/*
* Constants for the hash table of sleep queue chains.  These constants are
* the same ones that 4BSD (and possibly earlier versions of BSD) used.
* Basically, we ignore the lower 8 bits of the address since most wait
* channel pointers are aligned and only look at the next 7 bits for the
* hash.  SC_TABLESIZE must be a power of two for SC_MASK to work properly.
*/
#define	SC_TABLESIZE	128			/* Must be power of 2. */
#define	SC_MASK		(SC_TABLESIZE - 1)
#define	SC_SHIFT	8
#define	SC_HASH(wc)	(((uintptr_t)(wc) >> SC_SHIFT) & SC_MASK)
#define	SC_LOOKUP(wc)	&sleepq_chains[SC_HASH(wc)]

/*
* There two different lists of sleep queues.  Both lists are connected
* via the sq_hash entries.  The first list is the sleep queue chain list
* that a sleep queue is on when it is attached to a wait channel.  The
* second list is the free list hung off of a sleep queue that is attached
* to a wait channel.
*
* Each sleep queue also contains the wait channel it is attached to, the
* list of threads blocked on that wait channel, flags specific to the
* wait channel, and the lock used to synchronize with a wait channel.
* The flags are used to catch mismatches between the various consumers
* of the sleep queue API (e.g. sleep/wakeup and condition variables).
* The lock pointer is only used when invariants are enabled for various
* debugging checks.
*
* Locking key:
*  c - sleep queue chain lock
*/
struct sleepqueue {
	//TAILQ_HEAD(, thread) sq_blocked;	/* (c) Blocked threads. */
	LIST_ENTRY(sleepqueue) sq_hash;		/* (c) Chain and free list. */
	//LIST_HEAD(, sleepqueue) sq_free;	/* (c) Free queues. */
	struct  {								
		struct sleepqueue *lh_first;	/* first element */			
	}sq_free;
	
	void	*sq_wchan;			/* (c) Wait channel. */
	int	sq_type;			/* (c) Queue type. */
#ifdef INVARIANTS
	struct mtx *sq_lock;			/* (c) Associated lock. */
#endif
};
struct sleepqueue_chain {
	//LIST_HEAD(, sleepqueue) sc_queues;	/* List of sleep queues. */
	struct  {								
		struct sleepqueue *lh_first;	/* first element */			
	}sc_queues;
	struct mtx sc_lock;			/* Spin lock for this chain. */
#ifdef SLEEPQUEUE_PROFILING
	u_int	sc_depth;			/* Length of sc_queues. */
	u_int	sc_max_depth;			/* Max length of sc_queues. */
#endif
};
static struct sleepqueue_chain sleepq_chains[SC_TABLESIZE];

/*
* Look up the sleep queue associated with a given wait channel in the hash
* table locking the associated sleep queue chain.  Return holdind the sleep
* queue chain lock.  If no queue is found in the table, NULL is returned.
*/
struct sleepqueue *
sleepq_lookup(void *wchan)
{
	struct sleepqueue_chain *sc;
	struct sleepqueue *sq;
	
	sc = SC_LOOKUP(wchan);
	mtx_lock_spin(&sc->sc_lock);
	LIST_FOREACH(sq, &sc->sc_queues, sq_hash)
		if (sq->sq_wchan == wchan)
			return (sq);
		return (NULL);
}

/*
* Places the current thread on the sleepqueue for the specified wait
* channel.  If INVARIANTS is enabled, then it associates the passed in
* lock with the sleepq to make sure it is held when that sleep queue is
* woken up.
*/
void
sleepq_add(struct sleepqueue *sq, void *wchan, struct mtx *lock,
		   const char *wmesg, int flags)
{
	
}
/*
* Block the current thread until it is awakened from its sleep queue.
*/
void
sleepq_wait(void *wchan)
{
	
	//MPASS(!(curthread->td_flags & TDF_SINTR));
	//sleepq_switch(wchan);
	//mtx_unlock_spin(&sched_lock);
#ifdef hellox_dbg
	ISleep(100);
#endif
}

/*
* General sleep call.  Suspends the current process until a wakeup is
* performed on the specified identifier.  The process will then be made
* runnable with the specified priority.  Sleeps at most timo/hz seconds
* (0 means no timeout).  If pri includes PCATCH flag, signals are checked
* before and after sleeping, else signals are not checked.  Returns 0 if
* awakened, EWOULDBLOCK if the timeout expires.  If PCATCH is set and a
* signal needs to be delivered, ERESTART is returned if the current system
* call should be restarted if possible, and EINTR is returned if the system
* call should be interrupted by the signal (return EINTR).
*
* The mutex argument is exited before the caller is suspended, and
* entered before msleep returns.  If priority includes the PDROP
* flag the mutex is not entered before returning.
*/
int
msleep(ident, mtx, priority, wmesg, timo)
void *ident;
struct mtx *mtx;
int priority, timo;
const char *wmesg;
{
#if 1
	struct sleepqueue *sq;
	struct thread *td;
	struct proc *p;
	int catch, rval, sig, flags;
	
	catch = priority & PCATCH;
	rval = 0;
	
	
	sq = sleepq_lookup(ident);
	
	//	DROP_GIANT();
	// 	if (mtx != NULL) {
	// 		mtx_assert(mtx, MA_OWNED | MA_NOTRECURSED);
	// 		WITNESS_SAVE(&mtx->mtx_object, mtx);
	// 		mtx_unlock(mtx);
	// 	}
	
	/*
	* We put ourselves on the sleep queue and start our timeout
	* before calling thread_suspend_check, as we could stop there,
	* and a wakeup or a SIGCONT (or both) could occur while we were
	* stopped without resuming us.  Thus, we must be ready for sleep
	* when cursig() is called.  If the wakeup happens while we're
	* stopped, then td will no longer be on a sleep queue upon
	* return from cursig().
	*/
	flags = SLEEPQ_MSLEEP;
	if (catch)
		flags |= SLEEPQ_INTERRUPTIBLE;
	sleepq_add(sq, ident, mtx, wmesg, flags);
	
	sig = 0;
	
	/*
	* Adjust this thread's priority.
	*
	* XXX: do we need to save priority in td_base_pri?
	*/
	mtx_lock_spin(&sched_lock);
	//sched_prio(td, priority & PRIMASK);
	mtx_unlock_spin(&sched_lock);
	
	//if (timo && catch)
	//	rval = sleepq_timedwait_sig(ident, sig != 0);
	//else if (timo)
	//	rval = sleepq_timedwait(ident);
	//else if (catch)
	//	rval = sleepq_wait_sig(ident);
	//else {
	sleepq_wait(ident);
	rval = 0;
	//}
	//if (rval == 0 && catch)
	//	rval = sleepq_calc_signal_retval(sig);
	// #ifdef KTRACE
	// 	if (KTRPOINT(td, KTR_CSW))
	// 		ktrcsw(0, 0);
	// #endif
	// 	PICKUP_GIANT();
	if (mtx != NULL && !(priority & PDROP)) {
		mtx_lock(mtx);
		// WITNESS_RESTORE(&mtx->mtx_object, mtx);
	}
	return (rval);
#endif
	return 0;
}
u_int atomic_add_int(int *a, int n)
{
	*a += n;
	return (*a);
}
u_int atomic_fetchadd_int(int *a, int n)
{
	*a += n;
	return (*a);
}
u_int atomic_subtract_int(int *a, int n)
{
   *a -= n;
   //return (*a);
}
u_int atomic_add_long(int *a, long n)
{
	*a += n;
	//return (*a);
}
u_int atomic_set_long(int *a, long n)
{
	*a += n;
	//return (*a);
}
u_int atomic_set_int(int *a, int n)
{
	*a += n;
	//return (*a);
}
/*
* Record a select request.
*/
void
selrecord(selector, sip)
struct thread *selector;
struct selinfo *sip;
{
#if 0
	mtx_lock(&sellock);
	/*
	* If the selinfo's thread pointer is NULL then take ownership of it.
	*
	* If the thread pointer is not NULL and it points to another
	* thread, then we have a collision.
	*
	* If the thread pointer is not NULL and points back to us then leave
	* it alone as we've already added pointed it at us and added it to
	* our list.
	*/
	if (sip->si_thread == NULL) {
		sip->si_thread = selector;
		TAILQ_INSERT_TAIL(&selector->td_selq, sip, si_thrlist);
	} else if (sip->si_thread != selector) {
		sip->si_flags |= SI_COLL;
	}
	
	mtx_unlock(&sellock);
#endif
}

/*
* Make all threads sleeping on the specified identifier runnable.
*/
void
wakeup(ident)
register void *ident;
{
#ifdef hellox_dbg
	OS_Wakeup();
#endif
	//sleepq_broadcast(ident, SLEEPQ_MSLEEP, -1);LUOYU
}

/*
* Make a thread sleeping on the specified identifier runnable.
* May wake more than one thread if a target thread is currently
* swapped out.
*/
void
wakeup_one(ident)
register void *ident;
{
#ifdef hellox_dbg
	OS_Wakeup();
#endif
	//sleepq_signal(ident, SLEEPQ_MSLEEP, -1);LUOYU
}

/* Wake up a selecting thread, and set its priority. */
void
selwakeuppri(sip, pri)
struct selinfo *sip;
int pri;
{
#ifdef hellox_dbg
	OS_Wait();
#endif
	//doselwakeup(sip, pri);
}

/*
* Do a wakeup when a selectable event occurs.
*/
static void
doselwakeup(sip, pri)
struct selinfo *sip;
int pri;
{
#if 0
	struct thread *td;
	
	mtx_lock(&sellock);
	td = sip->si_thread;
	if ((sip->si_flags & SI_COLL) != 0) {
		nselcoll++;
		sip->si_flags &= ~SI_COLL;
		cv_broadcastpri(&selwait, pri);
	}
	if (td == NULL) {
		mtx_unlock(&sellock);
		return;
	}
	TAILQ_REMOVE(&td->td_selq, sip, si_thrlist);
	sip->si_thread = NULL;
	mtx_lock_spin(&sched_lock);
	td->td_flags &= ~TDF_SELECT;
	mtx_unlock_spin(&sched_lock);
	sleepq_remove(td, &selwait);
	mtx_unlock(&sellock);
#endif	
}

int
taskqueue_enqueue(struct taskqueue *queue, struct task *task)
{
	//LUOYU should add
	
	return 0;
}

u_int16_t
ip_randomid(void)
{
	int i, n;
	struct timeval time;
#if 0
	LUOYU
		/* XXX not reentrant */
		getmicrotime(&time);
	if (ru_counter >= RU_MAX || time.tv_sec > ru_reseed)
		ip_initid();
	
	if (!tmp)
		read_random((void *) &tmp, sizeof(tmp));
	
	/* Skip a random number of ids */
	n = tmp & 0x3; tmp = tmp >> 2;
	if (ru_counter + n >= RU_MAX)
		ip_initid();
	
	for (i = 0; i <= n; i++)
		/* Linear Congruential Generator */
		ru_x = (ru_a*ru_x + ru_b) % RU_M;
	
	ru_counter += i;
	
	return (ru_seed ^ pmod(ru_g,ru_seed2 ^ ru_x,RU_N)) | ru_msb;
#endif
	return 0x12345;
}


void
getmicrotime(struct timeval *tvp)
{
	
}
/*
* Copy src to string dst of size siz.  At most siz-1 characters
* will be copied.  Always NUL terminates (unless siz == 0).
* Returns strlen(src); if retval >= siz, truncation occurred.
*/
size_t strlcpy(dst, src, siz)
char *dst;
const char *src;
size_t siz;
{
	char *d = dst;
	const char *s = src;
	size_t n = siz;
	
	/* Copy as many bytes as will fit */
	if (n != 0 && --n != 0) {
		do {
			if ((*d++ = *s++) == 0)
				break;
		} while (--n != 0);
	}
	
	/* Not enough room in dst, add NUL and traverse rest of src */
	if (n == 0) {
		if (siz != 0)
			*d = '\0';		/* NUL-terminate dst */
		while (*s++)
			;
	}
	
	return(s - src - 1);	/* count does not include NUL */
}
/*
* Appends src to string dst of size siz (unlike strncat, siz is the
* full size of dst, not space left).  At most siz-1 characters
* will be copied.  Always NUL terminates (unless siz <= strlen(dst)).
* Returns strlen(src) + MIN(siz, strlen(initial dst)).
* If retval >= siz, truncation occurred.
*/
size_t
strlcat(dst, src, siz)
char *dst;
const char *src;
size_t siz;
{
	char *d = dst;
	const char *s = src;
	size_t n = siz;
	size_t dlen;
	
	/* Find the end of dst and adjust bytes left but don't go past end */
	while (n-- != 0 && *d != '\0')
		d++;
	dlen = d - dst;
	n = siz - dlen;
	
	if (n == 0)
		return(dlen + strlen(s));
	while (*s != '\0') {
		if (n != 1) {
			*d++ = *s;
			n--;
		}
		s++;
	}
	*d = '\0';
	
	return(dlen + (s - src));	/* count does not include NUL */
}
//size_t
//strlen(str)
//const char *str;
//{
//	register const char *s;
//	
//	for (s = str; *s; ++s);
//	return(s - str);
//}
//int
//strncmp(s1, s2, n)
//register const char *s1, *s2;
//register size_t n;
//{
//	
//	if (n == 0)
//		return (0);
//	do {
//		if (*s1 != *s2++)
//			return (*(const unsigned char *)s1 -
//			*(const unsigned char *)(s2 - 1));
//		if (*s1++ == 0)
//			break;
//	} while (--n != 0);
//	return (0);
//}

/*
* ppsratecheck(): packets (or events) per second limitation.
*
* Return 0 if the limit is to be enforced (e.g. the caller
* should drop a packet because of the rate limitation).
*
* maxpps of 0 always causes zero to be returned.  maxpps of -1
* always causes 1 to be returned; this effectively defeats rate
* limiting.
*
* Note that we maintain the struct timeval for compatibility
* with other bsd systems.  We reuse the storage and just monitor
* clock ticks for minimal overhead.  
*/
int
ppsratecheck(struct timeval *lasttime, int *curpps, int maxpps)
{
	int now;
	
	/*
	* Reset the last time and counter if this is the first call
	* or more than a second has passed since the last update of
	* lasttime.
	*/
	now = ticks;
	if (lasttime->tv_sec == 0 || (u_int)(now - lasttime->tv_sec) >= hz) {
		lasttime->tv_sec = now;
		*curpps = 1;
		return (maxpps != 0);
	} else {
		(*curpps)++;		/* NB: ignore potential overflow */
		return (maxpps < 0 || *curpps < maxpps);
	}
}

/*
* Return the difference between the timehands' counter value now and what
* was when we copied it to the timehands' offset_count.
*/
static __inline u_int
tc_delta(struct timehands *th)
{
	struct timecounter *tc;
	
	tc = th->th_counter;
	return ((tc->tc_get_timecount(tc) - th->th_offset_count) &
		tc->tc_counter_mask);
}

/*
* Functions for reading the time.  We have to loop until we are sure that
* the timehands that we operated on was not updated under our feet.  See
* the comment in <sys/time.h> for a description of these 12 functions.
*/

void
binuptime(struct bintime *bt)
{
	struct timehands *th;
	u_int gen;
	
	nbinuptime++;
	do {
		th = timehands;
		gen = th->th_generation;
		*bt = th->th_offset;
		bintime_addx(bt, th->th_scale * tc_delta(th));
	} while (gen == 0 || gen != th->th_generation);
}

void
bintime(struct bintime *bt)
{
	
	nbintime++;
	binuptime(bt);
	bintime_add(bt, &boottimebin);
}

