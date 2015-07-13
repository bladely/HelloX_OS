#ifndef _SYS_EVENT_H_
#define _SYS_EVENT_H_
#include "sys.h"
#include "interrupt.h"
#include "kqueue.h"
#define EVFILT_READ		(-1)
#define EVFILT_WRITE		(-2)
#define EVFILT_AIO		(-3)	/* attached to aio requests */
#define EVFILT_VNODE		(-4)	/* attached to vnodes */
#define EVFILT_PROC		(-5)	/* attached to struct proc */
#define EVFILT_SIGNAL		(-6)	/* attached to struct proc */
#define EVFILT_TIMER		(-7)	/* timers */
#define EVFILT_NETDEV		(-8)	/* network devices */
#define EVFILT_FS		(-9)	/* filesystem events */

#define EVFILT_SYSCOUNT		9

#define EV_SET(kevp_, a, b, c, d, e, f) do {	\
	struct kevent *kevp = (kevp_);		\
	(kevp)->ident = (a);			\
	(kevp)->filter = (b);			\
	(kevp)->flags = (c);			\
	(kevp)->fflags = (d);			\
	(kevp)->data = (e);			\
	(kevp)->udata = (f);			\
} while(0)

struct kevent {
	uintptr_t	ident;		/* identifier for this event */
	short		filter;		/* filter for event */
	u_short		flags;
	u_int		fflags;
	intptr_t	data;
	void		*udata;		/* opaque user data identifier */
};

/* actions */
#define EV_ADD		0x0001		/* add event to kq (implies enable) */
#define EV_DELETE	0x0002		/* delete event from kq */
#define EV_ENABLE	0x0004		/* enable event */
#define EV_DISABLE	0x0008		/* disable event (not reported) */

/* flags */
#define EV_ONESHOT	0x0010		/* only report one occurrence */
#define EV_CLEAR	0x0020		/* clear event state after reporting */

#define EV_SYSFLAGS	0xF000		/* reserved by system */
#define EV_FLAG1	0x2000		/* filter-specific flag */

/* returned values */
#define EV_EOF		0x8000		/* EOF detected */
#define EV_ERROR	0x4000		/* error, data contains errno */

/*
 * data/hint flags for EVFILT_{READ|WRITE}, shared with userspace
 */
#define NOTE_LOWAT	0x0001			/* low water mark */

/*
 * data/hint flags for EVFILT_VNODE, shared with userspace
 */
#define	NOTE_DELETE	0x0001			/* vnode was removed */
#define	NOTE_WRITE	0x0002			/* data contents changed */
#define	NOTE_EXTEND	0x0004			/* size increased */
#define	NOTE_ATTRIB	0x0008			/* attributes changed */
#define	NOTE_LINK	0x0010			/* link count changed */
#define	NOTE_RENAME	0x0020			/* vnode was renamed */
#define	NOTE_REVOKE	0x0040			/* vnode access was revoked */

/*
 * data/hint flags for EVFILT_PROC, shared with userspace
 */
#define	NOTE_EXIT	0x80000000		/* process exited */
#define	NOTE_FORK	0x40000000		/* process forked */
#define	NOTE_EXEC	0x20000000		/* process exec'd */
#define	NOTE_PCTRLMASK	0xf0000000		/* mask for hint bits */
#define	NOTE_PDATAMASK	0x000fffff		/* mask for pid */

/* additional flags for EVFILT_PROC */
#define	NOTE_TRACK	0x00000001		/* follow across forks */
#define	NOTE_TRACKERR	0x00000002		/* could not track child */
#define	NOTE_CHILD	0x00000004		/* am a child process */

/*
 * data/hint flags for EVFILT_NETDEV, shared with userspace
 */
#define NOTE_LINKUP	0x0001			/* link is up */
#define NOTE_LINKDOWN	0x0002			/* link is down */
#define NOTE_LINKINV	0x0004			/* link state is invalid */




struct knote;
struct klist{								
	struct  knote* slh_first;	/* first element */			
};

struct kqueue;
struct kqlist{								
	struct kqueue *slh_first;	/* first element */			
};

struct knlist {
	struct	mtx	*kl_lock;	/* lock to protect kll_list */
	struct	klist	kl_list;
};
/*
 * Setting the KN_INFLUX flag enables you to unlock the kq that this knote
 * is on, and modify kn_status as if you had the KQ lock.
 *
 * kn_sfflags, kn_sdata, and kn_kevent are protected by the knlist lock.
 */
struct knote {
	SLIST_ENTRY(knote)	kn_link;	/* for kq */
	SLIST_ENTRY(knote)	kn_selnext;	/* for struct selinfo */
	struct			knlist *kn_knlist;	/* f_attach populated */
	TAILQ_ENTRY(knote)	kn_tqe;
	struct			kqueue *kn_kq;	/* which queue we are on */
	struct 			kevent kn_kevent;
	int			kn_status;	/* protected by kq lock */
#define KN_ACTIVE	0x01			/* event has been triggered */
#define KN_QUEUED	0x02			/* event is on queue */
#define KN_DISABLED	0x04			/* event is disabled */
#define KN_DETACHED	0x08			/* knote is detached */
#define KN_INFLUX	0x10			/* knote is in flux */
#define KN_MARKER	0x20			/* ignore this knote */
#define KN_KQUEUE	0x40			/* this knote belongs to a kq */
#define KN_HASKQLOCK	0x80			/* for _inevent */
#define kn_flags	kn_kevent.flags
};



/*
 * Condition variable.  The waiters count is protected by the mutex that
 * protects the condition; that is, the mutex that is passed to cv_wait*()
 * and is held across calls to cv_signal() and cv_broadcast().  It is an
 * optimization to avoid looking up the sleep queue if there are no waiters.
 */
struct cv {
	const char	*cv_description;
	int		cv_waiters;
};

#endif
