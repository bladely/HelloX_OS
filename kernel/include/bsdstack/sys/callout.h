/********************************************************/
/****************** AUTHOR LUOYU ************************/
/********************************************************/

#ifndef _SYS_CALLOUT_H_
#define _SYS_CALLOUT_H_

#include <kqueue.h>
typedef void (timeout_t)(void *);

//SLIST_HEAD(callout_list, callout);
struct callout_list {								
	struct callout *slh_first;	/* first element */			
};
//TAILQ_HEAD(callout_tailq, callout);
struct callout_tailq {							
	struct callout *tqh_first;	/* first element */			
	struct callout **tqh_last;	/* addr of last next element */		
	TRACEBUF							
};
struct callout {
	union {
		SLIST_ENTRY(callout) sle;
		TAILQ_ENTRY(callout) tqe;
	} c_links;
	int	c_time;				/* ticks to the event */
	void	*c_arg;				/* function argument */
	void	(*c_func)(void *);	/* function to call */
	int	c_flags;			/* state of this entry */
};

#define	CALLOUT_LOCAL_ALLOC	0x0001 /* was allocated from callfree */
#define	CALLOUT_ACTIVE		0x0002 /* callout is currently active */
#define	CALLOUT_PENDING		0x0004 /* callout is waiting for timeout */
#define	CALLOUT_MPSAFE		0x0008 /* callout handler is mp safe */

struct callout_handle {
	struct callout *callout;
};

extern struct callout_list callfree;
extern struct callout *callout;
extern int ncallout;
extern struct callout_list *callwheel;
extern int callwheelsize, callwheelbits, callwheelmask, softticks;
extern struct mtx callout_lock;
#define	callout_active(c)	((c)->c_flags & CALLOUT_ACTIVE)
#define	callout_deactivate(c)	((c)->c_flags &= ~CALLOUT_ACTIVE)
#define	callout_drain(c)	_callout_stop_safe(c, 1)
void	callout_init(struct callout *, int);
#define	callout_pending(c)	((c)->c_flags & CALLOUT_PENDING)
void	callout_reset(struct callout *, int, void (*)(void *), void *);
#define	callout_stop(c)		_callout_stop_safe(c, 0)
int	_callout_stop_safe(struct callout *, int);

#endif /* _SYS_CALLOUT_H_ */
