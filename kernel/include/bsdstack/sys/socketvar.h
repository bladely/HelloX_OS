#ifndef _SYS_SOCKETVAR_H_
#define _SYS_SOCKETVAR_H_

#include "kqueue.h"			/* for TAILQ macros */
#include "selinfo.h"		/* for struct selinfo */
#include "libkern.h"

#define	ACCEPT_LOCK_ASSERT()		
#define	ACCEPT_UNLOCK_ASSERT()		
#define	ACCEPT_LOCK()			
#define	ACCEPT_UNLOCK()		
#define	SOCK_MTX(_so)			
#define	SOCK_LOCK(_so)			
#define	SOCK_OWNED(_so)			
#define	SOCK_UNLOCK(_so)		
#define	SOCK_LOCK_ASSERT(_so)		
#define KNOTE_UNLOCKED(so, num)
#define FILE_LOCK(so)
#define	SOCKBUF_MTX(_sb)		
#define	SOCKBUF_LOCK_INIT(_sb, _name) 
#define	SOCKBUF_LOCK_DESTROY(_sb)	
#define	SOCKBUF_LOCK(_sb)		
#define	SOCKBUF_OWNED(_sb)		
#define	SOCKBUF_UNLOCK(_sb)		
#define	SOCKBUF_LOCK_ASSERT(_sb)	
#define	SOCKBUF_UNLOCK_ASSERT(_sb)	
#define PROC_LOCK(p)
#define PROC_UNLOCK(p)
#define INP_INFO_RUNLOCK(p)
#define INP_INFO_RLOCK(p)
#define INP_LOCK(p)
#define INP_UNLOCK(p)
#define	NET_LOCK_GIANT() 
#define NET_UNLOCK_GIANT()  
#define	NET_ASSERT_GIANT()

#define M_SONAME 0

#define RADIX_NODE_HEAD_LOCK(rt)
#define RADIX_NODE_HEAD_UNLOCK(rt)
#define IFF_LOCKGIANT(ifp)
#define IFF_UNLOCKGIANT(ifp)

#define INP_LOCK_INIT(inp, d, t) 
#define INP_LOCK_DESTROY(inp)	
#define INP_LOCK(inp)		
#define INP_UNLOCK(inp)		
#define INP_LOCK_ASSERT(inp)	

#define KNOTE_LOCKED(d, k)
#define callout_init_mtx(c, mtx, flags)
#define	mtx_initialized(m)	
#define mtx_init(m, name, type, opts)
#define mtx_owned(m)	1
#define mtx_destroy(a)
#define mtx_recursed(m)	
#define mtx_assert(m, what)	(void)0

#define mtx_name(m)	
#define UIDINFO_LOCK(m)
#define UIDINFO_UNLOCK(m)

#define IF_AFDATA_TRYLOCK(m)
#define IF_AFDATA_UNLOCK(m)

#define KQ_LOCK(m)
#define KQ_UNLOCK(m)
#define RADIX_NODE_HEAD_LOCK_ASSERT(m)
#define mtx_lock_spin(m)
#define mtx_unlock_spin(m)

#define FILEDESC_LOCK(m)
#define FILEDESC_UNLOCK(m)

/*
 * Flags to sblock().
 */
#define	SBL_WAIT	0x00000001	/* Wait if not immediately available. */
#define	SBL_NOINTR	0x00000002	/* Force non-interruptible sleep. */
#define	SBL_VALID	(SBL_WAIT | SBL_NOINTR)

/*
 * Kernel structure per socket.
 * Contains send and receive buffer queues,
 * handle on protocol and pointer to protocol
 * private data and error information.
 */
typedef	u_quad_t so_gen_t;

/*-
 * Locking key to struct socket:
 * (a) constant after allocation, no locking required.
 * (b) locked by SOCK_LOCK(so).
 * (c) locked by SOCKBUF_LOCK(&so->so_rcv).
 * (d) locked by SOCKBUF_LOCK(&so->so_snd).
 * (e) locked by ACCEPT_LOCK().
 * (f) not locked since integer reads/writes are atomic.
 * (g) used only as a sleep/wakeup address, no value.
 * (h) locked by global mutex so_global_mtx.
 */
struct socket {
	int	so_count;		/* (b) reference count */
	short	so_type;		/* (a) generic type, see socket.h */
	short	so_options;		/* from socket call, see socket.h */
	short	so_linger;		/* time to linger while closing */
	short	so_state;		/* (b) internal state flags SS_* */
	int	so_qstate;		/* (e) internal state flags SQ_* */
	void	*so_pcb;		/* protocol control block */
	struct	protosw *so_proto;	/* (a) protocol handle */
/*
 * Variables for connection queuing.
 * Socket where accepts occur is so_head in all subsidiary sockets.
 * If so_head is 0, socket is not related to an accept.
 * For head socket so_incomp queues partially completed connections,
 * while so_comp is a queue of connections ready to be accepted.
 * If a connection is aborted and it has so_head set, then
 * it has to be pulled out of either so_incomp or so_comp.
 * We allow connections to queue up based on current queue lengths
 * and limit on number of queued connections for this socket.
 */
	struct	socket *so_head;	/* (e) back pointer to accept socket */
	//TAILQ_HEAD(, socket) so_incomp;	/* (e) queue of partial unaccepted connections */
	struct  {								\
		struct socket *tqh_first;	/* first element */			\
		struct socket **tqh_last;	/* addr of last next element */		\
		TRACEBUF							\
	}so_incomp;
	//TAILQ_HEAD(, socket) so_comp;	/* (e) queue of complete unaccepted connections */
	struct  {								\
		struct socket *tqh_first;	/* first element */			\
		struct socket **tqh_last;	/* addr of last next element */		\
		TRACEBUF							\
	}so_comp;
	//TAILQ_ENTRY(socket) so_list;	/* (e) list of unaccepted connections */
	struct  {								\
		struct socket *tqe_next;	/* first element */			\
		struct socket **tqe_prev;	/* addr of last next element */		\
		TRACEBUF							\
	}so_list;
	short	so_qlen;		/* (e) number of unaccepted connections */
	short	so_incqlen;		/* (e) number of unaccepted incomplete
					   connections */
	short	so_qlimit;		/* (e) max number queued connections */
	short	so_timeo;		/* (g) connection timeout */
	u_short	so_error;		/* (f) error affecting connection */
	struct	sigio *so_sigio;	/* [sg] information for async I/O or
					   out of band data (SIGURG) */
	u_long	so_oobmark;		/* (c) chars to oob mark */
	//TAILQ_HEAD(, aiocblist) so_aiojobq; /* AIO ops waiting on socket */
	struct  {								\
		struct aiocblist *tqh_first;	/* first element */			\
		struct aiocblist **tqh_last;	/* addr of last next element */		\
		TRACEBUF							\
	}so_aiojobq;
/*
 * Variables for socket buffering.
 */
	struct sockbuf {
		struct	selinfo sb_sel;	/* process selecting read/write */
#define	sb_startzero	sb_mb
		struct	mbuf *sb_mb;	/* (c/d) the mbuf chain */
		struct	mbuf *sb_mbtail; /* (c/d) the last mbuf in the chain */
		struct	mbuf *sb_lastrecord;	/* (c/d) first mbuf of last
						 * record in socket buffer */
		u_int	sb_cc;		/* (c/d) actual chars in buffer */
		u_int	sb_hiwat;	/* (c/d) max actual char count */
		u_int	sb_mbcnt;	/* (c/d) chars of mbufs used */
		u_int	sb_mbmax;	/* (c/d) max chars of mbufs to use */
		u_int	sb_ctl;		/* (c/d) non-data chars in buffer */
		int	sb_lowat;	/* (c/d) low water mark */
		int	sb_timeo;	/* (c/d) timeout for read/write */
		short	sb_flags;	/* (c/d) flags, see below */
		short	sb_state;	/* (c/d) socket state on sockbuf */
	} so_rcv, so_snd;
/*
 * Constants for sb_flags field of struct sockbuf.
 */
#define	SB_MAX		(256*1024)	/* default for max chars in sockbuf */
/*
 * Constants for sb_flags field of struct sockbuf.
 */
#define	SB_LOCK		0x01		/* lock on data queue */
#define	SB_WANT		0x02		/* someone is waiting to lock */
#define	SB_WAIT		0x04		/* someone is waiting for data/space */
#define	SB_SEL		0x08		/* someone is selecting */
#define	SB_ASYNC	0x10		/* ASYNC I/O, need signals */
#define	SB_UPCALL	0x20		/* someone wants an upcall */
#define	SB_NOINTR	0x40		/* operations not interruptible */
#define SB_AIO		0x80		/* AIO operations queued */
#define SB_KNOTE	0x100		/* kernel note attached */

	void	(*so_upcall)(struct socket *, void *, int);
	void	*so_upcallarg;
	struct	ucred *so_cred;		/* (a) user credentials */
	struct	label *so_label;	/* (b) MAC label for socket */
	struct	label *so_peerlabel;	/* (b) cached MAC label for peer */
	/* NB: generation count must not be first; easiest to make it last. */
	so_gen_t so_gencnt;		/* (h) generation count */
	void	*so_emuldata;		/* private data for emulators */
 	struct so_accf {
		struct	accept_filter *so_accept_filter;
		void	*so_accept_filter_arg;	/* saved filter args */
		char	*so_accept_filter_str;	/* saved user args */
	} *so_accf;
};

#define SB_EMPTY_FIXUP(sb) do {						\
	if ((sb)->sb_mb == NULL) {					\
		(sb)->sb_mbtail = NULL;					\
		(sb)->sb_lastrecord = NULL;				\
	}								\
} while (/*CONSTCOND*/0)


/*
 * Socket state bits.
 *
 * Historically, this bits were all kept in the so_state field.  For
 * locking reasons, they are now in multiple fields, as they are
 * locked differently.  so_state maintains basic socket state protected
 * by the socket lock.  so_qstate holds information about the socket
 * accept queues.  Each socket buffer also has a state field holding
 * information relevant to that socket buffer (can't send, rcv).  Many
 * fields will be read without locks to improve performance and avoid
 * lock order issues.  However, this approach must be used with caution.
 */
#define	SS_NOFDREF		0x0001	/* no file table ref any more */
#define	SS_ISCONNECTED		0x0002	/* socket connected to a peer */
#define	SS_ISCONNECTING		0x0004	/* in process of connecting to peer */
#define	SS_ISDISCONNECTING	0x0008	/* in process of disconnecting */
#define	SS_NBIO			0x0100	/* non-blocking ops */
#define	SS_ASYNC		0x0200	/* async i/o notify */
#define	SS_ISCONFIRMING		0x0400	/* deciding to accept connection req */
#define	SS_ISDISCONNECTED	0x2000	/* socket disconnected from peer */

/*
 * Socket state bits now stored in the socket buffer state field.
 */
#define	SBS_CANTSENDMORE	0x0010	/* can't send more data to peer */
#define	SBS_CANTRCVMORE		0x0020	/* can't receive more data from peer */
#define	SBS_RCVATMARK		0x0040	/* at mark on input */

/*
 * Socket state bits stored in so_qstate.
 */
#define	SQ_INCOMP		0x0800	/* unaccepted, incomplete connection */
#define	SQ_COMP			0x1000	/* unaccepted, complete connection */

/*
 * Macros for sockets and socket buffering.
 */

/*
 * Do we need to notify the other side when I/O is possible?
 */
#define	sb_notify(sb)	(((sb)->sb_flags & (SB_WAIT | SB_SEL | SB_ASYNC | \
    SB_UPCALL | SB_AIO | SB_KNOTE)) != 0)

/*
 * How much space is there in a socket buffer (so->so_snd or so->so_rcv)?
 * This is problematical if the fields are unsigned, as the space might
 * still be negative (cc > hiwat or mbcnt > mbmax).  Should detect
 * overflow and return 0.  Should use "lmin" but it doesn't exist now.
 */
#define	sbspace(sb) \
    ((long) imin((int)((sb)->sb_hiwat - (sb)->sb_cc), \
	 (int)((sb)->sb_mbmax - (sb)->sb_mbcnt)))

/* do we have to send all at once on a socket? */
#define	sosendallatonce(so) \
    ((so)->so_proto->pr_flags & PR_ATOMIC)

/* can we read something from so? */
#define	soreadable(so) \
    ((so)->so_rcv.sb_cc >= (so)->so_rcv.sb_lowat || \
	((so)->so_rcv.sb_state & SBS_CANTRCVMORE) || \
	!TAILQ_EMPTY(&(so)->so_comp) || (so)->so_error)

/* can we write something to so? */
#define	sowriteable(so) \
    ((sbspace(&(so)->so_snd) >= (so)->so_snd.sb_lowat && \
	(((so)->so_state&SS_ISCONNECTED) || \
	  ((so)->so_proto->pr_flags&PR_CONNREQUIRED)==0)) || \
     ((so)->so_snd.sb_state & SBS_CANTSENDMORE) || \
     (so)->so_error)

/* adjust counters in sb reflecting allocation of m */
#define	sballoc(sb, m) { \
	(sb)->sb_cc += (m)->m_len; \
	if ((m)->m_type != MT_DATA && (m)->m_type != MT_HEADER && \
	    (m)->m_type != MT_OOBDATA) \
		(sb)->sb_ctl += (m)->m_len; \
	(sb)->sb_mbcnt += MSIZE; \
	if ((m)->m_flags & M_EXT) \
		(sb)->sb_mbcnt += (m)->m_ext.ext_size; \
}

/* adjust counters in sb reflecting freeing of m */
#define	sbfree(sb, m) { \
	(sb)->sb_cc -= (m)->m_len; \
	if ((m)->m_type != MT_DATA && (m)->m_type != MT_HEADER && \
	    (m)->m_type != MT_OOBDATA) \
		(sb)->sb_ctl -= (m)->m_len; \
	(sb)->sb_mbcnt -= MSIZE; \
	if ((m)->m_flags & M_EXT) \
		(sb)->sb_mbcnt -= (m)->m_ext.ext_size; \
}

/*
 * Set lock on sockbuf sb; sleep if lock is already held.
 * Unless SB_NOINTR is set on sockbuf, sleep is interruptible.
 * Returns error without lock if sleep is interrupted.
 */
#define sblock(sb, wf) 

/* release lock on sockbuf sb */
#define	sbunlock(sb) 

/*
 * soref()/sorele() ref-count the socket structure.  Note that you must
 * still explicitly close the socket, but the last ref count will free
 * the structure.
 */
#define	soref(so) do {							\
	++(so)->so_count;						\
} while (0)

#define	sorele(so) do {							\
	/* if ((so)->so_count <= 0)	*/				\
	/* 	printf("sorele");	LUOYU	*/			\
	if (--(so)->so_count == 0)					\
		sofree(so);						\
	else {								\
	}								\
} while (0)

#define	sotryfree(so) do {						\
	ACCEPT_LOCK_ASSERT();						\
	SOCK_LOCK_ASSERT(so);						\
	if ((so)->so_count == 0)					\
		sofree(so);						\
	else {								\
		SOCK_UNLOCK(so);					\
		ACCEPT_UNLOCK();					\
	}								\
} while(0)

/*
 * In sorwakeup() and sowwakeup(), acquire the socket buffer lock to
 * avoid a non-atomic test-and-wakeup.  However, sowakeup is
 * responsible for releasing the lock if it is called.  We unlock only
 * if we don't call into sowakeup.  If any code is introduced that
 * directly invokes the underlying sowakeup() primitives, it must
 * maintain the same semantics.
 */
#define	sorwakeup_locked(so) do {					\
	SOCKBUF_LOCK_ASSERT(&(so)->so_rcv);				\
	if (sb_notify(&(so)->so_rcv))					\
		sowakeup((so), &(so)->so_rcv);	 			\
	else								\
		SOCKBUF_UNLOCK(&(so)->so_rcv);				\
} while (0)

#define	sorwakeup(so) do {						\
	SOCKBUF_LOCK(&(so)->so_rcv);					\
	sorwakeup_locked(so);						\
} while (0)

#define	sowwakeup_locked(so) do {					\
	SOCKBUF_LOCK_ASSERT(&(so)->so_snd);				\
	if (sb_notify(&(so)->so_snd))					\
		sowakeup((so), &(so)->so_snd); 				\
	else								\
		SOCKBUF_UNLOCK(&(so)->so_snd);				\
} while (0)

#define	sowwakeup(so) do {						\
	SOCKBUF_LOCK(&(so)->so_snd);					\
	sowwakeup_locked(so);						\
} while (0)

/*
 * Argument structure for sosetopt et seq.  This is in the KERNEL
 * section because it will never be visible to user code.
 */
enum sopt_dir { SOPT_GET, SOPT_SET };
struct sockopt {
	enum	sopt_dir sopt_dir; /* is this a get or a set? */
	int	sopt_level;	/* second arg of [gs]etsockopt */
	int	sopt_name;	/* third arg of [gs]etsockopt */
	void   *sopt_val;	/* fourth arg of [gs]etsockopt */
	size_t	sopt_valsize;	/* (almost) fifth arg of [gs]etsockopt */
	struct	thread *sopt_td; /* calling thread or null if kernel */
};
/*
struct accept_filter {
	char	accf_name[16];
	void	(*accf_callback)
		(struct socket *so, void *arg, int waitflag);
	void *	(*accf_create)
		(struct socket *so, char *arg);
	void	(*accf_destroy)
		(struct socket *so);
	SLIST_ENTRY(accept_filter) accf_next;
};
*/

extern int	maxsockets;
extern u_long	sb_max;
extern struct uma_zone *socket_zone;
extern so_gen_t so_gencnt;

struct mbuf;
struct sockaddr;
struct ucred;
struct uio;
struct	socket *soalloc(int mflags);
void	sofree(struct socket *so);
void	sorflush(struct socket *so);
void	sbrelease_locked(struct sockbuf *sb, struct socket *so);
void	socantsendmore_locked(struct socket *so);
void	sbrelease(struct sockbuf *sb, struct socket *so);
void	socantrcvmore_locked(struct socket *so);
int	sobind(struct socket *so, struct sockaddr *nam, struct thread *td);
int	getsockaddr(struct sockaddr **namp, caddr_t uaddr, size_t len);
void fputsock(struct socket *sp);
int	solisten(struct socket *so, int backlog, struct thread *td);
int	soaccept(struct socket *so, struct sockaddr **nam);
int	soconnect(struct socket *so, struct sockaddr *nam, struct thread *td);
int	sodisconnect(struct socket *so);
int	sockargs(struct mbuf **mp, caddr_t buf, int buflen, int type);
int	sosend(struct socket *so, struct sockaddr *addr, struct uio *uio,
	    struct mbuf *top, struct mbuf *control, int flags,
	    struct thread *td);
int	soreceive(struct socket *so, struct sockaddr **paddr, struct uio *uio,
	    struct mbuf **mp0, struct mbuf **controlp, int *flagsp);
int	soreserve(struct socket *so, u_long sndcc, u_long rcvcc);
void	sorflush(struct socket *so);
void	sbflush(struct sockbuf *sb);
void	sbflush_locked(struct sockbuf *sb);
void	sbinsertoob(struct sockbuf *sb, struct mbuf *m0);
void	sbinsertoob_locked(struct sockbuf *sb, struct mbuf *m0);
int	sbreserve(struct sockbuf *sb, u_long cc, struct socket *so,
	    struct thread *td);
int	sbreserve_locked(struct sockbuf *sb, u_long cc, struct socket *so,
	    struct thread *td);
void	sbdrop(struct sockbuf *sb, int len);
void	sbdrop_locked(struct sockbuf *sb, int len);
void	sbdroprecord(struct sockbuf *sb);
void	sbdroprecord_locked(struct sockbuf *sb);
int	sopoll(struct socket *so, int events, struct ucred *active_cred,
	    struct thread *td);
void	sowakeup(struct socket *so, struct sockbuf *sb);
void	soisconnected(struct socket *so);
void	soisconnecting(struct socket *so);
void	soisdisconnected(struct socket *so);
void	soisdisconnecting(struct socket *so);
int	solisten(struct socket *so, int backlog, struct thread *td);
int	socreate(int dom, struct socket **aso, int type, int proto,
	    struct ucred *cred, struct thread *td);
int	soclose(struct socket *so);
void	sodealloc(struct socket *so);

struct socket *
	sonewconn(struct socket *head, int connstatus);
int	sooptcopyin(struct sockopt *sopt, void *buf, size_t len, size_t minlen);
int	sooptcopyout(struct sockopt *sopt, const void *buf, size_t len);
	    
#ifdef SOCKBUF_DEBUG
void	sblastrecordchk(struct sockbuf *, const char *, int);
#define	SBLASTRECORDCHK(sb)	sblastrecordchk((sb), __FILE__, __LINE__)

void	sblastmbufchk(struct sockbuf *, const char *, int);
#define	SBLASTMBUFCHK(sb)	sblastmbufchk((sb), __FILE__, __LINE__)
#else
#define	SBLASTRECORDCHK(sb)      /* nothing */
#define	SBLASTMBUFCHK(sb)        /* nothing */
#endif /* SOCKBUF_DEBUG */

#endif /* !_SYS_SOCKETVAR_H_ */
