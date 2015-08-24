#include "bsdsys.h"
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
#include "ktime.h"
#include "bsdif.h"
#include "in_pcb.h"
#include "in_var.h"
#include "tcp_var.h"
#include "tcp_fsm.h"
#include "bsdip.h"
#include "kroute.h"
#include "tcp_ip.h"
#include "netisr.h"

int	maxsockets = 100;

u_long	sb_max = SB_MAX;
static	u_long sb_max_adj =
    SB_MAX * MCLBYTES / (MSIZE + MCLBYTES); /* adjusted sb_max */

static	u_long sb_efficiency = 8;	/* parameter for sbreserve() */



/*
 * Procedures to manipulate state flags of socket
 * and do appropriate wakeups.  Normal sequence from the
 * active (originating) side is that soisconnecting() is
 * called during processing of connect() call,
 * resulting in an eventual call to soisconnected() if/when the
 * connection is established.  When the connection is torn down
 * soisdisconnecting() is called during processing of disconnect() call,
 * and soisdisconnected() is called when the connection to the peer
 * is totally severed.  The semantics of these routines are such that
 * connectionless protocols can call soisconnected() and soisdisconnected()
 * only, bypassing the in-progress calls when setting up a ``connection''
 * takes no time.
 *
 * From the passive side, a socket is created with
 * two queues of sockets: so_incomp for connections in progress
 * and so_comp for connections already made and awaiting user acceptance.
 * As a protocol is preparing incoming connections, it creates a socket
 * structure queued on so_incomp by calling sonewconn().  When the connection
 * is established, soisconnected() is called, and transfers the
 * socket structure to so_comp, making it available to accept().
 *
 * If a socket is closed with sockets on either
 * so_incomp or so_comp, these sockets are dropped.
 *
 * If higher level protocols are implemented in
 * the kernel, the wakeups done here will sometimes
 * cause software-interrupt process scheduling.
 */

void
soisconnecting(so)
register struct socket *so;
{

    SOCK_LOCK(so);
    so->so_state &= ~(SS_ISCONNECTED | SS_ISDISCONNECTING);
    so->so_state |= SS_ISCONNECTING;
    SOCK_UNLOCK(so);
}

void
soisconnected(so)
struct socket *so;
{
    struct socket *head;

    SOCK_LOCK(so);
    so->so_state &= ~(SS_ISCONNECTING | SS_ISDISCONNECTING | SS_ISCONFIRMING);
    so->so_state |= SS_ISCONNECTED;
    SOCK_UNLOCK(so);
    ACCEPT_LOCK();
    head = so->so_head;
    if (head != NULL && (so->so_qstate & SQ_INCOMP))
    {
        if ((so->so_options & SO_ACCEPTFILTER) == 0)
        {
            TAILQ_REMOVE(&head->so_incomp, so, so_list);
            head->so_incqlen--;
            so->so_qstate &= ~SQ_INCOMP;
            TAILQ_INSERT_TAIL(&head->so_comp, so, so_list);
            head->so_qlen++;
            so->so_qstate |= SQ_COMP;
            ACCEPT_UNLOCK();
            sorwakeup(head);
            wakeup_one(&head->so_timeo);
        }
        else
        {
            ACCEPT_UNLOCK();
            SOCK_LOCK(so);
            //so->so_upcall =LUOYU
            //    head->so_accf->so_accept_filter->accf_callback;
            //so->so_upcallarg = head->so_accf->so_accept_filter_arg;
            so->so_rcv.sb_flags |= SB_UPCALL;
            so->so_options &= ~SO_ACCEPTFILTER;
            SOCK_UNLOCK(so);
            //so->so_upcall(so, so->so_upcallarg, M_TRYWAIT);
        }
        return;
    }
    ACCEPT_UNLOCK();
    wakeup(&so->so_timeo);
    sorwakeup(so);
    sowwakeup(so);
}

void
soisdisconnecting(so)
register struct socket *so;
{

    /*
     * XXXRW: This code separately acquires SOCK_LOCK(so) and
     * SOCKBUF_LOCK(&so->so_rcv) even though they are the same mutex to
     * avoid introducing the assumption  that they are the same.
     */
    SOCK_LOCK(so);
    so->so_state &= ~SS_ISCONNECTING;
    so->so_state |= SS_ISDISCONNECTING;
    SOCK_UNLOCK(so);
    SOCKBUF_LOCK(&so->so_rcv);
    so->so_rcv.sb_state |= SBS_CANTRCVMORE;
    sorwakeup_locked(so);
    SOCKBUF_LOCK(&so->so_snd);
    so->so_snd.sb_state |= SBS_CANTSENDMORE;
    sowwakeup_locked(so);
    wakeup(&so->so_timeo);
}

/*
 * When an attempt at a new connection is noted on a socket
 * which accepts connections, sonewconn is called.  If the
 * connection is possible (subject to space constraints, etc.)
 * then we allocate a new structure, propoerly linked into the
 * data structure of the original socket, and return this.
 * Connstatus may be 0, or SO_ISCONFIRMING, or SO_ISCONNECTED.
 *
 * note: the ref count on the socket is 0 on return
 */
struct socket *
sonewconn(head, connstatus)
register struct socket *head;
int connstatus;
{
    register struct socket *so;
    int over;

    ACCEPT_LOCK();
    over = (head->so_qlen > 3 * head->so_qlimit / 2);
    ACCEPT_UNLOCK();
    if (over)
        return ((struct socket *)0);
    so = soalloc(M_NOWAIT);
    if (so == NULL)
        return ((struct socket *)0);
    if ((head->so_options & SO_ACCEPTFILTER) != 0)
        connstatus = 0;
    so->so_head = head;
    so->so_type = head->so_type;
    so->so_options = head->so_options &~ SO_ACCEPTCONN;
    so->so_linger = head->so_linger;
    so->so_state = head->so_state | SS_NOFDREF;
    so->so_proto = head->so_proto;
    so->so_timeo = head->so_timeo;
    //so->so_cred = crhold(head->so_cred);
    //knlist_init(&so->so_rcv.sb_sel.si_note, SOCKBUF_MTX(&so->so_rcv));LUOYU
    //knlist_init(&so->so_snd.sb_sel.si_note, SOCKBUF_MTX(&so->so_snd));
    if (soreserve(so, head->so_snd.sb_hiwat, head->so_rcv.sb_hiwat) ||
            (*so->so_proto->pr_usrreqs->pru_attach)(so, 0, NULL))
    {
        sodealloc(so);
        return ((struct socket *)0);
    }
    ACCEPT_LOCK();
    if (connstatus)
    {
        TAILQ_INSERT_TAIL(&head->so_comp, so, so_list);
        so->so_qstate |= SQ_COMP;
        head->so_qlen++;
    }
    else
    {
        /*
         * XXXRW: Keep removing sockets from the head until there's
         * room for us to insert on the tail.  In pre-locking
         * revisions, this was a simple if(), but as we could be
         * racing with other threads and soabort() requires dropping
         * locks, we must loop waiting for the condition to be true.
         */
        while (head->so_incqlen > head->so_qlimit)
        {
            struct socket *sp;
            sp = TAILQ_FIRST(&head->so_incomp);
            TAILQ_REMOVE(&so->so_incomp, sp, so_list);
            head->so_incqlen--;
            sp->so_qstate &= ~SQ_INCOMP;
            sp->so_head = NULL;
            ACCEPT_UNLOCK();
            (void) soabort(sp);
            ACCEPT_LOCK();
        }
        TAILQ_INSERT_TAIL(&head->so_incomp, so, so_list);
        so->so_qstate |= SQ_INCOMP;
        head->so_incqlen++;
    }
    ACCEPT_UNLOCK();
    if (connstatus)
    {
        so->so_state |= connstatus;
        sorwakeup(head);
        wakeup_one(&head->so_timeo);
    }
    return (so);
}

/*
 * Drop data from (the front of) a sockbuf.
 */
void
sbdrop_locked(sb, len)
register struct sockbuf *sb;
register int len;
{
    register struct mbuf *m;
    struct mbuf *next;

    SOCKBUF_LOCK_ASSERT(sb);

    next = (m = sb->sb_mb) ? m->m_nextpkt : 0;
    while (len > 0)
    {
        if (m == 0)
        {
            if (next == 0)
                panic("sbdrop");
            m = next;
            next = m->m_nextpkt;
            continue;
        }
        if (m->m_len > len)
        {
            m->m_len -= len;
            m->m_data += len;
            sb->sb_cc -= len;
            if (m->m_type != MT_DATA && m->m_type != MT_HEADER &&
                    m->m_type != MT_OOBDATA)
                sb->sb_ctl -= len;
            break;
        }
        len -= m->m_len;
        sbfree(sb, m);
        m = m_free(m);
    }
    while (m && m->m_len == 0)
    {
        sbfree(sb, m);
        m = m_free(m);
    }
    if (m)
    {
        sb->sb_mb = m;
        m->m_nextpkt = next;
    }
    else
        sb->sb_mb = next;
    /*
     * First part is an inline SB_EMPTY_FIXUP().  Second part
     * makes sure sb_lastrecord is up-to-date if we dropped
     * part of the last record.
     */
    m = sb->sb_mb;
    if (m == NULL)
    {
        sb->sb_mbtail = NULL;
        sb->sb_lastrecord = NULL;
    }
    else if (m->m_nextpkt == NULL)
    {
        sb->sb_lastrecord = m;
    }
}

/*
 * Free all mbufs in a sockbuf.
 * Check that all resources are reclaimed.
 */
void
sbflush_locked(sb)
register struct sockbuf *sb;
{

    SOCKBUF_LOCK_ASSERT(sb);

    if (sb->sb_flags & SB_LOCK)
        panic("sbflush_locked: locked");
    while (sb->sb_mbcnt)
    {
        /*
         * Don't call sbdrop(sb, 0) if the leading mbuf is non-empty:
         * we would loop forever. Panic instead.
         */
        if (!sb->sb_cc && (sb->sb_mb == NULL || sb->sb_mb->m_len))
            break;
        sbdrop_locked(sb, (int)sb->sb_cc);
    }
    if (sb->sb_cc || sb->sb_mb || sb->sb_mbcnt)
        panic("sbflush_locked: cc %u || mb %p || mbcnt %u", sb->sb_cc, (void *)sb->sb_mb, sb->sb_mbcnt);
}

void
sbflush(sb)
register struct sockbuf *sb;
{

    SOCKBUF_LOCK(sb);
    sbflush_locked(sb);
    SOCKBUF_UNLOCK(sb);
}

void
soisdisconnected(so)
register struct socket *so;
{

    /*
     * XXXRW: This code separately acquires SOCK_LOCK(so) and
     * SOCKBUF_LOCK(&so->so_rcv) even though they are the same mutex to
     * avoid introducing the assumption  that they are the same.
     */
    /* XXXRW: so_state locking? */
    SOCK_LOCK(so);
    so->so_state &= ~(SS_ISCONNECTING | SS_ISCONNECTED | SS_ISDISCONNECTING);
    so->so_state |= SS_ISDISCONNECTED;
    SOCK_UNLOCK(so);
    SOCKBUF_LOCK(&so->so_rcv);
    so->so_rcv.sb_state |= SBS_CANTRCVMORE;
    sorwakeup_locked(so);
    SOCKBUF_LOCK(&so->so_snd);
    so->so_snd.sb_state |= SBS_CANTSENDMORE;
    sbdrop_locked(&so->so_snd, so->so_snd.sb_cc);
    sowwakeup_locked(so);
    wakeup(&so->so_timeo);
}


/*
 * Free mbufs held by a socket, and reserved mbuf space.
 */
void
sbrelease_locked(sb, so)
struct sockbuf *sb;
struct socket *so;
{
}

/*
 * Socantsendmore indicates that no more data will be sent on the
 * socket; it would normally be applied to a socket when the user
 * informs the system that no more data is to be sent, by the protocol
 * code (in case PRU_SHUTDOWN).  Socantrcvmore indicates that no more data
 * will be received, and will normally be applied to the socket by a
 * protocol when it detects that the peer will send no more data.
 * Data queued for reading in the socket may yet be read.
 */
void
socantsendmore_locked(so)
struct socket *so;
{

}
void
sbrelease(sb, so)
struct sockbuf *sb;
struct socket *so;
{
}

void
socantrcvmore_locked(so)
struct socket *so;
{

}

/*
 * Wait for data to arrive at/drain from a socket buffer.
 */
int
sbwait(sb)
struct sockbuf *sb;
{

    SOCKBUF_LOCK_ASSERT(sb);

    sb->sb_flags |= SB_WAIT;
    return (msleep(&sb->sb_cc, NULL, //&sb->sb_mtx,
                   (sb->sb_flags & SB_NOINTR) ? PSOCK : PSOCK | PCATCH, "sbwait",
                   sb->sb_timeo));
}
#ifndef _RLIM_T_DECLARED
typedef	__rlim_t	rlim_t;		/* resource limit */
#define	_RLIM_T_DECLARED
#endif
#define	RLIM_INFINITY	((rlim_t)(((u_quad_t)1 << 63) - 1))

int g_ui_sbsize = 1024;
/*
 * Change the total socket buffer size a user has used.
 */
int
chgsbsize(uip, hiwat, to, max)
struct	uidinfo	*uip;
u_int  *hiwat;
u_int	to;
rlim_t	max;
{
    rlim_t new;

    UIDINFO_LOCK(uip);
    //new = uip->ui_sbsize + to - *hiwat;LUOYU
    new = g_ui_sbsize + to - *hiwat;
    /* Don't allow them to exceed max, but allow subtraction */
    if (to > *hiwat && new > max)
    {
        UIDINFO_UNLOCK(uip);
        return (0);
    }
    //uip->ui_sbsize = new;
    g_ui_sbsize = new;
    UIDINFO_UNLOCK(uip);
    *hiwat = to;
    if (new < 0)
        printf("negative sbsize for uid = %d\n", g_ui_sbsize);
    return (1);
}

/*
 * Allot mbufs to a sockbuf.
 * Attempt to scale mbmax so that mbcnt doesn't become limiting
 * if buffering efficiency is near the normal case.
 */
int
sbreserve_locked(sb, cc, so, td)
struct sockbuf *sb;
u_long cc;
struct socket *so;
struct thread *td;
{

    rlim_t sbsize_limit;

    SOCKBUF_LOCK_ASSERT(sb);

    /*
     * td will only be NULL when we're in an interrupt
     * (e.g. in tcp_input())
     */
    if (cc > sb_max_adj)
        return (0);
    if (td != NULL)
    {
        //PROC_LOCK(td->td_proc);
        //sbsize_limit = lim_cur(td->td_proc, RLIMIT_SBSIZE);
        //PROC_UNLOCK(td->td_proc);
    }
    else
        sbsize_limit = RLIM_INFINITY;
    if (!chgsbsize(NULL, &sb->sb_hiwat, cc,
                   sbsize_limit))
        return (0);
    sb->sb_mbmax = min(cc * sb_efficiency, sb_max);
    if (sb->sb_lowat > sb->sb_hiwat)
        sb->sb_lowat = sb->sb_hiwat;
    return (1);
}

/*
 * Socket buffer (struct sockbuf) utility routines.
 *
 * Each socket contains two socket buffers: one for sending data and
 * one for receiving data.  Each buffer contains a queue of mbufs,
 * information about the number of mbufs and amount of data in the
 * queue, and other fields allowing select() statements and notification
 * on data availability to be implemented.
 *
 * Data stored in a socket buffer is maintained as a list of records.
 * Each record is a list of mbufs chained together with the m_next
 * field.  Records are chained together with the m_nextpkt field. The upper
 * level routine soreceive() expects the following conventions to be
 * observed when placing information in the receive buffer:
 *
 * 1. If the protocol requires each message be preceded by the sender's
 *    name, then a record containing that name must be present before
 *    any associated data (mbuf's must be of type MT_SONAME).
 * 2. If the protocol supports the exchange of ``access rights'' (really
 *    just additional data associated with the message), and there are
 *    ``rights'' to be received, then a record containing this data
 *    should be present (mbuf's must be of type MT_RIGHTS).
 * 3. If a name or rights record exists, then it must be followed by
 *    a data record, perhaps of zero length.
 *
 * Before using a new socket structure it is first necessary to reserve
 * buffer space to the socket, by calling sbreserve().  This should commit
 * some of the available buffer space in the system buffer pool for the
 * socket (currently, it does nothing but enforce limits).  The space
 * should be released by calling sbrelease() when the socket is destroyed.
 */

int
soreserve(so, sndcc, rcvcc)
register struct socket *so;
u_long sndcc, rcvcc;
{
    //struct thread *td = curthread;

    SOCKBUF_LOCK(&so->so_snd);
    SOCKBUF_LOCK(&so->so_rcv);
    if (sbreserve_locked(&so->so_snd, sndcc, so, NULL) == 0)
        goto bad;
    if (sbreserve_locked(&so->so_rcv, rcvcc, so, NULL) == 0)
        goto bad2;
    if (so->so_rcv.sb_lowat == 0)
        so->so_rcv.sb_lowat = 1;
    if (so->so_snd.sb_lowat == 0)
        so->so_snd.sb_lowat = MCLBYTES;
    if (so->so_snd.sb_lowat > so->so_snd.sb_hiwat)
        so->so_snd.sb_lowat = so->so_snd.sb_hiwat;
    SOCKBUF_UNLOCK(&so->so_rcv);
    SOCKBUF_UNLOCK(&so->so_snd);
    return (0);
bad2:
    sbrelease_locked(&so->so_snd, so);
bad:
    SOCKBUF_UNLOCK(&so->so_rcv);
    SOCKBUF_UNLOCK(&so->so_snd);
    return (ENOBUFS);
}
/*
 * Some routines that return EOPNOTSUPP for entry points that are not
 * supported by a protocol.  Fill in as needed.
 */
int
pru_accept_notsupp(struct socket *so, struct sockaddr **nam)
{
    return EOPNOTSUPP;
}

int
pru_connect_notsupp(struct socket *so, struct sockaddr *nam, struct thread *td)
{
    return EOPNOTSUPP;
}

int
pru_connect2_notsupp(struct socket *so1, struct socket *so2)
{
    return EOPNOTSUPP;
}

int
pru_control_notsupp(struct socket *so, u_long cmd, caddr_t data,
                    struct ifnet *ifp, struct thread *td)
{
    return EOPNOTSUPP;
}

int
pru_listen_notsupp(struct socket *so, struct thread *td)
{
    return EOPNOTSUPP;
}

int
pru_rcvd_notsupp(struct socket *so, int flags)
{
    return EOPNOTSUPP;
}

int
pru_rcvoob_notsupp(struct socket *so, struct mbuf *m, int flags)
{
    return EOPNOTSUPP;
}

/*
 * This isn't really a ``null'' operation, but it's the default one
 * and doesn't do anything destructive.
 */
int
pru_sense_null(struct socket *so, struct stat *sb)
{
    //sb->st_blksize = so->so_snd.sb_hiwat;
    return 0;
}

/*
 * For protocol types that don't keep cached copies of labels in their
 * pcbs, provide a null sosetlabel that does a NOOP.
 */
void
pru_sosetlabel_null(struct socket *so)
{

}

/*
 * Drop a record off the front of a sockbuf
 * and move the next record to the front.
 */
void
sbdroprecord_locked(sb)
register struct sockbuf *sb;
{
#if 1
    register struct mbuf *m;

    SOCKBUF_LOCK_ASSERT(sb);

    m = sb->sb_mb;
    if (m)
    {
        sb->sb_mb = m->m_nextpkt;
        do
        {
            sbfree(sb, m);
            m = m_free(m);
        }
        while (m);
    }
    SB_EMPTY_FIXUP(sb);
#endif
}

/*
 * Make a copy of a sockaddr in a malloced buffer of type M_SONAME.
 */
struct sockaddr *
sodupsockaddr(const struct sockaddr *sa, int mflags)
{
    struct sockaddr *sa2;

    sa2 = malloc(sa->sa_len);
    if (sa2)
        bcopy(sa, sa2, sa->sa_len);
    return sa2;
}

void
socantsendmore(so)
struct socket *so;
{

    SOCKBUF_LOCK(&so->so_snd);
    socantsendmore_locked(so);
    //mtx_assert(SOCKBUF_MTX(&so->so_snd), MA_NOTOWNED);
}

/*
 * Compress mbuf chain m into the socket
 * buffer sb following mbuf n.  If n
 * is null, the buffer is presumed empty.
 */
void
sbcompress(sb, m, n)
register struct sockbuf *sb;
register struct mbuf *m, *n;
{
    register int eor = 0;
    register struct mbuf *o;

    SOCKBUF_LOCK_ASSERT(sb);

    while (m)
    {
        eor |= m->m_flags & M_EOR;
        if (m->m_len == 0 &&
                (eor == 0 ||
                 (((o = m->m_next) || (o = n)) &&
                  o->m_type == m->m_type)))
        {
            if (sb->sb_lastrecord == m)
                sb->sb_lastrecord = m->m_next;
            m = m_free(m);
            continue;
        }
        if (n && (n->m_flags & M_EOR) == 0 &&
                M_WRITABLE(n) &&
                m->m_len <= MCLBYTES / 4 && /* XXX: Don't copy too much */
                m->m_len <= M_TRAILINGSPACE(n) &&
                n->m_type == m->m_type)
        {
            bcopy(mtod(m, caddr_t), mtod(n, caddr_t) + n->m_len,
                  (unsigned)m->m_len);
            n->m_len += m->m_len;
            sb->sb_cc += m->m_len;
            if (m->m_type != MT_DATA && m->m_type != MT_HEADER &&
                    m->m_type != MT_OOBDATA)
                /* XXX: Probably don't need.*/
                sb->sb_ctl += m->m_len;
            m = m_free(m);
            continue;
        }
        if (n)
            n->m_next = m;
        else
            sb->sb_mb = m;
        sb->sb_mbtail = m;
        sballoc(sb, m);
        n = m;
        m->m_flags &= ~M_EOR;
        m = m->m_next;
        n->m_next = 0;
    }
    if (eor)
    {
        if (n)
            n->m_flags |= eor;
        else
            printf("semi-panic: sbcompress\n");
    }
    SBLASTMBUFCHK(sb);
}

/*
 * This version of sbappend() should only be used when the caller
 * absolutely knows that there will never be more than one record
 * in the socket buffer, that is, a stream protocol (such as TCP).
 */
void
sbappendstream_locked(struct sockbuf *sb, struct mbuf *m)
{
    SOCKBUF_LOCK_ASSERT(sb);

    KASSERT(m->m_nextpkt == NULL, ("sbappendstream 0"));
    KASSERT(sb->sb_mb == sb->sb_lastrecord, ("sbappendstream 1"));

    SBLASTMBUFCHK(sb);

    sbcompress(sb, m, sb->sb_mbtail);

    sb->sb_lastrecord = sb->sb_mb;
    SBLASTRECORDCHK(sb);
}

/*
 * This version of sbappend() should only be used when the caller
 * absolutely knows that there will never be more than one record
 * in the socket buffer, that is, a stream protocol (such as TCP).
 */
void
sbappendstream(struct sockbuf *sb, struct mbuf *m)
{

    SOCKBUF_LOCK(sb);
    sbappendstream_locked(sb, m);
    SOCKBUF_UNLOCK(sb);
}

/*
 * Create a "control" mbuf containing the specified data
 * with the specified type for presentation on a socket buffer.
 */
struct mbuf *
sbcreatecontrol(p, size, type, level)
caddr_t p;
register int size;
int type, level;
{
    register struct cmsghdr *cp;
    struct mbuf *m;

    if (CMSG_SPACE((u_int)size) > MCLBYTES)
        return ((struct mbuf *) NULL);
    if (CMSG_SPACE((u_int)size) > MLEN)
        m = m_getcl(M_DONTWAIT, MT_CONTROL, 0);
    else
        m = m_get(M_DONTWAIT, MT_CONTROL);
    if (m == NULL)
        return ((struct mbuf *) NULL);
    cp = mtod(m, struct cmsghdr *);
    m->m_len = 0;
    KASSERT(CMSG_SPACE((u_int)size) <= M_TRAILINGSPACE(m),
            ("sbcreatecontrol: short mbuf"));
    if (p != NULL)
        (void)memcpy(CMSG_DATA(cp), p, size);
    m->m_len = CMSG_SPACE(size);
    cp->cmsg_len = CMSG_LEN(size);
    cp->cmsg_level = level;
    cp->cmsg_type = type;
    return (m);
}

/*
 * Wakeup processes waiting on a socket buffer.  Do asynchronous
 * notification via SIGIO if the socket has the SS_ASYNC flag set.
 *
 * Called with the socket buffer lock held; will release the lock by the end
 * of the function.  This allows the caller to acquire the socket buffer lock
 * while testing for the need for various sorts of wakeup and hold it through
 * to the point where it's no longer required.  We currently hold the lock
 * through calls out to other subsystems (with the exception of kqueue), and
 * then release it to avoid lock order issues.  It's not clear that's
 * correct.
 */
void
sowakeup(so, sb)
register struct socket *so;
register struct sockbuf *sb;
{

    SOCKBUF_LOCK_ASSERT(sb);

    selwakeuppri(&sb->sb_sel, PSOCK);
    sb->sb_flags &= ~SB_SEL;
    if (sb->sb_flags & SB_WAIT)
    {
        sb->sb_flags &= ~SB_WAIT;
        wakeup(&sb->sb_cc);
    }
    KNOTE_LOCKED(&sb->sb_sel.si_note, 0);
    SOCKBUF_UNLOCK(sb);

    //if ((so->so_state & SS_ASYNC) && so->so_sigio != NULL)LUOYU
    //	pgsigio(&so->so_sigio, SIGIO, 0);
    //if (sb->sb_flags & SB_UPCALL)
    //	(*so->so_upcall)(so, so->so_upcallarg, M_DONTWAIT);
    //if (sb->sb_flags & SB_AIO)
    //	aio_swake(so, sb);
    //mtx_assert(SOCKBUF_MTX(sb), MA_NOTOWNED);
}

int
sbreserve(sb, cc, so, td)
struct sockbuf *sb;
u_long cc;
struct socket *so;
struct thread *td;
{
    int error;

    SOCKBUF_LOCK(sb);
    error = sbreserve_locked(sb, cc, so, td);
    SOCKBUF_UNLOCK(sb);
    return (error);
}
#define SBLINKRECORD(sb, m0) do {					\
	SOCKBUF_LOCK_ASSERT(sb);					\
	if ((sb)->sb_lastrecord != NULL)				\
		(sb)->sb_lastrecord->m_nextpkt = (m0);			\
	else								\
		(sb)->sb_mb = (m0);					\
	(sb)->sb_lastrecord = (m0);					\
} while (/*CONSTCOND*/0)

/*
 * Append address and data, and optionally, control (ancillary) data
 * to the receive queue of a socket.  If present,
 * m0 must include a packet header with total length.
 * Returns 0 if no space in sockbuf or insufficient mbufs.
 */
int
sbappendaddr_locked(sb, asa, m0, control)
struct sockbuf *sb;
const struct sockaddr *asa;
struct mbuf *m0, *control;
{
    struct mbuf *m, *n, *nlast;
    int space = asa->sa_len;

    SOCKBUF_LOCK_ASSERT(sb);

    if (m0 && (m0->m_flags & M_PKTHDR) == 0)
        panic("sbappendaddr_locked");
    if (m0)
        space += m0->m_pkthdr.len;
    space += m_length(control, &n);

    if (space > sbspace(sb))
        return (0);
#if MSIZE <= 256
    if (asa->sa_len > MLEN)
        return (0);
#endif
    MGET(m, M_DONTWAIT, MT_SONAME);
    if (m == 0)
        return (0);
    m->m_len = asa->sa_len;
    bcopy(asa, mtod(m, caddr_t), asa->sa_len);
    if (n)
        n->m_next = m0;		/* concatenate data to control */
    else
        control = m0;
    m->m_next = control;
    for (n = m; n->m_next != NULL; n = n->m_next)
        sballoc(sb, n);
    sballoc(sb, n);
    nlast = n;
    SBLINKRECORD(sb, m);

    sb->sb_mbtail = nlast;
    SBLASTMBUFCHK(sb);

    SBLASTRECORDCHK(sb);
    return (1);
}

/*
 * Append address and data, and optionally, control (ancillary) data
 * to the receive queue of a socket.  If present,
 * m0 must include a packet header with total length.
 * Returns 0 if no space in sockbuf or insufficient mbufs.
 */
int
sbappendaddr(sb, asa, m0, control)
struct sockbuf *sb;
const struct sockaddr *asa;
struct mbuf *m0, *control;
{
    int retval;

    SOCKBUF_LOCK(sb);
    retval = sbappendaddr_locked(sb, asa, m0, control);
    SOCKBUF_UNLOCK(sb);
    return (retval);
}

void
socantrcvmore(so)
struct socket *so;
{

    SOCKBUF_LOCK(&so->so_rcv);
    socantrcvmore_locked(so);
    //mtx_assert(SOCKBUF_MTX(&so->so_rcv), MA_NOTOWNED);
}

/*
 * Drop data from (the front of) a sockbuf.
 */
void
sbdrop(sb, len)
register struct sockbuf *sb;
register int len;
{

    SOCKBUF_LOCK(sb);
    sbdrop_locked(sb, len);
    SOCKBUF_UNLOCK(sb);
}

/*
 * Wait on a condition variable, allowing interruption by signals.  Return 0 if
 * the thread was resumed with cv_signal or cv_broadcast, EINTR or ERESTART if
 * a signal was caught.  If ERESTART is returned the system call should be
 * restarted if possible.
 */
int
cv_wait_sig(struct cv *cvp, struct mtx *mp)
{
    struct sleepqueue *sq;
    struct thread *td;
    int rval, sig;



    sq = sleepq_lookup(cvp);


    cvp->cv_waiters++;
    mtx_unlock(mp);

    //sleepq_add(sq, cvp, mp, cvp->cv_description, SLEEPQ_CONDVAR |
    //    SLEEPQ_INTERRUPTIBLE);

    return (rval);
}

/*
 * Wait on a condition variable for at most timo/hz seconds, allowing
 * interruption by signals.  Returns 0 if the thread was resumed by cv_signal
 * or cv_broadcast, EWOULDBLOCK if the timeout expires, and EINTR or ERESTART if
 * a signal was caught.
 */
int
cv_timedwait_sig(struct cv *cvp, struct mtx *mp, int timo)
{
    struct sleepqueue *sq;
    struct thread *td;
    int rval;
    int sig;

    rval = 0;


    sq = sleepq_lookup(cvp);

    /*
     * Don't bother sleeping if we are exiting and not the exiting
     * thread or if our thread is marked as interrupted.
     */
    cvp->cv_waiters++;
    mtx_unlock(mp);

    //sleepq_add(sq, cvp, mp, cvp->cv_description, SLEEPQ_CONDVAR |
    //    SLEEPQ_INTERRUPTIBLE);
    mtx_lock(mp);

    return (rval);
}

