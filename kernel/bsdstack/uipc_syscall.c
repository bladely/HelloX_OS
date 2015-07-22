#include "sys.h"
#include "sysproto.h"
#include "domain.h"
#include "protosw.h"
#include "mbuf.h"
#include "socket.h"
#include "socketvar.h"
#include "kfcntl.h"
#include "kmalloc.h"
#include "iocomm.h"
#include "syscallsubr.h"
#include "kselect.h"
#include "kpoll.h"
static int sendit(struct thread *td, int s, struct msghdr *mp, int flags);

/*
 * Like fget() but loads the underlying socket, or returns an error if
 * the descriptor does not represent a socket.
 *
 * We bump the ref count on the returned socket.  XXX Also obtain the SX
 * lock in the future.
 */
int
fgetsock(int fd, struct socket **spp, u_int *fflagp)
{
#if 0
	struct file *fp;
	int error;

	NET_ASSERT_GIANT();

	*spp = NULL;
	if (fflagp != NULL)
		*fflagp = 0;
	if ((error = _fget(td, fd, &fp, 0, 0)) != 0)
		return (error);
	if (fp->f_type != DTYPE_SOCKET) {
		error = ENOTSOCK;
	} else {
		*spp = fp->f_data;
		if (fflagp)
			*fflagp = fp->f_flag;
		SOCK_LOCK(*spp);
		soref(*spp);
		SOCK_UNLOCK(*spp);
	}
	FILEDESC_UNLOCK(td->td_proc->p_fd);
	return (error);
#endif
	return 0;
}

/*
 * Kernel descriptor table.
 * One entry for each open kernel vnode and socket.
 *
 * Below is the list of locks that protects members in struct file.
 *
 * (fl)	filelist_lock
 * (f)	f_mtx in struct file
 * none	not locked
 */

struct file {
	
	int	f_nextoff;	/*
				 * offset of next expected read or write
				 */
};

struct ucred;
typedef int fo_rdwr_t(struct file *fp, struct uio *uio,
		    struct ucred *active_cred, int flags,
		    struct thread *td);

#define	FOF_OFFSET	1	/* Use the offset in uio argument */
typedef	int fo_ioctl_t(struct file *fp, u_long com, void *data,
		    struct ucred *active_cred, struct thread *td);
typedef	int fo_poll_t(struct file *fp, int events,
		    struct ucred *active_cred, struct thread *td);
typedef	int fo_kqfilter_t(struct file *fp, struct knote *kn);
typedef	int fo_stat_t(struct file *fp, struct stat *sb,
		    struct ucred *active_cred, struct thread *td);
typedef	int fo_close_t(struct file *fp, struct thread *td);
typedef	int fo_flags_t;

/* ARGSUSED */
int
soo_read(fd, uio, active_cred, flags, td)
	struct socket *fd;
	struct uio *uio;
	struct ucred *active_cred;
	struct thread *td;
	int flags;
{
	struct socket *so;
	int error = 0;
	so = fd;
	error = so->so_proto->pr_usrreqs->pru_soreceive(so, 0, uio, 0, 0, 0);
	return (error);
}

/* ARGSUSED */
int
soo_write(fd, uio, active_cred, flags, td)
	struct socket *fd;
	struct uio *uio;
	struct ucred *active_cred;
	struct thread *td;
	int flags;
{
	struct socket *so;
	int error = 0;
	so = fd;
	error = so->so_proto->pr_usrreqs->pru_sosend(so, 0, uio, 0, 0, 0,
						    uio->uio_td);
	return (error);
}
int
soo_ioctl(fp, cmd, data, active_cred, td)
	struct socket *fp;
	u_long cmd;
	void *data;
	struct ucred *active_cred;
	struct thread *td;
{
	register struct socket *so;
	
   so = fp;
	/*
	 * Interface/routing/protocol specific ioctls:
	 * interface and routing ioctls should have a
	 * different entry since a socket's unnecessary
	 */
	 
	if (IOCGROUP(cmd) == 'i')
		return (ifioctl(so, cmd, data, td));
	if (IOCGROUP(cmd) == 'r')
		return (rtioctl(cmd, data));
	
	return ((*so->so_proto->pr_usrreqs->pru_control)(so, cmd, data, 0, td));
}

int
soo_poll(fp, events, active_cred, td)
	struct file *fp;
	int events;
	struct ucred *active_cred;
	struct thread *td;
{
	struct socket *so = (struct socket *)fp;
	return so->so_proto->pr_usrreqs->pru_sopoll(so, events,
	    NULL, td);
}

int
soo_stat(fp, ub, active_cred, td)
	struct file *fp;
	struct stat *ub;
	struct ucred *active_cred;
	struct thread *td;
{
	//struct socket *so;
	int error;

	return (error);
}

/*
 * API socket close on file pointer.  We call soclose() to close the 
 * socket (including initiating closing protocols).  soclose() will
 * sorele() the file reference but the actual socket will not go away
 * until the socket's ref count hits 0.
 */
/* ARGSUSED */
int
soo_close(so, td)
	struct socket *so;
	struct thread *td;
{
	int error;
	if (so)
		error = soclose(so);
	return (error);
}

struct fileops {
	fo_rdwr_t	*fo_read;
	fo_rdwr_t	*fo_write;
	fo_ioctl_t	*fo_ioctl;
	fo_poll_t	*fo_poll;
	fo_kqfilter_t	*fo_kqfilter;
	fo_stat_t	*fo_stat;
	fo_close_t	*fo_close;
	fo_flags_t	fo_flags;	/* DFLAG_* below */
};

#define DFLAG_PASSABLE	0x01	/* may be passed via unix sockets. */
#define DFLAG_SEEKABLE	0x02	/* seekable / nonsequential */

struct	fileops socketops = {
	soo_read,
	soo_write,
	soo_ioctl,
	soo_poll,
	NULL,
	soo_stat,
	soo_close,
	DFLAG_PASSABLE
};

/*
 * MPSAFE
 */
int
socket(
		int	domain,
		int	type,
		int	protocol)
	
{
	struct socket *so;
	//struct file *fp;
	int error;

	/* An extra reference on `fp' has been held for us by falloc(). */
	NET_LOCK_GIANT();
	error = socreate(domain, &so, type, protocol, 0, NULL);
	NET_UNLOCK_GIANT();
	
	if (error) {
		
		return 0;//这里是最大的不同
	} else {
		//fp->f_data = so;	/* already has ref count */
		//fp->f_flag = FREAD|FWRITE;
		//fp->f_ops = &socketops;
		//fp->f_type = DTYPE_SOCKET;
		//FILEDESC_UNLOCK(fdp);
		//td->td_retval[0] = fd;
		
	}
	//fdrop(fp, td);
	
	return (int)(so);
}


/*
 * MPSAFE
 */
/* ARGSUSED */
int
bind(int	s,
		const struct sockaddr *name, socklen_t namelen)
{
	struct sockaddr *sa;
	int error;

	if ((error = getsockaddr(&sa, (caddr_t)name,namelen)) != 0)
		return (error);

	return (kern_bind(NULL, s, sa));
}
int
kern_bind(int td,
	int fd,
	struct sockaddr *sa)
{
	struct socket *so = (struct socket*)fd;
	int error;

	NET_LOCK_GIANT();
	if ((error = fgetsock(fd, &so, NULL)) != 0)
		goto done2;

	error = sobind(so, sa, NULL);

	fputsock(so);
done2:
	NET_UNLOCK_GIANT();
	FREE(sa, 0);
	return (error);
}

/*
 * MPSAFE
 */
/* ARGSUSED */
int
listen(
		int	s,
		int	backlog)
{
	struct socket *so = s;
	int error;

	NET_LOCK_GIANT();
	if ((error = fgetsock(s, &so, NULL)) == 0) {
		error = solisten(so, backlog, NULL);
		fputsock(so);
	}
	NET_UNLOCK_GIANT();
	return(error);
}

int
getsockaddr(namp, uaddr, len)
	struct sockaddr **namp;
	caddr_t uaddr;
	size_t len;
{
	struct sockaddr *sa;
	int error;

	if (len > SOCK_MAXADDRLEN)
		return (ENAMETOOLONG);
	if (len < offsetof(struct sockaddr, sa_data[0]))
		return (EINVAL);
	MALLOC(sa, struct sockaddr *, len, M_SONAME, M_WAITOK);
	error = copyin(uaddr, sa, len);
	error = 0;//LUOYU add
	if (error) {
		FREE(sa, M_SONAME);
	} else {
#if defined(COMPAT_OLDSOCK) && BYTE_ORDER != BIG_ENDIAN
		if (sa->sa_family == 0 && sa->sa_len < AF_MAX)
			sa->sa_family = sa->sa_len;
#endif
		sa->sa_len = len;
		*namp = sa;
	}
	return (error);
}

	
/*
 * accept1()
 * MPSAFE
 */
static int
accept1(
		int	s,
		struct sockaddr	*  name,
		socklen_t	*  anamelen,
		int compat)
{
	struct sockaddr *sa = NULL;
	socklen_t namelen;
	int error;
	struct socket *head, *so;
	int fd;
	u_int fflag;
	int tmp;

	if (name) {
		error = copyin(anamelen, &namelen, sizeof (namelen));
// 		if(error)LUOYU
// 			return (error);
// 		if (namelen < 0)
// 			return (EINVAL);
	}
	NET_LOCK_GIANT();
	error = fgetsock(s, &head, &fflag);
	head = s;//LUOYU
	fflag = 0;//LUOYU
	if (error)
		goto done2;
	if ((head->so_options & SO_ACCEPTCONN) == 0) {
		error = EINVAL;
		goto done;
	}
	ACCEPT_LOCK();
	if ((head->so_state & SS_NBIO) && TAILQ_EMPTY(&head->so_comp)) {
		ACCEPT_UNLOCK();
		error = EWOULDBLOCK;
		goto noconnection;
	}
	while (TAILQ_EMPTY(&head->so_comp) && head->so_error == 0) {
		if (head->so_rcv.sb_state & SBS_CANTRCVMORE) {
			head->so_error = ECONNABORTED;
			break;
		}
		error = msleep(&head->so_timeo, NULL, PSOCK | PCATCH,
		    "accept", 0);
		if (error) {
			ACCEPT_UNLOCK();
			goto noconnection;
		}
	}
	if (head->so_error) {
		error = head->so_error;
		head->so_error = 0;
		ACCEPT_UNLOCK();
		goto noconnection;
	}
	so = TAILQ_FIRST(&head->so_comp);
	KASSERT(!(so->so_qstate & SQ_INCOMP), ("accept1: so SQ_INCOMP"));
	KASSERT(so->so_qstate & SQ_COMP, ("accept1: so not SQ_COMP"));

	/*
	 * Before changing the flags on the socket, we have to bump the
	 * reference count.  Otherwise, if the protocol calls sofree(),
	 * the socket will be released due to a zero refcount.
	 */
	SOCK_LOCK(so);
	soref(so);			/* file descriptor reference */
	SOCK_UNLOCK(so);

	TAILQ_REMOVE(&head->so_comp, so, so_list);
	head->so_qlen--;
	so->so_state |= (head->so_state & SS_NBIO);
	so->so_qstate &= ~SQ_COMP;
	so->so_head = NULL;

	ACCEPT_UNLOCK();


	/* connection has been removed from the listen queue */
	KNOTE_UNLOCKED(&head->so_rcv.sb_sel.si_note, 0);

	/* Sync socket nonblocking/async state with file flags */
	tmp = fflag & FNONBLOCK;
	//(void) fo_ioctl(nfp, FIONBIO, &tmp, td->td_ucred, td);
	tmp = fflag & FASYNC;
	//(void) fo_ioctl(nfp, FIOASYNC, &tmp, td->td_ucred, td);
	sa = 0;
	error = soaccept(so, &sa);
	if (error) {
		/*
		 * return a namelen of zero for older code which might
		 * ignore the return value from accept.
		 */
		if (name != NULL) {
			namelen = 0;
			(void) copyout(&namelen,
			    anamelen, sizeof(*anamelen));
		}
		goto noconnection;
	}
	if (sa == NULL) {
		namelen = 0;
		if (name)
			goto gotnoname;
		error = 0;
		goto done;
	}
	if (name) {
		/* check sa_len before it is destroyed */
		if (namelen > sa->sa_len)
			namelen = sa->sa_len;
		error = copyout(sa, name, (u_int)namelen);
		error = 0;//LUOYU
		if (!error)
gotnoname:
			error = copyout(&namelen,
			    anamelen, sizeof (*anamelen));
			error = 0;//LUOYU
	}
noconnection:
	if (sa)
		FREE(sa, M_SONAME);


	/*
	 * Release explicitly held references before returning.
	 */
done:
	
	fputsock(head);
done2:
	NET_UNLOCK_GIANT();
	//return (error);
	return so;//LUOYU
}


/*
 * MPSAFE (accept1() is MPSAFE)
 */
int
accept(int	s,
		struct sockaddr	*  name,
		socklen_t	*  anamelen)
{

	return (accept1(s, name, anamelen, 0));
}


/*
 * MPSAFE
 */
/* ARGSUSED */
int
connect(
		int	s,
		caddr_t	name,
		int	namelen)
{
	struct sockaddr *sa;
	int error;

	error = getsockaddr(&sa, name, namelen);
	if (error)
		return (error);

	return (kern_connect(s, sa));
}
int
kern_connect(int fd,
	struct sockaddr *sa)
{
	struct socket *so = fd;
	int error, s;
	int interrupted = 0;

	NET_LOCK_GIANT();
	if ((error = fgetsock(fd, &so, NULL)) != 0)
		goto done2;
	if (so->so_state & SS_ISCONNECTING) {
		error = EALREADY;
		goto done1;
	}
#ifdef MAC
	SOCK_LOCK(so);
	error = mac_check_socket_connect(td->td_ucred, so, sa);
	SOCK_UNLOCK(so);
	if (error)
		goto bad;
#endif
	error = soconnect(so, sa, NULL);
	if (error)
		goto bad;
	if ((so->so_state & SS_NBIO) && (so->so_state & SS_ISCONNECTING)) {
		error = EINPROGRESS;
		goto done1;
	}
	s = splnet();
	SOCK_LOCK(so);
	while ((so->so_state & SS_ISCONNECTING) && so->so_error == 0) {
		error = msleep(&so->so_timeo, NULL, PSOCK | PCATCH,
		    "connec", 0);
		if (error) {
			if (error == EINTR || error == ERESTART)
				interrupted = 1;
			break;
		}
	}
	if (error == 0) {
		error = so->so_error;
		so->so_error = 0;
	}
	SOCK_UNLOCK(so);
	splx(s);
bad:
	if (!interrupted)
		so->so_state &= ~SS_ISCONNECTING;
	if (error == ERESTART)
		error = EINTR;
done1:
	fputsock(so);
done2:
	NET_UNLOCK_GIANT();
	FREE(sa, M_SONAME);
	return (error);
}

int
sockargs(mp, buf, buflen, type)
	struct mbuf **mp;
	caddr_t buf;
	int buflen, type;
{
	register struct sockaddr *sa;
	register struct mbuf *m;
	int error;

	if ((u_int)buflen > MLEN) {
			if ((u_int)buflen > MCLBYTES)
				return (EINVAL);
	}
	m = m_get(M_TRYWAIT, type);
	if (m == NULL)
		return (ENOBUFS);
	if ((u_int)buflen > MLEN) {
		MCLGET(m, M_TRYWAIT);
		if ((m->m_flags & M_EXT) == 0) {
			m_free(m);
			return (ENOBUFS);
		}
	}
	m->m_len = buflen;
	error = copyin(buf, mtod(m, caddr_t), (u_int)buflen);
	if (error)
		(void) m_free(m);
	else {
		*mp = m;
		if (type == MT_SONAME) {
			sa = mtod(m, struct sockaddr *);

			sa->sa_len = buflen;
		}
	}
	return (error);
}


static int
sendit(td, s, mp, flags)
	register struct thread *td;
	int s;
	register struct msghdr *mp;
	int flags;
{
	struct mbuf *control;
	struct sockaddr *to;
	int error;

	if (mp->msg_name != NULL) {
		error = getsockaddr(&to, mp->msg_name, mp->msg_namelen);
		if (error) {
			to = NULL;
			goto bad;
		}
		mp->msg_name = to;
	} else {
		to = NULL;
	}

	if (mp->msg_control) {
		if (mp->msg_controllen < sizeof(struct cmsghdr)
		) {
			error = EINVAL;
			goto bad;
		}
		error = sockargs(&control, mp->msg_control,
		    mp->msg_controllen, MT_CONTROL);
		if (error)
			goto bad;
	} else {
		control = NULL;
	}

	error = kern_sendit(td, s, mp, flags, control);

bad:
	if (to)
		FREE(to, M_SONAME);
	return (error);
}

int
kern_sendit(td, s, mp, flags, control)
	struct thread *td;
	int s;
	struct msghdr *mp;
	int flags;
	struct mbuf *control;
{
	struct uio auio;
	struct iovec *iov;
	struct socket *so;
	int i;
	int len, error;

	NET_LOCK_GIANT();
	//if ((error = fgetsock(s, &so, NULL)) != 0)
	//	goto bad2;
	so = (struct socket *)s;

	auio.uio_iov = mp->msg_iov;
	auio.uio_iovcnt = mp->msg_iovlen;
	auio.uio_segflg = UIO_SYSSPACE;//UIO_USERSPACE;LUOYU
	auio.uio_rw = UIO_WRITE;
	auio.uio_td = td;
	auio.uio_offset = 0;			/* XXX */
	auio.uio_resid = 0;
	iov = mp->msg_iov;
	for (i = 0; i < mp->msg_iovlen; i++, iov++) {
		if ((auio.uio_resid += iov->iov_len) < 0) {
			error = EINVAL;
			goto bad;
		}
	}
	len = auio.uio_resid;
	error = so->so_proto->pr_usrreqs->pru_sosend(so, mp->msg_name, &auio,
	    0, control, flags, td);
	if (error) {
		if (auio.uio_resid != len && (error == ERESTART ||
		    error == EINTR || error == EWOULDBLOCK))
			error = 0;
		/* Generation of SIGPIPE can be controlled per socket */
		if (error == EPIPE && !(so->so_options & SO_NOSIGPIPE)) {
			PROC_LOCK(td);
			//psignal(td->td_proc, SIGPIPE);
			PROC_UNLOCK(td);
		}
	}
	if (error == 0)
	{	//td->td_retval[0] = len - auio.uio_resid;
	}
bad:
	fputsock(so);
bad2:
	NET_UNLOCK_GIANT();
	return (error);
}

/*
 * MPSAFE
 */
int
sendto(int	s,
		caddr_t	buf,
		size_t	len,
		int	flags,
		caddr_t	to,
		int	tolen)
{
	struct msghdr msg;
	struct iovec aiov;
	int error;

	msg.msg_name = to;
	msg.msg_namelen = tolen;
	msg.msg_iov = &aiov;
	msg.msg_iovlen = 1;
	msg.msg_control = 0;
	aiov.iov_base = buf;
	aiov.iov_len = len;
	error = sendit(NULL, s, &msg, flags);
	return (error);
}
int 
send(int s,
		caddr_t buf,
		int len,
		int flags)
{
	
	//int error;

	return (sendto(s, buf, len, flags, NULL, 0));
}
static int
recvit(td, s, mp, namelenp)
	struct thread *td;
	int s;
	struct msghdr *mp;
	void *namelenp;
{
	struct uio auio;
	struct iovec *iov;
	int i;
	socklen_t len;
	int error;
	struct mbuf *m, *control = 0;
	caddr_t ctlbuf;
	struct socket *so = s;
	struct sockaddr *fromsa = 0;

	NET_LOCK_GIANT();
	if ((error = fgetsock(s, &so, NULL)) != 0) {
		NET_UNLOCK_GIANT();
		return (error);
	}


	auio.uio_iov = mp->msg_iov;
	auio.uio_iovcnt = mp->msg_iovlen;
	auio.uio_segflg = UIO_SYSSPACE;
	auio.uio_rw = UIO_READ;
	auio.uio_td = td;
	auio.uio_offset = 0;			/* XXX */
	auio.uio_resid = 0;
	iov = mp->msg_iov;
	for (i = 0; i < mp->msg_iovlen; i++, iov++) {
		if ((auio.uio_resid += iov->iov_len) < 0) {
			fputsock(so);
			NET_UNLOCK_GIANT();
			return (EINVAL);
		}
	}
	len = auio.uio_resid;
	error = so->so_proto->pr_usrreqs->pru_soreceive(so, &fromsa, &auio,
	    (struct mbuf **)0, mp->msg_control ? &control : (struct mbuf **)0,
	    &mp->msg_flags);
	if (error) {
		if (auio.uio_resid != (int)len && (error == ERESTART ||
		    error == EINTR || error == EWOULDBLOCK))
			error = 0;
	}
	if (error)
		goto out;
	//td->td_retval[0] = (int)len - auio.uio_resid;
	if (mp->msg_name) {
		len = mp->msg_namelen;
		if (len <= 0 || fromsa == 0)
			len = 0;
		else {
			/* save sa_len before it is destroyed by MSG_COMPAT */
			len = MIN(len, fromsa->sa_len);
			error = copyout(fromsa, mp->msg_name, (unsigned)len);
			if (error)
				goto out;
		}
		mp->msg_namelen = len;
		if (namelenp &&
		    (error = copyout(&len, namelenp, sizeof (socklen_t)))) {
			goto out;
		}
	}
	if (mp->msg_control) {
		len = mp->msg_controllen;
		m = control;
		mp->msg_controllen = 0;
		ctlbuf = mp->msg_control;

		while (m && len > 0) {
			unsigned int tocopy;

			if (len >= m->m_len)
				tocopy = m->m_len;
			else {
				mp->msg_flags |= MSG_CTRUNC;
				tocopy = len;
			}

			if ((error = copyout(mtod(m, caddr_t),
					ctlbuf, tocopy)) != 0)
				goto out;

			ctlbuf += tocopy;
			len -= tocopy;
			m = m->m_next;
		}
		mp->msg_controllen = ctlbuf - (caddr_t)mp->msg_control;
	}
out:
	fputsock(so);
	NET_UNLOCK_GIANT();
	if (fromsa)
		FREE(fromsa, M_SONAME);
	if (control)
		m_freem(control);
	return (error);
}

/*
 * MPSAFE
 */
int
recvfrom(
		int	s,
		caddr_t	buf,
		size_t	len,
		int	flags,
		struct sockaddr * 	from,
		socklen_t *  fromlenaddr)
{
	struct msghdr msg;
	struct iovec aiov;
	int error;

	if (fromlenaddr) {
		error = copyin(fromlenaddr,
		    &msg.msg_namelen, sizeof (msg.msg_namelen));
		if (error)
			goto done2;
	} else {
		msg.msg_namelen = 0;
	}
	msg.msg_name = from;
	msg.msg_iov = &aiov;
	msg.msg_iovlen = 1;
	aiov.iov_base = buf;
	aiov.iov_len = len;
	msg.msg_control = 0;
	msg.msg_flags = flags;
	error = recvit(NULL, s, &msg, fromlenaddr);
done2:
	return(error);
}

/*
 * MPSAFE
 */
int
sendmsg(
		int	s,
		caddr_t	umsg,
		int	flags)
{
	struct msghdr msg;
	struct iovec *iov;
	int error;

	bcopy(umsg, &msg, sizeof (msg));

	error = copyiniov(msg.msg_iov, msg.msg_iovlen, &iov, EMSGSIZE);
	if (error)
		return (error);
	msg.msg_iov = iov;
	error = sendit(NULL, s, &msg, flags);
	free(iov);
	return (error);
}

/*
 * MPSAFE
 */
int
recvmsg(
		int	s,
		struct	msghdr *uap_msg,
		int	flags)
{
	struct msghdr msg;
	struct iovec *uiov, *iov;
	int error;

	error = copyin(uap_msg, &msg, sizeof (msg));
	//if (error)
	//	return (error);
	error = copyiniov(msg.msg_iov, msg.msg_iovlen, &iov, EMSGSIZE);
	if (error)
		return (error);
	msg.msg_flags = flags;
	uiov = msg.msg_iov;
	msg.msg_iov = iov;
	error = recvit(NULL, s, &msg, NULL);
	if (error == 0) {
		msg.msg_iov = uiov;
		error = copyout(&msg, uap_msg, sizeof(msg));
	}
	free(iov);
	return (error);
}

/*
 * MPSAFE
 */
/* ARGSUSED */
int
setsockopt(
		int	s,
		int	level,
		int	name,
		caddr_t	val,
		int	valsize)
{

	return (kern_setsockopt(s, level, name,
	    val, UIO_SYSSPACE, valsize));
}

/*
 * MPSAFE
 */
/* ARGSUSED */
int
getsockopt(
		int	s,
		int	level,
		int	name,
		void * 	val,
		socklen_t *  avalsize
	)
{
	socklen_t valsize;
	int	error;

	if (val) {
		error = copyin(avalsize, &valsize, sizeof (valsize));
		if (error)
			return (error);
	}

	error = kern_getsockopt(NULL, s, level, name,
	    val, UIO_SYSSPACE, &valsize);

	if (error == 0)
		error = copyout(&valsize, avalsize, sizeof (valsize));
	return (error);
}

/*
 * Kernel version of getsockopt.
 * optval can be a userland or userspace. optlen is always a kernel pointer.
 */
int
kern_getsockopt(td, s, level, name, val, valseg, valsize)
	struct thread *td;
	int s;
	int level;
	int name;
	void *val;
	enum uio_seg valseg;
	socklen_t *valsize;
{
	int error;
	struct  socket *so;
	struct	sockopt sopt;

	if (val == NULL)
		*valsize = 0;
	if (*valsize < 0)
		return (EINVAL);

	sopt.sopt_dir = SOPT_GET;
	sopt.sopt_level = level;
	sopt.sopt_name = name;
	sopt.sopt_val = val;
	sopt.sopt_valsize = (size_t)*valsize; /* checked non-negative above */
	switch (valseg) {
	case UIO_USERSPACE:
		sopt.sopt_td = td;
		break;
	case UIO_SYSSPACE:
		sopt.sopt_td = NULL;
		break;
	default:
		panic("kern_getsockopt called with bad valseg");
	}

	NET_LOCK_GIANT();
	if ((error = fgetsock(td, s, &so, NULL)) == 0) {
		error = sogetopt(so, &sopt);
		*valsize = sopt.sopt_valsize;
		fputsock(so);
	}
	NET_UNLOCK_GIANT();
	return (error);
}

int
kern_setsockopt(s, level, name, val, valseg, valsize)
	int s;
	int level;
	int name;
	void *val;
	enum uio_seg valseg;
	socklen_t valsize;
{
	int error;
	struct socket *so = (struct socket*)s;
	struct sockopt sopt;

	if (val == NULL && valsize != 0)
		return (EFAULT);
	if (valsize < 0)
		return (EINVAL);

	sopt.sopt_dir = SOPT_SET;
	sopt.sopt_level = level;
	sopt.sopt_name = name;
	sopt.sopt_val = val;
	sopt.sopt_valsize = valsize;
	switch (valseg) {
	case UIO_USERSPACE:
		//sopt.sopt_td = td;
		break;
	case UIO_SYSSPACE:
		sopt.sopt_td = NULL;
		break;
	default:
		panic("kern_setsockopt called with bad valseg");
	}

	NET_LOCK_GIANT();
	//if ((error = fgetsock(NULL, s, &so, NULL)) == 0) {
		error = sosetopt(so, &sopt);
		fputsock(so);
	//}
	NET_UNLOCK_GIANT();
	return(error);
}
extern struct	fileops socketops;

int ioctl(fd, com, data)
	u_int32_t fd;
	u_long com;
	void *data;
{
   struct fileops *f_ops = &socketops;
	
	return ((*f_ops->fo_ioctl)(fd, com, data, NULL, NULL));
}

//replace "write" syscall
int so_write(int fd, void *buf, int nbyte)
{
   struct uio auio;
	struct iovec aiov;
	long cnt, error = 0;
	
	aiov.iov_base = (void *)(uintptr_t)buf;
	aiov.iov_len = nbyte;
	auio.uio_iov = &aiov;
	auio.uio_iovcnt = 1;
	auio.uio_offset = (__off_t)-1;
	if (nbyte > INT_MAX)
		return (EINVAL);
	auio.uio_resid = nbyte;
	auio.uio_rw = UIO_WRITE;
	auio.uio_segflg = UIO_SYSSPACE;
	auio.uio_td = NULL;

	cnt = nbyte;
	return (socketops.fo_write)(fd, &auio, NULL, 0, NULL);
}
//replace "read" syscall
int so_read(int fd, void *buf, int nbyte)
{
   struct uio auio;
	struct iovec aiov;
	long cnt, error = 0;
	
	aiov.iov_base = (void *)(uintptr_t)buf;
	aiov.iov_len = nbyte;
	auio.uio_iov = &aiov;
	auio.uio_iovcnt = 1;
	auio.uio_offset = (__off_t)-1;
	if (nbyte > INT_MAX)
		return (EINVAL);
	auio.uio_resid = nbyte;
	auio.uio_rw = UIO_READ;
	auio.uio_segflg = UIO_SYSSPACE;
	auio.uio_td = NULL;

	cnt = nbyte;
	return (socketops.fo_read)(fd, &auio, NULL, 0, NULL);
}
u_int		nselcoll;	/* Select collisions since boot */
struct mtx	sellock;
struct cv	selwait;

/*
 * Remove the references to the thread from all of the objects
 * we were polling.
 *
 * This code assumes that the underlying owner of the selinfo
 * structure will hold sellock before it changes it, and that
 * it will unlink itself from our list if it goes away.
 */
void
clear_selinfo_list(td)
	struct thread *td;
{
	struct selinfo *si;

	//mtx_assert(&sellock, MA_OWNED);
	//TAILQ_FOREACH(si, &td->td_selq, si_thrlist)
	//	si->si_thread = NULL;
	//TAILQ_INIT(&td->td_selq);
}

static int
selscan(td, ibits, obits, nfd)
	struct thread *td;
	fd_mask **ibits, **obits;
	int nfd;
{
	int msk, i, fd;
	fd_mask bits;
	struct file *fp;
	int n = 0;
	/* Note: backend also returns POLLHUP/POLLERR if appropriate. */
	static int flag[3] = { POLLRDNORM, POLLWRNORM, POLLRDBAND };
	//struct filedesc *fdp = td->td_proc->p_fd;

	FILEDESC_LOCK(fdp);
	for (msk = 0; msk < 3; msk++) {
		if (ibits[msk] == NULL)
			continue;
		for (i = 0; i < nfd; i += NFDBITS) {
			bits = ibits[msk][i/NFDBITS];
			/* ffs(int mask) not portable, fd_mask is long */
			for (fd = i; bits && fd < nfd; fd++, bits >>= 1) {
				if (!(bits & 1))
					continue;
// 				if ((fp = fget_locked(fdp, fd)) == NULL) {
// 					FILEDESC_UNLOCK(fdp);
// 					return (EBADF);
// 				}
				if (fo_poll(fp, flag[msk], NULL,
				    td)) {
					obits[msk][(fd)/NFDBITS] |=
					    ((fd_mask)1 << ((fd) % NFDBITS));
					n++;
				}
			}
		}
	}
	FILEDESC_UNLOCK(fdp);
	//td->td_retval[0] = n;
	return (n);//LUOYU modi
}

int
kern_select(struct thread *td, int nd, fd_set *fd_in, fd_set *fd_ou,
    fd_set *fd_ex, struct timeval *tvp)
{
	struct filedesc *fdp;
	/*
	 * The magic 2048 here is chosen to be just enough for FD_SETSIZE
	 * infds with the new FD_SETSIZE of 1024, and more than enough for
	 * FD_SETSIZE infds, outfds and exceptfds with the old FD_SETSIZE
	 * of 256.
	 */
	fd_mask s_selbits[howmany(2048, NFDBITS)];
	fd_mask *ibits[3], *obits[3], *selbits, *sbp;
	struct timeval atv, rtv, ttv;
	int error, timo;
	u_int ncoll, nbufbytes, ncpbytes, nfdbits;

	if (nd < 0)
		return (EINVAL);
	//fdp = td->td_proc->p_fd;
	/*
	 * XXX: kern_select() currently requires that we acquire Giant
	 * even if none of the file descriptors we poll requires Giant.
	 */
	mtx_lock(&Giant);
	FILEDESC_LOCK(fdp);

	//if (nd > td->td_proc->p_fd->fd_nfiles)
	//	nd = td->td_proc->p_fd->fd_nfiles;   /* forgiving; slightly wrong */
	FILEDESC_UNLOCK(fdp);

	/*
	 * Allocate just enough bits for the non-null fd_sets.  Use the
	 * preallocated auto buffer if possible.
	 */
	nfdbits = roundup(nd, NFDBITS);
	ncpbytes = nfdbits / NBBY;
	nbufbytes = 0;
	if (fd_in != NULL)
		nbufbytes += 2 * ncpbytes;
	if (fd_ou != NULL)
		nbufbytes += 2 * ncpbytes;
	if (fd_ex != NULL)
		nbufbytes += 2 * ncpbytes;
	if (nbufbytes <= sizeof s_selbits)
		selbits = &s_selbits[0];
	else
		selbits = malloc(nbufbytes);

	/*
	 * Assign pointers into the bit buffers and fetch the input bits.
	 * Put the output buffers together so that they can be bzeroed
	 * together.
	 */
	sbp = selbits;
#define	getbits(name, x) \
	do {								\
		if (name == NULL)					\
			ibits[x] = NULL;				\
		else {							\
			ibits[x] = sbp + nbufbytes / 2 / sizeof *sbp;	\
			obits[x] = sbp;					\
			sbp += ncpbytes / sizeof *sbp;			\
			error = copyin(name, ibits[x], ncpbytes);	\
			if (error != 0)					\
				goto done_nosellock;			\
		}							\
	} while (0)
	getbits(fd_in, 0);
	getbits(fd_ou, 1);
	getbits(fd_ex, 2);
#undef	getbits
	if (nbufbytes != 0)
		bzero(selbits, nbufbytes / 2);

	if (tvp != NULL) {
		atv = *tvp;
		if (itimerfix(&atv)) {
			error = EINVAL;
			goto done_nosellock;
		}
		getmicrouptime(&rtv);
		timevaladd(&atv, &rtv);
	} else {
		atv.tv_sec = 0;
		atv.tv_usec = 0;
	}
	timo = 0;
	//TAILQ_INIT(&td->td_selq);
	mtx_lock(&sellock);
retry:
	ncoll = nselcoll;
	mtx_lock_spin(&sched_lock);
	//td->td_flags |= TDF_SELECT;
	mtx_unlock_spin(&sched_lock);
	mtx_unlock(&sellock);

	error = selscan(td, ibits, obits, nd);
	mtx_lock(&sellock);
	if (error)// || td->td_retval[0])
		goto done;
	if (atv.tv_sec || atv.tv_usec) {
		getmicrouptime(&rtv);
		if (timevalcmp(&rtv, &atv, >=))
			goto done;
		ttv = atv;
		timevalsub(&ttv, &rtv);
		timo = ttv.tv_sec > 24 * 60 * 60 ?
		    24 * 60 * 60 * hz : tvtohz(&ttv);
	}

	/*
	 * An event of interest may occur while we do not hold
	 * sellock, so check TDF_SELECT and the number of
	 * collisions and rescan the file descriptors if
	 * necessary.
	 */
	mtx_lock_spin(&sched_lock);
	if (nselcoll != ncoll) {//LUOYU
		mtx_unlock_spin(&sched_lock);
		goto retry;
	}
	mtx_unlock_spin(&sched_lock);

	if (timo > 0)
		error = cv_timedwait_sig(&selwait, &sellock, timo);
	else
		error = cv_wait_sig(&selwait, &sellock);
	
	if (error == 0)
		goto retry;

done:
	clear_selinfo_list(td);
	mtx_lock_spin(&sched_lock);
	//td->td_flags &= ~TDF_SELECT;
	mtx_unlock_spin(&sched_lock);
	mtx_unlock(&sellock);

done_nosellock:
	/* select is not restarted after signals... */
	if (error == ERESTART)
		error = EINTR;
	if (error == EWOULDBLOCK)
		error = 0;
#define	putbits(name, x) \
	if (name && (error2 = copyout(obits[x], name, ncpbytes))) \
		error = error2;
	if (error == 0) {
		int error2;

		putbits(fd_in, 0);
		putbits(fd_ou, 1);
		putbits(fd_ex, 2);
#undef putbits
	}
	if (selbits != &s_selbits[0])
		free(selbits);

	mtx_unlock(&Giant);
	return (error);
}

/*
 * MPSAFE
 */
int
select(int	nd,
	fd_set	*in, fd_set *ou, fd_set *ex,
	struct	timeval *utv)
{
	struct timeval tv, *tvp;
	int error;

	if (utv != NULL) {
		error = copyin(utv, &tv, sizeof(tv));
		if (error)
			return (error);
		tvp = &tv;
	} else
		tvp = NULL;

	return (kern_select(NULL, nd, in, ou, ex, tvp));
}

static __inline int
fo_poll(fp, events, active_cred, td)
	struct file *fp;
	int events;
	struct ucred *active_cred;
	struct thread *td;
{

	return (socketops.fo_poll)(fp, events, active_cred, td);
}

int so_close(int fd)
{
   return (socketops.fo_close)(fd, NULL);
}
