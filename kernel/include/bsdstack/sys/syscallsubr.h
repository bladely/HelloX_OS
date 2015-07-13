#ifndef _SYS_SYSCALLSUBR_H_
#define _SYS_SYSCALLSUBR_H_


#include "uio.h"
#include "socket.h"
int	kern_bind(int fd, struct sockaddr *sa);
int	kern_connect(int fd, struct sockaddr *sa);

/* flags for kern_sigaction */
#define	KSA_OSIGSET	0x0001	/* uses osigact_t */
#define	KSA_FREEBSD4	0x0002	/* uses ucontext4 */
int	taskqueue_enqueue(struct taskqueue *queue, struct task *task);
int	kern_sendit(struct thread *td, int s, struct msghdr *mp, int flags,
	    struct mbuf *control);

#endif /* !_SYS_SYSCALLSUBR_H_ */
