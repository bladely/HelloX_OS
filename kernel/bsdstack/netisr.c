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
#include "netisr.h"
#include "interrupt.h"
volatile unsigned int	netisr;	/* scheduling bits for network */

struct netisr {
	netisr_t	*ni_handler;
	struct ifqueue	*ni_queue;
	int		ni_flags;
} netisrs[32];

static void *net_ih;


struct isrstat {
	int	isrs_count;			/* dispatch count */
	int	isrs_directed;			/* ...directly dispatched */
	int	isrs_deferred;			/* ...queued instead */
	int	isrs_queued;			/* intentionally queueued */
	int	isrs_drop;			/* dropped 'cuz no handler */
	int	isrs_swi_count;			/* swi_net handlers called */
};
static struct isrstat isrstat;

void
legacy_setsoftnet(void)
{
	//swi_sched(net_ih, 0);LUOYU !!!
}

/*
 * Same as above, but always queue.
 * This is either used in places where we are not confident that
 * direct dispatch is possible, or where queueing is required.
 * It returns (0) on success and ERRNO on failure.  On failure the
 * mbuf has been free'd.
 */
int
netisr_queue(int num, struct mbuf *m)
{
	struct netisr *ni;
	
	KASSERT(!(num < 0 || num >= (sizeof(netisrs)/sizeof(*netisrs))),
	    ("bad isr %d", num));
	ni = &netisrs[num];
	if (ni->ni_queue == NULL) {
		isrstat.isrs_drop++;
		m_freem(m);
		return (ENXIO);
	}
	isrstat.isrs_queued++;
	if (!IF_HANDOFF(ni->ni_queue, m, NULL))
		return (ENOBUFS);	/* IF_HANDOFF has free'd the mbuf */
	// schednetisr(num);LUOYU replace with ni->nihandle;
	ni->ni_handler(m);
	return (0);
}

void
netisr_register(int num, netisr_t *handler, struct ifqueue *inq, int flags)
{
	
	KASSERT(!(num < 0 || num >= (sizeof(netisrs)/sizeof(*netisrs))),
	    ("bad isr %d", num));
	netisrs[num].ni_handler = handler;
	netisrs[num].ni_queue = inq;
	if ((flags & NETISR_MPSAFE) && !debug_mpsafenet)
		flags &= ~NETISR_MPSAFE;
	netisrs[num].ni_flags = flags;
}

void
netisr_unregister(int num)
{
	struct netisr *ni;
	
	KASSERT(!(num < 0 || num >= (sizeof(netisrs)/sizeof(*netisrs))),
	    ("bad isr %d", num));
	ni = &netisrs[num];
	ni->ni_handler = NULL;
	if (ni->ni_queue != NULL)
		IF_DRAIN(ni->ni_queue);
	ni->ni_queue = NULL;
}


static int	netisr_enable = 1;//LUOYU set it 
/*
 * Process all packets currently present in a netisr queue.  Used to
 * drain an existing set of packets waiting for processing when we
 * begin direct dispatch, to avoid processing packets out of order.
 */
static void
netisr_processqueue(struct netisr *ni)
{
	struct mbuf *m;

	for (;;) {
		IF_DEQUEUE(ni->ni_queue, m);
		if (m == NULL)
			break;
		ni->ni_handler(m);
	}
}

/*
 * Call the netisr directly instead of queueing the packet, if possible.
 */
void
netisr_dispatch(int num, struct mbuf *m)
{
	struct netisr *ni;
	
	isrstat.isrs_count++;		/* XXX redundant */
	KASSERT(!(num < 0 || num >= (sizeof(netisrs)/sizeof(*netisrs))),
	    ("bad isr %d", num));
	ni = &netisrs[num];
	if (ni->ni_queue == NULL) {
		isrstat.isrs_drop++;
		m_freem(m);
		return;
	}
	/*
	 * Do direct dispatch only for MPSAFE netisrs (and
	 * only when enabled).  Note that when a netisr is
	 * marked MPSAFE we permit multiple concurrent instances
	 * to run.  We guarantee only the order in which
	 * packets are processed for each "dispatch point" in
	 * the system (i.e. call to netisr_dispatch or
	 * netisr_queue).  This insures ordering of packets
	 * from an interface but does not guarantee ordering
	 * between multiple places in the system (e.g. IP
	 * dispatched from interfaces vs. IP queued from IPSec).
	 */
	if (netisr_enable && (ni->ni_flags & NETISR_MPSAFE)) {
		isrstat.isrs_directed++;
		/*
		 * NB: We used to drain the queue before handling
		 * the packet but now do not.  Doing so here will
		 * not preserve ordering so instead we fallback to
		 * guaranteeing order only from dispatch points
		 * in the system (see above).
		 */
		ni->ni_handler(m);
	} else {
		isrstat.isrs_deferred++;
		if (IF_HANDOFF(ni->ni_queue, m, NULL))
			schednetisr(num);
	}
}

static void
swi_net(void *dummy)
{
	struct netisr *ni;
	u_int bits;
	int i;
#ifdef DEVICE_POLLING
	const int polling = 1;
#else
	const int polling = 0;
#endif

	do {
		bits = atomic_readandclear_int(&netisr);
		if (bits == 0)
			break;
		while ((i = ffs(bits)) != 0) {
			isrstat.isrs_swi_count++;
			i--;
			bits &= ~(1 << i);
			ni = &netisrs[i];
			if (ni->ni_handler == NULL) {
				printf("swi_net: unregistered isr %d.\n", i);
				continue;
			}
			if ((ni->ni_flags & NETISR_MPSAFE) == 0) {
				mtx_lock(&Giant);
				if (ni->ni_queue == NULL)
					ni->ni_handler(NULL);
				else
					netisr_processqueue(ni);
				mtx_unlock(&Giant);
			} else {
				if (ni->ni_queue == NULL)
					ni->ni_handler(NULL);
				else
					netisr_processqueue(ni);
			}
		}
	} while (polling);
}

static void
start_netisr(void *dummy)
{

	if (swi_add(NULL, "net", swi_net, NULL, SWI_NET, INTR_MPSAFE, &net_ih))
		panic("start_netisr");
}

