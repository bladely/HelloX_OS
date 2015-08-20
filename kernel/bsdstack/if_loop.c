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
#include "kin.h"
#include "in_pcb.h"
#include "in_var.h"
#include "if_var.h"
#include "sockio.h"
#include "kroute.h"
#include "netisr.h"
#include "if_clone.h"
#ifdef TINY_LOMTU
#define	LOMTU	(1024+512)
#elif defined(LARGE_LOMTU)
#define LOMTU	131072
#else
#define LOMTU	16384
#endif

#define LONAME	"lo"

struct lo_softc {
	struct	ifnet sc_if;		/* network-visible interface */
	LIST_ENTRY(lo_softc) sc_next;
};

struct ifnet *loif = NULL;			/* Used externally */
static LIST_HEAD(lo_list, lo_softc) lo_list;
int		loioctl(struct ifnet *, u_long, caddr_t);
static void	lortrequest(int, struct rtentry *, struct rt_addrinfo *);
int		looutput(struct ifnet *ifp, struct mbuf *m,
				 struct sockaddr *dst, struct rtentry *rt);

static void lo_clone_destroy(ifp)
struct ifnet *ifp;
{
	struct lo_softc *sc;
	
	sc = ifp->if_softc;
	
	/* XXX: destroying lo0 will lead to panics. */
	
	mtx_lock(&lo_mtx);
	LIST_REMOVE(sc, sc_next);
	mtx_unlock(&lo_mtx);
	//bpfdetach(ifp);
	if_detach(ifp);
	free(sc);
}

int
lo_clone_create(int unit)
{
	struct lo_softc *sc;
	//struct if_clone *ifc = (struct if_clone*)malloc(sizeof(struct if_clone));
	MALLOC(sc, struct lo_softc *, sizeof(*sc), M_LO, M_WAITOK | M_ZERO);
	memset(sc, 0, sizeof(struct lo_softc));
	memset(&sc->sc_if, 0, sizeof(struct ifnet));
	if_initname(&sc->sc_if, "lo", unit);
	sc->sc_if.if_mtu = LOMTU;
#if 1 /*KJZ add IFF_BROADCAST to correct Glibc getifaddr */
	sc->sc_if.if_flags = IFF_LOOPBACK | IFF_BROADCAST;
#else
	sc->sc_if.if_flags = IFF_LOOPBACK | IFF_MULTICAST;
#endif
	sc->sc_if.if_ioctl = loioctl;
	sc->sc_if.if_output = looutput;
	sc->sc_if.if_type = IFT_LOOP;
	sc->sc_if.if_snd.ifq_maxlen = ifqmaxlen;
	sc->sc_if.if_softc = sc;
	if_attach(&sc->sc_if);
	//bpfattach(&sc->sc_if, DLT_NULL, sizeof(u_int));
	mtx_lock(&lo_mtx);
	LIST_INSERT_HEAD(&lo_list, sc, sc_next);
	mtx_unlock(&lo_mtx);
	if (loif == NULL)
		loif = &sc->sc_if;
	
	return (0);
}

/*
 * if_simloop()
 *
 * This function is to support software emulation of hardware loopback,
 * i.e., for interfaces with the IFF_SIMPLEX attribute. Since they can't
 * hear their own broadcasts, we create a copy of the packet that we
 * would normally receive via a hardware loopback.
 *
 * This function expects the packet to include the media header of length hlen.
 */

int
if_simloop(ifp, m, af, hlen)
	struct ifnet *ifp;
	struct mbuf *m;
	int af;
	int hlen;
{
	int isr;

	//M_ASSERTPKTHDR(m);
	m_tag_delete_nonpersistent(m);
	m->m_pkthdr.rcvif = ifp;

	/* BPF write needs to be handled specially */
	if (af == AF_UNSPEC) {
		KASSERT(m->m_len >= sizeof(int), ("if_simloop: m_len"));
		af = *(mtod(m, int *));
		m->m_len -= sizeof(int);
		m->m_pkthdr.len -= sizeof(int);
		m->m_data += sizeof(int);
	}
#if 0
	LUOYU
	/* Let BPF see incoming packet */
	if (ifp->if_bpf) {
		if (ifp->if_bpf->bif_dlt == DLT_NULL) {
			u_int32_t af1 = af;	/* XXX beware sizeof(af) != 4 */
			/*
			 * We need to prepend the address family.
			 */
			bpf_mtap2(ifp->if_bpf, &af1, sizeof(af1), m);
		} else
			bpf_mtap(ifp->if_bpf, m);
	}
#endif
	/* Strip away media header */
	if (hlen > 0) {
		m_adj(m, hlen);
#if defined(__alpha__) || defined(__ia64__) || defined(__sparc64__)
		/* The alpha doesn't like unaligned data.
		 * We move data down in the first mbuf */
		if (mtod(m, vm_offset_t) & 3) {
			KASSERT(hlen >= 3, ("if_simloop: hlen too small"));
			bcopy(m->m_data, 
			    (char *)(mtod(m, vm_offset_t) 
				- (mtod(m, vm_offset_t) & 3)),
			    m->m_len);
			m->m_data -= (mtod(m,vm_offset_t) & 3);
		}
#endif
	}

	/* Deliver to upper layer protocol */
	switch (af) {
#ifdef INET
	case AF_INET:
		isr = NETISR_IP;
		break;
#endif
#ifdef INET6
	case AF_INET6:
		m->m_flags |= M_LOOP;
		isr = NETISR_IPV6;
		break;
#endif
	default:
		printf("if_simloop: can't handle af=%d\n", af);
		m_freem(m);
		return (EAFNOSUPPORT);
	}
	ifp->if_ipackets++;
	ifp->if_ibytes += m->m_pkthdr.len;
	netisr_queue(isr, m);	/* mbuf is free'd on failure. */
	return (0);
}


int
looutput(ifp, m, dst, rt)
struct ifnet *ifp;
register struct mbuf *m;
struct sockaddr *dst;
register struct rtentry *rt;
{
	M_ASSERTPKTHDR(m); /* check if we have the packet header */
	
	if (rt && rt->rt_flags & (RTF_REJECT|RTF_BLACKHOLE)) {
		m_freem(m);
		return (rt->rt_flags & RTF_BLACKHOLE ? 0 :
		rt->rt_flags & RTF_HOST ? EHOSTUNREACH : ENETUNREACH);
	}
	
	ifp->if_opackets++;
	ifp->if_obytes += m->m_pkthdr.len;
#if 1	/* XXX */
	switch (dst->sa_family) {
	case AF_INET:
	case AF_INET6:
	case AF_IPX:
	case AF_APPLETALK:
		break;
	default:
		printf("looutput: af=%d unexpected\n", dst->sa_family);
		m_freem(m);
		return (EAFNOSUPPORT);
	}
#endif
	return(if_simloop(ifp, m, dst->sa_family, 0));
}

/* ARGSUSED */
static void
lortrequest(cmd, rt, info)
int cmd;
struct rtentry *rt;
struct rt_addrinfo *info;
{
	RT_LOCK_ASSERT(rt);
	if (rt)
		rt->rt_rmx.rmx_mtu = rt->rt_ifp->if_mtu;
}

/*
* Process an ioctl request.
*/
/* ARGSUSED */
int
loioctl(ifp, cmd, data)
register struct ifnet *ifp;
u_long cmd;
caddr_t data;
{
	register struct ifaddr *ifa;
	register struct ifreq *ifr = (struct ifreq *)data;
	register int error = 0;
	
	switch (cmd) {
		
	case SIOCSIFADDR:
		ifp->if_flags |= IFF_UP | IFF_RUNNING;
		ifa = (struct ifaddr *)data;
		ifa->ifa_rtrequest = lortrequest;
		/*
		* Everything else is done at a higher level.
		*/
		break;
		
	case SIOCADDMULTI:
	case SIOCDELMULTI:
		if (ifr == 0) {
			error = EAFNOSUPPORT;		/* XXX */
			break;
		}
		switch (ifr->ifr_addr.sa_family) {
			
#ifdef INET
		case AF_INET:
			break;
#endif
#ifdef INET6
		case AF_INET6:
			break;
#endif
			
		default:
			error = EAFNOSUPPORT;
			break;
		}
		break;
		
		case SIOCSIFMTU:
			ifp->if_mtu = ifr->ifr_mtu;
			break;
			
		case SIOCSIFFLAGS:
			break;
			
		default:
			error = EINVAL;
	}
	return (error);
}
