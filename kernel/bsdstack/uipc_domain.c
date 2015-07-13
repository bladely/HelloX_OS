
#include "sys.h"
#include "sysproto.h"
#include "mbuf.h"
#include "domain.h"
#include "protosw.h"
#include "socket.h"
#include "socketvar.h"

struct domain *domains;		/* registered protocol domains */

/*
 * Add a new protocol domain to the list of supported domains
 * Note: you cant unload it again because  a socket may be using it.
 * XXX can't fail at this time.
 */
static void
net_init_domain(struct domain *dp)
{
	struct protosw *pr;

	if (dp->dom_init)
		(*dp->dom_init)();
	for (pr = dp->dom_protosw; pr < dp->dom_protoswNPROTOSW; pr++){
		//if (pr->pr_usrreqs == 0)
		//	panic("domaininit: %ssw[%d] has no usrreqs!",
		//	      dp->dom_name, 
		//	      (int)(pr - dp->dom_protosw));
		if (pr->pr_init)
			(*pr->pr_init)();
	}
	/*
	 * update global information about maximums
	 */
	max_hdr = max_linkhdr + max_protohdr;
	max_datalen = MHLEN - max_hdr;
}

/*
 * Add a new protocol domain to the list of supported domains
 * Note: you cant unload it again because  a socket may be using it.
 * XXX can't fail at this time.
 */
void
net_add_domain(void *data)
{
	struct domain *dp;

	dp = (struct domain *)data;
	//mtx_lock(&dom_mtx);
	dp->dom_next = domains;
	domains = dp;
	//mtx_unlock(&dom_mtx);
	net_init_domain(dp);
}
extern int	debug_mpsafenet;

/* ARGSUSED*/
void
domaininit(void *dummy)
{
	/*
	 * Before we do any setup, make sure to initialize the
	 * zone allocator we get struct sockets from.
	 */

	socket_zone = uma_zcreate("socket", sizeof(struct socket), 10, NULL, NULL,
	    UMA_ALIGN_PTR, UMA_ZONE_NOFREE);
	uma_zone_set_max(socket_zone, maxsockets);

	if (max_linkhdr < 16)		/* XXX */
		max_linkhdr = 16;

	if (debug_mpsafenet) {
		//callout_init(&pffast_callout, CALLOUT_MPSAFE); LUOYU
		//callout_init(&pfslow_callout, CALLOUT_MPSAFE);
	} else {
		//callout_init(&pffast_callout, 0);
		//callout_init(&pfslow_callout, 0);
	}

	//callout_reset(&pffast_callout, 1, pffasttimo, NULL);
	//callout_reset(&pfslow_callout, 1, pfslowtimo, NULL);
}

struct protosw *
pffindtype(family, type)
	int family;
	int type;
{
	register struct domain *dp;
	register struct protosw *pr;

	for (dp = domains; dp; dp = dp->dom_next)
		if (dp->dom_family == family)
			goto found;
	return (0);
found:
	for (pr = dp->dom_protosw; pr < dp->dom_protoswNPROTOSW; pr++)
		if (pr->pr_type && pr->pr_type == type)
			return (pr);
	return (0);
}

struct protosw *
pffindproto(family, protocol, type)
	int family;
	int protocol;
	int type;
{
	register struct domain *dp;
	register struct protosw *pr;
	struct protosw *maybe = 0;

	if (family == 0)
		return (0);
	for (dp = domains; dp; dp = dp->dom_next)
		if (dp->dom_family == family)
			goto found;
	return (0);
found:
	for (pr = dp->dom_protosw; pr < dp->dom_protoswNPROTOSW; pr++) {
		if ((pr->pr_protocol == protocol) && (pr->pr_type == type))
			return (pr);

		if (type == SOCK_RAW && pr->pr_type == SOCK_RAW &&
		    pr->pr_protocol == 0 && maybe == (struct protosw *)0)
			maybe = pr;
	}
	return (maybe);
}
	
void
pfctlinput(cmd, sa)
	int cmd;
	struct sockaddr *sa;
{
	register struct domain *dp;
	register struct protosw *pr;

	for (dp = domains; dp; dp = dp->dom_next)
		for (pr = dp->dom_protosw; pr < dp->dom_protoswNPROTOSW; pr++)
			if (pr->pr_ctlinput)
				(*pr->pr_ctlinput)(cmd, sa, (void *)0);
}

void
pfctlinput2(cmd, sa, ctlparam)
	int cmd;
	struct sockaddr *sa;
	void *ctlparam;
{
	struct domain *dp;
	struct protosw *pr;

	if (!sa)
		return;
	for (dp = domains; dp; dp = dp->dom_next) {
		/*
		 * the check must be made by xx_ctlinput() anyways, to
		 * make sure we use data item pointed to by ctlparam in
		 * correct way.  the following check is made just for safety.
		 */
		if (dp->dom_family != sa->sa_family)
			continue;

		for (pr = dp->dom_protosw; pr < dp->dom_protoswNPROTOSW; pr++)
			if (pr->pr_ctlinput)
				(*pr->pr_ctlinput)(cmd, sa, ctlparam);
	}
}
	
static void
pfslowtimo(arg)
	void *arg;
{
	register struct domain *dp;
	register struct protosw *pr;

	//NET_ASSERT_GIANT();

	for (dp = domains; dp; dp = dp->dom_next)
		for (pr = dp->dom_protosw; pr < dp->dom_protoswNPROTOSW; pr++)
			if (pr->pr_slowtimo)
				(*pr->pr_slowtimo)();
	//callout_reset(&pfslow_callout, hz/2, pfslowtimo, NULL);LUOYU
}

static void
pffasttimo(arg)
	void *arg;
{
	register struct domain *dp;
	register struct protosw *pr;

	//NET_ASSERT_GIANT();

	for (dp = domains; dp; dp = dp->dom_next)
		for (pr = dp->dom_protosw; pr < dp->dom_protoswNPROTOSW; pr++)
			if (pr->pr_fasttimo)
				(*pr->pr_fasttimo)();
	//callout_reset(&pffast_callout, hz/5, pffasttimo, NULL);LUOYU
}

