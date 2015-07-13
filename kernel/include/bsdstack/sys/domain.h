#ifndef _SYS_DOMAIN_H_
#define _SYS_DOMAIN_H_

struct domain {
	int	dom_family;		/* AF_xxx */
	char	*dom_name;
	void	(*dom_init)		/* initialize domain data structures */
		(void);
	int	(*dom_externalize)	/* externalize access rights */
		(struct mbuf *, struct mbuf **);
	void	(*dom_dispose)		/* dispose of internalized rights */
		(struct mbuf *);
	struct	protosw *dom_protosw, *dom_protoswNPROTOSW;
	struct	domain *dom_next;
	int	(*dom_rtattach)		/* initialize routing table */
		(void **, int);
	int	dom_rtoffset;		/* an arg to rtattach, in bits */
	int	dom_maxrtkey;		/* for routing layer */
	void	*(*dom_ifattach)(struct ifnet *);
	void	(*dom_ifdetach)(struct ifnet *, void *);
					/* af-dependent data on ifnet */
};

extern struct	domain *domains;
extern struct	domain localdomain;
extern void	net_add_domain(void *);
#endif
