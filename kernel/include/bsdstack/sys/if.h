/*
 * Copyright (c) 1982, 1986, 1989, 1993
 *	The Regents of the University of California.  All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 4. Neither the name of the University nor the names of its contributors
 *    may be used to endorse or promote products derived from this software
 *    without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE REGENTS AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE REGENTS OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 *
 *	@(#)if.h	8.1 (Berkeley) 6/10/93
 *           src/sys/net/if.h,v 1.88.2.2 2004/09/13 05:11:40 brooks Exp $
 */

#ifndef _NET_IF_H_
#define	_NET_IF_H_

#include <kqueue.h>
#include <ktime.h>
#if __BSD_VISIBLE

struct ifnet;
#endif
#define	RF_ALLOCATED	0x0001	/* resource has been reserved */
#define	RF_ACTIVE	0x0002	/* resource allocation has been activated */
#define	RF_SHAREABLE	0x0004	/* resource permits contemporaneous sharing */
#define	RF_TIMESHARE	0x0008	/* resource permits time-division sharing */
#define	RF_WANTED	0x0010	/* somebody is waiting for this resource */
#define	RF_FIRSTSHARE	0x0020	/* first in sharing list */
#define	RF_PREFETCHABLE	0x0040	/* resource is prefetchable */
#define	RF_OPTIONAL	0x0080	/* for bus_alloc_resources() */

#define	RF_ALIGNMENT_SHIFT	10 /* alignment size bit starts bit 10 */
#define	RF_ALIGNMENT_MASK	(0x003F << RF_ALIGNMENT_SHIFT)
				/* resource address alignemnt size bit mask */
#define	RF_ALIGNMENT_LOG2(x)	((x) << RF_ALIGNMENT_SHIFT)
#define	RF_ALIGNMENT(x)		(((x) & RF_ALIGNMENT_MASK) >> RF_ALIGNMENT_SHIFT)

enum	rman_type { RMAN_UNINIT = 0, RMAN_GAUGE, RMAN_ARRAY };

/*
 * String length exported to userspace for resource names, etc.
 */
#define RM_TEXTLEN	32


#define MAXMCADDR 80


#define device_method_t		kobj_method_t
struct kobj_method;
typedef struct kobj_method	kobj_method_t;
/*
 * Implementation of kobj.
 */
 /*
* A class is simply a method table and a sizeof value. When the first
* instance of the class is created, the method table will be compiled 
* into a form more suited to efficient method dispatch. This compiled 
* method table is always the first field of the object.
*/
#define KOBJ_CLASS_FIELDS						\
	const char	*name;		/* class name */		\
	kobj_method_t	*methods;	/* method table */		\
	size_t		size		/* object size */		

struct kobj_class {
	KOBJ_CLASS_FIELDS;
};
typedef struct kobj_class	*kobj_class_t;
/*
 * The ops table is used as a cache of results from kobj_lookup_method().
 */

#define KOBJ_CACHE_SIZE	256
 struct kobj_ops {
	kobj_method_t	*cache[KOBJ_CACHE_SIZE];
	kobj_class_t	cls;
};
 typedef struct kobj_ops		*kobj_ops_t;
#define KOBJ_FIELDS				\
	kobj_ops_t	ops

struct kobj {
	KOBJ_FIELDS;
};
struct kobjop_desc {
	unsigned int	id;		/* unique ID */
	kobj_method_t	*deflt;		/* default implementation */
};
typedef struct kobjop_desc	*kobjop_desc_t;
typedef int			(*kobjop_t)(void);
typedef struct kobj		*kobj_t;
struct kobj_method {
	kobjop_desc_t	desc;
	kobjop_t	func;
};
struct resource {
	u_long	r_start;	/* index of the first entry in this resource */
	u_long	r_end;		/* index of the last entry (inclusive) */
	u_int	r_flags;
	void	*r_virtual;	/* virtual address of this resource */
	int	r_rid;		/* optional rid for this resource. */
};
typedef struct kobj_class	driver_t;
typedef struct devclass		*devclass_t;
typedef struct device		*device_t;
#define KOBJMETHOD(NAME, FUNC) { NULL, (kobjop_t) FUNC }
#define	DEVMETHOD	KOBJMETHOD

/**
 * @brief State of the device.
 */
typedef enum device_state {
	DS_NOTPRESENT = 10,		/**< @brief not probed or probe failed */
	DS_ALIVE = 20,			/**< @brief probe succeeded */
	DS_ATTACHED = 30,		/**< @brief attach method called */
	DS_BUSY = 40			/**< @brief device is open */
} device_state_t;
/*
 * Used to attach drivers to devclasses.
 */
typedef struct driverlink *driverlink_t;
struct driverlink {
	kobj_class_t	driver;
	TAILQ_ENTRY(driverlink) link;	/* list of drivers in devclass */
};

/*
 * Forward declarations
 */
typedef TAILQ_HEAD(devclass_list, devclass) devclass_list_t;
typedef TAILQ_HEAD(driver_list, driverlink) driver_list_t;
typedef TAILQ_HEAD(device_list, device) device_list_t;
struct devclass {
	TAILQ_ENTRY(devclass) link;
	devclass_t	parent;		/* parent in devclass hierarchy */
	driver_list_t	drivers;     /* bus devclasses store drivers for bus */
	char		*name;
	device_t	*devices;	/* array of devices indexed by unit */
	int		maxunit;	/* size of devices array */
	
	//struct sysctl_ctx_list sysctl_ctx;
	//struct sysctl_oid *sysctl_tree;
};
/**
* @brief A device class
*
* The devclass object has two main functions in the system. The first
* is to manage the allocation of unit numbers for device instances
* and the second is to hold the list of device drivers for a
* particular bus type. Each devclass has a name and there cannot be
* two devclasses with the same name. This ensures that unique unit
* numbers are allocated to device instances.
*
* Drivers that support several different bus attachments (e.g. isa,
* pci, pccard) should all use the same devclass to ensure that unit
* numbers do not conflict.
*
* Each devclass may also have a parent devclass. This is used when
* searching for device drivers to allow a form of inheritance. When
* matching drivers with devices, first the driver list of the parent
* device's devclass is searched. If no driver is found in that list,
* the search continues in the parent devclass (if any).
*/


struct device {
	char *name;
	/*
	 * Device hierarchy.
	 */
	TAILQ_ENTRY(device)	link;	/**< list of devices in parent */
	TAILQ_ENTRY(device)	devlink; /**< global device list membership */
	device_t	parent;		/**< parent of this device  */
	device_list_t	children;	/**< list of child devices */
	/*
	 * Details of this device.
	 */
	driver_t	*driver;	/**< current driver */
	devclass_t	devclass;	/**< current device class */
	int		unit;		/**< current unit number */
	char*		nameunit;	/**< name+unit e.g. foodev0 */
	char*		desc;		/**< driver specific description */
	int		busy;		/**< count of calls to device_busy() */
	device_state_t	state;		/**< current device state  */
	u_int32_t	devflags;	/**< api level flags for device_get_flags() */
	u_short		flags;		/**< internal device flags  */
#define	DF_ENABLED	1		/* device should be probed/attached */
#define	DF_FIXEDCLASS	2		/* devclass specified at create time */
#define	DF_WILDCARD	4		/* unit was originally wildcard */
#define	DF_DESCMALLOCED	8		/* description was malloced */
#define	DF_QUIET	16		/* don't print verbose attach message */
#define	DF_DONENOMATCH	32		/* don't execute DEVICE_NOMATCH again */
#define	DF_EXTERNALSOFTC 64		/* softc not allocated by us */
	u_char	order;			/**< order from device_add_child_ordered() */
	u_char	pad;
	void	*ivars;			/**< instance variables  */
	void	*softc;			/**< current driver's variables  */

};

/*
 * Definitions for drivers which need to keep simple lists of resources
 * for their child devices.
 */
struct	resource;
#include "kqueue.h"
#include "socket.h"

/**
 * @brief A driver interrupt service routine
 */
typedef void driver_intr_t(void*);

extern void if_init(void *dummy);
extern void if_check(void *dummy );
extern void ether_ifattach(struct ifnet *ifp, const u_int8_t *llc);
extern void ether_ifdetach(struct ifnet *ifp);
extern int ether_ioctl(struct ifnet *ifp, int command, caddr_t data);

/*
 * Length of interface external name, including terminating '\0'.
 * Note: this is the same size as a generic device's external name.
 */
#define		IF_NAMESIZE	16
#if __BSD_VISIBLE
#define		IFNAMSIZ	IF_NAMESIZE
#define		IF_MAXUNIT	0x7fff	/* historical value */
#endif
#if __BSD_VISIBLE

/*
 * Structure used to query names of interface cloners.
 */

struct if_clonereq {
	int	ifcr_total;		/* total cloners (out) */
	int	ifcr_count;		/* room for this many in user buffer */
	char	*ifcr_buffer;		/* buffer for cloner names */
};

/*
 * Structure describing information about an interface
 * which may be of interest to management entities.
 */
struct if_data {
	/* generic interface information */
	u_char	ifi_type;		/* ethernet, tokenring, etc */
	u_char	ifi_physical;		/* e.g., AUI, Thinnet, 10base-T, etc */
	u_char	ifi_addrlen;		/* media address length */
	u_char	ifi_hdrlen;		/* media header length */
	u_char	ifi_link_state;		/* current link state */
	u_char	ifi_recvquota;		/* polling quota for receive intrs */
	u_char	ifi_xmitquota;		/* polling quota for xmit intrs */
	u_char	ifi_datalen;		/* length of this data struct */
	u_long	ifi_mtu;		/* maximum transmission unit */
	u_long	ifi_metric;		/* routing metric (external only) */
	u_long	ifi_baudrate;		/* linespeed */
	/* volatile statistics */
	u_long	ifi_ipackets;		/* packets received on interface */
	u_long	ifi_ierrors;		/* input errors on interface */
	u_long	ifi_opackets;		/* packets sent on interface */
	u_long	ifi_oerrors;		/* output errors on interface */
	u_long	ifi_collisions;		/* collisions on csma interfaces */
	u_long	ifi_ibytes;		/* total number of octets received */
	u_long	ifi_obytes;		/* total number of octets sent */
	u_long	ifi_imcasts;		/* packets received via multicast */
	u_long	ifi_omcasts;		/* packets sent via multicast */
	u_long	ifi_iqdrops;		/* dropped on input, this interface */
	u_long	ifi_noproto;		/* destined for unsupported protocol */
	u_long	ifi_hwassist;		/* HW offload capabilities */
	time_t	ifi_epoch;		/* time of attach or stat reset */
	struct	timeval ifi_lastchange;	/* time of last administrative change */
};

#define	IFF_UP		0x1		/* interface is up */
#define	IFF_BROADCAST	0x2		/* broadcast address valid */
#define	IFF_DEBUG	0x4		/* turn on debugging */
#define	IFF_LOOPBACK	0x8		/* is a loopback net */
#define	IFF_POINTOPOINT	0x10		/* interface is point-to-point link */
#define	IFF_SMART	0x20		/* interface manages own routes */
#define	IFF_RUNNING	0x40		/* resources allocated */
#define	IFF_NOARP	0x80		/* no address resolution protocol */
#define	IFF_PROMISC	0x100		/* receive all packets */
#define	IFF_ALLMULTI	0x200		/* receive all multicast packets */
#define	IFF_OACTIVE	0x400		/* transmission in progress */
#define	IFF_SIMPLEX	0x800		/* can't hear own transmissions */
#define	IFF_LINK0	0x1000		/* per link layer defined bit */
#define	IFF_LINK1	0x2000		/* per link layer defined bit */
#define	IFF_LINK2	0x4000		/* per link layer defined bit */
#define	IFF_ALTPHYS	IFF_LINK2	/* use alternate physical connection */
#define	IFF_MULTICAST	0x8000		/* supports multicast */
#define	IFF_POLLING	0x10000		/* Interface is in polling mode. */
#define	IFF_PPROMISC	0x20000		/* user-requested promisc mode */
#define	IFF_MONITOR	0x40000		/* user-requested monitor mode */
#define	IFF_STATICARP	0x80000		/* static ARP */
#define	IFF_NEEDSGIANT	0x100000	/* hold Giant over if_start calls */

/* flags set internally only: */
#define	IFF_CANTCHANGE \
	(IFF_BROADCAST|IFF_POINTOPOINT|IFF_RUNNING|IFF_OACTIVE|\
	    IFF_SIMPLEX|IFF_MULTICAST|IFF_ALLMULTI|IFF_SMART|IFF_PROMISC|\
	    IFF_POLLING)

/*
 * Values for if_link_state.
 */
#define	LINK_STATE_UNKNOWN	0	/* link invalid/unknown */
#define	LINK_STATE_DOWN		1	/* link is down */
#define	LINK_STATE_UP		2	/* link is up */

/*
 * Some convenience macros used for setting ifi_baudrate.
 * XXX 1000 vs. 1024? --thorpej@netbsd.org
 */
#define	IF_Kbps(x)	((x) * 1000)		/* kilobits/sec. */
#define	IF_Mbps(x)	(IF_Kbps((x) * 1000))	/* megabits/sec. */
#define	IF_Gbps(x)	(IF_Mbps((x) * 1000))	/* gigabits/sec. */

/* Capabilities that interfaces can advertise. */
#define	IFCAP_RXCSUM		0x00001  /* can offload checksum on RX */
#define	IFCAP_TXCSUM		0x00002  /* can offload checksum on TX */
#define	IFCAP_NETCONS		0x00004  /* can be a network console */
#define	IFCAP_VLAN_MTU		0x00008	/* VLAN-compatible MTU */
#define	IFCAP_VLAN_HWTAGGING	0x00010	/* hardware VLAN tag support */
#define	IFCAP_JUMBO_MTU		0x00020	/* 9000 byte MTU supported */
#define	IFCAP_POLLING		0x00040	/* driver supports polling */
#define	IFCAP_VLAN_HWCSUM	0x00080	/* can do IFCAP_HWCSUM on VLANs */
#define	IFCAP_TSO4		0x00100	/* can do TCP Segmentation Offload */
#define	IFCAP_TSO6		0x00200	/* can do TCP6 Segmentation Offload */
#define	IFCAP_LRO		0x00400	/* can do Large Receive Offload */
#define	IFCAP_WOL_UCAST		0x00800	/* wake on any unicast frame */
#define	IFCAP_WOL_MCAST		0x01000	/* wake on any multicast frame */
#define	IFCAP_WOL_MAGIC		0x02000	/* wake on any Magic Packet */
#define	IFCAP_TOE4		0x04000	/* interface can offload TCP */
#define	IFCAP_TOE6		0x08000	/* interface can offload TCP6 */
#define	IFCAP_VLAN_HWFILTER	0x10000 /* interface hw can filter vlan tag */
#define	IFCAP_POLLING_NOCOUNT	0x20000 /* polling ticks cannot be fragmented */
#define	IFCAP_VLAN_HWTSO	0x40000 /* can do IFCAP_TSO on VLANs */
#define	IFCAP_LINKSTATE		0x80000 /* the runtime link state is dynamic */
#define	IFCAP_NETMAP		0x100000 /* netmap mode supported/enabled */
#define IFCAP_HWCSUM		(IFCAP_RXCSUM | IFCAP_TXCSUM)

#define	IFQ_MAXLEN	50
#define	IFNET_SLOWHZ	1		/* granularity is 1 second */
#define IFCAP_HWCSUM	(IFCAP_RXCSUM | IFCAP_TXCSUM)
#define	IFCAP_TSO	(IFCAP_TSO4 | IFCAP_TSO6)
#define	IFCAP_WOL	(IFCAP_WOL_UCAST | IFCAP_WOL_MCAST | IFCAP_WOL_MAGIC)
#define	IFCAP_TOE	(IFCAP_TOE4 | IFCAP_TOE6)
/*
 * Message format for use in obtaining information about interfaces
 * from getkerninfo and the routing socket
 */
struct if_msghdr {
	u_short	ifm_msglen;	/* to skip over non-understood messages */
	u_char	ifm_version;	/* future binary compatibility */
	u_char	ifm_type;	/* message type */
	int	ifm_addrs;	/* like rtm_addrs */
	int	ifm_flags;	/* value of if_flags */
	u_short	ifm_index;	/* index for associated ifp */
	struct	if_data ifm_data;/* statistics and other data about if */
};

/*
 * Message format for use in obtaining information about interface addresses
 * from getkerninfo and the routing socket
 */
struct ifa_msghdr {
	u_short	ifam_msglen;	/* to skip over non-understood messages */
	u_char	ifam_version;	/* future binary compatibility */
	u_char	ifam_type;	/* message type */
	int	ifam_addrs;	/* like rtm_addrs */
	int	ifam_flags;	/* value of ifa_flags */
	u_short	ifam_index;	/* index for associated ifp */
	int	ifam_metric;	/* value of ifa_metric */
};

/*
 * Message format for use in obtaining information about multicast addresses
 * from the routing socket
 */
struct ifma_msghdr {
	u_short	ifmam_msglen;	/* to skip over non-understood messages */
	u_char	ifmam_version;	/* future binary compatibility */
	u_char	ifmam_type;	/* message type */
	int	ifmam_addrs;	/* like rtm_addrs */
	int	ifmam_flags;	/* value of ifa_flags */
	u_short	ifmam_index;	/* index for associated ifp */
};

/*
 * Message format announcing the arrival or departure of a network interface.
 */
struct if_announcemsghdr {
	u_short	ifan_msglen;	/* to skip over non-understood messages */
	u_char	ifan_version;	/* future binary compatibility */
	u_char	ifan_type;	/* message type */
	u_short	ifan_index;	/* index for associated ifp */
	char	ifan_name[IFNAMSIZ]; /* if name, e.g. "en0" */
	u_short	ifan_what;	/* what type of announcement */
};

#define	IFAN_ARRIVAL	0	/* interface arrival */
#define	IFAN_DEPARTURE	1	/* interface departure */

/*
 * Interface request structure used for socket
 * ioctl's.  All interface ioctl's must have parameter
 * definitions which begin with ifr_name.  The
 * remainder may be interface specific.
 */
struct	ifreq {
	char	ifr_name[IFNAMSIZ];		/* if name, e.g. "en0" */
	union {
		struct	sockaddr ifru_addr;
		struct	sockaddr ifru_dstaddr;
		struct	sockaddr ifru_broadaddr;
		short	ifru_flags[2];
		short	ifru_index;
		int	ifru_metric;
		int	ifru_mtu;
		int	ifru_phys;
		int	ifru_media;
		caddr_t	ifru_data;
		int	ifru_cap[2];
	} ifr_ifru;
#define	ifr_addr	ifr_ifru.ifru_addr	/* address */
#define	ifr_dstaddr	ifr_ifru.ifru_dstaddr	/* other end of p-to-p link */
#define	ifr_broadaddr	ifr_ifru.ifru_broadaddr	/* broadcast address */
#define	ifr_flags	ifr_ifru.ifru_flags[0]	/* flags (low 16 bits) */
#define	ifr_flagshigh	ifr_ifru.ifru_flags[1]	/* flags (high 16 bits) */
#define	ifr_metric	ifr_ifru.ifru_metric	/* metric */
#define	ifr_mtu		ifr_ifru.ifru_mtu	/* mtu */
#define ifr_phys	ifr_ifru.ifru_phys	/* physical wire */
#define ifr_media	ifr_ifru.ifru_media	/* physical media */
#define	ifr_data	ifr_ifru.ifru_data	/* for use by interface */
#define	ifr_reqcap	ifr_ifru.ifru_cap[0]	/* requested capabilities */
#define	ifr_curcap	ifr_ifru.ifru_cap[1]	/* current capabilities */
#define	ifr_index	ifr_ifru.ifru_index	/* interface index */
};

#define	_SIZEOF_ADDR_IFREQ(ifr) \
	((ifr).ifr_addr.sa_len > sizeof(struct sockaddr) ? \
	 (sizeof(struct ifreq) - sizeof(struct sockaddr) + \
	  (ifr).ifr_addr.sa_len) : sizeof(struct ifreq))

struct ifaliasreq {
	char	ifra_name[IFNAMSIZ];		/* if name, e.g. "en0" */
	struct	sockaddr ifra_addr;
	struct	sockaddr ifra_broadaddr;
	struct	sockaddr ifra_mask;
};

struct ifmediareq {
	char	ifm_name[IFNAMSIZ];	/* if name, e.g. "en0" */
	int	ifm_current;		/* current media options */
	int	ifm_mask;		/* don't care mask */
	int	ifm_status;		/* media status */
	int	ifm_active;		/* active options */
	int	ifm_count;		/* # entries in ifm_ulist array */
	int	*ifm_ulist;		/* media words */
};

/* 
 * Structure used to retrieve aux status data from interfaces.
 * Kernel suppliers to this interface should respect the formatting
 * needed by ifconfig(8): each line starts with a TAB and ends with
 * a newline.  The canonical example to copy and paste is in if_tun.c.
 */

#define	IFSTATMAX	800		/* 10 lines of text */
struct ifstat {
	char	ifs_name[IFNAMSIZ];	/* if name, e.g. "en0" */
	char	ascii[IFSTATMAX + 1];
};

/*
 * Structure used in SIOCGIFCONF request.
 * Used to retrieve interface configuration
 * for machine (useful for programs which
 * must know all networks accessible).
 */
struct	ifconf {
	int	ifc_len;		/* size of associated buffer */
	union {
		caddr_t	ifcu_buf;
		struct	ifreq *ifcu_req;
	} ifc_ifcu;
#define	ifc_buf	ifc_ifcu.ifcu_buf	/* buffer address */
#define	ifc_req	ifc_ifcu.ifcu_req	/* array of structures returned */
};


/*
 * Structure for SIOC[AGD]LIFADDR
 */
struct if_laddrreq {
	char	iflr_name[IFNAMSIZ];
	u_int	flags;
#define	IFLR_PREFIX	0x8000  /* in: prefix given  out: kernel fills id */
	u_int	prefixlen;         /* in/out */
	struct	sockaddr_storage addr;   /* in/out */
	struct	sockaddr_storage dstaddr; /* out */
};

#endif /* __BSD_VISIBLE */


struct if_nameindex {
	unsigned int	if_index;	/* 1, 2, ... */
	char		*if_name;	/* null terminated name: "le0", ... */
};


void			 if_freenameindex(struct if_nameindex *);
char			*if_indextoname(unsigned int, char *);
struct if_nameindex	*if_nameindex(void);
unsigned int		 if_nametoindex(const char *);

/* XXX - this should go away soon. */
#include <if_var.h>
/*
 * The INVARIANTS-enabled mtx_assert() functionality.
 *
 * The constants need to be defined for INVARIANT_SUPPORT infrastructure
 * support as _mtx_assert() itself uses them and the latter implies that
 * _mtx_assert() must build.
 */
#define MA_OWNED	0x01
#define MA_NOTOWNED	0x02
#define MA_RECURSED	0x04
#define MA_NOTRECURSED	0x08
/*
 * Mutex types and options passed to mtx_init().  MTX_QUIET can also be
 * passed in.
 */
#define	MTX_DEF		0x00000000	/* DEFAULT (sleep) lock */ 
#define MTX_SPIN	0x00000001	/* Spin lock (disables interrupts) */
#define MTX_RECURSE	0x00000004	/* Option: lock allowed to recurse */
#define	MTX_NOWITNESS	0x00000008	/* Don't do any witness checking. */
#define	MTX_DUPOK	0x00000020	/* Don't log a duplicate acquire */

/*
 * Common lock type names.
 */
#define	MTX_NETWORK_LOCK	"network driver"
#endif /* !_NET_IF_H_ */
