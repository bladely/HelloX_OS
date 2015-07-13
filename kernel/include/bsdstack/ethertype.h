#ifndef __PACKET_TYPE__
#define __PACKET_TYPE__
/*
 * Ethernet types.
 *
 * We wrap the declarations with #ifdef, so that if a file includes
 * <netinet/if_ether.h>, which may declare some of these, we don't
 * get a bunch of complaints from the C compiler about redefinitions
 * of these values.
 *
 * We declare all of them here so that no file has to include
 * <netinet/if_ether.h> if all it needs are ETHERTYPE_ values.
 */

#ifndef ETHERTYPE_PUP
#define	ETHERTYPE_PUP		0x0200	/* PUP protocol */
#endif
#ifndef ETHERTYPE_IP
#define	ETHERTYPE_IP		0x0800	/* IP protocol */
#endif
#ifndef ETHERTYPE_ARP
#define ETHERTYPE_ARP		0x0806	/* Addr. resolution protocol */
#endif
#ifndef ETHERTYPE_REVARP
#define ETHERTYPE_REVARP	0x8035	/* reverse Addr. resolution protocol */
#endif
#ifndef ETHERTYPE_NS
#define ETHERTYPE_NS		0x0600
#endif
#ifndef	ETHERTYPE_SPRITE
#define	ETHERTYPE_SPRITE	0x0500
#endif
#ifndef ETHERTYPE_TRAIL
#define ETHERTYPE_TRAIL		0x1000
#endif
#ifndef	ETHERTYPE_MOPDL
#define	ETHERTYPE_MOPDL		0x6001
#endif
#ifndef	ETHERTYPE_MOPRC
#define	ETHERTYPE_MOPRC		0x6002
#endif
#ifndef	ETHERTYPE_DN
#define	ETHERTYPE_DN		0x6003
#endif
#ifndef	ETHERTYPE_LAT
#define	ETHERTYPE_LAT		0x6004
#endif
#ifndef ETHERTYPE_SCA
#define ETHERTYPE_SCA		0x6007
#endif
#ifndef	ETHERTYPE_LANBRIDGE
#define	ETHERTYPE_LANBRIDGE	0x8038
#endif
#ifndef	ETHERTYPE_DECDNS
#define	ETHERTYPE_DECDNS	0x803c
#endif
#ifndef	ETHERTYPE_DECDTS
#define	ETHERTYPE_DECDTS	0x803e
#endif
#ifndef	ETHERTYPE_VEXP
#define	ETHERTYPE_VEXP		0x805b
#endif
#ifndef	ETHERTYPE_VPROD
#define	ETHERTYPE_VPROD		0x805c
#endif
#ifndef ETHERTYPE_ATALK
#define ETHERTYPE_ATALK		0x809b
#endif
#ifndef ETHERTYPE_AARP
#define ETHERTYPE_AARP		0x80f3
#endif
#ifndef	ETHERTYPE_8021Q
#define	ETHERTYPE_8021Q		0x8100
#endif
#ifndef ETHERTYPE_IPX
#define ETHERTYPE_IPX		0x8137
#endif
#ifndef ETHERTYPE_IPV6
#define ETHERTYPE_IPV6		0x86dd
#endif
#ifndef ETHERTYPE_PPP
#define	ETHERTYPE_PPP		0x880b
#endif
#ifndef	ETHERTYPE_MPLS
#define	ETHERTYPE_MPLS		0x8847
#endif
#ifndef	ETHERTYPE_MPLS_MULTI
#define	ETHERTYPE_MPLS_MULTI	0x8848
#endif
#ifndef ETHERTYPE_PPPOED
#define ETHERTYPE_PPPOED	0x8863
#endif
#ifndef ETHERTYPE_PPPOES
#define ETHERTYPE_PPPOES	0x8864
#endif
#ifndef ETHERTYPE_PPPOED2
#define ETHERTYPE_PPPOED2	0x3c12
#endif
#ifndef ETHERTYPE_PPPOES2
#define ETHERTYPE_PPPOES2	0x3c13
#endif
#ifndef	ETHERTYPE_LOOPBACK
#define	ETHERTYPE_LOOPBACK	0x9000
#endif
#ifndef	ETHERTYPE_VMAN
#define	ETHERTYPE_VMAN	        0x9100 /* Extreme VMAN Protocol */ 
#endif
#ifndef	ETHERTYPE_ISO
#define	ETHERTYPE_ISO           0xfefe  /* nonstandard - used in Cisco HDLC encapsulation */
#endif
struct tok {
	int v;			/* value */
	const char *s;		/* string */
};

extern const struct tok ethertype_values[];
struct pcap_pkthdr {
	struct timeval ts; /* time stamp */
	u_int32_t caplen; /* length of portion present */
	u_int32_t len; /* length this packet (off wire) */
};
/*
* The number of bytes in an ethernet (MAC) address.
*/
#define	ETHER_ADDR_LEN		6

/*
* Length of a DEC/Intel/Xerox or 802.3 Ethernet header; note that some
* compilers may pad "struct ether_header" to a multiple of 4 bytes,
* for example, so "sizeof (struct ether_header)" may not give the right
* answer.
*/
#define ETHER_HDRLEN		14


#define TFTP_PORT 69		/*XXX*/
#define KERBEROS_PORT 88	/*XXX*/
#define SUNRPC_PORT 111		/*XXX*/
#define SNMP_PORT 161		/*XXX*/
#define NTP_PORT 123		/*XXX*/
#define SNMPTRAP_PORT 162	/*XXX*/
#define ISAKMP_PORT 500		/*XXX*/
#define TIMED_PORT 525		/*XXX*/
#define RIP_PORT 520		/*XXX*/
#define LDP_PORT 646
#define AODV_PORT 654		/*XXX*/
#define KERBEROS_SEC_PORT 750	/*XXX*/
#define L2TP_PORT 1701		/*XXX*/
#define ISAKMP_PORT_USER1 7500	/*XXX - nonstandard*/
#define ISAKMP_PORT_USER2 8500	/*XXX - nonstandard*/
#define RX_PORT_LOW 7000	/*XXX*/
#define RX_PORT_HIGH 7009	/*XXX*/
#define NETBIOS_NS_PORT   137
#define NETBIOS_DGRAM_PORT   138
#define CISCO_AUTORP_PORT 496	/*XXX*/
#define RADIUS_PORT 1645
#define RADIUS_NEW_PORT 1812
#define RADIUS_ACCOUNTING_PORT 1646
#define RADIUS_NEW_ACCOUNTING_PORT 1813
#define HSRP_PORT 1985		/*XXX*/
#define LWRES_PORT		921
#define ZEPHYR_SRV_PORT		2103
#define ZEPHYR_CLT_PORT		2104
#define MPLS_LSP_PING_PORT      3503 /* draft-ietf-mpls-lsp-ping-02.txt */
#define BFD_CONTROL_PORT        3784 /* draft-katz-ward-bfd-v4v6-1hop-00.txt */
#define BFD_ECHO_PORT           3785 /* draft-katz-ward-bfd-v4v6-1hop-00.txt */



extern int aflag;		/* translate network and broadcast addresses */
extern int dflag;		/* print filter code */
extern int eflag;		/* print ethernet header */
extern int fflag;		/* don't translate "foreign" IP address */
extern int nflag;		/* leave addresses as numbers */
extern int Nflag;		/* remove domains from printed host names */
extern int qflag;		/* quick (shorter) output */
extern int Rflag;		/* print sequence # field in AH/ESP*/
extern int sflag;		/* use the libsmi to translate OIDs */
extern int Sflag;		/* print raw TCP sequence numbers */
extern int tflag;		/* print packet arrival time */
extern int uflag;		/* Print undecoded NFS handles */
extern int vflag;		/* verbose */
extern int xflag;		/* print packet in hex */
extern int Xflag;		/* print packet in hex/ascii */
extern int Aflag;		/* print packet only in ascii observing TAB, LF, CR and SPACE as graphical chars */
extern char *espsecret;

extern int packettype;		/* as specified by -T */
#define PT_VAT		1	/* Visual Audio Tool */
#define PT_WB		2	/* distributed White Board */
#define PT_RPC		3	/* Remote Procedure Call */
#define PT_RTP		4	/* Real-Time Applications protocol */
#define PT_RTCP		5	/* Real-Time Applications control protocol */
#define PT_SNMP		6	/* Simple Network Management Protocol */
#define PT_CNFP		7	/* Cisco NetFlow protocol */
#define PT_TFTP		8	/* trivial file transfer protocol */
#define PT_AODV		9	/* Ad-hoc On-demand Distance Vector Protocol */
extern char *program_name;	/* used to generate self-identifying messages */

extern int thiszone;	/* seconds offset from gmt to local time */

extern int snaplen;
/* global pointer to end of current packet (during printing) */
extern const u_char *snapend;

#ifndef IPPROTO_IP
#define	IPPROTO_IP		0		/* dummy for IP */
#endif
#ifndef IPPROTO_HOPOPTS
#define IPPROTO_HOPOPTS		0		/* IPv6 hop-by-hop options */
#endif
#ifndef IPPROTO_ICMP
#define	IPPROTO_ICMP		1		/* control message protocol */
#endif
#ifndef IPPROTO_IGMP
#define	IPPROTO_IGMP		2		/* group mgmt protocol */
#endif
#ifndef IPPROTO_IPV4
#define IPPROTO_IPV4		4
#endif
#ifndef IPPROTO_TCP
#define	IPPROTO_TCP		6		/* tcp */
#endif
#ifndef IPPROTO_EGP
#define	IPPROTO_EGP		8		/* exterior gateway protocol */
#endif
#ifndef IPPROTO_IGRP
#define IPPROTO_IGRP		9
#endif
#ifndef IPPROTO_UDP
#define	IPPROTO_UDP		17		/* user datagram protocol */
#endif
#ifndef IPPROTO_IPV6
#define IPPROTO_IPV6		41
#endif
#ifndef IPPROTO_ROUTING
#define IPPROTO_ROUTING		43		/* IPv6 routing header */
#endif
#ifndef IPPROTO_FRAGMENT
#define IPPROTO_FRAGMENT	44		/* IPv6 fragmentation header */
#endif
#ifndef IPPROTO_RSVP
#define IPPROTO_RSVP		46 		/* resource reservation */
#endif
#ifndef IPPROTO_GRE
#define	IPPROTO_GRE		47		/* General Routing Encap. */
#endif
#ifndef IPPROTO_ESP
#define	IPPROTO_ESP		50		/* SIPP Encap Sec. Payload */
#endif
#ifndef IPPROTO_AH
#define	IPPROTO_AH		51		/* SIPP Auth Header */
#endif
#ifndef IPPROTO_MOBILE
#define IPPROTO_MOBILE		55
#endif
#ifndef IPPROTO_ICMPV6
#define IPPROTO_ICMPV6		58		/* ICMPv6 */
#endif
#ifndef IPPROTO_NONE
#define IPPROTO_NONE		59		/* IPv6 no next header */
#endif
#ifndef IPPROTO_DSTOPTS
#define IPPROTO_DSTOPTS		60		/* IPv6 destination options */
#endif
#ifndef IPPROTO_MOBILITY_OLD
/*
* The current Protocol Numbers list says that the IP protocol number for
* mobility headers is 135; it cites draft-ietf-mobileip-ipv6-24, but
* that draft doesn't actually give a number.
*
* It appears that 62 used to be used, even though that's assigned to
* a protocol called CFTP; however, the only reference for CFTP is a
* Network Message from BBN back in 1982, so, for now, we support 62,
* aas well as 135, as a protocol number for mobility headers.
*/
#define IPPROTO_MOBILITY_OLD	62
#endif
#ifndef IPPROTO_ND
#define	IPPROTO_ND		77		/* Sun net disk proto (temp.) */
#endif
#ifndef IPPROTO_IGRP
#define	IPPROTO_IGRP		88		/* Cisco/GXS IGRP */
#endif
#ifndef IPPROTO_OSPF
#define IPPROTO_OSPF		89
#endif
#ifndef IPPROTO_PIM
#define IPPROTO_PIM		103
#endif
#ifndef IPPROTO_IPCOMP
#define IPPROTO_IPCOMP		108
#endif
#ifndef IPPROTO_VRRP
#define IPPROTO_VRRP		112
#endif
#ifndef IPPROTO_SCTP
#define IPPROTO_SCTP		132
#endif
#ifndef IPPROTO_MOBILITY
#define IPPROTO_MOBILITY	135
#endif



#define RPC_MSG_VERSION		((u_int32_t) 2)
#define RPC_SERVICE_PORT	((u_short) 2048)

/*
 * Bottom up definition of an rpc message.
 * NOTE: call and reply use the same overall stuct but
 * different parts of unions within it.
 */

enum msg_type {
	CALL=0,
	REPLY=1
};

enum reply_stat {
	MSG_ACCEPTED=0,
	MSG_DENIED=1
};

enum accept_stat {
	SUCCESS=0,
	PROG_UNAVAIL=1,
	PROG_MISMATCH=2,
	PROC_UNAVAIL=3,
	GARBAGE_ARGS=4,
	SYSTEM_ERR=5
};

enum reject_stat {
	RPC_MISMATCH=0,
	AUTH_ERROR=1
};

/*
 * Reply part of an rpc exchange
 */
typedef int bool_t;
typedef int enum_t;

typedef u_int32_t rpcprog_t;
typedef u_int32_t rpcvers_t;
typedef u_int32_t rpcproc_t;
typedef u_int32_t rpcprot_t;
typedef u_int32_t rpcport_t;
typedef   int rpc_inline_t;

 /*
 * Authentication info.  Opaque to client.
*/
struct opaque_auth {
	enum_t	oa_flavor;		/* flavor of auth */
	caddr_t	oa_base;		/* address of more auth stuff */
	u_int	oa_length;		/* not to exceed MAX_AUTH_BYTES */
};
/*
* The XDR handle.
* Contains operation which is being applied to the stream,
* an operations vector for the particular implementation (e.g. see xdr_mem.c),
* and two private fields for the use of the particular implementation.
*/
typedef struct __rpc_xdr {
	enum xdr_op	x_op;		/* operation; fast additional param */
	const struct xdr_ops {
		/* get a long from underlying stream */
		bool_t	(*x_getlong)(struct __rpc_xdr *, long *);
		/* put a long to " */
		bool_t	(*x_putlong)(struct __rpc_xdr *, const long *);
		/* get some bytes from " */
		bool_t	(*x_getbytes)(struct __rpc_xdr *, char *, u_int);
		/* put some bytes to " */
		bool_t	(*x_putbytes)(struct __rpc_xdr *, const char *, u_int);
		/* returns bytes off from beginning */
		u_int	(*x_getpostn)(struct __rpc_xdr *);
		/* lets you reposition the stream */
		bool_t  (*x_setpostn)(struct __rpc_xdr *, u_int);
		/* buf quick ptr to buffered data */
		int *(*x_inline)(struct __rpc_xdr *, u_int);
		/* free privates of this xdr_stream */
		void	(*x_destroy)(struct __rpc_xdr *);
		bool_t	(*x_control)(struct __rpc_xdr *, int, void *);
	} *x_ops;
	char *	 	x_public;	/* users' data */
	void *		x_private;	/* pointer to private data */
	char * 		x_base;		/* private used for position info */
	u_int		x_handy;	/* extra private word */
} XDR;

typedef	bool_t (*xdrproc_t)(XDR *, void *, u_int);

/*
 * Reply to an rpc request that was accepted by the server.
 * Note: there could be an error even though the request was
 * accepted.
 */
struct accepted_reply {
	struct opaque_auth	ar_verf;
	enum accept_stat	ar_stat;
	union {
		struct {
			rpcvers_t low;
			rpcvers_t high;
		} AR_versions;
		struct {
			caddr_t	where;
			xdrproc_t proc;
		} AR_results;
		/* and many other null cases */
	} ru;
#define	ar_results	ru.AR_results
#define	ar_vers		ru.AR_versions
};

/*
 * Reply to an rpc request that was rejected by the server.
 */
struct rejected_reply {
	enum reject_stat rj_stat;
	union {
		struct {
			rpcvers_t low;
			rpcvers_t high;
		} RJ_versions;
		enum auth_stat RJ_why;  /* why authentication did not work */
	} ru;
#define	rj_vers	ru.RJ_versions
#define	rj_why	ru.RJ_why
};

/*
 * Body of a reply to an rpc request.
 */
struct reply_body {
	enum reply_stat rp_stat;
	union {
		struct accepted_reply RP_ar;
		struct rejected_reply RP_dr;
	} ru;
#define	rp_acpt	ru.RP_ar
#define	rp_rjct	ru.RP_dr
};

/*
 * Body of an rpc request call.
 */
struct call_body {
	rpcvers_t cb_rpcvers;	/* must be equal to two */
	rpcprog_t cb_prog;
	rpcvers_t cb_vers;
	rpcproc_t cb_proc;
	struct opaque_auth cb_cred;
	struct opaque_auth cb_verf; /* protocol specific - provided by client */
};

/*
 * The rpc message
 */
struct rpc_msg {
	u_int32_t		rm_xid;
	enum msg_type		rm_direction;
	union {
		struct call_body RM_cmb;
		struct reply_body RM_rmb;
	} ru;
#define	rm_call		ru.RM_cmb
#define	rm_reply	ru.RM_rmb
};
#define	acpted_rply	ru.RM_rmb.ru.RP_ar
#define	rjcted_rply	ru.RM_rmb.ru.RP_dr

/*
 * Constants as defined in the Sun NFS Version 2 and 3 specs.
 * "NFS: Network File System Protocol Specification" RFC1094
 * and in the "NFS: Network File System Version 3 Protocol
 * Specification"
 */

#define NFS_PORT	2049
#define	NFS_PROG	100003
#define NFS_VER2	2
#define	NFS_VER3	3
#define NFS_V2MAXDATA	8192
#define	NFS_MAXDGRAMDATA 16384
#define	NFS_MAXDATA	32768
#define	NFS_MAXPATHLEN	1024
#define	NFS_MAXNAMLEN	255
#define	NFS_MAXPKTHDR	404
#define NFS_MAXPACKET	(NFS_MAXPKTHDR + NFS_MAXDATA)
#define	NFS_MINPACKET	20
#define	NFS_FABLKSIZE	512	/* Size in bytes of a block wrt fa_blocks */

/* Stat numbers for rpc returns (version 2 and 3) */
#define	NFS_OK			0
#define	NFSERR_PERM		1
#define	NFSERR_NOENT		2
#define	NFSERR_IO		5
#define	NFSERR_NXIO		6
#define	NFSERR_ACCES		13
#define	NFSERR_EXIST		17
#define	NFSERR_XDEV		18	/* Version 3 only */
#define	NFSERR_NODEV		19
#define	NFSERR_NOTDIR		20
#define	NFSERR_ISDIR		21
#define	NFSERR_INVAL		22	/* Version 3 only */
#define	NFSERR_FBIG		27
#define	NFSERR_NOSPC		28
#define	NFSERR_ROFS		30
#define	NFSERR_MLINK		31	/* Version 3 only */
#define	NFSERR_NAMETOL		63
#define	NFSERR_NOTEMPTY		66
#define	NFSERR_DQUOT		69
#define	NFSERR_STALE		70
#define	NFSERR_REMOTE		71	/* Version 3 only */
#define	NFSERR_WFLUSH		99	/* Version 2 only */
#define	NFSERR_BADHANDLE	10001	/* The rest Version 3 only */
#define	NFSERR_NOT_SYNC		10002
#define	NFSERR_BAD_COOKIE	10003
#define	NFSERR_NOTSUPP		10004
#define	NFSERR_TOOSMALL		10005
#define	NFSERR_SERVERFAULT	10006
#define	NFSERR_BADTYPE		10007
#define	NFSERR_JUKEBOX		10008
#define NFSERR_TRYLATER		NFSERR_JUKEBOX
#define	NFSERR_STALEWRITEVERF	30001	/* Fake return for nfs_commit() */

#define NFSERR_RETVOID		0x20000000 /* Return void, not error */
#define NFSERR_AUTHERR		0x40000000 /* Mark an authentication error */
#define NFSERR_RETERR		0x80000000 /* Mark an error return for V3 */

/* Sizes in bytes of various nfs rpc components */
#define	NFSX_UNSIGNED	4

/* specific to NFS Version 2 */
#define	NFSX_V2FH	32
#define	NFSX_V2FATTR	68
#define	NFSX_V2SATTR	32
#define	NFSX_V2COOKIE	4
#define NFSX_V2STATFS	20

/* specific to NFS Version 3 */
#if 0
#define NFSX_V3FH		(sizeof (fhandle_t)) /* size this server uses */
#endif
#define	NFSX_V3FHMAX		64	/* max. allowed by protocol */
#define NFSX_V3FATTR		84
#define NFSX_V3SATTR		60	/* max. all fields filled in */
#define NFSX_V3SRVSATTR		(sizeof (struct nfsv3_sattr))
#define NFSX_V3POSTOPATTR	(NFSX_V3FATTR + NFSX_UNSIGNED)
#define NFSX_V3WCCDATA		(NFSX_V3POSTOPATTR + 8 * NFSX_UNSIGNED)
#define NFSX_V3COOKIEVERF 	8
#define NFSX_V3WRITEVERF 	8
#define NFSX_V3CREATEVERF	8
#define NFSX_V3STATFS		52
#define NFSX_V3FSINFO		48
#define NFSX_V3PATHCONF		24

/* variants for both versions */
#define NFSX_FH(v3)		((v3) ? (NFSX_V3FHMAX + NFSX_UNSIGNED) : \
					NFSX_V2FH)
#define NFSX_SRVFH(v3)		((v3) ? NFSX_V3FH : NFSX_V2FH)
#define	NFSX_FATTR(v3)		((v3) ? NFSX_V3FATTR : NFSX_V2FATTR)
#define NFSX_PREOPATTR(v3)	((v3) ? (7 * NFSX_UNSIGNED) : 0)
#define NFSX_POSTOPATTR(v3)	((v3) ? (NFSX_V3FATTR + NFSX_UNSIGNED) : 0)
#define NFSX_POSTOPORFATTR(v3)	((v3) ? (NFSX_V3FATTR + NFSX_UNSIGNED) : \
					NFSX_V2FATTR)
#define NFSX_WCCDATA(v3)	((v3) ? NFSX_V3WCCDATA : 0)
#define NFSX_WCCORFATTR(v3)	((v3) ? NFSX_V3WCCDATA : NFSX_V2FATTR)
#define	NFSX_SATTR(v3)		((v3) ? NFSX_V3SATTR : NFSX_V2SATTR)
#define	NFSX_COOKIEVERF(v3)	((v3) ? NFSX_V3COOKIEVERF : 0)
#define	NFSX_WRITEVERF(v3)	((v3) ? NFSX_V3WRITEVERF : 0)
#define NFSX_READDIR(v3)	((v3) ? (5 * NFSX_UNSIGNED) : \
					(2 * NFSX_UNSIGNED))
#define	NFSX_STATFS(v3)		((v3) ? NFSX_V3STATFS : NFSX_V2STATFS)

/* nfs rpc procedure numbers (before version mapping) */
#define	NFSPROC_NULL		0
#define	NFSPROC_GETATTR		1
#define	NFSPROC_SETATTR		2
#define	NFSPROC_LOOKUP		3
#define	NFSPROC_ACCESS		4
#define	NFSPROC_READLINK	5
#define	NFSPROC_READ		6
#define	NFSPROC_WRITE		7
#define	NFSPROC_CREATE		8
#define	NFSPROC_MKDIR		9
#define	NFSPROC_SYMLINK		10
#define	NFSPROC_MKNOD		11
#define	NFSPROC_REMOVE		12
#define	NFSPROC_RMDIR		13
#define	NFSPROC_RENAME		14
#define	NFSPROC_LINK		15
#define	NFSPROC_READDIR		16
#define	NFSPROC_READDIRPLUS	17
#define	NFSPROC_FSSTAT		18
#define	NFSPROC_FSINFO		19
#define	NFSPROC_PATHCONF	20
#define	NFSPROC_COMMIT		21

/* And leasing (nqnfs) procedure numbers (must be last) */
#define	NQNFSPROC_GETLEASE	22
#define	NQNFSPROC_VACATED	23
#define	NQNFSPROC_EVICTED	24

#define NFSPROC_NOOP		25
#define	NFS_NPROCS		26

/* Actual Version 2 procedure numbers */
#define	NFSV2PROC_NULL		0
#define	NFSV2PROC_GETATTR	1
#define	NFSV2PROC_SETATTR	2
#define	NFSV2PROC_NOOP		3
#define	NFSV2PROC_ROOT		NFSV2PROC_NOOP	/* Obsolete */
#define	NFSV2PROC_LOOKUP	4
#define	NFSV2PROC_READLINK	5
#define	NFSV2PROC_READ		6
#define	NFSV2PROC_WRITECACHE	NFSV2PROC_NOOP	/* Obsolete */
#define	NFSV2PROC_WRITE		8
#define	NFSV2PROC_CREATE	9
#define	NFSV2PROC_REMOVE	10
#define	NFSV2PROC_RENAME	11
#define	NFSV2PROC_LINK		12
#define	NFSV2PROC_SYMLINK	13
#define	NFSV2PROC_MKDIR		14
#define	NFSV2PROC_RMDIR		15
#define	NFSV2PROC_READDIR	16
#define	NFSV2PROC_STATFS	17

/*
 * Constants used by the Version 3 protocol for various RPCs
 */
#define NFSV3SATTRTIME_DONTCHANGE	0
#define NFSV3SATTRTIME_TOSERVER		1
#define NFSV3SATTRTIME_TOCLIENT		2

#define NFSV3ATTRTIME_NMODES		3

#define NFSV3ACCESS_READ		0x01
#define NFSV3ACCESS_LOOKUP		0x02
#define NFSV3ACCESS_MODIFY		0x04
#define NFSV3ACCESS_EXTEND		0x08
#define NFSV3ACCESS_DELETE		0x10
#define NFSV3ACCESS_EXECUTE		0x20

#define NFSV3WRITE_UNSTABLE		0
#define NFSV3WRITE_DATASYNC		1
#define NFSV3WRITE_FILESYNC		2

#define NFSV3WRITE_NMODES		3

#define NFSV3CREATE_UNCHECKED		0
#define NFSV3CREATE_GUARDED		1
#define NFSV3CREATE_EXCLUSIVE		2

#define NFSV3CREATE_NMODES		3

#define NFSV3FSINFO_LINK		0x01
#define NFSV3FSINFO_SYMLINK		0x02
#define NFSV3FSINFO_HOMOGENEOUS		0x08
#define NFSV3FSINFO_CANSETTIME		0x10

/* Conversion macros */
#define	vtonfsv2_mode(t,m) \
		txdr_unsigned(((t) == VFIFO) ? MAKEIMODE(VCHR, (m)) : \
				MAKEIMODE((t), (m)))
#define vtonfsv3_mode(m)	txdr_unsigned((m) & 07777)
#define	nfstov_mode(a)		(fxdr_unsigned(u_int16_t, (a))&07777)
#define	vtonfsv2_type(a)	txdr_unsigned(nfsv2_type[((int32_t)(a))])
#define	vtonfsv3_type(a)	txdr_unsigned(nfsv3_type[((int32_t)(a))])
#define	nfsv2tov_type(a)	nv2tov_type[fxdr_unsigned(u_int32_t,(a))&0x7]
#define	nfsv3tov_type(a)	nv3tov_type[fxdr_unsigned(u_int32_t,(a))&0x7]

/* File types */
typedef enum { NFNON=0, NFREG=1, NFDIR=2, NFBLK=3, NFCHR=4, NFLNK=5,
	NFSOCK=6, NFFIFO=7 } nfs_type;

/* Structs for common parts of the rpc's */
/*
 * File Handle (32 bytes for version 2), variable up to 64 for version 3.
 * File Handles of up to NFS_SMALLFH in size are stored directly in the
 * nfs node, whereas larger ones are malloc'd. (This never happens when
 * NFS_SMALLFH is set to 64.)
 * NFS_SMALLFH should be in the range of 32 to 64 and be divisible by 4.
 */
#ifndef NFS_SMALLFH
#define NFS_SMALLFH	64
#endif
union nfsfh {
/*	fhandle_t fh_generic; */
	u_char    fh_bytes[NFS_SMALLFH];
};
typedef union nfsfh nfsfh_t;

struct nfsv2_time {
	u_int32_t nfsv2_sec;
	u_int32_t nfsv2_usec;
};
typedef struct nfsv2_time	nfstime2;

struct nfsv3_time {
	u_int32_t nfsv3_sec;
	u_int32_t nfsv3_nsec;
};
typedef struct nfsv3_time	nfstime3;

/*
 * Quads are defined as arrays of 2 longs to ensure dense packing for the
 * protocol and to facilitate xdr conversion.
 */
struct nfs_uquad {
	u_int32_t nfsuquad[2];
};
typedef	struct nfs_uquad	nfsuint64;

#if 0 /* XXX - this doesn't seemed to be used and it doesn't work
       * with non-gcc, so comment it out for now.
       */

/*
 * Used to convert between two u_longs and a u_quad_t.
 */
union nfs_quadconvert {
	u_int32_t lval[2];
	u_int64_t qval;
};
typedef union nfs_quadconvert	nfsquad_t;

#endif

/*
 * NFS Version 3 special file number.
 */
struct nfsv3_spec {
	u_int32_t specdata1;
	u_int32_t specdata2;
};
typedef	struct nfsv3_spec	nfsv3spec;

/*
 * File attributes and setable attributes. These structures cover both
 * NFS version 2 and the version 3 protocol. Note that the union is only
 * used so that one pointer can refer to both variants. These structures
 * go out on the wire and must be densely packed, so no quad data types
 * are used. (all fields are longs or u_longs or structures of same)
 * NB: You can't do sizeof(struct nfs_fattr), you must use the
 *     NFSX_FATTR(v3) macro.
 */
struct nfs_fattr {
	u_int32_t fa_type;
	u_int32_t fa_mode;
	u_int32_t fa_nlink;
	u_int32_t fa_uid;
	u_int32_t fa_gid;
	union {
		struct {
			u_int32_t nfsv2fa_size;
			u_int32_t nfsv2fa_blocksize;
			u_int32_t nfsv2fa_rdev;
			u_int32_t nfsv2fa_blocks;
			u_int32_t nfsv2fa_fsid;
			u_int32_t nfsv2fa_fileid;
			nfstime2  nfsv2fa_atime;
			nfstime2  nfsv2fa_mtime;
			nfstime2  nfsv2fa_ctime;
		} fa_nfsv2;
		struct {
			nfsuint64 nfsv3fa_size;
			nfsuint64 nfsv3fa_used;
			nfsv3spec nfsv3fa_rdev;
			nfsuint64 nfsv3fa_fsid;
			nfsuint64 nfsv3fa_fileid;
			nfstime3  nfsv3fa_atime;
			nfstime3  nfsv3fa_mtime;
			nfstime3  nfsv3fa_ctime;
		} fa_nfsv3;
	} fa_un;
};

/* and some ugly defines for accessing union components */
#define	fa2_size		fa_un.fa_nfsv2.nfsv2fa_size
#define	fa2_blocksize		fa_un.fa_nfsv2.nfsv2fa_blocksize
#define	fa2_rdev		fa_un.fa_nfsv2.nfsv2fa_rdev
#define	fa2_blocks		fa_un.fa_nfsv2.nfsv2fa_blocks
#define	fa2_fsid		fa_un.fa_nfsv2.nfsv2fa_fsid
#define	fa2_fileid		fa_un.fa_nfsv2.nfsv2fa_fileid
#define	fa2_atime		fa_un.fa_nfsv2.nfsv2fa_atime
#define	fa2_mtime		fa_un.fa_nfsv2.nfsv2fa_mtime
#define	fa2_ctime		fa_un.fa_nfsv2.nfsv2fa_ctime
#define	fa3_size		fa_un.fa_nfsv3.nfsv3fa_size
#define	fa3_used		fa_un.fa_nfsv3.nfsv3fa_used
#define	fa3_rdev		fa_un.fa_nfsv3.nfsv3fa_rdev
#define	fa3_fsid		fa_un.fa_nfsv3.nfsv3fa_fsid
#define	fa3_fileid		fa_un.fa_nfsv3.nfsv3fa_fileid
#define	fa3_atime		fa_un.fa_nfsv3.nfsv3fa_atime
#define	fa3_mtime		fa_un.fa_nfsv3.nfsv3fa_mtime
#define	fa3_ctime		fa_un.fa_nfsv3.nfsv3fa_ctime

struct nfsv2_sattr {
	u_int32_t sa_mode;
	u_int32_t sa_uid;
	u_int32_t sa_gid;
	u_int32_t sa_size;
	nfstime2  sa_atime;
	nfstime2  sa_mtime;
};

/*
 * NFS Version 3 sattr structure for the new node creation case.
 */
struct nfsv3_sattr {
	u_int32_t   sa_modeset;
	u_int32_t   sa_mode;
	u_int32_t   sa_uidset;
	u_int32_t   sa_uid;
	u_int32_t   sa_gidset;
	u_int32_t   sa_gid;
	u_int32_t   sa_sizeset;
	u_int32_t   sa_size;
	u_int32_t   sa_atimetype;
	nfstime3  sa_atime;
	u_int32_t   sa_mtimetype;
	nfstime3  sa_mtime;
};

struct nfs_statfs {
	union {
		struct {
			u_int32_t nfsv2sf_tsize;
			u_int32_t nfsv2sf_bsize;
			u_int32_t nfsv2sf_blocks;
			u_int32_t nfsv2sf_bfree;
			u_int32_t nfsv2sf_bavail;
		} sf_nfsv2;
		struct {
			nfsuint64 nfsv3sf_tbytes;
			nfsuint64 nfsv3sf_fbytes;
			nfsuint64 nfsv3sf_abytes;
			nfsuint64 nfsv3sf_tfiles;
			nfsuint64 nfsv3sf_ffiles;
			nfsuint64 nfsv3sf_afiles;
			u_int32_t nfsv3sf_invarsec;
		} sf_nfsv3;
	} sf_un;
};

#define sf_tsize	sf_un.sf_nfsv2.nfsv2sf_tsize
#define sf_bsize	sf_un.sf_nfsv2.nfsv2sf_bsize
#define sf_blocks	sf_un.sf_nfsv2.nfsv2sf_blocks
#define sf_bfree	sf_un.sf_nfsv2.nfsv2sf_bfree
#define sf_bavail	sf_un.sf_nfsv2.nfsv2sf_bavail
#define sf_tbytes	sf_un.sf_nfsv3.nfsv3sf_tbytes
#define sf_fbytes	sf_un.sf_nfsv3.nfsv3sf_fbytes
#define sf_abytes	sf_un.sf_nfsv3.nfsv3sf_abytes
#define sf_tfiles	sf_un.sf_nfsv3.nfsv3sf_tfiles
#define sf_ffiles	sf_un.sf_nfsv3.nfsv3sf_ffiles
#define sf_afiles	sf_un.sf_nfsv3.nfsv3sf_afiles
#define sf_invarsec	sf_un.sf_nfsv3.nfsv3sf_invarsec

struct nfsv3_fsinfo {
	u_int32_t fs_rtmax;
	u_int32_t fs_rtpref;
	u_int32_t fs_rtmult;
	u_int32_t fs_wtmax;
	u_int32_t fs_wtpref;
	u_int32_t fs_wtmult;
	u_int32_t fs_dtpref;
	nfsuint64 fs_maxfilesize;
	nfstime3  fs_timedelta;
	u_int32_t fs_properties;
};

struct nfsv3_pathconf {
	u_int32_t pc_linkmax;
	u_int32_t pc_namemax;
	u_int32_t pc_notrunc;
	u_int32_t pc_chownrestricted;
	u_int32_t pc_caseinsensitive;
	u_int32_t pc_casepreserving;
};



struct LAP {
	u_int8_t	dst;
	u_int8_t	src;
	u_int8_t	type;
};
#define lapShortDDP	1	/* short DDP type */
#define lapDDP		2	/* DDP type */
#define lapKLAP		'K'	/* Kinetics KLAP type */



/*
 * Define constants based on rfc883
 */
#define PACKETSZ	512		/* maximum packet size */
#define MAXDNAME	256		/* maximum domain name */
#define MAXCDNAME	255		/* maximum compressed domain name */
#define MAXLABEL	63		/* maximum length of domain label */
	/* Number of bytes of fixed size data in query structure */
#define QFIXEDSZ	4
	/* number of bytes of fixed size data in resource record */
#define RRFIXEDSZ	10

/*
 * Internet nameserver port number
 */
#define NAMESERVER_PORT	53
#define MULTICASTDNS_PORT	5353

/*
 * Currently defined opcodes
 */
#define QUERY		0x0		/* standard query */
#define IQUERY		0x1		/* inverse query */
#define STATUS		0x2		/* nameserver status query */
#if 0
#define xxx		0x3		/* 0x3 reserved */
#endif
	/* non standard - supports ALLOW_UPDATES stuff from Mike Schwartz */
#define UPDATEA		0x9		/* add resource record */
#define UPDATED		0xa		/* delete a specific resource record */
#define UPDATEDA	0xb		/* delete all named resource record */
#define UPDATEM		0xc		/* modify a specific resource record */
#define UPDATEMA	0xd		/* modify all named resource record */

#define ZONEINIT	0xe		/* initial zone transfer */
#define ZONEREF		0xf		/* incremental zone referesh */

/*
 * Undefine various #defines from various System V-flavored OSes (Solaris,
 * SINIX, HP-UX) so the compiler doesn't whine that we redefine them.
 */
#ifdef T_NULL
#undef T_NULL
#endif
#ifdef T_OPT
#undef T_OPT
#endif
#ifdef T_UNSPEC
#undef T_UNSPEC
#endif
#ifdef NOERROR
#undef NOERROR
#endif

/*
 * Currently defined response codes
 */
#define NOERROR		0		/* no error */
#define FORMERR		1		/* format error */
#define SERVFAIL	2		/* server failure */
#define NXDOMAIN	3		/* non existent domain */
#define NOTIMP		4		/* not implemented */
#define REFUSED		5		/* query refused */
	/* non standard */
#define NOCHANGE	0xf		/* update failed to change db */

/*
 * Type values for resources and queries
 */
#define T_A		1		/* host address */
#define T_NS		2		/* authoritative server */
#define T_MD		3		/* mail destination */
#define T_MF		4		/* mail forwarder */
#define T_CNAME		5		/* connonical name */
#define T_SOA		6		/* start of authority zone */
#define T_MB		7		/* mailbox domain name */
#define T_MG		8		/* mail group member */
#define T_MR		9		/* mail rename name */
#define T_NULL		10		/* null resource record */
#define T_WKS		11		/* well known service */
#define T_PTR		12		/* domain name pointer */
#define T_HINFO		13		/* host information */
#define T_MINFO		14		/* mailbox information */
#define T_MX		15		/* mail routing information */
#define T_TXT		16		/* text strings */
#define	T_RP		17		/* responsible person */
#define	T_AFSDB		18		/* AFS cell database */
#define T_X25		19		/* X_25 calling address */
#define T_ISDN		20		/* ISDN calling address */
#define T_RT		21		/* router */
#define	T_NSAP		22		/* NSAP address */
#define	T_NSAP_PTR	23		/* reverse lookup for NSAP */
#define T_SIG		24		/* security signature */
#define T_KEY		25		/* security key */
#define T_PX		26		/* X.400 mail mapping */
#define T_GPOS		27		/* geographical position (withdrawn) */
#define T_AAAA		28		/* IP6 Address */
#define T_LOC		29		/* Location Information */
#define T_NXT		30		/* Next Valid Name in Zone */
#define T_EID		31		/* Endpoint identifier */
#define T_NIMLOC	32		/* Nimrod locator */
#define T_SRV		33		/* Server selection */
#define T_ATMA		34		/* ATM Address */
#define T_NAPTR		35		/* Naming Authority PoinTeR */
#define T_A6		38		/* IP6 address */
#define T_DNAME		39		/* non-terminal redirection */
#define T_OPT		41		/* EDNS0 option (meta-RR) */
	/* non standard */
#define T_UINFO		100		/* user (finger) information */
#define T_UID		101		/* user ID */
#define T_GID		102		/* group ID */
#define T_UNSPEC	103		/* Unspecified format (binary data) */
#define T_UNSPECA	104		/* "unspecified ascii". Ugly MIT hack */
	/* Query type values which do not appear in resource records */
#define T_TKEY		249		/* Transaction Key [RFC2930] */
#define T_TSIG		250		/* Transaction Signature [RFC2845] */
#define T_IXFR		251		/* incremental transfer [RFC1995] */
#define T_AXFR		252		/* transfer zone of authority */
#define T_MAILB		253		/* transfer mailbox records */
#define T_MAILA		254		/* transfer mail agent records */
#define T_ANY		255		/* wildcard match */

/*
 * Values for class field
 */

#define C_IN		1		/* the arpa internet */
#define C_CHAOS		3		/* for chaos net (MIT) */
#define C_HS		4		/* for Hesiod name server (MIT) (XXX) */
	/* Query class values which do not appear in resource records */
#define C_ANY		255		/* wildcard match */
#define C_CACHE_FLUSH	0x8000		/* mDNS cache flush flag */

/*
 * Status return codes for T_UNSPEC conversion routines
 */
#define CONV_SUCCESS 0
#define CONV_OVERFLOW -1
#define CONV_BADFMT -2
#define CONV_BADCKSUM -3
#define CONV_BADBUFLEN -4

/*
 * Structure for query header.
 */
typedef struct {
	u_int16_t id;		/* query identification number */
	u_int8_t  flags1;	/* first byte of flags */
	u_int8_t  flags2;	/* second byte of flags */
	u_int16_t qdcount;	/* number of question entries */
	u_int16_t ancount;	/* number of answer entries */
	u_int16_t nscount;	/* number of authority entries */
	u_int16_t arcount;	/* number of resource entries */
} HEADER;


struct bootp {
	u_int8_t	bp_op;		/* packet opcode type */
	u_int8_t	bp_htype;	/* hardware addr type */
	u_int8_t	bp_hlen;	/* hardware addr length */
	u_int8_t	bp_hops;	/* gateway hops */
	u_int32_t	bp_xid;		/* transaction ID */
	u_int16_t	bp_secs;	/* seconds since boot began */
	u_int16_t	bp_flags;	/* flags - see bootp_flag_values[] in print-bootp.c */
	struct in_addr	bp_ciaddr;	/* client IP address */
	struct in_addr	bp_yiaddr;	/* 'your' IP address */
	struct in_addr	bp_siaddr;	/* server IP address */
	struct in_addr	bp_giaddr;	/* gateway IP address */
	u_int8_t	bp_chaddr[16];	/* client hardware address */
	u_int8_t	bp_sname[64];	/* server host name */
	u_int8_t	bp_file[128];	/* boot file name */
	u_int8_t	bp_vend[64];	/* vendor-specific area */
};

/*
 * UDP port numbers, server and client.
 */
#define	IPPORT_BOOTPS		67
#define	IPPORT_BOOTPC		68

#define BOOTPREPLY		2
#define BOOTPREQUEST		1

/*
 * Vendor magic cookie (v_magic) for CMU
 */
#define VM_CMU		"CMU"

/*
 * Vendor magic cookie (v_magic) for RFC1048
 */
#define VM_RFC1048	{ 99, 130, 83, 99 }



/*
 * RFC1048 tag values used to specify what information is being supplied in
 * the vendor field of the packet.
 */

#define TAG_PAD			((u_int8_t)   0)
#define TAG_SUBNET_MASK		((u_int8_t)   1)
#define TAG_TIME_OFFSET		((u_int8_t)   2)
#define TAG_GATEWAY		((u_int8_t)   3)
#define TAG_TIME_SERVER		((u_int8_t)   4)
#define TAG_NAME_SERVER		((u_int8_t)   5)
#define TAG_DOMAIN_SERVER	((u_int8_t)   6)
#define TAG_LOG_SERVER		((u_int8_t)   7)
#define TAG_COOKIE_SERVER	((u_int8_t)   8)
#define TAG_LPR_SERVER		((u_int8_t)   9)
#define TAG_IMPRESS_SERVER	((u_int8_t)  10)
#define TAG_RLP_SERVER		((u_int8_t)  11)
#define TAG_HOSTNAME		((u_int8_t)  12)
#define TAG_BOOTSIZE		((u_int8_t)  13)
#define TAG_END			((u_int8_t) 255)
/* RFC1497 tags */
#define	TAG_DUMPPATH		((u_int8_t)  14)
#define	TAG_DOMAINNAME		((u_int8_t)  15)
#define	TAG_SWAP_SERVER		((u_int8_t)  16)
#define	TAG_ROOTPATH		((u_int8_t)  17)
#define	TAG_EXTPATH		((u_int8_t)  18)
/* RFC2132 */
#define	TAG_IP_FORWARD		((u_int8_t)  19)
#define	TAG_NL_SRCRT		((u_int8_t)  20)
#define	TAG_PFILTERS		((u_int8_t)  21)
#define	TAG_REASS_SIZE		((u_int8_t)  22)
#define	TAG_DEF_TTL		((u_int8_t)  23)
#define	TAG_MTU_TIMEOUT		((u_int8_t)  24)
#define	TAG_MTU_TABLE		((u_int8_t)  25)
#define	TAG_INT_MTU		((u_int8_t)  26)
#define	TAG_LOCAL_SUBNETS	((u_int8_t)  27)
#define	TAG_BROAD_ADDR		((u_int8_t)  28)
#define	TAG_DO_MASK_DISC	((u_int8_t)  29)
#define	TAG_SUPPLY_MASK		((u_int8_t)  30)
#define	TAG_DO_RDISC		((u_int8_t)  31)
#define	TAG_RTR_SOL_ADDR	((u_int8_t)  32)
#define	TAG_STATIC_ROUTE	((u_int8_t)  33)
#define	TAG_USE_TRAILERS	((u_int8_t)  34)
#define	TAG_ARP_TIMEOUT		((u_int8_t)  35)
#define	TAG_ETH_ENCAP		((u_int8_t)  36)
#define	TAG_TCP_TTL		((u_int8_t)  37)
#define	TAG_TCP_KEEPALIVE	((u_int8_t)  38)
#define	TAG_KEEPALIVE_GO	((u_int8_t)  39)
#define	TAG_NIS_DOMAIN		((u_int8_t)  40)
#define	TAG_NIS_SERVERS		((u_int8_t)  41)
#define	TAG_NTP_SERVERS		((u_int8_t)  42)
#define	TAG_VENDOR_OPTS		((u_int8_t)  43)
#define	TAG_NETBIOS_NS		((u_int8_t)  44)
#define	TAG_NETBIOS_DDS		((u_int8_t)  45)
#define	TAG_NETBIOS_NODE	((u_int8_t)  46)
#define	TAG_NETBIOS_SCOPE	((u_int8_t)  47)
#define	TAG_XWIN_FS		((u_int8_t)  48)
#define	TAG_XWIN_DM		((u_int8_t)  49)
#define	TAG_NIS_P_DOMAIN	((u_int8_t)  64)
#define	TAG_NIS_P_SERVERS	((u_int8_t)  65)
#define	TAG_MOBILE_HOME		((u_int8_t)  68)
#define	TAG_SMPT_SERVER		((u_int8_t)  69)
#define	TAG_POP3_SERVER		((u_int8_t)  70)
#define	TAG_NNTP_SERVER		((u_int8_t)  71)
#define	TAG_WWW_SERVER		((u_int8_t)  72)
#define	TAG_FINGER_SERVER	((u_int8_t)  73)
#define	TAG_IRC_SERVER		((u_int8_t)  74)
#define	TAG_STREETTALK_SRVR	((u_int8_t)  75)
#define	TAG_STREETTALK_STDA	((u_int8_t)  76)
/* DHCP options */
#define	TAG_REQUESTED_IP	((u_int8_t)  50)
#define	TAG_IP_LEASE		((u_int8_t)  51)
#define	TAG_OPT_OVERLOAD	((u_int8_t)  52)
#define	TAG_TFTP_SERVER		((u_int8_t)  66)
#define	TAG_BOOTFILENAME	((u_int8_t)  67)
#define	TAG_DHCP_MESSAGE	((u_int8_t)  53)
#define	TAG_SERVER_ID		((u_int8_t)  54)
#define	TAG_PARM_REQUEST	((u_int8_t)  55)
#define	TAG_MESSAGE		((u_int8_t)  56)
#define	TAG_MAX_MSG_SIZE	((u_int8_t)  57)
#define	TAG_RENEWAL_TIME	((u_int8_t)  58)
#define	TAG_REBIND_TIME		((u_int8_t)  59)
#define	TAG_VENDOR_CLASS	((u_int8_t)  60)
#define	TAG_CLIENT_ID		((u_int8_t)  61)
/* RFC 2241 */
#define	TAG_NDS_SERVERS		((u_int8_t)  85)
#define	TAG_NDS_TREE_NAME	((u_int8_t)  86)
#define	TAG_NDS_CONTEXT		((u_int8_t)  87)
/* RFC 2242 */
#define	TAG_NDS_IPDOMAIN	((u_int8_t)  62)
#define	TAG_NDS_IPINFO		((u_int8_t)  63)
/* RFC 2485 */
#define	TAG_OPEN_GROUP_UAP	((u_int8_t)  98)
/* RFC 2563 */
#define	TAG_DISABLE_AUTOCONF	((u_int8_t) 116)
/* RFC 2610 */
#define	TAG_SLP_DA		((u_int8_t)  78)
#define	TAG_SLP_SCOPE		((u_int8_t)  79)
/* RFC 2937 */
#define	TAG_NS_SEARCH		((u_int8_t) 117)
/* RFC 3011 */
#define	TAG_IP4_SUBNET_SELECT	((u_int8_t) 118)
/* ftp://ftp.isi.edu/.../assignments/bootp-dhcp-extensions */
#define	TAG_USER_CLASS		((u_int8_t)  77)
#define	TAG_SLP_NAMING_AUTH	((u_int8_t)  80)
#define	TAG_CLIENT_FQDN		((u_int8_t)  81)
#define	TAG_AGENT_CIRCUIT	((u_int8_t)  82)
#define	TAG_AGENT_REMOTE	((u_int8_t)  83)
#define	TAG_AGENT_MASK		((u_int8_t)  84)
#define	TAG_TZ_STRING		((u_int8_t)  88)
#define	TAG_FQDN_OPTION		((u_int8_t)  89)
#define	TAG_AUTH		((u_int8_t)  90)
#define	TAG_VINES_SERVERS	((u_int8_t)  91)
#define	TAG_SERVER_RANK		((u_int8_t)  92)
#define	TAG_CLIENT_ARCH		((u_int8_t)  93)
#define	TAG_CLIENT_NDI		((u_int8_t)  94)
#define	TAG_CLIENT_GUID		((u_int8_t)  97)
#define	TAG_LDAP_URL		((u_int8_t)  95)
#define	TAG_6OVER4		((u_int8_t)  96)
#define	TAG_PRINTER_NAME	((u_int8_t) 100)
#define	TAG_MDHCP_SERVER	((u_int8_t) 101)
#define	TAG_IPX_COMPAT		((u_int8_t) 110)
#define	TAG_NETINFO_PARENT	((u_int8_t) 112)
#define	TAG_NETINFO_PARENT_TAG	((u_int8_t) 113)
#define	TAG_URL			((u_int8_t) 114)
#define	TAG_FAILOVER		((u_int8_t) 115)
#define	TAG_EXTENDED_REQUEST	((u_int8_t) 126)
#define	TAG_EXTENDED_OPTION	((u_int8_t) 127)


/* DHCP Message types (values for TAG_DHCP_MESSAGE option) */
#define		DHCPDISCOVER	1
#define		DHCPOFFER	2
#define		DHCPREQUEST	3
#define		DHCPDECLINE	4
#define		DHCPACK		5
#define		DHCPNAK		6
#define		DHCPRELEASE	7
#define		DHCPINFORM	8


/*
 * "vendor" data permitted for CMU bootp clients.
 */

struct cmu_vend {
	u_int8_t	v_magic[4];	/* magic number */
	u_int32_t	v_flags;	/* flags/opcodes, etc. */
	struct in_addr	v_smask;	/* Subnet mask */
	struct in_addr	v_dgate;	/* Default gateway */
	struct in_addr	v_dns1, v_dns2; /* Domain name servers */
	struct in_addr	v_ins1, v_ins2; /* IEN-116 name servers */
	struct in_addr	v_ts1, v_ts2;	/* Time servers */
	u_int8_t	v_unused[24];	/* currently unused */
};


/* v_flags values */
#define VF_SMASK	1	/* Subnet mask field contains valid data */


extern void safeputchar(int);
extern void safeputs(const char *);


/*
* The processor natively handles unaligned loads, so we can just
* cast the pointer and fetch through it.
*/
#define EXTRACT_16BITS(p) \
((u_int16_t)ntohs(*(const u_int16_t *)(p)))
#define EXTRACT_32BITS(p) \
((u_int32_t)ntohl(*(const u_int32_t *)(p)))

#define EXTRACT_24BITS(p) \
	((u_int32_t)((u_int32_t)*((const u_int8_t *)(p) + 0) << 16 | \
		     (u_int32_t)*((const u_int8_t *)(p) + 1) << 8 | \
		     (u_int32_t)*((const u_int8_t *)(p) + 2)))

/* Little endian protocol host order macros */

#define EXTRACT_LE_8BITS(p) (*(p))
#define EXTRACT_LE_16BITS(p) \
	((u_int16_t)((u_int16_t)*((const u_int8_t *)(p) + 1) << 8 | \
		     (u_int16_t)*((const u_int8_t *)(p) + 0)))
#define EXTRACT_LE_32BITS(p) \
	((u_int32_t)((u_int32_t)*((const u_int8_t *)(p) + 3) << 24 | \
		     (u_int32_t)*((const u_int8_t *)(p) + 2) << 16 | \
		     (u_int32_t)*((const u_int8_t *)(p) + 1) << 8 | \
		     (u_int32_t)*((const u_int8_t *)(p) + 0)))

extern const u_char *snapend;

/*
* True if  "l" bytes of "var" were captured.
*
* The "snapend - (l) <= snapend" checks to make sure "l" isn't so large
* that "snapend - (l)" underflows.
*
* The check is for <= rather than < because "l" might be 0.
*/
#define TTEST2(var, l) 1

/* True if "var" was captured */
#define TTEST(var) TTEST2(var, sizeof(var))

/* Bail if "l" bytes of "var" were not captured */
#define TCHECK2(var, l) if (!TTEST2(var, l)) goto trunc

/* Bail if "var" was not captured */
#define TCHECK(var) /*TCHECK2(var, sizeof(var))*/



/*
 * This stuff should come from a system header file, but there's no
 * obviously portable way to do that and it's not really going
 * to change from system to system.
 */

/*
 * A somewhat abstracted view of the LLC header
 */

struct llc {
	u_int8_t dsap;
	u_int8_t ssap;
	union {
		u_int8_t u_ctl;
		u_int16_t is_ctl;
		struct {
			u_int8_t snap_ui;
			u_int8_t snap_pi[5];
		} snap;
		struct {
			u_int8_t snap_ui;
			u_int8_t snap_orgcode[3];
			u_int8_t snap_ethertype[2];
		} snap_ether;
	} ctl;
};

#define	llcui		ctl.snap.snap_ui
#define	llcpi		ctl.snap.snap_pi
#define	llc_orgcode	ctl.snap_ether.snap_orgcode
#define	llc_ethertype	ctl.snap_ether.snap_ethertype
#define	llcis		ctl.is_ctl
#define	llcu		ctl.u_ctl

#define	LLC_U_FMT	3
#define	LLC_GSAP	1
#define LLC_S_FMT	1

#define	LLC_U_POLL	0x10
#define	LLC_IS_POLL	0x0100
#define	LLC_XID_FI	0x81

#define	LLC_U_CMD(u)	((u) & 0xef)
#define	LLC_UI		0x03
#define	LLC_UA		0x63
#define	LLC_DISC	0x43
#define	LLC_DM		0x0f
#define	LLC_SABME	0x6f
#define	LLC_TEST	0xe3
#define	LLC_XID		0xaf
#define	LLC_FRMR	0x87

#define	LLC_S_CMD(is)	(((is) >> 1) & 0x03)
#define	LLC_RR		0x0001
#define	LLC_RNR		0x0005
#define	LLC_REJ		0x0009

#define LLC_IS_NR(is)	(((is) >> 9) & 0x7f)
#define LLC_I_NS(is)	(((is) >> 1) & 0x7f)

#ifndef LLCSAP_NULL
#define	LLCSAP_NULL		0x00
#endif
#ifndef LLCSAP_GLOBAL
#define	LLCSAP_GLOBAL		0xff
#endif
#ifndef LLCSAP_8021B_I
#define	LLCSAP_8021B_I		0x02
#endif
#ifndef LLCSAP_8021B_G
#define	LLCSAP_8021B_G		0x03
#endif
#ifndef LLCSAP_IP
#define	LLCSAP_IP		0x06
#endif
#ifndef LLCSAP_PROWAYNM
#define	LLCSAP_PROWAYNM		0x0e
#endif
#ifndef LLCSAP_8021D
#define	LLCSAP_8021D		0x42
#endif
#ifndef LLCSAP_RS511
#define	LLCSAP_RS511		0x4e
#endif
#ifndef LLCSAP_ISO8208
#define	LLCSAP_ISO8208		0x7e
#endif
#ifndef LLCSAP_PROWAY
#define	LLCSAP_PROWAY		0x8e
#endif
#ifndef LLCSAP_SNAP
#define	LLCSAP_SNAP		0xaa
#endif
#ifndef LLCSAP_IPX
#define LLCSAP_IPX		0xe0
#endif
#ifndef LLCSAP_NETBEUI
#define LLCSAP_NETBEUI		0xf0
#endif
#ifndef LLCSAP_ISONS
#define	LLCSAP_ISONS		0xfe
#endif

#define	OUI_ENCAP_ETHER	0x000000	/* encapsulated Ethernet */
#define	OUI_CISCO	0x00000c	/* Cisco protocols */
#define	OUI_CISCO_90	0x0000f8	/* Cisco bridging */
#define OUI_RFC2684	0x0080c2	/* RFC 2684 bridged Ethernet */
#define	OUI_APPLETALK	0x080007	/* Appletalk */

/*
 * PIDs for use with OUI_CISCO.
 */
#define	PID_CISCO_CDP		0x2000	/* Cisco Discovery Protocol */

/*
 * PIDs for use with OUI_RFC2684.
 */
#define PID_RFC2684_ETH_FCS	0x0001	/* Ethernet, with FCS */
#define PID_RFC2684_ETH_NOFCS	0x0007	/* Ethernet, without FCS */
#define PID_RFC2684_802_4_FCS	0x0002	/* 802.4, with FCS */
#define PID_RFC2684_802_4_NOFCS	0x0008	/* 802.4, without FCS */
#define PID_RFC2684_802_5_FCS	0x0003	/* 802.5, with FCS */
#define PID_RFC2684_802_5_NOFCS	0x0009	/* 802.5, without FCS */
#define PID_RFC2684_FDDI_FCS	0x0004	/* FDDI, with FCS */
#define PID_RFC2684_FDDI_NOFCS	0x000a	/* FDDI, without FCS */
#define PID_RFC2684_802_6_FCS	0x0005	/* 802.6, with FCS */
#define PID_RFC2684_802_6_NOFCS	0x000b	/* 802.6, without FCS */
#define PID_RFC2684_BPDU	0x000e	/* BPDUs */


#define ESRC(ep) ((ep)->ether_shost)
#define EDST(ep) ((ep)->ether_dhost)

#ifndef NTOHL
#define NTOHL(x)	(x) = ntohl(x)
#define NTOHS(x)	(x) = ntohs(x)
#define HTONL(x)	(x) = htonl(x)
#define HTONS(x)	(x) = htons(x)
#endif


#define ipaddr_string(p) getname((const u_char *)(p))
#ifndef toascii
#define toascii(c) ((c) & 0x7f)
#endif

#define DEFAULT_SNAPLEN 68	/* ether + IPv4 + TCP + 14 */

#endif
