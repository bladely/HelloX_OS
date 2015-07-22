/********************************************************/
/****************** AUTHOR LUOYU ************************/
/********************************************************/
#include "uio.h"
#include "sys.h"
#include "libkern.h"
#include "kin.h"
#include "ip.h"
#include "ip_icmp.h"
#include "socket.h"
#include "sockio.h"
#include "if.h"
#include "if_dl.h"
#include "ethernet.h"
#include "kroute.h"
#include "if_arp.h"
#include "if_ether.h"

#include "io.h"
//from Windows
#include <process.h>
//#include "ips_config.h"

const char IP_ADDR[] = "10.1.1.1";
typedef unsigned short u_short;
void routepr();
void pmsg_addrs(char *cp, int addrs);
void pmsg_common(struct rt_msghdr *rtm);
void sockaddr(char *addr, 	struct sockaddr *sa);


extern int errno;

int set_netmask(int cfgId, char * netmask)
{	
#if 0
	struct ifreq ifr;
	struct sockaddr_in netmask_addr;
	memset(&ifr, 0, sizeof(ifr));
	memset(&netmask_addr, 0, sizeof(netmask_addr));
	strcpy(ifr.ifr_name, ENUM_DEV);
	
    bzero(&netmask_addr,sizeof(struct sockaddr_in));
    netmask_addr.sin_family = PF_INET;
    netmask_addr.sin_addr.s_addr = inet_addr(netmask);
	
    memcpy(&ifr.ifr_ifru.ifru_addr, &netmask_addr,sizeof(struct sockaddr_in));
	
    if(ioctl(cfgId,SIOCSIFNETMASK,&ifr) < 0)
    {
        perror("ioctl");
        return -1;
    }
#endif	
    return 0;
	
}
int set_lookbackIpAddr(int cfgId)
{	
	
	//int			sockfd;
	struct ifreq		ifr;
	struct ifaliasreq	ifra;
	struct sockaddr_in	*sin;
	
	/* First get its old IP address */
	
	memset(&ifr, 0, sizeof(ifr));
	memset(&sin, 0, sizeof(sin));
	strcpy(ifr.ifr_name, "lo0");
	
	/* Then delete it */	
	memset(&ifra, 0, sizeof(ifra));
	strncpy(ifra.ifra_name, "lo0", sizeof(ifra.ifra_name)-1);
	ifra.ifra_addr = ifr.ifr_addr;
	/*
	if (ioctl(cfgId, SIOCDIFADDR, &ifra) < 0) {
	
	  exit(4);
	  }
	  
	*/	/* And now assign the new IP address */
	sin = (struct sockaddr_in *)&ifra.ifra_addr;
	sin->sin_family = AF_INET;
	sin->sin_len = sizeof(struct sockaddr_in);
	
	sin->sin_addr.s_addr = bsd_inet_addr("127.0.0.1");
	
	sin = (struct sockaddr_in *)&ifra.ifra_broadaddr;
	sin->sin_family = AF_INET;
	sin->sin_len = sizeof(struct sockaddr_in);
	sin->sin_addr.s_addr = 0xff000000;
	
	sin = (struct sockaddr_in *)&ifra.ifra_mask;
	sin->sin_family = AF_INET;
	sin->sin_len = sizeof(struct sockaddr_in);
	
	sin->sin_addr.s_addr = bsd_inet_addr("255.0.0.0");
	
	if (ioctl(cfgId, SIOCAIFADDR, &ifra) < 0) {
		_hx_printf("%s %d\n", __FUNCTION__, __LINE__);
		return 0;
		exit(6);
	}
	
	return 0;
	
}

int set_ipAddr(int cfgId, char *devName, char if_index, char * ipAddr)
{	
#if 0
	struct ifreq ifr;
	struct sockaddr_in sin;
	memset(&ifr, 0, sizeof(ifr));
	memset(&sin, 0, sizeof(sin));
	strcpy(ifr.ifr_name, ENUM_DEV);
	
	sin.sin_family = AF_INET;
	sin.sin_len = sizeof(sin);
	sin.sin_addr.s_addr = htonl(inet_addr(ipAddr));
	memcpy((char *) &ifr.ifr_addr, (char *) &sin, sizeof(struct sockaddr_in));
	if (ioctl(cfgId, SIOCSIFADDR, &ifr) < 0)
	{
		printf("set interface error!\n");
		return -1;
	}
	
    return 0;
#endif
	char if_xname[IFNAMSIZ] = {0};
	struct ifreq		ifr;
	struct ifaliasreq	ifra;
	struct sockaddr_in	*sin;
	
	/* First get its old IP address */
	
	memset(&ifr, 0, sizeof(ifr));
	memset(&sin, 0, sizeof(sin));
	sprintf(if_xname, "%s%d", devName, if_index);
	strcpy(ifr.ifr_name, if_xname);
	
	
	
	/* Then delete it */	
	memset(&ifra, 0, sizeof(ifra));
	strncpy(ifra.ifra_name, if_xname, sizeof(ifra.ifra_name)-1);
	ifra.ifra_addr = ifr.ifr_addr;
	/*
	if (ioctl(cfgId, SIOCDIFADDR, &ifra) < 0) {
	
	  exit(4);
	  }
	  
	*/	/* And now assign the new IP address */
	sin = (struct sockaddr_in *)&ifra.ifra_addr;
	sin->sin_family = AF_INET;
	sin->sin_len = sizeof(struct sockaddr_in);
	sin->sin_addr.s_addr = bsd_inet_addr(ipAddr);
	
	sin = (struct sockaddr_in *)&ifra.ifra_broadaddr;
	sin->sin_family = AF_INET;
	sin->sin_len = sizeof(struct sockaddr_in);
	sin->sin_addr.s_addr = (bsd_inet_addr(ipAddr) & 0x00ffffff) | 0xff000000;
	
	sin = (struct sockaddr_in *)&ifra.ifra_mask;
	sin->sin_family = AF_INET;
	sin->sin_len = sizeof(struct sockaddr_in);
	sin->sin_addr.s_addr = bsd_inet_addr("255.255.255.0");
	if (ioctl(cfgId, SIOCAIFADDR, &ifra) < 0) {
		
		exit(6);
	}
	
	return 0;
	
}
void get_ip(int cfgId, char *devName, int if_index)
{
	struct sockaddr *sa;
	struct ifreq ifr;
	char if_name[IFNAMSIZ] = {0};
	char netaddr[INET_ADDRSTRLEN];

	sprintf(if_name, "%s%d", devName, if_index);
	strcpy(ifr.ifr_name, if_name);
	if((ioctl(cfgId,SIOCGIFADDR,(caddr_t)&ifr,sizeof(struct ifreq)))<0)
		return;
	sa=(struct sockaddr *)&(ifr.ifr_addr);
	switch(sa->sa_family){
	case AF_INET6:
		break;
	default : 
		{
			struct in_addr *ipaddr = &((struct sockaddr_in *)sa)->sin_addr;
			strcpy(netaddr,bsd_inet_ntoa(*ipaddr));
		}
	}
	printf("%s ip address as %s\n", if_name, netaddr);
	
	return;
}
int get_netmask(int cfgId, char *devName, int if_index)
{
    struct sockaddr_in * ptr;
    struct ifreq ifr;
	char if_name[IFNAMSIZ] = {0};
	sprintf(if_name, "%s%d", devName, if_index);
    strcpy(ifr.ifr_name, if_name);
	
    if(ioctl(cfgId,SIOCGIFNETMASK,&ifr) < 0)
    {
		printf("ioctl SIOCGIFNETMASK error");
		return -1;
    }
	
    ptr = (struct sockaddr_in *)&ifr.ifr_ifru.ifru_addr;
    //ptr->sin_addr.s_addr = ntohl(ptr->sin_addr.s_addr);
    printf("Netmask:%s\n",bsd_inet_ntoa(ptr->sin_addr));
	
    return 0;
}


#define SEQ             9999
#define DEFAULT_PID 0

struct {
	struct	rt_msghdr m_rtm;
	char	m_space[512];
} m_rtmsg;
union	sockunion {
	struct	sockaddr sa;
	struct	sockaddr_in sin;
#ifdef INET6
	struct	sockaddr_in6 sin6;
#endif
	//struct	sockaddr_at sat;
	struct	sockaddr_dl sdl;
	struct	sockaddr_inarp sinarp;
	struct	sockaddr_storage ss; /* added to avoid memory overrun */
} so_dst, so_gate, so_mask, so_genmask, so_ifa, so_ifp;
int rtm_addrs;
int nr_rtm_addrs;
char metricnames[] =
"\011pksent\010rttvar\7rtt\6ssthresh\5sendpipe\4recvpipe\3expire\2hopcount"
"\1mtu";
char routeflags[] =
"\1UP\2GATEWAY\3HOST\4REJECT\5DYNAMIC\6MODIFIED\7DONE\010MASK_PRESENT"
"\011CLONING\012XRESOLVE\013LLINFO\014STATIC\015BLACKHOLE\016b016"
"\017PROTO2\020PROTO1\021PRCLONING\022WASCLONED\023PROTO3\024CHAINDELETE"
"\025PINNED\026LOCAL\027BROADCAST\030MULTICAST";
char ifnetflags[] =
"\1UP\2BROADCAST\3DEBUG\4LOOPBACK\5PTP\6b6\7RUNNING\010NOARP"
"\011PPROMISC\012ALLMULTI\013OACTIVE\014SIMPLEX\015LINK0\016LINK1"
"\017LINK2\020MULTICAST";
char addrnames[] =
"\1DST\2GATEWAY\3NETMASK\4GENMASK\5IFP\6IFA\7AUTHOR\010BRD";

void
bprintf(fp, b, s)
FILE *fp;
int b;
u_char *s;
{
	int i;
	int gotsome = 0;
	
	if (b == 0)
		return;
	while ((i = *s++) != 0) {
		if (b & (1 << (i-1))) {
			if (gotsome == 0)
				i = '<';
			else
				i = ',';
			(void) putc(i, fp);
			gotsome = 1;
			for (; (i = *s) > 32; s++)
				(void) putc(i, fp);
		} else
			while (*s > 32)
				s++;
	}
	if (gotsome)
		(void) putc('>', fp);
}

const char *
routename(sa)
struct sockaddr *sa;
{
	char *cp;
	static char line[MAXHOSTNAMELEN + 1];
	struct hostent *hp;
	static char domain[MAXHOSTNAMELEN + 1];
	static int first = 1, n;
	
	if (first) {
		first = 0;
		/*if (gethostname(domain, MAXHOSTNAMELEN) == 0 &&
		(cp = strchr(domain, '.'))) {
		domain[MAXHOSTNAMELEN] = '\0';
		(void) strcpy(domain, cp + 1);
	} else*/
		domain[0] = 0;
	}
	
	if (sa->sa_len == 0)
		strcpy(line, "default");
	else switch (sa->sa_family) {
		
	case AF_INET:
		{	struct in_addr in;
		in = ((struct sockaddr_in *)sa)->sin_addr;
		
		cp = 0;
		if (in.s_addr == INADDR_ANY || sa->sa_len < 4)
			cp = "default";
		if (cp == 0) {
			//hp = gethostbyaddr((char *)&in, sizeof (struct in_addr),
			//	AF_INET);
			
		}
		if (cp) {
			strncpy(line, cp, sizeof(line) - 1);
			line[sizeof(line) - 1] = '\0';
		} else
			(void) sprintf(line, "%s", bsd_inet_ntoa(in));
		break;
		}
		
		
	case AF_LINK:
		//return (link_ntoa((struct sockaddr_dl *)sa));
		break;
	default:
		{	u_short *s = (u_short *)sa;
		u_short *slim = s + ((sa->sa_len + 1) >> 1);
		char *cp = line + sprintf(line, "(%d)", sa->sa_family);
		char *cpe = line + sizeof(line);
		
		while (++s < slim && cp < cpe) /* start with sa->sa_data */
			if ((n = snprintf(cp, cpe - cp, " %x", *s)) > 0)
				cp += n;
			else
				*cp = '\0';
			break;
		}
	}
	return (line);
}
char *msgtypes[] = {
	"",
	"RTM_ADD: Add Route",
	"RTM_DELETE: Delete Route",
	"RTM_CHANGE: Change Metrics or flags",
	"RTM_GET: Report Metrics",
	"RTM_LOSING: Kernel Suspects Partitioning",
	"RTM_REDIRECT: Told to use different route",
	"RTM_MISS: Lookup failed on this address",
	"RTM_LOCK: fix specified metrics",
	"RTM_OLDADD: caused by SIOCADDRT",
	"RTM_OLDDEL: caused by SIOCDELRT",
	"RTM_RESOLVE: Route created by cloning",
	"RTM_NEWADDR: address being added to iface",
	"RTM_DELADDR: address being removed from iface",
	"RTM_IFINFO: iface status change",
	"RTM_NEWMADDR: new multicast group membership on iface",
	"RTM_DELMADDR: multicast group membership removed from iface",
	"RTM_IFANNOUNCE: interface arrival/departure",
	0,
};
extern int verbose;
void
print_rtmsg(rtm, msglen)
	struct rt_msghdr *rtm;
	int msglen;
{
	struct if_msghdr *ifm;
	struct ifa_msghdr *ifam;
#ifdef RTM_NEWMADDR
	struct ifma_msghdr *ifmam;
#endif
	struct if_announcemsghdr *ifan;
	char *state;

	if (verbose == 0)
		return;
	if (rtm->rtm_version != RTM_VERSION) {
		(void) printf("routing message version %d not understood\n",
		    rtm->rtm_version);
		return;
	}
	if (msgtypes[rtm->rtm_type] != NULL)
		(void)printf("%s: ", msgtypes[rtm->rtm_type]);
	else
		(void)printf("#%d: ", rtm->rtm_type);
	(void)printf("len %d, ", rtm->rtm_msglen);
	switch (rtm->rtm_type) {
	case RTM_IFINFO:
		ifm = (struct if_msghdr *)rtm;
		(void) printf("if# %d, ", ifm->ifm_index);
		switch (ifm->ifm_data.ifi_link_state) {
		case LINK_STATE_DOWN:
			state = "down";
			break;
		case LINK_STATE_UP:
			state = "up";
			break;
		default:
			state = "unknown";
			break;
		}
		(void) printf("link: %s, flags:", state);
		bprintf(stdout, ifm->ifm_flags, ifnetflags);
		pmsg_addrs((char *)(ifm + 1), ifm->ifm_addrs);
		break;
	case RTM_NEWADDR:
	case RTM_DELADDR:
		ifam = (struct ifa_msghdr *)rtm;
		(void) printf("metric %d, flags:", ifam->ifam_metric);
		bprintf(stdout, ifam->ifam_flags, routeflags);
		pmsg_addrs((char *)(ifam + 1), ifam->ifam_addrs);
		break;
#ifdef RTM_NEWMADDR
	case RTM_NEWMADDR:
	case RTM_DELMADDR:
		ifmam = (struct ifma_msghdr *)rtm;
		pmsg_addrs((char *)(ifmam + 1), ifmam->ifmam_addrs);
		break;
#endif
	case RTM_IFANNOUNCE:
		ifan = (struct if_announcemsghdr *)rtm;
		(void) printf("if# %d, what: ", ifan->ifan_index);
		switch (ifan->ifan_what) {
		case IFAN_ARRIVAL:
			printf("arrival");
			break;
		case IFAN_DEPARTURE:
			printf("departure");
			break;
		default:
			printf("#%d", ifan->ifan_what);
			break;
		}
		printf("\n");
		break;

	default:
		(void) printf("pid: %ld, seq %d, errno %d, flags:",
			(long)rtm->rtm_pid, rtm->rtm_seq, rtm->rtm_errno);
		bprintf(stdout, rtm->rtm_flags, routeflags);
		pmsg_common(rtm);
	}
}

void
print_getmsg(rtm, msglen)
struct rt_msghdr *rtm;
int msglen;
{
	struct sockaddr *dst = NULL, *gate = NULL, *mask = NULL;
	struct sockaddr_dl *ifp = NULL;
	struct sockaddr *sa;
	char *cp;
	int i;
	
	(void) printf("   route to: %s\n", routename(&so_dst));
	if (rtm->rtm_version != RTM_VERSION) {
		printf("routing message version %d not understood",
			rtm->rtm_version);
		return;
	}
	if (rtm->rtm_msglen > msglen) {
		printf("message length mismatch, in packet %d, returned %d",
			rtm->rtm_msglen, msglen);
	}
	if (rtm->rtm_errno)  {
		errno = rtm->rtm_errno;
		printf("message indicates error %d", errno);
		return;
	}
	cp = ((char *)(rtm + 1));
	if (rtm->rtm_addrs)
		for (i = 1; i; i <<= 1)
			if (i & rtm->rtm_addrs) {
				sa = (struct sockaddr *)cp;
				switch (i) {
				case RTA_DST:
					dst = sa;
					break;
				case RTA_GATEWAY:
					gate = sa;
					break;
				case RTA_NETMASK:
					mask = sa;
					break;
				case RTA_IFP:
					if (sa->sa_family == AF_LINK &&
						((struct sockaddr_dl *)sa)->sdl_nlen)
						ifp = (struct sockaddr_dl *)sa;
					break;
				}
				cp += SA_SIZE(sa);
			}
			if (dst && mask)
				mask->sa_family = dst->sa_family;	/* XXX */
			if (dst)
				(void)printf("destination: %s\n", routename(dst));
			if (mask) {
				(void)printf("       mask: %s\n", routename(mask));
			}
			if (gate && rtm->rtm_flags & RTF_GATEWAY)
				(void)printf("    gateway: %s\n", routename(gate));
			if (ifp)
				(void)printf("  interface: %.*s\n",
				ifp->sdl_nlen, ifp->sdl_data);
			(void)printf("      flags: ");
			bprintf(stdout, rtm->rtm_flags, routeflags);
#define lock(f)	((rtm->rtm_rmx.rmx_locks & __CONCAT(RTV_,f)) ? 'L' : ' ')
#define msec(u)	(((u) + 500) / 1000)		/* usec to msec */
			
			(void) printf("\n%s\n", "\
recvpipe  sendpipe  ssthresh  rtt,msec    rttvar  hopcount      mtu ");
			printf("%8ld  ", rtm->rtm_rmx.rmx_recvpipe);
			printf("%8ld  ", rtm->rtm_rmx.rmx_sendpipe );
			printf("%8ld  ", rtm->rtm_rmx.rmx_ssthresh);
			printf("%8ld  ", msec(rtm->rtm_rmx.rmx_rtt));
			printf("%8ld  ", msec(rtm->rtm_rmx.rmx_rttvar));
			printf("%8ld  ", rtm->rtm_rmx.rmx_hopcount);
			printf("%8ld ", rtm->rtm_rmx.rmx_mtu);
			//if (rtm->rtm_rmx.rmx_expire)
			//	rtm->rtm_rmx.rmx_expire -= time(0);
			//printf("%8ld\n", rtm->rtm_rmx.rmx_expire);
#undef lock
#undef msec
}
#define NEXTADDR(w, u) \
	if (rtm_addrs & (w)) {\
	l = SA_SIZE(&(u.sa)); memcpy(cp, &(u), l); cp += l;\
	}
void show_ip_route(char *ipaddr)
{
	int                     sockfd;
	pid_t                   pid;
	ssize_t                 n;
	struct sockaddr         *sa, *rti_info[RTAX_MAX];
	struct sockaddr_in      *sin;
	unsigned char           *ptr;
	char *cp = m_rtmsg.m_space;
	int l;
	if (NULL == ipaddr)
	{
	   printf("Input IP address\n");
	   return;
	}
	sockfd = socket(AF_ROUTE, SOCK_RAW, 0); /* need superuser privileges */
#define rtm m_rtmsg.m_rtm
	rtm.rtm_version = RTM_VERSION;
	rtm.rtm_type = RTM_GET;
	rtm.rtm_flags = RTF_STATIC| RTF_UP | RTF_HOST | RTF_GATEWAY;
	rtm.rtm_addrs = rtm_addrs = RTA_DST | RTA_IFP;
	rtm.rtm_pid = DEFAULT_PID;
	rtm.rtm_seq = SEQ;
	
	bzero(&so_dst, sizeof(so_dst));
	bzero(&so_gate, sizeof(so_gate));
	bzero(&so_mask, sizeof(so_mask));
	bzero(&so_genmask, sizeof(so_genmask));
	bzero(&so_ifp, sizeof(so_ifp));
	bzero(&so_ifa, sizeof(so_ifa));
	
	so_dst.sin.sin_family = AF_INET;
	so_dst.sin.sin_len = sizeof(struct sockaddr_in);
	so_dst.sin.sin_addr.s_addr = bsd_inet_addr(ipaddr);
	
	so_ifp.sdl.sdl_family = AF_LINK;
	so_ifp.sdl.sdl_len = sizeof(struct sockaddr_dl);
	
	NEXTADDR(RTA_DST, so_dst);
	NEXTADDR(RTA_GATEWAY, so_gate);
	NEXTADDR(RTA_NETMASK, so_mask);
	NEXTADDR(RTA_GENMASK, so_genmask);
	NEXTADDR(RTA_IFP, so_ifp);
	NEXTADDR(RTA_IFA, so_ifa);
	
	rtm.rtm_msglen = l = cp - (char *)&m_rtmsg;
	so_write(sockfd, (char *)&m_rtmsg, rtm.rtm_msglen);
	
	do {
		n = so_read(sockfd, (char *)&m_rtmsg, sizeof(m_rtmsg));
	} while (rtm.rtm_type != RTM_GET || rtm.rtm_seq != SEQ ||
		rtm.rtm_pid != DEFAULT_PID);
	/* end getrt1 */
	print_getmsg(&m_rtmsg, m_rtmsg.m_rtm.rtm_msglen);
	printf("\n");
	so_close(sockfd);
}

/*
* Note: doing an SIOCIGIFFLAGS scribbles on the union portion
* of the ifreq structure, which may confuse other parts of ifconfig.
* Make a private copy so we can avoid that.
*/
void
setifflags(int s)
{
#if 0
	struct ifreq		my_ifr;
	struct	ifreq		ifr;
	memset(&ifr, 0, sizeof(ifr));
	strcpy(ifr.ifr_name, ENUM_DEV);
	bcopy((char *)&ifr, (char *)&my_ifr, sizeof(struct ifreq));
	
	if (ioctl(s, SIOCGIFFLAGS, (caddr_t)&my_ifr) < 0) {
		
		exit(1);
	}
	strncpy(my_ifr.ifr_name, ENUM_DEV, sizeof (my_ifr.ifr_name));
	
	my_ifr.ifr_flags |= IFF_UP;
	my_ifr.ifr_flagshigh = IFF_UP >> 16;
	if (ioctl(s, SIOCSIFFLAGS, (caddr_t)&my_ifr) < 0)
		exit(0);
#endif		
}

#if 0
int BISConfig(void *ips_all)
{
	int cfgId;
	IPS_CFG_IFA *ifCfg = ips_all->config.ifa;
	lo_clone_create(0);
	
	cfgId = socket(AF_INET, SOCK_DGRAM, IPPROTO_IP);
	
	set_lookbackIpAddr(cfgId);
	//get_ip(cfgId, "lo", 0);
	while(ifCfg)
	{
		if ( bsd_inet_addr(ifCfg->ipaddr) == INADDR_NONE)
			set_ipAddr(cfgId, ifCfg->ifName, ifCfg->index, IP_ADDR);
		else
			set_ipAddr(cfgId, ifCfg->ifName, ifCfg->index, ifCfg->ipaddr);
		
		/* the following functions is for test ioctl, write, read and route */	
		//get_ip(cfgId, ifCfg->ifName, ifCfg->index);
		//get_netmask(cfgId, ifCfg->ifName, ifCfg->index);
		//get_route(ifCfg->ipaddr);
		ifCfg = ifCfg->next;
	}
	so_close(cfgId);

	add_static_route();
	//setifflags(cfgId);
	//routepr();

	return 0;
}
#endif
int BISConfig()
{
	int cfgId;
	lo_clone_create(0);
	
	cfgId = socket(AF_INET, SOCK_DGRAM, IPPROTO_IP);
	
	set_lookbackIpAddr(cfgId);
	
	so_close(cfgId);
	return 0;
}
//extern IPS_ALL g_ips_all;
void show_ip_interface()
{
#ifdef hellox_dbg
	int cfgId;
	IPS_CFG_IFA *ifCfg = g_ips_all.config.ifa;
	cfgId = socket(AF_INET, SOCK_DGRAM, IPPROTO_IP);
	get_ip(cfgId, "lo", 0);
	while(ifCfg)
	{	
		/* the following functions is for test ioctl, write, read and route */	
		get_ip(cfgId, ifCfg->ifName, ifCfg->index);
		get_netmask(cfgId, ifCfg->ifName, ifCfg->index);
		//get_route(ifCfg->ipaddr);
		ifCfg = ifCfg->next;
	}
	so_close(cfgId);
#endif
}
/*
 * Structures returned by network data base library.  All addresses are
 * supplied in host order, and returned in network order (suitable for
 * use in system calls).
 */
struct	ortentry route;

int	iflag, verbose, aflen = sizeof (struct sockaddr_in);
int	locking, lockrest, debugonly;

int	forcehost, forcenet, doflush, nflag, af, qflag, tflag;
struct keytab {
	char	*kt_cp;
	int	kt_i;
} keywords[] = {
#define K_ADD   1
        {"add", K_ADD},
#define K_ATALK 2
        {"atalk", K_ATALK},
#define K_BLACKHOLE     3
        {"blackhole", K_BLACKHOLE},
#define K_CHANGE        4
        {"change", K_CHANGE},
#define K_CLONING       5
        {"cloning", K_CLONING},
#define K_DELETE        6
        {"delete", K_DELETE},
#define K_DST   7
        {"dst", K_DST},
#define K_EXPIRE        8
        {"expire", K_EXPIRE},
#define K_FLUSH 9
        {"flush", K_FLUSH},
#define K_GATEWAY       10
        {"gateway", K_GATEWAY},
#define K_GENMASK       11
        {"genmask", K_GENMASK},
#define K_GET   12
        {"get", K_GET},
#define K_HOST  13
        {"host", K_HOST},
#define K_HOPCOUNT      14
        {"hopcount", K_HOPCOUNT},
#define K_IFACE 15
        {"iface", K_IFACE},
#define K_INTERFACE     16
        {"interface", K_INTERFACE},
#define K_IFA   17
        {"ifa", K_IFA},
#define K_IFP   18
        {"ifp", K_IFP},
#define K_INET  19
        {"inet", K_INET},
#define K_INET6 20
        {"inet6", K_INET6},
#define K_ISO   21
        {"iso", K_ISO},
#define K_LINK  22
        {"link", K_LINK},
#define K_LLINFO        23
        {"llinfo", K_LLINFO},
#define K_LOCK  24
        {"lock", K_LOCK},
#define K_LOCKREST      25
        {"lockrest", K_LOCKREST},
#define K_MASK  26
        {"mask", K_MASK},
#define K_MONITOR       27
        {"monitor", K_MONITOR},
#define K_MTU   28
        {"mtu", K_MTU},
#define K_NET   29
        {"net", K_NET},
#define K_NETMASK       30
        {"netmask", K_NETMASK},
#define K_NOSTATIC      31
        {"nostatic", K_NOSTATIC},
#define K_OSI   32
        {"osi", K_OSI},
#define K_PREFIXLEN     33
        {"prefixlen", K_PREFIXLEN},
#define K_PROTO1        34
        {"proto1", K_PROTO1},
#define K_PROTO2        35
        {"proto2", K_PROTO2},
#define K_PROXY 36
        {"proxy", K_PROXY},
#define K_RECVPIPE      37
        {"recvpipe", K_RECVPIPE},
#define K_REJECT        38
        {"reject", K_REJECT},
#define K_RTT   39
        {"rtt", K_RTT},
#define K_RTTVAR        40
        {"rttvar", K_RTTVAR},
#define K_SA    41
        {"sa", K_SA},
#define K_SENDPIPE      42
        {"sendpipe", K_SENDPIPE},
#define K_SSTHRESH      43
        {"ssthresh", K_SSTHRESH},
#define K_STATIC        44
        {"static", K_STATIC},
#define K_X25   45
        {"x25", K_X25},
#define K_XNS   46
        {"xns", K_XNS},
#define K_XRESOLVE      47
        {"xresolve", K_XRESOLVE},	
		{0, 0}
};
struct	rt_metrics rt_metrics;
u_long  rtm_inits;
void
pmsg_addrs(	char	*cp,	int	addrs)
{
	struct sockaddr *sa;
	int i;

	if (addrs == 0) {
		(void) putchar('\n');
		return;
	}
	(void) printf("\nsockaddrs: ");
	bprintf(stdout, addrs, addrnames);
	(void) putchar('\n');
	for (i = 1; i; i <<= 1)
		if (i & addrs) {
			sa = (struct sockaddr *)cp;
			(void) printf(" %s", routename(sa));
			cp += SA_SIZE(sa);
		}
	(void) putchar('\n');
	//(void) fflush(stdout);
}

void
pmsg_common(struct rt_msghdr *rtmh)
{
	(void) printf("\nlocks: ");
	bprintf(stdout, rtmh->rtm_rmx.rmx_locks, metricnames);
	(void) printf(" inits: ");
	bprintf(stdout, rtmh->rtm_inits, metricnames);
	pmsg_addrs(((char *)(rtmh + 1)), rtmh->rtm_addrs);
}

void
set_metric(value, key)
char *value;
int key;
{
	int flag = 0;
	u_long noval, *valp = &noval;
	
	switch (key) {
#define caseof(x, y, z)	case x: valp = &rt_metrics.z; flag = y; break
		caseof(K_MTU, RTV_MTU, rmx_mtu);
		caseof(K_HOPCOUNT, RTV_HOPCOUNT, rmx_hopcount);
		caseof(K_EXPIRE, RTV_EXPIRE, rmx_expire);
		caseof(K_RECVPIPE, RTV_RPIPE, rmx_recvpipe);
		caseof(K_SENDPIPE, RTV_SPIPE, rmx_sendpipe);
		caseof(K_SSTHRESH, RTV_SSTHRESH, rmx_ssthresh);
		caseof(K_RTT, RTV_RTT, rmx_rtt);
		caseof(K_RTTVAR, RTV_RTTVAR, rmx_rttvar);
	}
	rtm_inits |= flag;
	if (lockrest || locking)
		rt_metrics.rmx_locks |= flag;
	if (locking)
		locking = 0;
	*valp = atoi(value);
}

int
prefixlen(s)
char *s;
{
	int len = atoi(s), q, r;
	int max;
	char *p;
	
	rtm_addrs |= RTA_NETMASK;	
	switch (af) {
#ifdef INET6
	case AF_INET6:
		max = 128;
		p = (char *)&so_mask.sin6.sin6_addr;
		break;
#endif
	case AF_INET:
		max = 32;
		p = (char *)&so_mask.sin.sin_addr;
		break;
	default:
		(void) fprintf(stderr, "prefixlen not supported in this af\n");
		exit(1);
		/*NOTREACHED*/
	}
	
	if (len < 0 || max < len) {
		(void) fprintf(stderr, "%s: bad value\n", s);
		exit(1);
	}
	
	q = len >> 3;
	r = len & 7;
	so_mask.sa.sa_family = af;
	so_mask.sa.sa_len = aflen;
	memset((void *)p, 0, max / 8);
	if (q > 0)
		memset((void *)p, 0xff, q);
	if (r > 0)
		*((u_char *)p + q) = (0xff00 >> r) & 0xff;
	if (len == max)
		return -1;
	else
		return len;
}
typedef union sockunion *sup;
struct ifaddrs {
	struct ifaddrs  *ifa_next;
	char		*ifa_name;
	u_int		 ifa_flags;
	struct sockaddr	*ifa_addr;
	struct sockaddr	*ifa_netmask;
	struct sockaddr	*ifa_dstaddr;
	void		*ifa_data;
};

/*
 * This may have been defined in <net/if.h>.  Note that if <net/if.h> is
 * to be included it must be included before this header file.
 */
#ifndef	ifa_broadaddr
#define	ifa_broadaddr	ifa_dstaddr	/* broadcast address interface */
#endif

void
inet_makenetandmask(net, sin, bits)
	u_long net, bits;
	struct sockaddr_in *sin;
{
	u_long addr, mask = 0;
	char *cp;

	nr_rtm_addrs |= RTA_NETMASK;
	if (net == 0)
		mask = addr = 0;
	else if (net < 128) {
		addr = net << IN_CLASSA_NSHIFT;
		mask = IN_CLASSA_NET;
	} else if (net < 65536) {
		addr = net << IN_CLASSB_NSHIFT;
		mask = IN_CLASSB_NET;
	} else if (net < 16777216L) {
		addr = net << IN_CLASSC_NSHIFT;
		mask = IN_CLASSC_NET;
	} else {
		addr = net;
		if ((addr & IN_CLASSA_HOST) == 0)
			mask =  IN_CLASSA_NET;
		else if ((addr & IN_CLASSB_HOST) == 0)
			mask =  IN_CLASSB_NET;
		else if ((addr & IN_CLASSC_HOST) == 0)
			mask =  IN_CLASSC_NET;
		else
			mask = -1;
	}
	if (bits)
		mask = 0xffffffff << (32 - bits);
	sin->sin_addr.s_addr = htonl(addr);
	sin = &so_mask.sin;
	sin->sin_addr.s_addr = htonl(mask);
	sin->sin_len = 0;
	sin->sin_family = 0;
	cp = (char *)(&sin->sin_addr + 1);
	while (*--cp == 0 && cp > (char *)sin)
		;
	sin->sin_len = 1 + cp - (char *)sin;
}

/*
 * Interpret an argument as a network address of some kind,
 * returning 1 if a host address, 0 if a network address.
 */
int
getaddr(which, s, hpp)
	int which;
	char *s;
	struct hostent **hpp;
{
	sup su;
	struct hostent *hp;
	struct netent *np;
	u_long val;
	char *q;
	int afamily;  /* local copy of af so we can change it */

	if (af == 0) {
		af = AF_INET;
		aflen = sizeof(struct sockaddr_in);
	}
	afamily = af;
	nr_rtm_addrs |= which;
	switch (which) {
	case RTA_DST:
		su = &so_dst;
		break;
	case RTA_GATEWAY:
		su = &so_gate;
		if (iflag) {
			struct ifaddrs *ifap, *ifa;
			struct sockaddr_dl *sdl = NULL;

			//if (getifaddrs(&ifap))
			//	printf("getifaddrs");

			for (ifa = ifap; ifa; ifa = ifa->ifa_next) {
				if (ifa->ifa_addr->sa_family != AF_LINK)
					continue;

				if (strcmp(s, ifa->ifa_name))
					continue;

				sdl = (struct sockaddr_dl *)ifa->ifa_addr;
			}
			/* If we found it, then use it */
			if (sdl) {
				/*
				 * Copy is safe since we have a
				 * sockaddr_storage member in sockunion{}.
				 * Note that we need to copy before calling
				 * freeifaddrs().
				 */
				memcpy(&su->sdl, sdl, sdl->sdl_len);
			}
			//freeifaddrs(ifap);
			if (sdl)
				return(1);
		}
		break;
	case RTA_NETMASK:
		su = &so_mask;
		break;
	case RTA_GENMASK:
		su = &so_genmask;
		break;
	case RTA_IFP:
		su = &so_ifp;
		afamily = AF_LINK;
		break;
	case RTA_IFA:
		su = &so_ifa;
		break;
	default:
		printf("internal error");
		/*NOTREACHED*/
	}
	su->sa.sa_len = aflen;
	su->sa.sa_family = afamily; /* cases that don't want it have left already */
	if (strcmp(s, "default") == 0) {
		/*
		 * Default is net 0.0.0.0/0 
		 */
		switch (which) {
		case RTA_DST:
			forcenet++;
#if 0
			bzero(su, sizeof(*su));	/* for readability */
#endif
			(void) getaddr(RTA_NETMASK, s, 0);
			break;
#if 0
		case RTA_NETMASK:
		case RTA_GENMASK:
			bzero(su, sizeof(*su));	/* for readability */
#endif
		}
		return (0);
	}
	switch (afamily) {
#ifdef INET6
	case AF_INET6:
	{
		struct addrinfo hints, *res;

		q = NULL;
		if (which == RTA_DST && (q = strchr(s, '/')) != NULL)
			*q = '\0';
		memset(&hints, 0, sizeof(hints));
		hints.ai_family = afamily;	/*AF_INET6*/
		hints.ai_flags = AI_NUMERICHOST;
		hints.ai_socktype = SOCK_DGRAM;		/*dummy*/
		if (getaddrinfo(s, "0", &hints, &res) != 0 ||
		    res->ai_family != AF_INET6 ||
		    res->ai_addrlen != sizeof(su->sin6)) {
			(void) fprintf(stderr, "%s: bad value\n", s);
			exit(1);
		}
		memcpy(&su->sin6, res->ai_addr, sizeof(su->sin6));
#ifdef __KAME__
		if ((IN6_IS_ADDR_LINKLOCAL(&su->sin6.sin6_addr) ||
		     IN6_IS_ADDR_MC_LINKLOCAL(&su->sin6.sin6_addr)) &&
		    su->sin6.sin6_scope_id) {
			*(u_int16_t *)&su->sin6.sin6_addr.s6_addr[2] =
				htons(su->sin6.sin6_scope_id);
			su->sin6.sin6_scope_id = 0;
		}
#endif
		freeaddrinfo(res);
		if (q != NULL)
			*q++ = '/';
		if (which == RTA_DST)
			return (inet6_makenetandmask(&su->sin6, q));
		return (0);
	}
#endif /* INET6 */

	case AF_LINK:
		//link_addr(s, &su->sdl);
		return (1);


	case PF_ROUTE:
		su->sa.sa_len = sizeof(*su);
		sockaddr(s, &su->sa);
		return (1);

	case AF_INET:
	default:
		break;
	}

	if (hpp == NULL)
		hpp = &hp;
	*hpp = NULL;

	q = strchr(s,'/');
	if (q && which == RTA_DST) {
		*q = '\0';
		if ((val = bsd_inet_addr(s)) != INADDR_NONE) {
			inet_makenetandmask(
				htonl(val), &su->sin, strtoul(q+1, 0, 0));//LUOYU modi val --> htonl(val) 2010-10-21 for show route statistic 
			return (0);
		}
		*q = '/';
	}
	if ((which != RTA_DST || forcenet == 0) &&
	    bsd_inet_aton(s, &su->sin.sin_addr)) 
	{
		val = su->sin.sin_addr.s_addr;
		if (which != RTA_DST || forcehost ||
		    bsd_inet_ntoa(su->sin.sin_addr) != INADDR_ANY)
			return (1);
		else {
			val = ntohl(val);
			goto netdone;
		}
	}
	//if (which == RTA_DST && forcehost == 0 &&
	//    ((val = inet_network(s)) != INADDR_NONE ||
	//    ((np = getnetbyname(s)) != NULL && (val = np->n_net) != 0))) {
netdone:
		inet_makenetandmask(val, &su->sin, 0);
		return (0);
	//}
	//hp = gethostbyname(s);
	//if (hp) {
	//	*hpp = hp;
	//	su->sin.sin_family = hp->h_addrtype;
	//	memmove((char *)&su->sin.sin_addr, hp->h_addr,
	//	    MIN(hp->h_length, sizeof(su->sin.sin_addr)));
	//	return (1);
	//}
	printf("bad address: %s", s);
}

void
mask_addr()
{
	int olen = so_mask.sa.sa_len;
	char *cp1 = olen + (char *)&so_mask, *cp2;

	for (so_mask.sa.sa_len = 0; cp1 > (char *)&so_mask; )
		if (*--cp1 != 0) {
			so_mask.sa.sa_len = 1 + cp1 - (char *)&so_mask;
			break;
		}
	if ((nr_rtm_addrs & RTA_DST) == 0)
		return;
	switch (so_dst.sa.sa_family) {
	case AF_INET:
#ifdef INET6
	case AF_INET6:
#endif
	case AF_APPLETALK:
	case 0:
		return;
	}
	cp1 = so_mask.sa.sa_len + 1 + (char *)&so_dst;
	cp2 = so_dst.sa.sa_len + 1 + (char *)&so_dst;
	while (cp2 > cp1)
		*--cp2 = 0;
	cp2 = so_mask.sa.sa_len + 1 + (char *)&so_mask;
	while (cp1 > so_dst.sa.sa_data)
		*--cp1 &= *--cp2;
}

int
rtmsg(int cfgId, int cmd, int flags)
{
	static int seq;
	int rlen;
	char *cp = m_rtmsg.m_space;
	int l;

// #define NEXTADDR(w, u) \
// 	if (rtm_addrs & (w)) {\
// 	    l = SA_SIZE(&(u.sa)); memmove(cp, &(u), l); cp += l;\
// 	    if (verbose) sodump(&(u),"u");\
// 	}

	errno = 0;
	memset(&m_rtmsg, 0, sizeof(m_rtmsg));
	if (cmd == 'a')
		cmd = RTM_ADD;
	else if (cmd == 'c')
		cmd = RTM_CHANGE;
	else if (cmd == 'g') {
		cmd = RTM_GET;
		if (so_ifp.sa.sa_family == 0) {
			so_ifp.sa.sa_family = AF_LINK;
			so_ifp.sa.sa_len = sizeof(struct sockaddr_dl);
			nr_rtm_addrs |= RTA_IFP;
		}
	} else
		cmd = RTM_DELETE;
#define rtm m_rtmsg.m_rtm
	rtm.rtm_type = cmd;
	rtm.rtm_flags = flags;
	rtm.rtm_version = RTM_VERSION;
	rtm.rtm_seq = ++seq;
	rtm.rtm_addrs = nr_rtm_addrs;
	rtm.rtm_rmx = rt_metrics;
	rtm.rtm_inits = rtm_inits;

	if (nr_rtm_addrs & RTA_NETMASK)
		mask_addr();
#define NRNEXTADDR(w, u) \
	if (nr_rtm_addrs & (w)) {\
	l = SA_SIZE(&(u.sa)); memcpy(cp, &(u), l); cp += l;\
	}
	NRNEXTADDR(RTA_DST, so_dst);
	//so_gate.sin.sin_addr.s_addr = htonl(so_gate.sin.sin_addr.s_addr);
	NRNEXTADDR(RTA_GATEWAY, so_gate);
	//so_mask.sin.sin_addr.s_addr = htonl(so_mask.sin.sin_addr.s_addr);
	NRNEXTADDR(RTA_NETMASK, so_mask);
	NRNEXTADDR(RTA_GENMASK, so_genmask);
	NRNEXTADDR(RTA_IFP, so_ifp);
	NRNEXTADDR(RTA_IFA, so_ifa);
	rtm.rtm_msglen = l = cp - (char *)&m_rtmsg;
	if (verbose)
		print_rtmsg(&rtm, l);
	if (debugonly)
		return (0);
	if ((rlen = so_write(cfgId, (char *)&m_rtmsg, l)) < 0) {
		if (errno == EPERM)
			printf("writing to routing socket");
		printf("writing to routing socket");
		return (-1);
	}
	if (cmd == RTM_GET) {
		do {
			l = so_read(cfgId, (char *)&m_rtmsg, sizeof(m_rtmsg));
		} while (l > 0 && (rtm.rtm_seq != seq || rtm.rtm_pid != 0));
		if (l < 0)
			printf("read from routing socket");
		else
			print_getmsg(&rtm, l);
	}
#undef rtm
	return (0);
}

int
keyword(cp)
	char *cp;
{
	struct keytab *kt = keywords;

	while (kt->kt_cp && strcmp(kt->kt_cp, cp))
		kt++;
	return kt->kt_i;
}


void
newroute(int cfgId, 
	int argc,
	char **argv)
{
	char *cmd, *dest = "", *gateway = "", *err;
	int ishost = 0, proxy = 0, ret, attempts, oerrno, flags = RTF_STATIC;
	int key;
	struct hostent *hp = 0;

	cmd = argv[0];
	//if (*cmd != 'g')
	//	so_close(cfgId, 0); /* Don't want to read back our messages */
	while (--argc > 0) {
		if (**(++argv)== '-') {
			switch (key = keyword(1 + *argv)) {
			case K_LINK:
				af = AF_LINK;
				aflen = sizeof(struct sockaddr_dl);
				break;
			case K_INET:
				af = AF_INET;
				aflen = sizeof(struct sockaddr_in);
				break;
#ifdef INET6
			case K_INET6:
				af = AF_INET6;
				aflen = sizeof(struct sockaddr_in6);
				break;
#endif
			
			case K_IFACE:
			case K_INTERFACE:
				iflag++;
				break;
			case K_NOSTATIC:
				flags &= ~RTF_STATIC;
				break;
			case K_LLINFO:
				flags |= RTF_LLINFO;
				break;
			case K_LOCK:
				locking = 1;
				break;
			case K_LOCKREST:
				lockrest = 1;
				break;
			case K_HOST:
				forcehost++;
				break;
			case K_REJECT:
				flags |= RTF_REJECT;
				break;
			case K_BLACKHOLE:
				flags |= RTF_BLACKHOLE;
				break;
			case K_PROTO1:
				flags |= RTF_PROTO1;
				break;
			case K_PROTO2:
				flags |= RTF_PROTO2;
				break;
			case K_PROXY:
				proxy = 1;
				break;
			case K_CLONING:
				flags |= RTF_CLONING;
				break;
			case K_XRESOLVE:
				flags |= RTF_XRESOLVE;
				break;
			case K_STATIC:
				flags |= RTF_STATIC;
				break;
			case K_IFA:
				//if (!--argc)
					//usage((char *)NULL);
				(void) getaddr(RTA_IFA, *++argv, 0);
				break;
			case K_IFP:
				//if (!--argc)
				//	usage((char *)NULL);
				(void) getaddr(RTA_IFP, *++argv, 0);
				break;
			case K_GENMASK:
				//if (!--argc)
				//	usage((char *)NULL);
				(void) getaddr(RTA_GENMASK, *++argv, 0);
				break;
			case K_GATEWAY:
				//if (!--argc)
				//	usage((char *)NULL);
				(void) getaddr(RTA_GATEWAY, *++argv, 0);
				break;
			case K_DST:
				//if (!--argc)
				//	usage((char *)NULL);
				ishost = getaddr(RTA_DST, *++argv, &hp);
				dest = *argv;
				break;
			case K_NETMASK:
				//if (!--argc)
				//	usage((char *)NULL);
				(void) getaddr(RTA_NETMASK, *++argv, 0);
				/* FALLTHROUGH */
			case K_NET:
				forcenet++;
				break;
			case K_PREFIXLEN:
				//if (!--argc)
				//	usage((char *)NULL);
				if (prefixlen(*++argv) == -1) {
					forcenet = 0;
					ishost = 1;
				} else {
					forcenet = 1;
					ishost = 0;
				}
				break;
			case K_MTU:
			case K_HOPCOUNT:
			case K_EXPIRE:
			case K_RECVPIPE:
			case K_SENDPIPE:
			case K_SSTHRESH:
			case K_RTT:
			case K_RTTVAR:
				//if (!--argc)
				//	usage((char *)NULL);
				set_metric(*++argv, key);
				break;
			default:
				//usage(1+*argv);
				;
			}
		} else {
			if ((nr_rtm_addrs & RTA_DST) == 0) {
				dest = *argv;
				ishost = getaddr(RTA_DST, *argv, &hp);
			} else if ((nr_rtm_addrs & RTA_GATEWAY) == 0) {
				gateway = *argv;
				(void) getaddr(RTA_GATEWAY, *argv, &hp);
			} else {
				(void) getaddr(RTA_NETMASK, *argv, 0);
				forcenet = 1;
			}
		}
	}
	if (forcehost) {
		ishost = 1;
#ifdef INET6
		if (af == AF_INET6) {
			nr_rtm_addrs &= ~RTA_NETMASK;
			memset((void *)&so_mask, 0, sizeof(so_mask));
		}
#endif 
	}
	if (forcenet)
		ishost = 0;
	flags |= RTF_UP;
	if (ishost)
		flags |= RTF_HOST;
	if (iflag == 0)
		flags |= RTF_GATEWAY;
	if (proxy) {
		so_dst.sinarp.sin_other = SIN_PROXY;
		flags |= RTF_ANNOUNCE;
	}
	for (attempts = 1; ; attempts++) {
		errno = 0;
		if ((ret = rtmsg(cfgId, *cmd, flags)) == 0)
			break;
		if (errno != ENETUNREACH && errno != ESRCH)
			break;
		if (af == AF_INET && *gateway && hp && hp->h_addr_list[1]) {
			hp->h_addr_list++;
			memmove(&so_gate.sin.sin_addr, hp->h_addr_list[0],
			    MIN(hp->h_length, sizeof(so_gate.sin.sin_addr)));
		} else
			break;
	}
	if (*cmd == 'g')
		exit(0);
	if (!qflag) {
		oerrno = errno;
		(void) printf("%s %s %s", cmd, ishost? "host" : "net", dest);
		if (*gateway) {
			(void) printf(": gateway %s", gateway);
			if (attempts > 1 && ret == 0 && af == AF_INET)
			    (void) printf(" (%s)",
				bsd_inet_ntoa(((struct sockaddr_in *)&route.rt_gateway)->sin_addr));
		}
		if (ret == 0) {
			(void) printf("\n");
		} else {
			switch (oerrno) {
			case ESRCH:
				err = "not in table";
				break;
			case EBUSY:
				err = "entry in use";
				break;
			case ENOBUFS:
				err = "routing table overflow";
				break;
			case EDQUOT: /* handle recursion avoidance in rt_setgate() */
				err = "gateway uses the same route";
				break;
			default:
				err = strerror(oerrno);
				break;
			}
			(void) printf(": %s\n", err);
		}
	}
	return(ret != 0);
}
/* States*/
#define VIRGIN	0
#define GOTONE	1
#define GOTTWO	2
/* Inputs */
#define	DIGIT	(4*0)
#define	END	(4*1)
#define DELIM	(4*2)

void
sockaddr(addr, sa)
	char *addr;
	struct sockaddr *sa;
{
	char *cp = (char *)sa;
	int size = sa->sa_len;
	char *cplim = cp + size;
	int byte = 0, state = VIRGIN, new = 0 /* foil gcc */;

	memset(cp, 0, size);
	cp++;
	do {
		if ((*addr >= '0') && (*addr <= '9')) {
			new = *addr - '0';
		} else if ((*addr >= 'a') && (*addr <= 'f')) {
			new = *addr - 'a' + 10;
		} else if ((*addr >= 'A') && (*addr <= 'F')) {
			new = *addr - 'A' + 10;
		} else if (*addr == 0)
			state |= END;
		else
			state |= DELIM;
		addr++;
		switch (state /* | INPUT */) {
		case GOTTWO | DIGIT:
			*cp++ = byte; /*FALLTHROUGH*/
		case VIRGIN | DIGIT:
			state = GOTONE; byte = new; continue;
		case GOTONE | DIGIT:
			state = GOTTWO; byte = new + (byte << 4); continue;
		default: /* | DELIM */
			state = VIRGIN; *cp++ = byte; byte = 0; continue;
		case GOTONE | END:
		case GOTTWO | END:
			*cp++ = byte; /* FALLTHROUGH */
		case VIRGIN | END:
			break;
		}
		break;
	} while (cp < cplim);
	sa->sa_len = cp - (char *)sa;
}


int add_static_route()
{
	int cfgId = 0;
	char cmd[] = "add";
	char opn[] = "-net";
	char dst[] = "20.1.1.0/24";
	char gw[] = "10.1.1.3";
	char *argv1[4] = {cmd, opn, dst, gw};/* because we will modify dst */
	cfgId = socket(AF_ROUTE, SOCK_RAW, 0);
    newroute(cfgId, 4, argv1);
	so_close(cfgId);
    return 0;
}
