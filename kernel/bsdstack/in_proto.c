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
#include "ktime.h"
#include "if.h"
#include "in_pcb.h"
#include "in_var.h"
#include "tcp_var.h"
#include "tcp_fsm.h"
#include "ip.h"
#include "kroute.h"
#include "tcp_ip.h"
#include "netisr.h"
#include "udp_var.h"
#include "ip_icmp.h"

//#include <netinet/sctp_pcb.h>
//#include <netinet/sctp.h>
//#include <netinet/sctp_var.h>
extern	struct domain inetdomain;
static	struct pr_usrreqs nousrreqs;

struct protosw inetsw[] = {
{ 0,		&inetdomain,	0,		0,
  0,		0,		0,		0,
  0,
  ip_init,	0,		ip_slowtimo,	ip_drain,
  &nousrreqs
},
{ SOCK_DGRAM,	&inetdomain,	IPPROTO_UDP,	PR_ATOMIC|PR_ADDR,
  bsd_udp_input,	0,		udp_ctlinput,	ip_ctloutput,
  0,
  udp_init,	0,		0,		0,
  &udp_usrreqs
},
{ SOCK_STREAM,	&inetdomain,	IPPROTO_TCP,
	PR_CONNREQUIRED|PR_IMPLOPCL|PR_WANTRCVD,
  bsd_tcp_input,	0,		tcp_ctlinput,	tcp_ctloutput,
  0,
  tcp_init,	0,		tcp_slowtimo,	tcp_drain,
  &tcp_usrreqs
},
//{ 
//	SOCK_STREAM,
//	&inetdomain,
//   IPPROTO_SCTP,
//   PR_WANTRCVD,
//   sctp_input,
//   NULL,
//   sctp_ctlinput,	
//   sctp_ctloutput,
//   NULL,
//   sctp_init,	
//   NULL,NULL,
//   sctp_drain,
//   &sctp_usrreqs
//},
{ SOCK_RAW,	&inetdomain,	IPPROTO_RAW,	PR_ATOMIC|PR_ADDR,
  rip_input,	0,		rip_ctlinput,	rip_ctloutput,
  0,
  0,		0,		0,		0,
  &rip_usrreqs
},
{ SOCK_RAW,	&inetdomain,	IPPROTO_ICMP,	PR_ATOMIC|PR_ADDR|PR_LASTHDR,
  bsd_icmp_input,	0,		0,		rip_ctloutput,
  0,
  0,		0,		0,		0,
  &rip_usrreqs
},
	/* raw wildcard */
{ SOCK_RAW,	&inetdomain,	0,		PR_ATOMIC|PR_ADDR,
  rip_input,	0,		0,		rip_ctloutput,
  0,
  rip_init,	0,		0,		0,
  &rip_usrreqs
},
};
extern int	in_inithead(void **head, int off);

struct domain inetdomain =
    { AF_INET, "internet", 0, 0, 0,
      inetsw,
      &inetsw[sizeof(inetsw)/sizeof(inetsw[0])], 0,
      in_inithead, 32, sizeof(struct sockaddr_in)
    };
