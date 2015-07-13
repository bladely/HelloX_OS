/********************************************************/
/****************** AUTHOR LUOYU ************************/
/********************************************************/

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
//#include "IPS_CONFIG.h"
extern struct domain inetdomain;
extern struct domain routedomain;
extern void init_param1(void);
extern void init_param2(void);
extern void init_param3(void);
extern void install_dev();
extern void uma_startup(void *bootmem);
extern void mbuf_init(void *dummy);
extern void domaininit(void *dummy);
extern void rts_init(void);
extern void route_init(void);
extern void arp_init(void);

//extern IPS_ALL g_ips_all;
void DOMAIN_SET(struct domain *name)
{
	net_add_domain(name);
	
}
void BISStartup()
{
	//IPS_CFG_IFA *ifCfg;
	int i = 0;
	init_param1();
	init_param2(1000);
	init_param3(1000);
	//OSAL_Startup();
	if_init(NULL);
	//ifCfg = g_ips_all.config.ifa;
	/*for( ;ifCfg != NULL; )
	{
		install_dev(ifCfg);
		ifCfg = ifCfg->next;
		i ++;
	}*/
	
	uma_startup(NULL);
	mbuf_init(NULL);
	domaininit(NULL);
	//rip_init();在net_add_domain中初始化
	//udp_init();
	DOMAIN_SET(&inetdomain);
	DOMAIN_SET(&routedomain);
	rts_init();
	route_init();
	arp_init();
}

