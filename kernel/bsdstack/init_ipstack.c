/********************************************************/
/****************** AUTHOR LUOYU ************************/
/********************************************************/

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
#include "ktime.h"
#include "bsdif.h"
#include "in_pcb.h"
#include "in_var.h"
#include "tcp_var.h"
#include "tcp_fsm.h"
#include "bsdip.h"
#include "kroute.h"
#include "tcp_ip.h"
#include "netisr.h"
#include "ips_config.h"
extern struct domain inetdomain;
extern struct domain routedomain;
extern void init_param1(void);
extern void init_param2(long physpages);
extern void init_param3(long kmempages);
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
    int i = 0;

    //IPS_CFG_IFA *ifCfg;

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
    PciMatchDriver();
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

    BISConfig();
    //test_ping("192.168.56.1");
}

