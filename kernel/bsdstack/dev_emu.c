

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
#include "if_dl.h"
#include "if_arp.h"
#include "sbuf.h"
#include "ethernet.h"
#include "if_vlan_var.h"
#include "if_media.h"
//#include "ips_config.h"
//#include "ip_osal.h"

#if 0
//#pragma comment(lib, "IP_HAL.lib")
//#include "ip_hal.h"
/* status */
#define FXP_CB_STATUS_OK	0x2000
#define FXP_CB_STATUS_C		0x8000
/* commands */
#define FXP_CB_COMMAND_NOP	0x0
#define FXP_CB_COMMAND_IAS	0x1
#define FXP_CB_COMMAND_CONFIG	0x2
#define FXP_CB_COMMAND_MCAS	0x3
#define FXP_CB_COMMAND_XMIT	0x4
#define FXP_CB_COMMAND_UCODE	0x5
#define FXP_CB_COMMAND_DUMP	0x6
#define FXP_CB_COMMAND_DIAG	0x7
#define FXP_CB_COMMAND_LOADFILT	0x8
#define FXP_CB_COMMAND_IPCBXMIT 0x9

/* command flags */
#define FXP_CB_COMMAND_SF	0x0008	/* simple/flexible mode */
#define FXP_CB_COMMAND_I	0x2000	/* generate interrupt on completion */
#define FXP_CB_COMMAND_S	0x4000	/* suspend on completion */
#define FXP_CB_COMMAND_EL	0x8000	/* end of list */

#define FXP_PORT_SOFTWARE_RESET		0
#define FXP_PORT_SELFTEST		1
#define FXP_PORT_SELECTIVE_RESET	2
#define FXP_PORT_DUMP			3

#define FXP_SCB_RUS_IDLE		0
#define FXP_SCB_RUS_SUSPENDED		1
#define FXP_SCB_RUS_NORESOURCES		2
#define FXP_SCB_RUS_READY		4
#define FXP_SCB_RUS_SUSP_NORBDS		9
#define FXP_SCB_RUS_NORES_NORBDS	10
#define FXP_SCB_RUS_READY_NORBDS	12

#define FXP_SCB_CUS_IDLE		0
#define FXP_SCB_CUS_SUSPENDED		1
#define FXP_SCB_CUS_ACTIVE		2

#define FXP_SCB_INTR_DISABLE		0x01	/* Disable all interrupts */
#define FXP_SCB_INTR_SWI		0x02	/* Generate SWI */
#define FXP_SCB_INTMASK_FCP		0x04
#define FXP_SCB_INTMASK_ER		0x08
#define FXP_SCB_INTMASK_RNR		0x10
#define FXP_SCB_INTMASK_CNA		0x20
#define FXP_SCB_INTMASK_FR		0x40
#define FXP_SCB_INTMASK_CXTNO		0x80

#define FXP_SCB_STATACK_FCP		0x01	/* Flow Control Pause */
#define FXP_SCB_STATACK_ER		0x02	/* Early Receive */
#define FXP_SCB_STATACK_SWI		0x04
#define FXP_SCB_STATACK_MDI		0x08
#define FXP_SCB_STATACK_RNR		0x10
#define FXP_SCB_STATACK_CNA		0x20
#define FXP_SCB_STATACK_FR		0x40
#define FXP_SCB_STATACK_CXTNO		0x80

#define FXP_SCB_COMMAND_CU_NOP		0x00
#define FXP_SCB_COMMAND_CU_START	0x10
#define FXP_SCB_COMMAND_CU_RESUME	0x20
#define FXP_SCB_COMMAND_CU_DUMP_ADR	0x40
#define FXP_SCB_COMMAND_CU_DUMP		0x50
#define FXP_SCB_COMMAND_CU_BASE		0x60
#define FXP_SCB_COMMAND_CU_DUMPRESET	0x70

#define FXP_SCB_COMMAND_RU_NOP		0
#define FXP_SCB_COMMAND_RU_START	1
#define FXP_SCB_COMMAND_RU_RESUME	2
#define FXP_SCB_COMMAND_RU_ABORT	4
#define FXP_SCB_COMMAND_RU_LOADHDS	5
#define FXP_SCB_COMMAND_RU_BASE		6
#define FXP_SCB_COMMAND_RU_RBDRESUME	7

#define FXP_FLAG_MWI_ENABLE	0x0001	/* MWI enable */
#define FXP_FLAG_READ_ALIGN	0x0002	/* align read access with cacheline */
#define FXP_FLAG_WRITE_ALIGN	0x0004	/* end write on cacheline */
#define FXP_FLAG_EXT_TXCB	0x0008	/* enable use of extended TXCB */
#define FXP_FLAG_SERIAL_MEDIA	0x0010	/* 10Mbps serial interface */
#define FXP_FLAG_LONG_PKT_EN	0x0020	/* enable long packet reception */
#define FXP_FLAG_ALL_MCAST	0x0040	/* accept all multicast frames */
#define FXP_FLAG_CU_RESUME_BUG	0x0080	/* requires workaround for CU_RESUME */
#define FXP_FLAG_UCODE		0x0100	/* ucode is loaded */
#define FXP_FLAG_DEFERRED_RNR	0x0200	/* DEVICE_POLLING deferred RNR */
#define FXP_FLAG_EXT_RFA	0x0400	/* extended RFDs for csum offload */
#define FXP_FLAG_SAVE_BAD	0x0800	/* save bad pkts: bad size, CRC, etc */



struct fxp_cb_mcs {
	u_int16_t cb_status;
	u_int16_t cb_command;
	u_int32_t link_addr;
	u_int16_t mc_cnt;
	u_int8_t mc_addr[MAXMCADDR][6];
};

#define MAXUCODESIZE 192
struct fxp_cb_ucode {
	u_int16_t cb_status;
	u_int16_t cb_command;
	u_int32_t link_addr;
	u_int32_t ucode[MAXUCODESIZE];
};

/*
* NOTE: Elements are ordered for optimal cacheline behavior, and NOT
*	 for functional grouping.
*/
struct fxp_softc {
	struct arpcom arpcom;		/* per-interface network data */
	struct resource *mem;		/* resource descriptor for registers */
	int rtp;			/* register resource type */
	int rgd;			/* register descriptor in use */
	struct resource *irq;		/* resource descriptor for interrupt */
	void *ih;			/* interrupt handler cookie */
	struct mtx sc_mtx;
	struct fxp_stats *fxp_stats;	/* Pointer to interface stats */
	u_int32_t stats_addr;		/* DMA address of the stats structure */
	int rx_idle_secs;		/* # of seconds RX has been idle */
	struct fxp_cb_mcs *mcsp;	/* Pointer to mcast setup descriptor */
	u_int32_t mcs_addr;		/* DMA address of the multicast cmd */
	device_t miibus;
	device_t dev;
	int need_mcsetup;		/* multicast filter needs programming */
	int tunable_int_delay;		/* interrupt delay value for ucode */
	int tunable_bundle_max;		/* max # frames per interrupt (ucode) */
	int tunable_noflow;		/* flow control disabled */
	int rnr;			/* RNR events */
	int eeprom_size;		/* size of serial EEPROM */
	int suspended;			/* 0 = normal  1 = suspended or dead */
	int cu_resume_bug;
	int revision;
	int flags;
	u_int32_t saved_maps[5];	/* pci data */
	u_int32_t saved_biosaddr;
	u_int8_t saved_intline;
	u_int8_t saved_cachelnsz;
	u_int8_t saved_lattimer;
	u_int8_t rfa_size;
	u_int32_t recvSocket;
	u_int16_t recvPort;
};
#define	sc_if			arpcom.ac_if

static int		fxp_probe(device_t dev);
static int		fxp_attach(device_t dev);
static int		fxp_detach(device_t dev);
static int		fxp_shutdown(device_t dev);
static int		fxp_suspend(device_t dev);
static int		fxp_resume(device_t dev);

void		fxp_intr(void *xsc);
static void		fxp_intr_body(struct fxp_softc *sc, struct ifnet *ifp);
static void 		fxp_init(void *xsc);
static void 		fxp_init_body(struct fxp_softc *sc);
static void 		fxp_tick(void *xsc);
static void 		fxp_start(struct ifnet *ifp);
static void 		fxp_start_body(struct ifnet *ifp);
static void		fxp_stop(struct fxp_softc *sc);
static void 		fxp_release(struct fxp_softc *sc);
static int		fxp_ioctl(struct ifnet *ifp, u_long command,
						  caddr_t data);
static void 		fxp_watchdog(struct ifnet *ifp);
static int		fxp_add_rfabuf(struct fxp_softc *sc,
							   struct fxp_rx *rxp);
static int		fxp_mc_addrs(struct fxp_softc *sc);
static void		fxp_mc_setup(struct fxp_softc *sc);
static u_int16_t	fxp_eeprom_getword(struct fxp_softc *sc, int offset,
									   int autosize);
static void 		fxp_eeprom_putword(struct fxp_softc *sc, int offset,
									   u_int16_t data);
static void		fxp_autosize_eeprom(struct fxp_softc *sc);
static void		fxp_read_eeprom(struct fxp_softc *sc, u_char *data,
								int offset, int words);
static void		fxp_write_eeprom(struct fxp_softc *sc, u_short *data,
								 int offset, int words);
static int		fxp_ifmedia_upd(struct ifnet *ifp);
static void		fxp_ifmedia_sts(struct ifnet *ifp,
								struct ifmediareq *ifmr);
static int		fxp_serial_ifmedia_upd(struct ifnet *ifp);
static void		fxp_serial_ifmedia_sts(struct ifnet *ifp,
									   struct ifmediareq *ifmr);
static void		fxp_miibus_writereg(device_t dev, int phy, int reg,
									int value);
static void		fxp_load_ucode(struct fxp_softc *sc);

extern unsigned long _beginthread( void( __cdecl *start_address )( void * ), unsigned stack_size, void *arglist );

const	char *device_get_name(device_t dev);
void	*device_get_softc(device_t dev);
int device_get_unit(device_t dev);


extern int Dev_Send(int sockSend, int peerport, char *buf, int len);
extern int Dev_Recv(int socketRecv, char *buffer);




static device_method_t fxp_methods[] = {
	/* Device interface */
	DEVMETHOD(device_probe,		fxp_probe),
		DEVMETHOD(device_attach,	fxp_attach),
		DEVMETHOD(device_detach,	fxp_detach),
		DEVMETHOD(device_shutdown,	fxp_shutdown),
		DEVMETHOD(device_suspend,	fxp_suspend),
		DEVMETHOD(device_resume,	fxp_resume),
		
	{ 0, 0 }
};


static driver_t fxp_driver = {
	"fxp",
		fxp_methods,
		sizeof(struct fxp_softc),
};

extern int g_HalDevSend;
extern int g_HalDevRecv;


static devclass_t fxp_devclass;

/*
* Wait for the previous command to be accepted (but not necessarily
* completed).
*/
static void
fxp_scb_wait(struct fxp_softc *sc)
{
	
}

static void
fxp_scb_cmd(struct fxp_softc *sc, int cmd)
{
	
}
#ifdef hellox_dbg
extern IPS_ALL g_ips_all;
#endif
static void
fxp_read_eeprom( device_t dev, u_char *data, int offset, int words)
{
#ifdef hellox_dbg
	int i;
	IPS_CFG_IFA *ifCfg;
#pragma pack(1)
	struct macAddr{
		u_char data[2];
		union 
		{
			u_int32_t i;
			u_char data[4];
		}low;
	}myMacAddr;
#pragma pack()
	ifCfg = g_ips_all.config.ifa;
	while(ifCfg)
	{	
		char ifName[IFNAMSIZ] = {0};
		short *a;
		sprintf(ifName, "%s%d", ifCfg->ifName, ifCfg->index);
		if ((StrCmp(ifCfg->ifName, dev->name) != 0) || ifCfg->index != dev->unit)
		{
			ifCfg = ifCfg->next;
			continue;
		}
		a  = ifCfg->mac;
		for (i = 0; i < 6; i ++)
		{
			short tmp = htons(*a & 0x0f0f);
			
			data[i] = tmp| tmp >>4;
			a = a + 1;
			a =(char*)a + 1;
		}
		ifCfg = ifCfg->next;
	}
#endif
}


/*
* Return identification string if this device is ours.
*/
static int
fxp_probe(device_t dev)
{
	return -1;
}

//device_t g_dev_emu = NULL;
int g_threadHandler = 0;
#if 0
void install_dev(void *ifCfg)
{

	struct fxp_softc *softc = (struct fxp_softc*)malloc(sizeof(*softc));
	device_t dev;
	ifCfg->dev_p = (device_t)malloc(sizeof(*ifCfg->dev_p));
	dev = ifCfg->dev_p;
	//g_dev_emu = dev;
	memset(ifCfg->dev_p, 0, sizeof(struct device));
	memset(softc, 0, sizeof(struct fxp_softc));
	dev->name = ifCfg->ifName;//(char*)ENUML_DEV_NAME;
	dev->unit = ifCfg->index;
	dev->softc = softc;
	fxp_attach(dev);
	
	if_check(NULL);
	
	//_beginthread( fxp_intr, 0, NULL );
	g_hInterThreadId = Dev_Setup_Intr(fxp_intr, ifCfg->dev_recv_port);	
}
#endif
void install_dev(char *ifName, uint32_t index)
{

	struct fxp_softc *softc = (struct fxp_softc*)malloc(sizeof(*softc));
	device_t dev = (device_t)malloc(sizeof(device_t));
	//g_dev_emu = dev;
	//memset(dev, 0, sizeof(*device_t));
	memset(softc, 0, sizeof(struct fxp_softc));
	//dev->name = ifName;//(char*)ENUML_DEV_NAME;
	//dev->unit = index;
	//dev->softc = softc;
	fxp_attach(dev);
	
	if_check(NULL);
	
	//_beginthread( fxp_intr, 0, NULL );
	//g_hInterThreadId = Dev_Setup_Intr(fxp_intr, ifCfg->dev_recv_port);
	
}

static int
fxp_attach(device_t dev)
{
	int error = 0;
	struct fxp_softc *sc = device_get_softc(dev);
	struct ifnet *ifp;
	sc->dev = dev;
	
	/*
	* Read MAC address.
	*/
	fxp_read_eeprom(dev, sc->arpcom.ac_enaddr, 0, ETHER_ADDR_LEN);
	// 	sc->arpcom.ac_enaddr[0] = myea[0] & 0xff;
	// 	sc->arpcom.ac_enaddr[1] = myea[0] >> 8;
	// 	sc->arpcom.ac_enaddr[2] = myea[1] & 0xff;
	// 	sc->arpcom.ac_enaddr[3] = myea[1] >> 8;
	// 	sc->arpcom.ac_enaddr[4] = myea[2] & 0xff;
	// 	sc->arpcom.ac_enaddr[5] = myea[2] >> 8;
	ifp = &sc->arpcom.ac_if;
	memset(ifp, 0, sizeof(struct ifnet));//LUOYU add
	if_initname(ifp, device_get_name(dev), device_get_unit(dev));
	ifp->if_baudrate = 100000000;
	ifp->if_init = fxp_init;
	ifp->if_softc = sc;
	ifp->if_flags = IFF_BROADCAST | IFF_SIMPLEX ;
	ifp->if_ioctl = fxp_ioctl;
	ifp->if_start = fxp_start;
	ifp->if_watchdog = fxp_watchdog;
	
	ifp->if_capabilities = ifp->if_capenable = 0;
#define FXP_FLAG_EXT_RFA	0x0400	/* extended RFDs for csum offload */
	
	/* Enable checksum offload for 82550 or better chips */
	if (sc->flags & FXP_FLAG_EXT_RFA) {
		ifp->if_hwassist =(CSUM_TCP | CSUM_UDP);
		ifp->if_capabilities |= IFCAP_HWCSUM;
		ifp->if_capenable |= IFCAP_HWCSUM;
	}
	
#ifdef DEVICE_POLLING
	/* Inform the world we support polling. */
	ifp->if_capabilities |= IFCAP_POLLING;
	ifp->if_capenable |= IFCAP_POLLING;
#endif
	
	/*
	* Attach the interface.
	*/
	ether_ifattach(ifp, sc->arpcom.ac_enaddr);
	
	/*
	* Tell the upper layer(s) we support long frames.
	* Must appear after the call to ether_ifattach() because
	* ether_ifattach() sets ifi_hdrlen to the default value.
	*/
	ifp->if_data.ifi_hdrlen = sizeof(struct ether_vlan_header);
	ifp->if_capabilities |= IFCAP_VLAN_MTU;
	ifp->if_capenable |= IFCAP_VLAN_MTU; /* the hw bits already set */
	
	
										 /* 
										 * Hook our interrupt after all initialization is complete.
										 * XXX This driver has been tested with the INTR_MPSAFFE flag set
										 * however, ifp and its functions are not fully locked so MPSAFE
										 * should not be used unless you can handle potential data loss.
	*/
	//error = bus_setup_intr(dev, sc->irq, INTR_TYPE_NET | INTR_MPSAFE,
	//		       fxp_intr, sc, &sc->ih);
	if (error) {
		//device_printf(dev, "could not setup irq\n");
		ether_ifdetach(&sc->arpcom.ac_if);
		goto fail;
	}
	
fail:
	if (error)
		fxp_release(sc);
	return (error);
}

/*
* Release all resources.  The softc lock should not be held and the
* interrupt should already be torn down.
*/
static void
fxp_release(struct fxp_softc *sc)
{
	
}

/*
* Detach interface.
*/
static int
fxp_detach(device_t dev)
{
	struct fxp_softc *sc = dev->softc;
	int s;
	
	s = splimp();
	
	sc->suspended = 1;	/* Do same thing as we do for suspend */
						/*
						* Close down routes etc.
	*/
	ether_ifdetach(&sc->arpcom.ac_if);
	
	sc->ih = NULL;
	
	splx(s);
	
	/* Release our allocated resources. */
	fxp_release(sc);
	return (0);
}

/*
* Device shutdown routine. Called at system shutdown after sync. The
* main purpose of this routine is to shut off receiver DMA so that
* kernel memory doesn't get clobbered during warmboot.
*/
static int
fxp_shutdown(device_t dev)
{
/*
* Make sure that DMA is disabled prior to reboot. Not doing
* do could allow DMA to corrupt kernel memory during the
* reboot before the driver initializes.
	*/
	fxp_stop((struct fxp_softc *) dev->softc);
	return (0);
}

/*
* Device suspend routine.  Stop the interface and save some PCI
* settings in case the BIOS doesn't restore them properly on
* resume.
*/
static int
fxp_suspend(device_t dev)
{
	struct fxp_softc *sc = dev->softc;
	int s;
	
	s = splimp();
	
	fxp_stop(sc);
	
	
	sc->suspended = 1;
	
	splx(s);
	return (0);
}

/*
* Device resume routine.  Restore some PCI settings in case the BIOS
* doesn't, re-enable busmastering, and restart the interface if
* appropriate.
*/
static int
fxp_resume(device_t dev)
{
	return (0);
}

/*
* Grab the softc lock and call the real fxp_start_body() routine
*/
static void
fxp_start(struct ifnet *ifp)
{
	struct fxp_softc *sc = ifp->if_softc;
	
	fxp_start_body(ifp);
}
/*
* Start packet transmission on the interface.  
* This routine must be called with the softc lock held, and is an
* internal entry point only.
*/
static char _send_buff[8192] = {0};
static void
fxp_start_body(struct ifnet *ifp)
{
#ifdef hellox_dbg
	struct fxp_softc *sc = ifp->if_softc;
	//struct fxp_tx *txp;
	struct mbuf *mb_head;
	
	int len = 0;
	int pos = 0;
	IPS_CFG_IFA *ifCfg;
	/*
	* See if we need to suspend xmit until the multicast filter
	* has been reprogrammed (which can only be done at the head
	* of the command chain).
	*/
	if (sc->need_mcsetup) {
		return;
	}
	
	IFQ_DRV_DEQUEUE(&ifp->if_snd, mb_head);
	if (mb_head == NULL)
		return;
	memset(_send_buff, 0, 8192);
    //struct ip *pip = NULL;
	for (; mb_head != NULL && (mb_head->m_data != 0); 
	mb_head = mb_head->m_next) /*pChunk->mBlkHdr.m_next*/
    {
        
        /* if this cluster is empty  */
        if (mb_head->m_len <= 0)
            continue;
        /* get fragment length */
        len = mb_head->m_len;
        
        bcopy(mb_head->m_data, &_send_buff[pos], len);
        pos += len;
	}
	ifCfg = g_ips_all.config.ifa;
	while(ifCfg)
	{
		char if_name[IFNAMSIZ] = {0};
		sprintf(if_name, "%s%d", ifCfg->ifName, ifCfg->index);
		if (StrCmp(if_name, ifp->if_xname) == 0)
		{
			if (ifCfg->halDevSendHandler != 0)
				Dev_Send(ifCfg->halDevSendHandler, ifCfg->dev_send_port, 
				   _send_buff, pos);	
			break;
		}
		ifCfg = ifCfg->next;

	}
#endif
}


/*
* Process interface interrupts.
*/
void
fxp_intr(void *halHandler)
{
#ifdef hellox_dbg
	struct fxp_softc *sc;
	struct ifnet *ifp;
	IPS_CFG_IFA *ifCfg;
	unsigned short recv_port = (short)(short*)halHandler;
	ifCfg = g_ips_all.config.ifa;
	while(ifCfg)
	{
		if (ifCfg->dev_recv_port == recv_port)
		{
			break;
		}
		ifCfg = ifCfg->next;
	}
	if (ifCfg == NULL)
		return;

	sc = ((device_t)ifCfg->dev_p)->softc;
	ifp = &sc->sc_if;
	sc->recvSocket = ifCfg->halDevRecvHandler;
	sc->recvPort = recv_port;
	//printf("%s prepare for recving data in port %d\n", ifp->if_xname, sc->recvPort);
	//Sys_Get_ThreadId(&g_hInterThreadId);
	while(1)
	{
		fxp_intr_body(sc, ifp);
		if (g_bIntrThreadExit == 1)
		{
			g_hInterThreadId = 0;
			return;
		}
	}
#endif
}

static void
fxp_txeof(struct fxp_softc *sc)
{
	
}
static char _recv_buff[8192] = {0};
static void
fxp_intr_body(struct fxp_softc *sc, struct ifnet *ifp)
{
	struct mbuf *m;
	int n;
	
	
	/*
	* Just return if nothing happened on the receive side.
	*/
retry_recv:	 
	memset(_recv_buff, 0, 8192);
	n = Dev_Recv(sc->recvSocket, _recv_buff);
	if (n <= 0)
	{
		goto retry_recv;
	}
	
	if (sc->suspended) {
		return;
	}
	/*
	* Process receiver interrupts. If a no-resource (RNR)
	* condition exists, get whatever packets we can and
	* re-start the receiver.
	*
	* When using polling, we do not process the list to completion,
	* so when we get an RNR interrupt we must defer the restart
	* until we hit the last buffer with the C bit set.
	* If we run out of cycles and rfa_headm has the C bit set,
	* record the pending RNR in the FXP_FLAG_DEFERRED_RNR flag so
	* that the info will be used in the subsequent polling cycle.
	*/
	MGETHDR(m, M_DONTWAIT, MT_DATA);
	if(m == NULL) {
		/* eat packet if get mbuf fail!! */
		return;
	}
	m->m_pkthdr.rcvif = &sc->arpcom.ac_if;
	m->m_pkthdr.len = m->m_len = n;
	if(n > MHLEN) {
		MCLGET(m, M_DONTWAIT);
		if((m->m_flags & M_EXT) == 0) {
			m_freem(m);
			//ar_eat_packet(sc, 1);
			return;
		}
	}
	memcpy(m->m_data, _recv_buff, n);
	//for (;;) {
	//m = NULL;//LUOYU
	
	//Sys_Mutex_Lock();
	(*ifp->if_input)(ifp, m);
	//Sys_Mutex_Unlock();
}

/*
* Stop the interface. Cancels the statistics updater and resets
* the interface.
*/
static void
fxp_stop(struct fxp_softc *sc)
{
	struct ifnet *ifp = &sc->sc_if;
	
	ifp->if_flags &= ~(IFF_RUNNING | IFF_OACTIVE);
	ifp->if_timer = 0;
	
	
}

/*
* Watchdog/transmission transmit timeout handler. Called when a
* transmission is started on the interface, but no interrupt is
* received before the timeout. This usually indicates that the
* card has wedged for some reason.
*/
static void
fxp_watchdog(struct ifnet *ifp)
{
	struct fxp_softc *sc = ifp->if_softc;
	ifp->if_oerrors++;
	
	fxp_init_body(sc);
}

/*
* Acquire locks and then call the real initialization function.  This
* is necessary because ether_ioctl() calls if_init() and this would
* result in mutex recursion if the mutex was held.
*/
static void
fxp_init(void *xsc)
{
	struct fxp_softc *sc = xsc;
	
	fxp_init_body(sc);
}

/*
* Perform device initialization. This routine must be called with the
* softc lock held.
*/
static void
fxp_init_body(struct fxp_softc *sc)
{
	struct ifnet *ifp = &sc->sc_if;
	int prm, s;
	u_int8_t macaddr[6];
	s = splimp();
	/*
	* Cancel any pending I/O
	*/
	fxp_stop(sc);
	
	prm = (ifp->if_flags & IFF_PROMISC) ? 1 : 0;
	
	
	/*
	* Initialize the multicast address list.
	*/
	if (fxp_mc_addrs(sc)) {
	}
	
	
	
	
	/*
	* Now initialize the station address. Temporarily use the TxCB
	* memory area like we did above for the config CB.
	*/
	
	bcopy(sc->arpcom.ac_enaddr, macaddr, //LUOYU
		sizeof(sc->arpcom.ac_enaddr));
	
	
	ifp->if_flags |= IFF_RUNNING;
	ifp->if_flags &= ~IFF_OACTIVE;
	/*
	* Start stats updater.
	*/
	//callout_reset(&sc->stat_ch, hz, fxp_tick, sc);LUOYU
	splx(s);
}

static int
fxp_serial_ifmedia_upd(struct ifnet *ifp)
{
	
	return (0);
}

static void
fxp_serial_ifmedia_sts(struct ifnet *ifp, struct ifmediareq *ifmr)
{
	
	ifmr->ifm_active = IFM_ETHER|IFM_MANUAL;
}

static int
fxp_ioctl(struct ifnet *ifp, u_long command, caddr_t data)
{
	struct fxp_softc *sc = ifp->if_softc;
	struct ifreq *ifr = (struct ifreq *)data;
	int mask, s, error = 0;
	
	/*
	* Detaching causes us to call ioctl with the mutex owned.  Preclude
	* that by saying we're busy if the lock is already held.
	*/
	s = splimp();
	
	switch (command) {
	case SIOCSIFFLAGS:
		if (ifp->if_flags & IFF_ALLMULTI)
			sc->flags |= FXP_FLAG_ALL_MCAST;
		else
			sc->flags &= ~FXP_FLAG_ALL_MCAST;
		
			/*
			* If interface is marked up and not running, then start it.
			* If it is marked down and running, stop it.
			* XXX If it's up then re-initialize it. This is so flags
			* such as IFF_PROMISC are handled.
		*/
		if (ifp->if_flags & IFF_UP) {
			fxp_init_body(sc);
		} else {
			if (ifp->if_flags & IFF_RUNNING)
				fxp_stop(sc);
		}
		break;
		
	case SIOCADDMULTI:
	case SIOCDELMULTI:
		if (ifp->if_flags & IFF_ALLMULTI)
			sc->flags |= FXP_FLAG_ALL_MCAST;
		else
			sc->flags &= ~FXP_FLAG_ALL_MCAST;
			/*
			* Multicast list has changed; set the hardware filter
			* accordingly.
		*/
		if ((sc->flags & FXP_FLAG_ALL_MCAST) == 0)
			fxp_mc_setup(sc);
			/*
			* fxp_mc_setup() can set FXP_FLAG_ALL_MCAST, so check it
			* again rather than else {}.
		*/
		if (sc->flags & FXP_FLAG_ALL_MCAST)
			fxp_init_body(sc);
		error = 0;
		break;
		
	case SIOCSIFMEDIA:
	case SIOCGIFMEDIA:
		break;
		
	case SIOCSIFCAP:
		mask = ifp->if_capenable ^ ifr->ifr_reqcap;
		if (mask & IFCAP_POLLING)
			ifp->if_capenable ^= IFCAP_POLLING;
		if (mask & IFCAP_VLAN_MTU) {
			if (ifp->if_flags & IFF_UP)
				fxp_init_body(sc);
		}
		break;
		
	default:
	/* 
	* ether_ioctl() will eventually call fxp_start() which
	* will result in mutex recursion so drop it first.
		*/
		error = ether_ioctl(ifp, command, data);
	}
	splx(s);
	return (error);
}

/*
* Fill in the multicast address list and return number of entries.
*/
static int
fxp_mc_addrs(struct fxp_softc *sc)
{
	struct ifnet *ifp = &sc->sc_if;
	struct ifmultiaddr *ifma;
	int nmcasts;
	
	nmcasts = 0;
	if ((sc->flags & FXP_FLAG_ALL_MCAST) == 0) {
		TAILQ_FOREACH(ifma, &ifp->if_multiaddrs, ifma_link) {
			if (ifma->ifma_addr->sa_family != AF_LINK)
				continue;
			if (nmcasts >= MAXMCADDR) {
				sc->flags |= FXP_FLAG_ALL_MCAST;
				nmcasts = 0;
				break;
			}
			bcopy(LLADDR((struct sockaddr_dl *)ifma->ifma_addr),
				&sc->mcsp->mc_addr[nmcasts][0], ETHER_ADDR_LEN);
			nmcasts++;
		}
	}
	return (nmcasts);
}

/*
* Program the multicast filter.
*
* We have an artificial restriction that the multicast setup command
* must be the first command in the chain, so we take steps to ensure
* this. By requiring this, it allows us to keep up the performance of
* the pre-initialized command ring (esp. link pointers) by not actually
* inserting the mcsetup command in the ring - i.e. its link pointer
* points to the TxCB ring, but the mcsetup descriptor itself is not part
* of it. We then can do 'CU_START' on the mcsetup descriptor and have it
* lead into the regular TxCB ring when it completes.
*
* This function must be called at splimp.
*/
static void
fxp_mc_setup(struct fxp_softc *sc)
{
	struct fxp_cb_mcs *mcsp = sc->mcsp;
	struct ifnet *ifp = &sc->sc_if;
	int count;
	
	/*
	* If there are queued commands, we must wait until they are all
	* completed. If we are already waiting, then add a NOP command
	* with interrupt option so that we're notified when all commands
	* have been completed - fxp_start() ensures that no additional
	* TX commands will be added when need_mcsetup is true.
	*/
	sc->need_mcsetup = 0;
	
	/*
	* Initialize multicast setup descriptor.
	*/
	//mcsp->cb_status = 0;
	//mcsp->cb_command = htole16(FXP_CB_COMMAND_MCAS |
	//    FXP_CB_COMMAND_S | FXP_CB_COMMAND_I);
	//(void) fxp_mc_addrs(sc);
	
	/*
	* Wait until command unit is not active. This should never
	* be the case when nothing is queued, but make sure anyway.
	*/
	count = 100;
	
	/*
	* Start the multicast setup command.
	*/
	fxp_scb_wait(sc);
	fxp_scb_cmd(sc, FXP_SCB_COMMAND_CU_START);
	
	ifp->if_timer = 2;
	return;
}

/**
* @brief Return the name of the device's devclass or @c NULL if there
* is none.
*/
const char *
device_get_name(device_t dev)
{
#if 0
	if (dev != NULL && dev->devclass)
		return (devclass_get_name(dev->devclass));
#endif		
	return dev->name;
}

/**
* @brief Return the device's unit number.
*/
int
device_get_unit(device_t dev)
{
	return (dev->unit);
}
void *
device_get_softc(device_t dev)
{
	return (dev->softc);
}

#endif