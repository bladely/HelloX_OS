//***********************************************************************/
//    Author                    : Garry
//    Original Date             : Aug 02, 2015
//    Module Name               : pcnet.c
//    Module Funciton           : 
//                                This module countains the implementation code
//                                of PCNet 79C973 or 79C975 NIC controllers.
//    Last modified Author      :
//    Last modified Date        :
//    Last modified Content     :
//                                1.
//                                2.
//    Lines number              :
//***********************************************************************/

#include <StdAfx.h>
#include <pci_drv.h>
#include <kapi.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#if 0
#include "lwip/opt.h"
#include "lwip/def.h"
#include "lwip/mem.h"
#include "lwip/pbuf.h"
#include "lwip/sys.h"
#include "lwip/stats.h"
#include "lwip/snmp.h"
#include "lwip/tcpip.h"
#include "lwip/dhcp.h"
#include "ethernet/ethif.h"
#endif

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
#include "if_dl.h"
#include "bsdif.h"
#include "sbuf.h"
#include "ethernet.h"


#include "mbuf.h"
#include "bsdip.h"
#include "bsdtcp.h"
#include "bsdudp.h"
#include "pcnet.h"

//PCNet NIC's control struct list,each element in this list for each NIC in system.
static  pcnet_priv_t* lp = NULL;
static unsigned char* pcnet_recv(pcnet_priv_t *pcndev,int* pPktLen);

//A helper routine to show all PCNet NIC devices in lp list.
static void ShowAllNICs()
{
	pcnet_priv_t* dev = lp;
	int index = 0;

	while (dev)
	{
		if (dev->available)  //Available device,show it.
		{
			_hx_printf("PCNet: NIC device[%d] information:\r\n", index++);
			_hx_printf("    chip version:    0x%X.\r\n", dev->chip_ver);
			_hx_printf("    chip name   :    %s.\r\n", dev->chip_name);
			_hx_printf("    MAC address :    %02X-%02X-%02X-%02X-%02X-%02X.\r\n",
				dev->macAddr[0],
				dev->macAddr[1],
				dev->macAddr[2],
				dev->macAddr[3],
				dev->macAddr[4],
				dev->macAddr[5]);
			_hx_printf("\r\n");
		}
		else
		{
			_hx_printf("PCNet: Encounter an unavailable NIC device.\r\n");
		}
		dev = dev->next;
	}
}

//Several helper routines to access PCNet's internal registers.
static __U16 pcnet_read_csr(pcnet_priv_t *dev, int index)
{
	__outw(index, dev->ioBase + PCNET_RAP);
	return __inw(dev->ioBase + PCNET_RDP);
}

static void pcnet_write_csr(pcnet_priv_t *dev, int index, __U16 val)
{
	__outw(index, dev->ioBase + PCNET_RAP);
	__outw(val, dev->ioBase + PCNET_RDP);
}

static __U16 pcnet_read_bcr(pcnet_priv_t *dev, int index)
{
	__outw(index, dev->ioBase + PCNET_RAP);
	return __inw(dev->ioBase + PCNET_BDP);
}

static void pcnet_write_bcr(pcnet_priv_t *dev, int index, __U16 val)
{
	__outw(index, dev->ioBase + PCNET_RAP);
	__outw(val, dev->ioBase + PCNET_BDP);
}

static void pcnet_reset(pcnet_priv_t *dev)
{
	__inw(dev->ioBase + PCNET_RESET);
	
}

static int pcnet_check(pcnet_priv_t *dev)
{
	__outw(88, dev->ioBase + PCNET_RAP);
	return __inw(dev->ioBase + PCNET_RAP) == 88;
}

//Interrupt control routines,enable or disable receiving interrupt.
static void pcnet_enable_rint(pcnet_priv_t* dev, BOOL bEnable)
{
	__U16 csr0, csr3;

	if (bEnable)
	{
		csr0 = pcnet_read_csr(dev, 0);
		//Set IENA bits of CSR0,to enable interrupt.
		csr0 |= (1 << 6);
		pcnet_write_csr(dev, 0, csr0);
		//Clear RINTM bit in interrupt mask register.
		csr3 = pcnet_read_csr(dev, 3);
		csr3 &= (~(1 << 10));
		pcnet_write_csr(dev, 3, csr3);
	}
	else  //Shoud disable the RINT interrupt.
	{
		csr3 = pcnet_read_csr(dev, 3);
		csr3 |= (1 << 10);
		pcnet_write_csr(dev, 3,csr3);
	}
	return;
}

//Interrupt control routines,enable or disable send over interrupt.
static void pcnet_enable_sint(pcnet_priv_t* dev, BOOL bEnable)
{
	__U16 csr0, csr3;

	if (bEnable)
	{
		csr0 = pcnet_read_csr(dev, 0);
		//Set IENA bits of CSR0,to enable interrupt.
		csr0 |= (1 << 6);
		pcnet_write_csr(dev, 0, csr0);
		//Clear SINTM bit in interrupt mask register.
		csr3 = pcnet_read_csr(dev, 3);
		csr3 &= (~(1 << 9));
		pcnet_write_csr(dev, 3, csr3);
	}
	else  //Shoud disable the SINT interrupt.
	{
		csr3 = pcnet_read_csr(dev, 3);
		csr3 |= (1 << 9);
		pcnet_write_csr(dev, 3,csr3);
	}
	return;
}

//Interrupt control routines,enable or disable initialization done interrupt.
static void pcnet_enable_idint(pcnet_priv_t* dev, BOOL bEnable)
{
	__U16 csr0, csr3;

	if (bEnable)
	{
		csr0 = pcnet_read_csr(dev, 0);
		//Set IENA bits of CSR0,to enable interrupt.
		csr0 |= (1 << 6);
		pcnet_write_csr(dev, 0, csr0);
		//Clear IDOINTM bit in interrupt mask register.
		csr3 = pcnet_read_csr(dev, 3);
		csr3 &= (~(1 << 8));
		pcnet_write_csr(dev, 3, csr3);
	}
	else  //Shoud disable the IDOINT interrupt.
	{
		csr3 = pcnet_read_csr(dev, 3);
		csr3 |= (1 << 8);
		pcnet_write_csr(dev, 3,csr3);
	}
	return;
}

//Acknowledge rint interrupt.
static void pcnet_ack_rint(pcnet_priv_t* dev)
{
	__U16 csr0 = 0;
	csr0 = pcnet_read_csr(dev, 0);
	csr0 |= (1 << 10);
	pcnet_write_csr(dev, 0, csr0);
}

//Acknowledge sint interrupt.
static void pcnet_ack_sint(pcnet_priv_t* dev)
{
	__U16 csr0 = 0;
	csr0 = pcnet_read_csr(dev, 0);
	csr0 |= (1 << 9);
	pcnet_write_csr(dev, 0, csr0);
}

//Acknowledge idint interrupt.
static void pcnet_ack_idint(pcnet_priv_t* dev)
{
	__U16 csr0 = 0;
	csr0 = pcnet_read_csr(dev, 0);
	csr0 |= (1 << 8);
	pcnet_write_csr(dev, 0, csr0);
}

//Enable all PCNet NIC's interrupt,only rint,sint,idint are enavbled.This function
//should be invoked at the end of the PCNet driver's entry point,since it may lead to system crash
//when data structures are not established before the end of driver's entry point.
static void EnableAllInterrupt()
{
	pcnet_priv_t* dev = lp;

	while (dev)
	{
		if (dev->available)  //Only available NIC's interrupt is set.
		{
			pcnet_enable_rint(dev, TRUE);
			pcnet_enable_sint(dev, TRUE);
			pcnet_enable_idint(dev, TRUE);
		}
		dev = dev->next;
	}
}

//Enumerates all PCNet NICs in system,by searching the PCI bus device list.
//Create a pcnet_priv_t structure for each PCNet NIC device.
static BOOL EnumPCNet_NIC()
{
	__PHYSICAL_DEVICE*    pDev   = NULL;
	__IDENTIFIER          devId;
	pcnet_priv_t*         priv   = NULL;
	__U16                 iobase = 0;
	LPVOID                memAddr = NULL;
	int                   intVector = 0;
	int                   index = 0;
	BOOL                  bResult = FALSE;

	//Set device ID accordingly.
	devId.dwBusType                     = BUS_TYPE_PCI;
	devId.Bus_ID.PCI_Identifier.ucMask  = PCI_IDENTIFIER_MASK_VENDOR | PCI_IDENTIFIER_MASK_DEVICE;
	devId.Bus_ID.PCI_Identifier.wVendor = PCNET_VENDOR_ID;
	devId.Bus_ID.PCI_Identifier.wDevice = PCNET_DEVICE_ID;

	//Try to fetch the physical device with the specified ID.
	pDev = DeviceManager.GetDevice(
		&DeviceManager,
		BUS_TYPE_PCI,
		&devId,
		NULL);
	if (NULL == pDev)  //PCNet may not exist.
	{
#ifdef __PCNET_DEBUG
		_hx_printf("PCNet: Can not get any PCNet device in system.\r\n");
#endif
		return bResult;
	}
	
	//Got a valid device,retrieve it's hardware resource and save them into 
	//pcnet_priv_t structure.
	while (pDev)
	{
		for (index = 0; index < MAX_RESOURCE_NUM; index++)
		{
			if (pDev->Resource[index].dwResType == RESOURCE_TYPE_INTERRUPT)
			{
				intVector = pDev->Resource[index].Dev_Res.ucVector;
			}
			if (pDev->Resource[index].dwResType == RESOURCE_TYPE_IO)
			{
				iobase = pDev->Resource[index].Dev_Res.IOPort.wStartPort;
			}
			if (pDev->Resource[index].dwResType == RESOURCE_TYPE_MEMORY)
			{
				memAddr = pDev->Resource[index].Dev_Res.MemoryRegion.lpStartAddr;
			}
		}
		//Check if the device with valid resource.
		if ((0 == intVector) && (0 == iobase))
		{
#ifdef __PCNET_DEBUG
			_hx_printf("PCNet: Find a device without valid resource.\r\n");
#endif
			continue;  //Continue to process next device.
		}

		//Now allocate a pcnet_priv_t structure and fill the resource.
		priv = (pcnet_priv_t*)_hx_malloc(sizeof(pcnet_priv_t));
		if (NULL == priv)
		{
#ifdef __PCNET_DEBUG
			_hx_printf("PCNet: Can not allocate memory for pcnet_priv_t structure.\r\n");
#endif
			goto __TERMINAL;
		}
		priv->ioBase = iobase;
		priv->intVector = intVector;
		priv->pPhyDev = pDev;
		priv->hInterrupt = NULL;
		priv->available = 0;  //Will be changed to 1 in probe process.

		//Link the structure to global list.
		priv->next = lp;
		lp = priv;

#ifdef __PCNET_DEBUG
		_hx_printf("PCNet: Get a PCNet NIC device[int = %d,iobase = 0x%X].\r\n",
			intVector,
			iobase);
#endif

		//Try to fetch another PCNet device.
		pDev = DeviceManager.GetDevice(
			&DeviceManager,
			BUS_TYPE_PCI,
			&devId,
			pDev);
	}
	bResult = TRUE;

__TERMINAL:
	if (!bResult)
	{
#ifdef __PCNET_DEBUG
		_hx_printf("PCNet: Enumerate PCNet NIC device failed.\r\n");
#endif
		//May release resource,such as pcnet_priv_t structures here.
	}
	return bResult;
}

//A local helper routine to probe one PCNet NIC in system.
//It will fill the pcnet_priv_t structure accordingly.
static BOOL ProbePCNetNIC(pcnet_priv_t* dev)
{
	unsigned int i = 0;

	//Reset the PCNet controller.
	pcnet_reset(dev);

	//Check if register access is working.
	if (pcnet_read_csr(dev, 0) != 4 || !pcnet_check(dev))
	{
#ifdef __PCNET_DEBUG
		_hx_printf("PCNet: Register access is not working.\r\n");
#endif
		return FALSE;
	}

	//Try to identify the chip's version and name.
	dev->chip_ver = pcnet_read_csr(dev, 88) | (pcnet_read_csr(dev, 89) << 16);
	if ((dev->chip_ver & 0xFFF) != 0x03)
	{
#ifdef __PCNET_DEBUG
		_hx_printf("PCNet: Chip version is not match.\r\n");
#endif
		return FALSE;
	}
	switch ((dev->chip_ver >> 12) & 0xFFFF)
	{
	case 0x2621:
		dev->chip_name = "PCnet/PCI II 79C970A";
		break;
	case 0x2625:
		dev->chip_name = "PCnet/FAST III 79C973";
		break;
	case 0x2627:
		dev->chip_name = "PCnet/FAST III 79C975";
		break;
	default:
#ifdef __PCNET_DEBUG
		_hx_printf("PCNet: Chip verion is not supported[0x%X].\r\n", dev->chip_ver);
#endif
		return FALSE;
	}

	//Fetch chip's MAC address.
	for (i = 0; i < 3; i++) {
		unsigned int val;
		val = pcnet_read_csr(dev, i + 12) & 0x0ffff;
		/* There may be endianness issues here. */
		dev->macAddr[2 * i] = val & 0x0ff;
		dev->macAddr[2 * i + 1] = (val >> 8) & 0x0ff;
	}

	//Set the pcnet_priv_t structure available.
	dev->available = 1;
	return TRUE;
}

//Probe all NICs in one operation.
static BOOL ProbePCNetNICs()
{
	pcnet_priv_t* pcndev = lp;
	BOOL bResult = FALSE;

	while (pcndev)
	{
		if (ProbePCNetNIC(pcndev))
		{
			//Any one successful probing will lead the whole function successfully.
			bResult = TRUE;
		}
		pcndev = pcndev->next;
	}
	return bResult;
}
static void PCNInterruptRxBody(pcnet_priv_t* pcndev)
{
	struct mbuf *m;
	int pktLen;
	char* rawPkt = NULL;
	
	struct ifnet* ifp = pcndev->ifp;
	rawPkt = pcnet_recv(pcndev, &pktLen);
	if (rawPkt == NULL)
		return;
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
	m->m_pkthdr.rcvif = ifp;
	m->m_pkthdr.len = m->m_len = pktLen;
	if(pktLen > MHLEN) {
		MCLGET(m, M_DONTWAIT);
		if((m->m_flags & M_EXT) == 0) {
			m_freem(m);
			//ar_eat_packet(sc, 1);
			return;
		}
	}
	
	memcpy(m->m_data, rawPkt, pktLen);
	printf("%s call if_input\n", __FUNCTION__);
	(*ifp->if_input)(ifp, m);
	
}
//Interrupt handler of PCNet.
static BOOL PCNetInterrupt(LPVOID lpESP, LPVOID lpParam)
{
	pcnet_priv_t* pcndev = (pcnet_priv_t*)lpParam;
	__U16 csr0 = 0;
	BOOL  bResult = FALSE;
	
	while((csr0 = pcnet_read_csr(pcndev, 0)) & (1 << 7))  //Check INTR bit of CSR0.
	{
		//_hx_printf("%s csr0 0x%x\n", __FUNCTION__, csr0);
		bResult = TRUE;  //Indicates the interrupt is processed.
		if (csr0 & (1 << 8)) //IDINT.
		{
			pcnet_ack_idint(pcndev);
			continue;
		}
		if (csr0 & (1 << 9)) //TINT.
		{
			pcnet_ack_sint(pcndev);
			continue;
		}
		if (csr0 & (1 << 10)) //RINT.
		{
			//Notify the ethernet core thread to launch a polling immediately.
			//EthernetManager.TriggerReceive(dev->pEthInt);
			PCNInterruptRxBody(pcndev);
			pcnet_ack_rint(pcndev);
			continue;
		}
		//Acknowledge all other interrupts.
		pcnet_write_csr(pcndev, 0, csr0);
		_hx_printf("Warning: Unhandled interrupt in PCNet NIC driver,CSR0 = 0x%X.\r\n", csr0);
	}
	return bResult;
}

//Initialize one PCNet NIC.
static BOOL InitPCNetNIC(pcnet_priv_t* pcndev)
{
	__PHYSICAL_DEVICE* pPhyDev = NULL;
	DWORD              dwCommand = 0;
	BOOL               bResult = FALSE;
	struct pcnet_uncached_priv* uc;
	int val, i;
	__U32 addr;
	unsigned char* rx_buff = NULL;

	if (NULL == pcndev)
	{
		goto __TERMINAL;
	}
	pPhyDev = pcndev->pPhyDev;
	
	//Set bus master and enable IO.
	dwCommand = PCNET_PCI_COMMAND_BMEN | PCNET_PCI_COMMAND_IOEN;
	if (!pPhyDev->WriteDeviceConfig(pPhyDev, PCI_CONFIG_OFFSET_COMMAND, dwCommand,2))
	{
#ifdef __PCNET_DEBUG
		_hx_printf("PCNet: Can not write command into PCI device.\r\n");
#endif
		goto __TERMINAL;
	}
	
	/* Switch pcnet to 32bit mode */
	pcnet_write_bcr(pcndev, 20, 2);
	/* Set/reset autoselect bit */
	val = pcnet_read_bcr(pcndev, 2) & ~2;
	val |= 2;
	pcnet_write_bcr(pcndev, 2, val);
	/* Enable auto negotiate, setup, disable fd */
	val = pcnet_read_bcr(pcndev, 32) & ~0x98;
	val |= 0x20;
	pcnet_write_bcr(pcndev, 32, val);
	
	/*
	* Enable NOUFLO on supported controllers, with the transmit
	* start point set to the full packet. This will cause entire
	* packets to be buffered by the ethernet controller before
	* transmission, eliminating underflows which are common on
	* slower devices. Controllers which do not support NOUFLO will
	* simply be left with a larger transmit FIFO threshold.
	*/
	val = pcnet_read_bcr(pcndev, 18);
	val |= 1 << 11;
	pcnet_write_bcr(pcndev, 18, val);
	val = pcnet_read_csr(pcndev, 80);
	val |= 0x3 << 10;
	pcnet_write_csr(pcndev, 80, val);

	//Install interrupt handler for current NIC.Please be noted that the actual
	//interrupt vector value should add INTERRUPT_VECTOR_BASE.
	if (pcndev->intVector && (pcndev->intVector < MAX_INTERRUPT_VECTOR - INTERRUPT_VECTOR_BASE))
	{
		pcndev->hInterrupt = ConnectInterrupt(
			PCNetInterrupt,
			pcndev,
			pcndev->intVector + INTERRUPT_VECTOR_BASE);
		if (NULL == pcndev->hInterrupt)  //Failed to create interrupt object.
		{
			goto __TERMINAL;
		}
		//Enable IDINT since it may triggered by the initialization process.
		//pcnet_enable_idint(dev, TRUE);
	}

	//Initializes the control block of the NIC,include Init Block,RX and TX rings.
	//It's a bit complicated caused by the alignment,which is required by the PCNet
	//controller that both Init Block and TX/RX ring must be aligned with 16 boundary.
	pcndev->uc = pcndev->uc_unalign = NULL;
	pcndev->rx_buf = pcndev->rx_buf_unalign = NULL;
#ifdef __CFG_SYS_VMM
	//Use virtual memory mechanism to implement the un-cached zone.
	uc = (struct pcnet_uncached_priv*)VirtualAlloc(
		NULL,sizeof(struct pcnet_uncached_priv) + 0x10,
		VIRTUAL_AREA_ALLOCATE_IOCOMMIT,
		VIRTUAL_AREA_ACCESS_RW,
		"PCNET_UNCACHE");
#ifdef __PCNET_DEBUG
	_hx_printf("PCNet: Allocate uc at va = 0x%0X,pa = 0x%0X\r\n", uc,PCI_TO_MEM_LE(uc,uc));
#endif
#else
	//Use normal memory with cache flushing mechanism to implement the un-cached
	//zone.
	uc = (struct pcnet_uncached_priv*)_hx_malloc(sizeof(struct pcnet_uncached_priv) + 0x10);
#endif
	if (NULL == uc)
	{
#ifdef __PCNET_DEBUG
		_hx_printf("PCNet: Allocate pcnet_uncached_priv failed.\r\n");
#endif
		goto __TERMINAL;
	}
#ifdef __PCNET_DEBUG
	_hx_printf("PCNet: Allocate uncached pcnet_uncached_priv at 0x%X.\r\n", uc);
#endif
	pcndev->uc_unalign = uc;
	//Align to 16.
	addr = (__U32)uc;
	addr = (addr + 0x0F) & ~0x0F;
	pcndev->uc = (struct pcnet_uncached_priv*)addr;

	//Allocate rx buffer.
	rx_buff = (unsigned char*)_hx_malloc(sizeof(*pcndev->rx_buf) + 0x10);
	if (NULL == rx_buff)
	{
#ifdef __PCNET_DEBUG
		_hx_printf("PCNet: Can not allocate memory for rx_buff.\r\n");
#endif
		goto __TERMINAL;
	}
	pcndev->rx_buf_unalign = rx_buff;
	//Align to 16.
	addr = (__U32)rx_buff;
	addr = (addr + 0x0F) & ~0x0F;
	pcndev->rx_buf = (unsigned char*)addr;

	uc = pcndev->uc;
	//Initialize Init Block.
	uc->init_block.mode = cpu_to_le16(0x0000);
	uc->init_block.filter[0] = 0x00000000;
	uc->init_block.filter[1] = 0x00000000;
	
	/*
	* Initialize the Rx ring.
	*/
	pcndev->cur_rx = 0;
	for (i = 0; i < RX_RING_SIZE; i++) {
		uc->rx_ring[i].base = (__U32)PCI_TO_MEM_LE(dev, (*pcndev->rx_buf)[i]);
		uc->rx_ring[i].buf_length = cpu_to_le16(-PKT_BUF_SZ);
		uc->rx_ring[i].status = cpu_to_le16(0x8000);
#ifdef __PCNET_DEBUG
			_hx_printf("PCNet: Rx%d: base=0x%x buf_length=0x%x status=0x%x\r\n", i,
				uc->rx_ring[i].base, uc->rx_ring[i].buf_length,
				uc->rx_ring[i].status);
#endif
	}
	
	/*
	* Initialize the Tx ring. The Tx buffer address is filled in as
	* needed, but we do need to clear the upper ownership bit.
	*/
	pcndev->cur_tx = 0;
	for (i = 0; i < TX_RING_SIZE; i++) {
		uc->tx_ring[i].base = 0;
		uc->tx_ring[i].status = 0;
	}

	/*
	* Setup Init Block.
	*/
#ifdef __PCNET_DEBUG
	_hx_printf("PCNet: Init block at 0x%p: MAC.\r\n", &dev->uc->init_block);
#endif
	for (i = 0; i < 6; i++) {
		pcndev->uc->init_block.phys_addr[i] = pcndev->macAddr[i];
	}
	uc->init_block.tlen_rlen = cpu_to_le16(TX_RING_LEN_BITS | RX_RING_LEN_BITS);
	uc->init_block.rx_ring = (__U32)PCI_TO_MEM_LE(pcndev, uc->rx_ring);
	uc->init_block.tx_ring = (__U32)PCI_TO_MEM_LE(pcndev, uc->tx_ring);
	
	/*
	* Tell the controller where the Init Block is located.
	*/
	__BARRIER();
#if !defined(__CFG_SYS_VMM)
	//Use cache flushing to guarantee the memory synchronization
	__FLUSH_CACHE(uc, sizeof(*uc), CACHE_FLUSH_WRITEBACK);
#endif
	addr = (__U32)PCI_TO_MEM_LE(pcndev, &pcndev->uc->init_block);
	pcnet_write_csr(pcndev, 1, addr & 0xffff);
	pcnet_write_csr(pcndev, 2, (addr >> 16) & 0xffff);
	
	pcnet_write_csr(pcndev, 4, 0x0915);
	pcnet_write_csr(pcndev, 0, 0x0001);        /* start */

	/* Wait for Init Done bit */
	for (i = 10000; i > 0; i--) {
		if (pcnet_read_csr(pcndev, 0) & 0x0100)
		{
			break;
		}
		__MicroDelay(10);
	}
	if (i <= 0) {
		_hx_printf("PCNet: Init timeout,controller init failed\r\n");
		pcnet_reset(pcndev);
		goto __TERMINAL;
	}
	/*
	* Finally start network controller operation.
	*/
	pcnet_write_csr(pcndev, 0, 0x0002);
#ifdef __PCNET_DEBUG
	_hx_printf("PCNet: Initialize NIC successfully.\r\n");
#endif
	bResult = TRUE;

__TERMINAL:
	if (!bResult)  //Release resource.
	{
		if (pcndev->uc_unalign)
		{
#ifdef __CFG_SYS_VMM
			VirtualFree(pcndev->uc_unalign);
#else
			_hx_free(dev->uc_unalign);
#endif
		}
		if (pcndev->rx_buf_unalign)
		{
			_hx_free(pcndev->rx_buf_unalign);
		}
		if (pcndev->hInterrupt)
		{
			DisconnectInterrupt(pcndev->hInterrupt);
		}
		pcndev->available = 0;  //Set as unavailable.
	}
	return bResult;
}
void
pcn_init(void *arg)
{
    pcnet_priv_t *adapter = arg;

    
}
/*********************************************************************
 *  Ioctl entry point
 *
 *  em_ioctl is called when the user wants to configure the
 *  interface.
 *
 *  return 0 on success, positive on failure
 **********************************************************************/

int
pcn_ioctl(struct ifnet *ifp, u_long command, caddr_t data)
{
    pcnet_priv_t	*adapter = ifp->if_softc;
    struct ifreq *ifr = (struct ifreq *)data;
#ifdef INET
    struct ifaddr *ifa = (struct ifaddr *)data;
#endif
    int error = 0;

   /* if (adapter->in_detach)
        return (error);
*/
    switch (command)
    {
    case SIOCSIFADDR:
#ifdef INET
        if (ifa->ifa_addr->sa_family == AF_INET)
        {
            printf("%s:%d AF_INET\n", __FUNCTION__, __LINE__);
            /*
             * XXX
             * Since resetting hardware takes a very long time
             * and results in link renegotiation we only
             * initialize the hardware only when it is absolutely
             * required.
             */
            ifp->if_flags |= IFF_UP;
            //if (!(ifp->if_drv_flags & IFF_DRV_RUNNING)) {
            //EM_CORE_LOCK(adapter);
            pcn_init(adapter);
            //EM_CORE_UNLOCK(adapter);
            //}
            arp_ifinit(ifp, ifa);
        }
        else
#endif
            error = ether_ioctl(ifp, command, data);
        break;
    case SIOCSIFMTU:
    {
        int max_frame_size;

        //IOCTL_DEBUGOUT("ioctl rcv'd: SIOCSIFMTU (Set Interface MTU)");

        //EM_CORE_LOCK(adapter);
        /*switch (adapter->hw.mac.type)
        {
        case e1000_82542:
            max_frame_size = ETHER_MAX_LEN;
            break;
        default:
            max_frame_size = MAX_JUMBO_FRAME_SIZE;
        }*/
        if (ifr->ifr_mtu > max_frame_size - ETHER_HDR_LEN -
                ETHER_CRC_LEN)
        {
            //EM_CORE_UNLOCK(adapter);
            error = EINVAL;
            break;
        }

        ifp->if_mtu = ifr->ifr_mtu;
        /*adapter->max_frame_size =
            ifp->if_mtu + ETHER_HDR_LEN + ETHER_CRC_LEN;
        lem_init_locked(adapter);*/
        //EM_CORE_UNLOCK(adapter);
        break;
    }
    case SIOCSIFFLAGS:
        //IOCTL_DEBUGOUT("ioctl rcv'd:\
		//    SIOCSIFFLAGS (Set Interface Flags)");
        //EM_CORE_LOCK(adapter);
        if (ifp->if_flags & IFF_UP)
        {
            /*if ((ifp->if_drv_flags & IFF_DRV_RUNNING)) {
            	if ((ifp->if_flags ^ adapter->if_flags) &
            	    (IFF_PROMISC | IFF_ALLMULTI)) {
            		lem_disable_promisc(adapter);
            		lem_set_promisc(adapter);
            	}
            } else
            	lem_init_locked(adapter);*/
        }
        else
            /*if (ifp->if_drv_flags & IFF_DRV_RUNNING) {
            	EM_TX_LOCK(adapter);
            	lem_stop(adapter);
            	EM_TX_UNLOCK(adapter);
            }*/
            //adapter->if_flags = ifp->if_flags;
        //EM_CORE_UNLOCK(adapter);
        break;
    case SIOCADDMULTI:
    case SIOCDELMULTI:
        //IOCTL_DEBUGOUT("ioctl rcv'd: SIOC(ADD|DEL)MULTI");
        /*if (ifp->if_drv_flags & IFF_DRV_RUNNING) {
        	EM_CORE_LOCK(adapter);
        	lem_disable_intr(adapter);
        	lem_set_multi(adapter);
        	if (adapter->hw.mac.type == e1000_82542 &&
        		    adapter->hw.revision_id == E1000_REVISION_2) {
        		lem_initialize_receive_unit(adapter);
        	}
        #ifdef DEVICE_POLLING
        	if (!(ifp->if_capenable & IFCAP_POLLING))
        #endif
        		lem_enable_intr(adapter);
        	EM_CORE_UNLOCK(adapter);
        }*/
        break;
    case SIOCSIFMEDIA:
        /* Check SOL/IDER usage */
        //EM_CORE_LOCK(adapter);
        /*if (e1000_check_reset_block(&adapter->hw))
        {
            EM_CORE_UNLOCK(adapter);
            device_printf(adapter->dev, "Media change is"
                          " blocked due to SOL/IDER session.\n");
            break;
        }*/
        //EM_CORE_UNLOCK(adapter);
    case SIOCGIFMEDIA:
        //IOCTL_DEBUGOUT("ioctl rcv'd: \
		//    SIOCxIFMEDIA (Get/Set Interface Media)");
        //error = ifmedia_ioctl(ifp, ifr, &adapter->media, command);
        break;
    case SIOCSIFCAP:
    {
        int mask, reinit;

        //IOCTL_DEBUGOUT("ioctl rcv'd: SIOCSIFCAP (Set Capabilities)");
        reinit = 0;
        mask = ifr->ifr_reqcap ^ ifp->if_capenable;
        if (mask & IFCAP_HWCSUM)
        {
            ifp->if_capenable ^= IFCAP_HWCSUM;
            reinit = 1;
        }
        if (mask & IFCAP_VLAN_HWTAGGING)
        {
            ifp->if_capenable ^= IFCAP_VLAN_HWTAGGING;
            reinit = 1;
        }
        if ((mask & IFCAP_WOL) &&
                (ifp->if_capabilities & IFCAP_WOL) != 0)
        {
            if (mask & IFCAP_WOL_MCAST)
                ifp->if_capenable ^= IFCAP_WOL_MCAST;
            if (mask & IFCAP_WOL_MAGIC)
                ifp->if_capenable ^= IFCAP_WOL_MAGIC;
        }
        //if (reinit && (ifp->if_drv_flags & IFF_DRV_RUNNING))
        pcn_init(adapter);
        //VLAN_CAPABILITIES(ifp);
        break;
    }

    default:
        error = ether_ioctl(ifp, command, data);
        break;
    }

    return (error);
}
static char _send_buff[2048] = {0};
void
pcn_start(struct ifnet *ifp)
{
    pcnet_priv_t *adapter = ifp->if_softc;
    struct mbuf	*m_head;
    int pos = 0;
    IFQ_DRV_DEQUEUE(&ifp->if_snd, m_head);
	if (m_head == NULL)
	  	return;
	for (; m_head != NULL && (m_head->m_data != 0); m_head = m_head->m_next) /*pChunk->mBlkHdr.m_next*/
    {
        int len = 0;
        /* if this cluster is empty  */
        if (m_head->m_len <= 0)
            continue;
        /* get fragment length */
        len = m_head->m_len;
        
        bcopy(m_head->m_data, &_send_buff[pos], len);
        pos += len;
	}
	printf("%s call pcnet_send %d\n", __FUNCTION__, pos);
	pcnet_send(adapter, _send_buff, pos);
    //EM_TX_LOCK(adapter);
    //if (ifp->if_drv_flags & IFF_DRV_RUNNING)
    //lem_start_locked(ifp);
    //EM_TX_UNLOCK(adapter);
}

/*********************************************************************
 *
 *  Setup networking device structure and register an interface.
 *
 **********************************************************************/
int
pcn_ifattach(device_t dev, pcnet_priv_t *adapter)
{
    struct ifnet   *ifp;

    
    ifp = adapter->ifp = if_alloc(IFT_ETHER);
    if (ifp == NULL)
    {
        device_printf(dev, "can not allocate ifnet structure\n");
        return (-1);
    }
    if_initname(ifp, device_get_name(dev), device_get_unit(dev));
	
    ifp->if_mtu = ETHERMTU;
    ifp->if_init =  pcn_init;
    ifp->if_softc = adapter;
    ifp->if_flags = IFF_BROADCAST | IFF_SIMPLEX | IFF_MULTICAST;
    ifp->if_ioctl = pcn_ioctl;
    ifp->if_start = pcn_start;
    //IFQ_SET_MAXLEN(&ifp->if_snd, adapter->num_tx_desc - 1);
    //ifp->if_snd.ifq_drv_maxlen = adapter->num_tx_desc - 1;
    IFQ_SET_READY(&ifp->if_snd);
	
    ether_ifattach(ifp, adapter->macAddr);
    if_check(NULL);
	ifp->if_flags |= (IFF_UP | IFF_RUNNING);
    return (0);
}

//Initialie all PCNet NICs in system.
static BOOL InitPCNetNICs(device_t dev)
{
	pcnet_priv_t* pcndev = lp;
	BOOL bResult = FALSE;

	while (pcndev)
	{
		if (InitPCNetNIC(pcndev))
		{
			//Any one successful probing will lead the whole function successfully.
			pcn_ifattach(dev, pcndev);
			bResult = TRUE;
		}
		pcndev = pcndev->next;
	}
	return bResult;
}

//Send a packet through the PCNet NIC.
static int pcnet_send(pcnet_priv_t *pcndev, void *packet, int pkt_len)
{
	int i, status;
	__U16 csr0;
	struct pcnet_tx_head *entry = &pcndev->uc->tx_ring[pcndev->cur_tx];

#ifdef __PCNET_DEBUG
	_hx_printf("Tx%d: %d bytes from 0x%p.\r\n", pcndev->cur_tx, pkt_len,packet);
#endif

	//Synchronize cache to memory.
	__FLUSH_CACHE(packet, pkt_len, CACHE_FLUSH_WRITEBACK);

	/* Wait for completion by testing the OWN bit */
	for (i = 1000; i > 0; i--) {
#if !defined(__CFG_SYS_VMM)
		__FLUSH_CACHE(&entry->status, sizeof(entry_status), CACHE_FLUSH_INVALIDATE);
#endif
		status = __readw(&entry->status);
		if ((status & 0x8000) == 0)
		{
			break;
		}
		__MicroDelay(100);
#ifdef __PCNET_DEBUG
		_hx_printf(".");
#endif
	}
	if (i <= 0) {
		_hx_printf("PCNet: TIMEOUT: Tx%d failed (status = 0x%x).\r\n",pcndev->cur_tx, status);
		pkt_len = 0;
		goto failure;
	}

	/*
	* Setup Tx ring. Caution: the write order is important here,
	* set the status with the "ownership" bits last.
	*/
	__writew(-pkt_len, &entry->length);
	__writel(0, &entry->misc);
	__writel(PCI_TO_MEM_LE(pcndev, packet), &entry->base);
	__writew(0x8300, &entry->status);
#if !defined(__CFG_SYS_VMM)
	__FLUSH_CACHE(&entry, sizeof(entry), CACHE_FLUSH_WRITEBACK);
#endif
	
	/* Trigger an immediate send poll. We should retrieve the CSR0 register and then
	   Set the poll demand bit instead by writting 0x0008 directly,which will lead
	   the NIC disabling all interrupts. */
	csr0 = pcnet_read_csr(pcndev, 0);
	csr0 |= 0x0008;
	pcnet_write_csr(pcndev, 0, csr0);

failure:
	if (++pcndev->cur_tx >= TX_RING_SIZE)
	{
		pcndev->cur_tx = 0;
	}
#ifdef __PCNET_DEBUG
	_hx_printf("Send done.\r\n");
#endif
	return pkt_len;
}

//Receive a packet from PCNet NIC,it maybe called by the polling process
//of HelloX's network framework.
static unsigned char* pcnet_recv(pcnet_priv_t *pcndev,int* pPktLen)
{
	struct pcnet_rx_head *entry;
	unsigned char *buf = NULL;
	int pkt_len = 0;
	__U16 status, err_status;
	
	while (1) {
		entry = &pcndev->uc->rx_ring[pcndev->cur_rx];
		
		/*
		* If we own the next entry, it's a new packet. Send it up.
		*/
#if !defined(__CFG_SYS_VMM)
		__FLUSH_CACHE(&entry->status, sizeof(entry->status), CACHE_FLUSH_INVALIDATE);
#endif
		status = __readw(&entry->status);
		if ((status & 0x8000) != 0)
		{
			break;
		}
		err_status = status >> 8;
		
		if (err_status != 0x03) {       /* There was an error. */
			_hx_printf("PCNet: Rx%d", pcndev->cur_rx);
#ifdef __PCNET_DEBUG
			_hx_printf(" (status=0x%x)", err_status);
#endif
			if (err_status & 0x20)
				_hx_printf(" Frame");
			if (err_status & 0x10)
				_hx_printf(" Overflow");
			if (err_status & 0x08)
				_hx_printf(" CRC");
			if (err_status & 0x04)
				_hx_printf(" Fifo");
			_hx_printf(" Error\r\n");
			status &= 0x03ff;
		}
		else {
			pkt_len = (__readl(&entry->msg_length) & 0xfff) - 4;
				if (pkt_len < 60) {
					_hx_printf("PCNet: Rx%d: invalid packet length %d\r\n",
						pcndev->cur_rx, pkt_len);
				}
				else {
					buf = (*pcndev->rx_buf)[pcndev->cur_rx];
					__FLUSH_CACHE(buf, buf + pkt_len, CACHE_FLUSH_INVALIDATE);
					//NetReceive(buf, pkt_len);
#ifdef __PCNET_DEBUG
					_hx_printf("PCNet: Rx%d: %d bytes from 0x%p\r\n",
						pcndev->cur_rx, pkt_len, buf);
#endif
				}
		}
		status |= 0x8000;
		__writew(status, &entry->status);
        if (++pcndev->cur_rx >= RX_RING_SIZE)
				pcndev->cur_rx = 0;

		if (buf)  //Received a packet,return it.
		{
			goto __TERMINAL;
		}
	}
__TERMINAL:
	if (pPktLen)
	{
		*pPktLen = pkt_len;  //Return the packet's length.
	}
	return buf;
}

//Initializer of the ethernet interface,it will be called by HelloX's ethernet framework.
//No need to specify it if no customized requirement.
//static BOOL Ethernet_Int_Init(__ETHERNET_INTERFACE* pInt)
//{
//	return TRUE;
//}

//Control functions of the ethernet interface.Some special operations,such as
//scaninn or association in WLAN,should be implemented in this routine,since they
//are not common operations for Ethernet.
//static BOOL Ethernet_Ctrl(__ETHERNET_INTERFACE* pInt, DWORD dwOperation, LPVOID pData)
//{
//	return TRUE;
//}

//Send a ethernet frame out through Marvell wifi interface.The frame's content is in pInt's
//send buffer.
//static BOOL Ethernet_SendFrame(__ETHERNET_INTERFACE* pInt)
//{
//	BOOL          bResult = FALSE;
//	pcnet_priv_t* dev = NULL;
//
//	if (NULL == pInt)
//	{
//		goto __TERMINAL;
//	}
//	if ((0 == pInt->buffSize) || (pInt->buffSize > ETH_DEFAULT_MTU))  //No data to send or exceed the MTU.
//	{
//		goto __TERMINAL;
//	}
//
//	//Invoke sending routine of NIC to do actual transmition.
//	dev = pInt->pIntExtension;
//	if (0 == pcnet_send(dev, pInt->SendBuff, pInt->buffSize))
//	{
//		goto __TERMINAL;
//	}
//	bResult = TRUE;
//
//__TERMINAL:
//	return bResult;
//}

/**
*
* Receive a frame from ehternet link.
* Should allocate a pbuf and transfer the bytes of the incoming
* packet from the interface into the pbuf.
*
*/
//static struct pbuf* Ethernet_RecvFrame(__ETHERNET_INTERFACE* pInt)
//{
//
//	struct pbuf    *p  = NULL;
//	struct pbuf    *q  = NULL;
//	int            len = 0;
//	pcnet_priv_t*  dev = NULL;
//	unsigned char* buf = NULL;
//
//	if (NULL == pInt)
//	{
//		return NULL;
//	}
//	dev = (pcnet_priv_t*)pInt->pIntExtension;
//	if (NULL == dev)
//	{
//		return NULL;
//	}
//
//	buf = pcnet_recv(dev, &len);
//	if (!buf)  //No packet received.
//	{
//		return NULL;
//	}
//
//	//Received a pakcet,delivery it to IP stack.
//	if (len > 0)
//	{
//		int      l = 0;
//
//		/* We allocate a pbuf chain of pbufs from the pool. */
//		p = pbuf_alloc(PBUF_RAW, len, PBUF_POOL);
//		if (p != NULL)
//		{
//			for (q = p; q != NULL; q = q->next)
//			{
//				memcpy((u8_t*)q->payload, buf, q->len);
//				l = l + q->len;
//			}
//		}
//		else
//		{
//#ifdef __PCNET_DEBUG
//			_hx_printf("PCNet: Allocate pbuf failed in RecvFrame.\r\n");
//#endif
//		}
//	}
//	return p;
//}

//Initializer of the PCNet Ethernet Driver,it's a global function and is called
//by Ethernet Manager in process of initialization.
BOOL PCNet_Drv_Initialize(LPVOID pData)
{
	//__ETHERNET_INTERFACE* pNetInt = NULL;
	char strEthName[64];
	pcnet_priv_t* pcndev = lp;
	device_t dev;
	int index = 0;
	BOOL bResult = FALSE;
	
	BISStartup();
	dev = (device_t)malloc(sizeof(*dev));
	memset(dev, 0, sizeof(*dev));
	//memset(softc, 0, sizeof(struct adapter));
	dev->name = "pcn";//(char*)ENUML_DEV_NAME;
	dev->unit = 0;
	dev->softc = pcndev;
			//dev->phyDev = pDev;
#ifdef __PCNET_DEBUG
	_hx_printf("\r\n");  //Start a new line.
#endif

	//Enumerate all PCNet NIC device(s) in system.
	if (!EnumPCNet_NIC())
	{
#ifdef __PCNET_DEBUG
		_hx_printf("PCNet: Can not enumerate PCNet NIC device.\r\n");
#endif
		goto __TERMINAL;
	}

	//Probe all PCNet NICs.
	if (!ProbePCNetNICs())
	{
#ifdef __PCNET_DEBUG
		_hx_printf("PCNet: Probe NIC failed.\r\n");
#endif
		goto __TERMINAL;
	}

	//Initialize all NICs in system.
	if (!InitPCNetNICs(dev))
	{
#ifdef __PCNET_DEBUG
		_hx_printf("PCNet: Initialize NICs failed.\r\n");
#endif
		goto __TERMINAL;
	}

	//Show all NICs in system.
//#ifdef __PCNET_DEBUG
	ShowAllNICs();
//#endif
#if 0
	//Register the ethernet interface to HelloX's network framework.
	dev = lp;
	index = 0;
	while (dev)
	{
		//Skip the NICs that is not available.
		if (!dev->available)
		{
			dev = dev->next;
			index ++;
			continue;
		}

		//Construct interface's name.
		_hx_sprintf(strEthName, PCNET_INT_NAME, index);
		dev->pEthInt = EthernetManager.AddEthernetInterface(
			strEthName,
			dev->macAddr,
			(LPVOID)dev,
			Ethernet_Int_Init,
			Ethernet_SendFrame,
			Ethernet_RecvFrame,
			Ethernet_Ctrl);
		if (NULL == dev->pEthInt)
		{
#ifdef __PCNET_DEBUG
			_hx_printf("PCNet: Add Ethernet Interface failid[index = %d].\r\n",index);
#endif
			//Mark the structure as unavailable,it will be released later.
			dev->available = 0;
		}
		//Process next one.
		dev = dev->next;
		index ++;
	}
#endif
	//Enable all interrupts of ALL NICs in system.
	EnableAllInterrupt();
	BISConfig();
	//Mark the driver loading process is successful.
	bResult = TRUE;

__TERMINAL:
	return bResult;
}
