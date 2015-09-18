

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
#include "if_vlan_var.h"
#include "if_media.h"
#include "e1000_api.h"
#include "if_lem.h"
#include "pcireg.h"
#include "pcivar.h"
#include "mbuf.h"
#include "bsdip.h"
#include "bsdtcp.h"
#include "bsdudp.h"
//#include "ips_config.h"
//#include "ip_osal.h"
#ifndef __STDAFX_H__
#include "..\INCLUDE\STDAFX.H"
#endif

#ifndef __KAPI_H__
#include "..\INCLUDE\KAPI.H"
#endif
#define EM_INT_VECTOR 0xa
//Global variables used by this module.
static HANDLE g_hE1kIntHandler = NULL;     //Interrupt object handle,to preserve
//the interrupt object.
static device_t EnumE1000_NIC();
static char lem_strings[] =
{
    "Intel(R) PRO/1000 Legacy Network Connection"
};
/*********************************************************************
 *  Legacy Em Driver version:
 *********************************************************************/
char lem_driver_version[] = "1.0.3";



//Unload entry for MOUSE driver.
static DWORD E1000Destroy(__COMMON_OBJECT *lpDriver,
                          __COMMON_OBJECT *lpDevice,
                          __DRCB          *lpDrcb)
{
    DisconnectInterrupt(g_hE1kIntHandler);  //Release key board interrupt.
    return 0;
}

//Interrupt handler of MOUSE.
static BOOL E1000IntHandler(LPVOID pParam, LPVOID pEsp)
{
    static BYTE MsgCount    = 0;
    static WORD x           = 0;
    static BOOL xpostive    = TRUE;   //True if x scale is postive.
    static WORD y           = 0;
    static BOOL ypostive    = TRUE;   //True if y scale is postive.
    static BOOL bLDPrev     = FALSE;  //Left button previous status,TRUE if down.
    static BOOL bRDPrev     = FALSE;  //Right button previous status,TRUE if down.
    static BOOL bLDCurr     = FALSE;  //Current left button status,TRUE if down.
    static BOOL bRDCurr     = FALSE;  //Current Right button status,TRUE if down.
    static BOOL bHasLDown   = FALSE;  //Left button has down before this down status.
    static BOOL bHasRDown   = FALSE;
    static DWORD dwTickCount = 0;
    __DEVICE_MESSAGE dmsg;
    UCHAR  data;

    _hx_printf("enter %s\n", __FUNCTION__);
    return TRUE;
}
static device_t EnumE1000_NIC()
{
	__PHYSICAL_DEVICE*    pDev   = NULL;
	__IDENTIFIER          devId;
	__U16                 iobase = 0;
	LPVOID                memAddr = NULL;
	int                   intVector = 0;
	int                   index = 0;
	BOOL                  bResult = FALSE;
	device_t 			  dev = NULL;
	//Set device ID accordingly.
	// { 0x8086, E1000_DEV_ID_82540EM,		PCI_ANY_ID, PCI_ANY_ID, 0},
	devId.dwBusType                     = BUS_TYPE_PCI;
	devId.Bus_ID.PCI_Identifier.ucMask  = PCI_IDENTIFIER_MASK_VENDOR | PCI_IDENTIFIER_MASK_DEVICE;
	devId.Bus_ID.PCI_Identifier.wVendor = 0x8086;
	devId.Bus_ID.PCI_Identifier.wDevice = E1000_DEV_ID_82540EM;

	//Try to fetch the physical device with the specified ID.
	pDev = DeviceManager.GetDevice(
		&DeviceManager,
		BUS_TYPE_PCI,
		&devId,
		NULL);
	if (NULL == pDev)  //PCNet may not exist.
	{
		_hx_printf("EnumE1000_NIC: Can not get any e1000 device in system.\r\n");

		return NULL;
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
		printf("intVector=%d, iobase=0x%x, memAddr=0x%x\n", intVector, iobase, memAddr);
		//Check if the device with valid resource.
		if ((0 == intVector) && (0 == iobase))
		{
			_hx_printf("EnumE1000_NIC: Find a device without valid resource.\r\n");
			break;  //Continue to process next device.
		}
		else {
			struct adapter *softc = (struct adapter *)malloc(sizeof(*softc));
			dev = (device_t)malloc(sizeof(*dev));
			memset(dev, 0, sizeof(*dev));
			memset(softc, 0, sizeof(struct adapter));
			dev->name = "pcn";//(char*)ENUML_DEV_NAME;
			dev->unit = 0;
			dev->softc = softc;
			dev->phyDev = pDev;
			dev->desc = (char *)malloc(strlen(lem_strings) + strlen(lem_driver_version) + 2);
			sprintf(dev->desc, "%s %s",
					lem_strings,
					lem_driver_version);
			break;
		}
	}
	return dev;

__TERMINAL:
	if (!bResult)
	{

		//May release resource,such as pcnet_priv_t structures here.
	}
	return NULL;
}

//Main entry point of E1000 driver.
BOOL E1000_Drv_Initialize(__DRIVER_OBJECT *lpDriverObject)
{
    __DEVICE_OBJECT  *lpDevObject = NULL;
    BOOL              bResult     = FALSE;
    device_t          dev = NULL;
	BISStartup();
	if ((dev = EnumE1000_NIC()) == NULL)
		return FALSE;
	
    lem_attach(dev);
    BISConfig();
    //test_ping("192.168.56.1");
    return TRUE;
}

