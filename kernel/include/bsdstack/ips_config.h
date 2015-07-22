/********************************************************/
/****************** AUTHOR LUOYU ************************/
/********************************************************/
#ifndef INCLUDE_CONFIG_IPS_FILE
#define INCLUDE_CONFIG_IPS_FILE
#include "sys.h"


typedef struct  _tagIPS_CFG_IFA
{
    struct _tagIPS_CFG_IFA * next;
	char *ifName;
	int index;
	char *mac;
	int numOfIp;
	char *ipaddr;
	int ipmask;
	unsigned short dev_send_port;
	unsigned short dev_recv_port;
	/* the following is not contained in xml file */
	int halDevSendHandler;
	int halDevRecvHandler;
	int* dev_p;
}IPS_CFG_IFA;
typedef struct _tagIPS_Config
{
	int numOfIf;
	IPS_CFG_IFA *ifa;
}IPS_CONFIG;
typedef struct _tagIPS_TEST
{
	struct 
	{
	int enable;
	unsigned char* dstAddr;
	int role;
	unsigned short port;
	}tcp;
}IPS_TEST;
typedef struct _tagIPS_All
{
	IPS_CONFIG config;
	//IPS_TEST test;
}IPS_ALL;


int BISConfig();


#endif

