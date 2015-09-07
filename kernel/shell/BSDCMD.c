//***********************************************************************/
//    Author                    : Luoyu
//    Original Date             : Sep 7,2015
//    Module Name               : BSDCMD.c
//    Module Funciton           : 
//    Description               : 
//                                Network diagnostic application,common used
//                                network tools such as ping/tracert,are implemented
//                                in network.c file.
//    Last modified Author      :
//    Last modified Date        : 
//    Last modified Content     :
//                                1.
//                                2.
//    Lines number              :
//    Extra comment             : 
//***********************************************************************/

#ifndef __STDAFX_H__
#include "../INCLUDE/StdAfx.h"
#endif

#include "shell.h"



#include "BSDCMD.h"
#include "string.h"
#include "stdio.h"

#define  BSDSTACK_PROMPT_STR   "[bsdcmd_view]"

//
//Pre-declare routines.
//
static DWORD CommandParser(LPCSTR);
static DWORD help(__CMD_PARA_OBJ*);        //help sub-command's handler.
static DWORD _exit(__CMD_PARA_OBJ*);        //exit sub-command's handler.
static DWORD bsdping(__CMD_PARA_OBJ*);
static DWORD bsdrouteshow(__CMD_PARA_OBJ*);

//
//The following is a map between command and it's handler.
//
static struct __FDISK_CMD_MAP{
	LPSTR                lpszCommand;
	DWORD                (*CommandHandler)(__CMD_PARA_OBJ*);
	LPSTR                lpszHelpInfo;
}BsdStackCmdMap[] = {
	
	{"ping",       bsdping,    "  ping     : Check a specified host's reachbility."},
	{"routeshow",  bsdrouteshow,   "  routeshow: Show all route entry."},
	{"exit",       _exit,      "  exit     : Exit the application."},
	{"help",       help,      "  help     : Print out this screen."},
 
	{NULL,		   NULL,      NULL}
};


static DWORD QueryCmdName(LPSTR pMatchBuf,INT nBufLen)
{
	static DWORD dwIndex = 0;

	if(pMatchBuf == NULL)
	{
		dwIndex    = 0;	
		return SHELL_QUERY_CONTINUE;
	}

	if(NULL == BsdStackCmdMap[dwIndex].lpszCommand)
	{
		dwIndex = 0;
		return SHELL_QUERY_CANCEL;	
	}

	strncpy(pMatchBuf,BsdStackCmdMap[dwIndex].lpszCommand,nBufLen);
	dwIndex ++;

	return SHELL_QUERY_CONTINUE;	
}

//
//The following routine processes the input command string.
//
static DWORD CommandParser(LPCSTR lpszCmdLine)
{
	DWORD                  dwRetVal          = SHELL_CMD_PARSER_INVALID;
	DWORD                  dwIndex           = 0;
	__CMD_PARA_OBJ*        lpCmdParamObj     = NULL;

	if((NULL == lpszCmdLine) || (0 == lpszCmdLine[0]))    //Parameter check
	{
		return SHELL_CMD_PARSER_INVALID;
	}

	lpCmdParamObj = FormParameterObj(lpszCmdLine);
	
	
	if(NULL == lpCmdParamObj)    //Can not form a valid command parameter object.
	{
		return SHELL_CMD_PARSER_FAILED;
	}

	//if(0 == lpCmdParamObj->byParameterNum)  //There is not any parameter.
	//{
	//	return SHELL_CMD_PARSER_FAILED;
	//}
	//CD_PrintString(lpCmdParamObj->Parameter[0],TRUE);

	//
	//The following code looks up the command map,to find the correct handler that handle
	//the current command.Calls the corresponding command handler if found,otherwise SYS_DIAG_CMD_PARSER_INVALID
	//will be returned to indicate this case.
	//
	while(TRUE)
	{
		if(NULL == BsdStackCmdMap[dwIndex].lpszCommand)
		{
			dwRetVal = SHELL_CMD_PARSER_INVALID;
			break;
		}
		if(StrCmp(BsdStackCmdMap[dwIndex].lpszCommand,lpCmdParamObj->Parameter[0]))  //Find the handler.
		{
			dwRetVal = BsdStackCmdMap[dwIndex].CommandHandler(lpCmdParamObj);
			break;
		}
		else
		{
			dwIndex ++;
		}
	}

	//Release parameter object.
	if(NULL != lpCmdParamObj)
	{
		ReleaseParameterObj(lpCmdParamObj);
	}

	return dwRetVal;
}

//
//This is the application's entry point.
//
DWORD BsdStackCmdEntry(LPVOID p)
{
	return Shell_Msg_Loop(BSDSTACK_PROMPT_STR,CommandParser,QueryCmdName);	
}

//
//The exit command's handler.
//
static DWORD _exit(__CMD_PARA_OBJ* lpCmdObj)
{
	return SHELL_CMD_PARSER_TERMINAL;
}

//
//The help command's handler.
//
static DWORD help(__CMD_PARA_OBJ* lpCmdObj)
{
	DWORD               dwIndex = 0;

	while(TRUE)
	{
		if(NULL == BsdStackCmdMap[dwIndex].lpszHelpInfo)
			break;

		PrintLine(BsdStackCmdMap[dwIndex].lpszHelpInfo);
		dwIndex ++;
	}
	return SHELL_CMD_PARSER_SUCCESS;
}

//route command's implementation.
static DWORD bsdrouteshow(__CMD_PARA_OBJ* lpCmdObj)
{
	show_route_statistic();
	return SHELL_CMD_PARSER_SUCCESS;
}

//ping command's implementation.
static DWORD bsdping(__CMD_PARA_OBJ* lpCmdObj)
{	
	__PING_PARAM     PingParam;
	struct in_addr        ipAddr;
	int              count      = 3;    //Ping counter.
	int              size       = 64;   //Ping packet size.
	BYTE             index      = 1;
	DWORD            dwRetVal   = SHELL_CMD_PARSER_FAILED;
	__CMD_PARA_OBJ*  pCurCmdObj = lpCmdObj;
	int 			 addrIdx 	 = 0;

	if(pCurCmdObj->byParameterNum <= 1)
	{
		return dwRetVal;
	}

	while(index < lpCmdObj->byParameterNum)
	{
		if(strcmp(pCurCmdObj->Parameter[index],"-c") == 0)
		{
			index ++;
			if(index >= lpCmdObj->byParameterNum)
			{
				break;
			}
			count    = atoi(pCurCmdObj->Parameter[index]);
		}
		else if(strcmp(pCurCmdObj->Parameter[index],"-s") == 0)
		{
			index ++;
			if(index >= lpCmdObj->byParameterNum)
			{
				break;
			}
			size   = atoi(pCurCmdObj->Parameter[index]);
		}
		else
		{
			ipAddr.s_addr = bsd_inet_addr(pCurCmdObj->Parameter[index]);
			addrIdx = index;
		}
		_hx_printf("%s\n", pCurCmdObj->Parameter[index]);
		index ++;
	}
	
	if(ipAddr.s_addr != 0)
	{
		dwRetVal    = SHELL_CMD_PARSER_SUCCESS;
	}

	PingParam.count      = count;
	PingParam.targetAddr = ipAddr;
	PingParam.size       = size;

	//Call ping entry routine.
	test_ping(pCurCmdObj->Parameter[addrIdx]);
	
	return dwRetVal;
}

