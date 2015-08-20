/********************************************************/
/****************** AUTHOR LUOYU ************************/
/********************************************************/

#include "uio.h"
#include "bsdsys.h"
#include "libkern.h"
#include "kin.h"
#include "bsdip.h"
#include "ip_icmp.h"
#include "socket.h"
#include "sockio.h"
#include "bsdif.h"
#include "ethernet.h"
#include "ips_config.h"

extern int so_read(int fd, void *buf, int nbyte);
extern in_addr_t inet_addr(const char *cp);
extern int accept(int	s, struct sockaddr	*  name,	socklen_t	*  anamelen);
extern int connect(int	s,		caddr_t	name,		int	namelen);
extern int bind(int	s,		const struct sockaddr *name, socklen_t namelen);
#define MAX_PING_PKT_LEN 100
void recv_echo_reply(int sockfd)
{
	char buf[MAX_PING_PKT_LEN];
	ssize_t n;
	struct ip *ip;
	struct icmp *icmp;
	while (1) {
		
		if ((n = so_read(sockfd, buf, sizeof(buf))) == -1)
		{
			printf("read failed %d\n", n);
			return;
		}
		
		ip = (struct ip *)buf;
		if (ip->ip_p != IPPROTO_ICMP) {
			printf("protocol error.rn");
			exit(1);
		}
		icmp = (struct icmp *)(buf + sizeof(struct ip));
		if (icmp->icmp_type == ICMP_ECHOREPLY) {
			if (icmp->icmp_id != 0) {
				printf("not this process.rn\n");
				exit(1);
			} else {
				printf("destination host is alive.rn\n");
				break;
			}
		}
	}
}
void send_echo_req(int sockfd, struct sockaddr_in *dstaddr)
{
	char buf[MAX_PING_PKT_LEN] = {0};
	int   optlevel,
         option,
         optval,
         rc;  
	size_t len = sizeof(struct icmp);
	struct icmp *icmp;
	socklen_t dstlen = sizeof(struct sockaddr_in);
	
   /* Enable TOS option */
   optval = 1;
   optlevel = IPPROTO_IP;
   option   = IP_TOS;
	//setsockopt(sockfd, IPPROTO_IP, IP_TOS, &option, sizeof(option));
	
	bzero(buf, sizeof(buf));
	icmp = (struct icmp *)buf;
	icmp->icmp_type = ICMP_ECHO;
	icmp->icmp_code = 0;
	icmp->icmp_id = 0;
	icmp->icmp_seq = 1;
	icmp->icmp_cksum = cal_chksum((uint16_t *) icmp, sizeof(struct icmp));
	
	if (len = sendto(sockfd, buf, MAX_PING_PKT_LEN, 0, (struct sockaddr *)dstaddr, dstlen) == -1)
	{
		printf("sendto failed %d\n", len);
	}
	else
	{
		struct in_addr *ipaddr = &dstaddr->sin_addr;
		char netaddr[INET_ADDRSTRLEN];
		//ipaddr->s_addr = ntohl(ipaddr->s_addr);
		strcpy(netaddr, bsd_inet_ntoa(*ipaddr));
		
		printf("Send icmp echo to %s\n", netaddr);
		
	}
}
void test_ping(char *ipAddr)
{
	struct sockaddr_in dst;
	int icmpSocketId = -1;
	printf("Start Testing ping....\n");
	
	icmpSocketId = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP);
	
	
	bzero(&dst,sizeof(dst));
	dst.sin_family=AF_INET;
	
	dst.sin_addr.s_addr = bsd_inet_addr(ipAddr);
	
	send_echo_req(icmpSocketId, &dst);
	return;
	Sleep(1000);
	//ISleep(1000);
	recv_echo_reply(icmpSocketId);
	so_close(icmpSocketId);
}

#define TCP_SERVER_PORT 23009
#define TCP_MAX_MSG 100 
int test_tcp_server(unsigned short port)
{	
    int server;
    struct sockaddr_in local;
    int client;
    struct sockaddr_in from;
    int fromlen = sizeof(from);
	
    printf("Starting up TCP server ...\r\n");
	
    local.sin_family = AF_INET; //Address family
    local.sin_addr.s_addr = INADDR_ANY; //Wild card IP address
    local.sin_port = htons(port);//(u_short)TCP_SERVER_PORT); //port to use//the socket function creates our SOCKET
    server = socket(AF_INET, SOCK_STREAM, 0);
	
    if(server == -1)
    {
        return -1;
    }
	
    if (bind(server, (struct sockaddr*)&local, sizeof(local))!=0)
    {
        return -1;
    }
	
    if(listen(server,10)!=0)
    {
        return -1;
    }
		
    while(1)//we are looping endlessly
    {
        char temp[1222] = {0};
		int n = 0;
        client=accept(server, (struct sockaddr*)&from,&fromlen);
		
        sprintf(temp,"Your IP is %s\n",bsd_inet_ntoa(from.sin_addr));
		
        //we simply send this string to the client
        n = send(client, temp, strlen(temp), 0);
        //printf("Connection from %s\n", inet_ntoa(from.sin_addr));
		printf("send %d bytes OK\n", n);
        //close the client socket
        so_close(client);
		
    }
	
    //closesocket() closes the socket and releases the socket descriptor
    so_close(server);
}
int test_tcp_client(char *ipaddr, unsigned short port)
{
	int ssock;
	int clen;
	struct sockaddr_in server_addr;
	char buf[TCP_MAX_MSG];
	if((ssock=socket(PF_INET,SOCK_STREAM,IPPROTO_TCP))<0){
		perror("socket error:");
		exit(1);
	}
	clen = sizeof(server_addr);
	memset(&server_addr,0,sizeof(server_addr));
	server_addr.sin_family     = AF_INET;
	server_addr.sin_addr.s_addr= bsd_inet_addr(ipaddr);
	server_addr.sin_port       = htons(port);//htons(TCP_SERVER_PORT);
	if (connect(ssock, (struct sockaddr *)&server_addr, clen)<0){
		perror("connect error:");
		return (1);
	}
	memset(buf, 0, TCP_MAX_MSG);
	if (so_read(ssock, buf, TCP_MAX_MSG) < 0)
	{
		perror("read error:");
		return (1);
	}
	printf("\nread: %s\n",buf);
	so_close(ssock);
	return 0;
	
}
