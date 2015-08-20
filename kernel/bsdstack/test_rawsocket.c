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
/* the following three files are for raw socket and udp recvmsg */
#include <uio.h>
#include <kfcntl.h>
#include <bsdudp.h>

#define SUCCESS_EC 0
#define UNSUCCESSFUL_EC -1
/*****************
  define
 *****************/
#define TYPE_OF_SERVICE     0x88
#define CONNECTION_LIMIT    5
#define PORT_RANGE_MIN      49152

/*****************
  struct
 *****************/ 

#define MAX_IP_PKT_LEN		256
#define BFD_PORT            4784

static int g_IcmpSndSocketId = -1;
static int g_IcmpRecvSocketId = -1;

static int g_BfdSndSocketId = -1;
static int g_BfdRecvSocketId = -1;

int
recvfrom(
		 int	s,
		 caddr_t	buf,
		 size_t	len,
		 int	flags,
		 struct sockaddr * 	from,
		 socklen_t *  fromlenaddr);


static void    __delete_icmp_send_socket__r()
{
   if (g_IcmpSndSocketId >= 0)
      so_close(g_IcmpSndSocketId);
   g_IcmpSndSocketId = -1;
}

static uint32_t __create_icmp_send_socket__r()
{
   int   optlevel,
         option,
         optval,
         rc;  

   if (g_IcmpSndSocketId >= 0)
      return SUCCESS_EC;

   g_IcmpSndSocketId = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP);
   if (g_IcmpSndSocketId < 0) {
     g_IcmpSndSocketId = -1;
     return UNSUCCESSFUL_EC;
   }

   /* Enable the IP header include option */
   optval = 1;
   optlevel = IPPROTO_IP;
   option   = IP_HDRINCL;
   rc = setsockopt(g_IcmpSndSocketId, optlevel, option, (char *)&optval, sizeof(optval));
   if (rc < 0) {
     __delete_icmp_send_socket__r();
     return UNSUCCESSFUL_EC;
   }
   return SUCCESS_EC;
}

static void    __delete_icmp_recv_socket__r()
{
   if (g_IcmpRecvSocketId >= 0)
      so_close(g_IcmpRecvSocketId);
   g_IcmpRecvSocketId = -1;
}

static uint32_t __create_icmp_recv_socket__r()
{
   if (g_IcmpRecvSocketId >= 0)
      return SUCCESS_EC;

   
   g_IcmpRecvSocketId = socket(PF_INET, SOCK_RAW, IPPROTO_ICMP);
   if (g_IcmpRecvSocketId < 0) {
      g_IcmpRecvSocketId = -1;
      return UNSUCCESSFUL_EC;
   }
   return SUCCESS_EC;
}

static void    __delete_bfd_send_socket__r()
{
   if (g_BfdSndSocketId >= 0)
      so_close(g_BfdSndSocketId);
   g_BfdSndSocketId = -1;
}

static uint32_t __create_bfd_send_socket__r()
{
    int     optlevel,
            option,
            optval,
            rc;  

    if (g_BfdSndSocketId >= 0)
      return SUCCESS_EC;
    
    g_BfdSndSocketId = socket(AF_INET, SOCK_RAW, IPPROTO_UDP);
    if (g_BfdSndSocketId < 0) {
        g_BfdSndSocketId = -1;
        return UNSUCCESSFUL_EC;
    }

    /* Enable the IP header include option */
    optval = 1;
    optlevel = IPPROTO_IP;
    option   = IP_HDRINCL;
    rc = setsockopt(g_BfdSndSocketId, optlevel, option, (char *)&optval, sizeof(optval));
    if (rc < 0) {
        __delete_bfd_send_socket__r();
        return UNSUCCESSFUL_EC;
    }
	return SUCCESS_EC;
}

static void    __delete_bfd_recv_socket__r()
{
   if (g_BfdRecvSocketId >= 0)
      so_close(g_BfdRecvSocketId);
   g_BfdRecvSocketId = -1;
}

static uint32_t __create_bfd_recv_socket__r()
{
   struct sockaddr_in in;
   int opt, flags;
   int nRetValue = 0;

   if (g_BfdRecvSocketId >= 0)
      return SUCCESS_EC;

   g_BfdRecvSocketId = socket(PF_INET, SOCK_DGRAM, IPPROTO_UDP);
   if (g_BfdRecvSocketId < 0) {	
      g_BfdRecvSocketId = -1;
   	return UNSUCCESSFUL_EC;
   }
   in.sin_family = AF_INET;
   in.sin_port = htons(BFD_PORT);
   in.sin_addr.s_addr = INADDR_ANY;
   nRetValue = bind(g_BfdRecvSocketId, (struct sockaddr *)&in, sizeof(in));
   if (nRetValue < 0) {
		__delete_bfd_recv_socket__r();
      return UNSUCCESSFUL_EC;
	}
    
	/* set msg recv flag */
	//if (fcntl(g_BfdRecvSocketId, F_GETFL) & O_NONBLOCK) //LUOYU
	//	flags |= MSG_DONTWAIT;

	/* Set the IP_RECVDSTADDR option (BSD). */
   opt = 1;
#if defined(IP_RECVDSTADDR)      
   nRetValue = setsockopt(g_BfdRecvSocketId, IPPROTO_IP, IP_RECVDSTADDR, &opt, sizeof(opt)); 
#elif defined(IP_PKTINFO)     
   nRetValue = setsockopt(g_BfdRecvSocketId, IPPROTO_IP, IP_PKTINFO, &opt, sizeof(opt));
#endif 
	if (nRetValue < 0) {
		__delete_bfd_recv_socket__r();
      return UNSUCCESSFUL_EC;
	}
  
	return SUCCESS_EC;
}
/*****************
  implementation
 *****************/

/**
 * \brief       Init socket communication
 *
 * \retval      none
 *
 * \remarks     none 
 *
 * \see         none
 *
 * \warning     none
 */
 
void fnSocketInit (void)
{ 
   g_IcmpSndSocketId  = -1;
   g_IcmpRecvSocketId = -1;

   g_BfdSndSocketId   = -1;
   g_BfdRecvSocketId  = -1;
   
}


/**
 * \brief       Release space reserved by socket
 *
 * \retval      none
 *
 * \remarks     none
 *
 * \see         fnSocketInit, fnSocketSend
 *
 * \warning     none
 */
void close_all_sockets (void)
{
   __delete_icmp_send_socket__r();
   __delete_bfd_send_socket__r();
   __delete_icmp_recv_socket__r();
   __delete_bfd_recv_socket__r();
   return;
}


/**
 * \brief       Receive a Bfd packet from a socket
 *
 * \param[out]   ptBfd pointer to store Bfd data packet
 * \param[in]    socket socket Id to use for receiving
 * \param[in]    ip_address ipAddress of remote sender
 *
 * \retval      0 upon success, -1 otherwise
 *
 * \remarks     none
 *
 * \see         fnSocketInit, fnSocketSend
 *
 * \warning     none
 */
int fnSocketRecv (struct icmp * packet, int socket, unsigned long * ip_address)
{
    unsigned char recv_buf[512];
    struct  sockaddr_in from;
    struct ip*iphdr;  
    struct icmp *icmphdr; 
    int from_len, iphdr_len, icmp_len;
    int recv_len = 0;

    if(packet == NULL || ip_address == NULL)
    {
        return -1;
    }

    memset(recv_buf, 0x00, sizeof(recv_buf));
    memset(&from, 0x00, sizeof(from));
    from_len = sizeof(from);
    
    recv_len = recvfrom(socket, recv_buf, sizeof(recv_buf),                  
                        MSG_DONTWAIT, (struct sockaddr *) &(from), &(from_len));                      

    if (recv_len <= 0)
    {
        return -1;
    }    
    
    if (from_len <= 0)
    {
        return 0;
    }

    iphdr = (struct ip *)recv_buf;        
    iphdr_len = iphdr->ip_hl<<2;        
    icmphdr = (struct icmp *)(recv_buf + iphdr_len);        
    icmp_len = recv_len - iphdr_len;        
    if (icmp_len < sizeof(struct icmp))                
       return 0;          
    if (icmphdr->icmp_type!=ICMP_ECHOREPLY)             
       return 0;           

    /*store into bfd packet data structure*/
    memset(packet, 0x00, sizeof(struct icmp));
    memcpy(packet, icmphdr, MIN(icmp_len, sizeof(struct icmp)));
    //packet->opt.opt_len = icmp_len;

    *ip_address = from.sin_addr.s_addr;

    return icmp_len;
}



/**
 * \brief       This function calculates the 16-bit one's complement sum
 *              for the supplied buffer.
 *
 * \param[in]    buffer
 * \param[in]    size of calculation 
 *
 * \retval      always be a short number 
 *
 * \remarks     none
 *
 * \see         InitIpv4Header, ComputeUdpPseudoHeaderChecksumV4
 *
 * \warning     none
 */

unsigned short cal_chksum(unsigned short *addr,int len)
{      
   int nleft=len;
   int sum=0;
   unsigned short *w=addr;
   unsigned short answer=0;
   while(nleft>1)
   {       
      sum+=*w++;
      nleft-=2;
   }
   if( nleft==1)
   {      
      *(unsigned char *)(&answer)=*(unsigned char *)w;
      sum+=answer;
   }
   sum=(sum>>16)+(sum&0xffff);
   sum+=(sum>>16);
   answer=~sum;
   return answer;
}

/**
 * \brief       Initialize the IPv4 header with the version, header length,
 *              total length, ttl, protocol value, and source and destination
 *              addresses.
 * \param[out]  a pointer of ipv4 header 
 * \param[in]   src ip address
 * \param[in]   dest ip address
 * \param[in]   payload length include UDP/TCP header length
 *
 * \retval      total length of packet 
 *
 * \remarks     none
 *
 * \see         fnSendRawPacket
 *
 * \warning     none
 */
int init_ipv4_header(
    char *buf, 
    unsigned int src, 
    unsigned int dest, 
    int payloadlen,
    unsigned char protocol,
    unsigned char tos,
    unsigned char ttl
    )
{
    struct ip    *v4hdr=NULL;

    v4hdr = (struct ip *)buf;
	 v4hdr->ip_hl = sizeof(struct ip) / sizeof(unsigned long);
	 v4hdr->ip_v = 4;
    v4hdr->ip_tos         = tos;
    v4hdr->ip_len = sizeof(struct ip) + payloadlen;
    v4hdr->ip_id          = 0;
    v4hdr->ip_off      = 0;
    v4hdr->ip_ttl         = ttl;
    v4hdr->ip_p    = protocol;
    v4hdr->ip_sum    = 0;
    v4hdr->ip_src.s_addr = htonl(src);
    v4hdr->ip_dst.s_addr = htonl(dest);

    v4hdr->ip_sum    = cal_chksum((unsigned short *)v4hdr, sizeof(struct ip));
    
    return sizeof(struct ip);
}

/**
 * \brief       Setup the UDP header which is fairly simple. Grab the ports and
 *              stick in the total payload length.
 *
 * \param[out]   buffer pointer to udp packet
 * \param[in]    src port number 
 * \param[in]    dest port number 
 * \param[in]    payload length   
 *
 * \retval      total length of packet 
 *
 * \remarks     none
 *
 * \see         fnSendRawPacket
 *
 * \warning     none
 */
int init_icmp_header(unsigned char * sendbuf, struct icmp * header, int payload_len)
{
   struct icmp * packet = (struct icmp *)sendbuf;
   unsigned char * payload = sendbuf + sizeof(struct icmp);
   int i; 
   memcpy(packet, header, sizeof(struct icmp));
   for (i=0; i<payload_len; i++) {
      payload[i] = i & 0x00FF;
   }
   packet->icmp_type = ICMP_ECHO;
   packet->icmp_code = ICMP_ECHO;
   packet->icmp_cksum = 0;    
   packet->icmp_cksum = cal_chksum((unsigned short*)packet, sizeof(struct icmp) + payload_len);

   return sizeof(struct icmp) + payload_len;
}

/**
 * \brief       Send the udp packets with RAW SOCKET
 *
 * \param[in]     src ip address 
 * \param[in]     dest ip address 
 * \param[in]     src port number
 * \param[in]     dest port number
 * \param[in]     buffer pointer to payload of BFD
 * \param[in]     buffer length
 *
 * \retval      the number of bytes send successful
 *				less Zero if failed
 *
 * \remarks     none
 *
 * \see         fnTxThread
 *
 * \warning     none
 */
int send_icmp_raw_packet( unsigned long srcip, unsigned long dstip, 
					struct icmp * buf, int payload_len)
{
   char 	sendbuf[MAX_IP_PKT_LEN]={0};
   int     iphdrlen,
           allsize;
   int     rc;  
   struct  sockaddr_in    ReceiverAddr;

   bzero(&ReceiverAddr, sizeof(ReceiverAddr));
   ReceiverAddr.sin_family = AF_INET;
   ReceiverAddr.sin_port = 0;    
   ReceiverAddr.sin_addr.s_addr = dstip;
   
   allsize = sizeof(struct ip) + sizeof(struct icmp) + payload_len;

   /* Initialize the v4 header */
   iphdrlen = init_ipv4_header(sendbuf, srcip, dstip, sizeof(struct icmp) + payload_len, IPPROTO_ICMP, TYPE_OF_SERVICE, 128);
   /* Initialize the ICMP header */
   init_icmp_header(&sendbuf[iphdrlen], buf, payload_len);

   rc = sendto(g_IcmpSndSocketId,
                sendbuf,
                allsize,
                0,
                (struct sockaddr*)&ReceiverAddr,
                sizeof(ReceiverAddr)
                );
#if DEBUG_PKT
    if (rc < 0)
    {
      perror("sendto() failed:\n");
    }
    else
    {
      printf("Send %d bytes from %s to %s", allsize, ip_2_str__r(srcip), ip_2_str__r(dstip));        
    }
#endif	
    return rc;
}

#pragma pack(1)
struct icmp_header_t
{
	unsigned char	type;
	unsigned char	code;
	unsigned short	chk_sum;
	unsigned short	sess_id;
	unsigned short	seq_num;
} ;
typedef struct icmp_header_t icmp_header_t;
struct bfd_packet_t
{
#if BYTE_ORDER == LITTLE_ENDIAN
	unsigned char diag:5,
vers:3;
	unsigned char __M:1,
__D:1,
__A:1,
__C:1,
__F:1,
__P:1,
sta:2;
#endif
#if BYTE_ORDER == BIG_ENDIAN
	unsigned char vers:3,
diag:5;
	unsigned char sta:2,
__P:1,
__F:1,
__C:1,
__A:1,
__D:1,
__M:1;
#endif  
	unsigned char detectMult;
	unsigned char length;
	unsigned int  myDiscr;           
	unsigned int  yourDiscr;         
	unsigned int  desiredMinTX;      
	unsigned int  requiredMinRx;     
	unsigned int  requiredMinEchoRx; 
} ;
typedef struct bfd_packet_t bfd_packet_t;
#pragma pack()



void* icmp_recv_thread (void *arg)
{
   struct sockaddr_in from;
   int recv_len, fl;
   unsigned char buff[512]; 
   struct icmp *icmp;
   struct ip *iphdr;  
   icmp_header_t *icmphdr; 
   int iphdr_len, icmp_len = 0;

   while(1)
   {
      fl = sizeof(from);
      memset(buff, 0x00, sizeof(buff));
      memset(&from, 0x00, sizeof(from));

      if (__create_icmp_recv_socket__r() != SUCCESS_EC) {
         Sleep(1000);
         continue;
      }
      recv_len = recvfrom(g_IcmpRecvSocketId, buff, 512, 0, (struct sockaddr *)&from, &fl);
      if (recv_len <= 0) {
         if (recv_len != 0) 
            __delete_icmp_recv_socket__r(); 
         continue;
      } 

      iphdr = (struct ip *)buff;
      iphdr_len = iphdr->ip_hl<<2;
      if (iphdr->ip_p != IPPROTO_ICMP)
         continue;
      icmphdr = (struct icmp *)(buff + iphdr_len);        
      icmp_len = recv_len - iphdr_len;        
      if (icmp_len < sizeof(icmp_header_t))                
         continue; 
      if (icmphdr->type != ICMP_ECHOREPLY)             
         continue; 

#ifdef DEBUG_PKT        
      fnSysLog(LOG_TYPE_T_TEXT_I_C, ICMP_RX_THREAD, "%s Received %d bytes from %s to %s", __FUNCTION__, recv_len, ip_2_str__r(event.icmp.remote_ip), ip_2_str__r(event.icmp.local_ip));
#endif
   }

	__delete_icmp_recv_socket__r();
	return NULL;
}
void* send_icmp_packet (int local_ip, int remote_ip )
{
	int res;
    if (__create_icmp_send_socket__r() == SUCCESS_EC) {
		struct icmp icmp;
       res = send_icmp_raw_packet(local_ip, remote_ip, &icmp.icmp_pptr, 10);
    }
    if (res <= 0) {
       /*TODO:

         In which case should we recreate send socket???
       */
	}
   
   return NULL;
}


/**
 * \brief       Compute the UDP pseudo header checksum. The UDP checksum is based
 *              on the following fields:
 *               o source IP address
 *               o destination IP address
 *               o 8-bit zero field
 *               o 8-bit protocol field
 *               o 16-bit UDP length
 *               o 16-bit source port
 *               o 16-bit destination port
 *               o 16-bit UDP packet length
 *               o 16-bit UDP checksum (zero)
 *               o UDP payload (padded to the next 16-bit boundary)
 *              This routine copies these fields to a temporary buffer and computes
 *              the checksum from that.
 * \param[out]  a pointer of ipv4 header 
 * \param[out]  a pointer of udp header  
 * \param[in]   pure payload
 * \param[in]   payload length
 *
 * \retval      none 
 *
 * \remarks     none
 *
 * \see         fnSendRawPacket
 *
 * \warning     none
 */
void complete_udp_header_with_chksum(
    void    *iphdr,
    struct udphdr *udphdr,
    char    *payload,
    int      payloadlen
    )
{
    struct  ip   *v4hdr=NULL;
    unsigned long zero=0;
    char          buf[1000],
                 *ptr=NULL;
    int           chksumlen=0,
                  i;
    
    ptr = buf;

    v4hdr = (struct  ip *)iphdr;

    // Include the source and destination IP addresses
    memcpy(ptr, &v4hdr->ip_src,  sizeof(v4hdr->ip_src));  
    ptr += sizeof(v4hdr->ip_src);
    chksumlen += sizeof(v4hdr->ip_src);

    memcpy(ptr, &v4hdr->ip_dst, sizeof(v4hdr->ip_dst)); 
    ptr += sizeof(v4hdr->ip_dst);
    chksumlen += sizeof(v4hdr->ip_dst);
    
    // Include the 8 bit zero field
    memcpy(ptr, &zero, 1);
    ptr++;
    chksumlen += 1;

    // Protocol
    memcpy(ptr, &v4hdr->ip_p, sizeof(v4hdr->ip_p)); 
    ptr += sizeof(v4hdr->ip_p);
    chksumlen += sizeof(v4hdr->ip_p);

    // UDP length
    memcpy(ptr, &udphdr->uh_ulen, sizeof(udphdr->uh_ulen)); 
    ptr += sizeof(udphdr->uh_ulen);
    chksumlen += sizeof(udphdr->uh_ulen);
    
    // UDP source port
    memcpy(ptr, &udphdr->uh_sport, sizeof(udphdr->uh_sport)); 
    ptr += sizeof(udphdr->uh_sport);
    chksumlen += sizeof(udphdr->uh_sport);

    // UDP destination port
    memcpy(ptr, &udphdr->uh_dport, sizeof(udphdr->uh_dport)); 
    ptr += sizeof(udphdr->uh_dport);
    chksumlen += sizeof(udphdr->uh_dport);

    // UDP length again
    memcpy(ptr, &udphdr->uh_ulen, sizeof(udphdr->uh_ulen)); 
    ptr += sizeof(udphdr->uh_ulen);
    chksumlen += sizeof(udphdr->uh_ulen);
   
    // 16-bit UDP checksum, zero 
    memcpy(ptr, &zero, sizeof(unsigned short));
    ptr += sizeof(unsigned short);
    chksumlen += sizeof(unsigned short);

    // payload
    memcpy(ptr, payload, payloadlen);
    ptr += payloadlen;
    chksumlen += payloadlen;

    // pad to next 16-bit boundary
    for(i=0 ; i < payloadlen%2 ; i++, ptr++)
    {
        //fnSysLog(LOG_TYPE_T_TEXT_I_C, ENB_MAIN_THREAD, "pad one byte\n");
        *ptr = 0;
        ptr++;
        chksumlen++;
    }

    // Compute the checksum and put it in the UDP header
    udphdr->uh_sum = cal_chksum((unsigned short *)buf, chksumlen);

    return;
}

/**
 * \brief       Setup the UDP header which is fairly simple. Grab the ports and
 *              stick in the total payload length.
 *
 * \param[out]   buffer pointer to udp packet
 * \param[in]    src port number 
 * \param[in]    dest port number 
 * \param[in]    payload length   
 *
 * \retval      total length of packet 
 *
 * \remarks     none
 *
 * \see         fnSendRawPacket
 *
 * \warning     none
 */
int init_udp_header(
    char *buf, 
    int srcprt,
    int dstprt, 
    int       payloadlen
    )
{
    struct udphdr *udphdr=NULL;

    udphdr = (struct udphdr *)buf;
    udphdr->uh_sport = htons(srcprt);
    udphdr->uh_dport = htons(dstprt);
    udphdr->uh_ulen = htons(sizeof(struct udphdr) + payloadlen);

    return sizeof(struct udphdr);
}

/**
 * \brief       Send the udp packets with RAW SOCKET
 *
 * \param[in]     src ip address 
 * \param[in]     dest ip address 
 * \param[in]     src port number
 * \param[in]     dest port number
 * \param[in]     buffer pointer to payload of BFD
 * \param[in]     buffer length
 *
 * \retval      the number of bytes send successful
 *				less Zero if failed
 *
 * \remarks     none
 *
 * \see         fnTxThread
 *
 * \warning     none
 */
int send_mhop_raw_packet( unsigned long srcip, unsigned long dstip, 
					int srcprt, int dstprt, char *buf, int bufsize)
{
    char 	sendbuf[MAX_IP_PKT_LEN]={0};
    int     iphdrlen,
            allsize,
            udphdrlen;
    int     rc;  
    struct  sockaddr_in    ReceiverAddr;

    ReceiverAddr.sin_family = AF_INET;
    ReceiverAddr.sin_port = htons(dstprt);    
    ReceiverAddr.sin_addr.s_addr = dstip;
    
    allsize = sizeof(struct ip) + sizeof(struct udphdr) + bufsize;

    iphdrlen = init_ipv4_header(sendbuf, srcip, dstip, bufsize + sizeof(struct udphdr), IPPROTO_UDP, TYPE_OF_SERVICE, 128);
    /* Initialize the UDP header */
    udphdrlen = init_udp_header(
           &sendbuf[iphdrlen], 
            srcprt, 
            dstprt, 
            bufsize
            );

    /* Compute the UDP checksum */
    complete_udp_header_with_chksum(
            sendbuf, 
            (struct udphdr *)&sendbuf[iphdrlen], 
            buf, 
            bufsize
            );

    /* Copy the payload to the end of the header */
    memcpy(&sendbuf[iphdrlen + udphdrlen], buf, bufsize);

    rc = sendto(g_BfdSndSocketId,
                 sendbuf,
                 allsize,
                 0,
                 (const struct sockaddr*)&ReceiverAddr,
                 sizeof(ReceiverAddr)
                 );
#ifdef DEBUG_BFD     
    if (rc < 0)
    {
        fnSysLog(LOG_TYPE_T_TEXT_I_C, TX_THREAD, "sendto() failed: %s %d %s\n", __FUNCTION__,errno, strerror(errno));
    }
    else
    {
        fnSysLog(LOG_TYPE_T_TEXT_I_C, TX_THREAD, "%s Sendto %d bytes OK\n", __FUNCTION__, rc);
    }
#endif	
    return rc;
}

void* send_mhop_packet (int local_ip, int remote_ip)
{
    int           l_result = 0;
	bfd_packet_t bfd;
	bzero(&bfd, sizeof(struct bfd_packet_t));
    if (__create_bfd_send_socket__r() == SUCCESS_EC) {
       l_result = send_mhop_raw_packet(local_ip, remote_ip, BFD_PORT, BFD_PORT, 
                                       &bfd, sizeof(struct bfd_packet_t));
    }
    if (l_result <= 0) {
	}
   
   return NULL;
}

/**
 * \brief       receive message from special UDP socket.
 *				we don't use the normal recvfrom instead of 
 *				recvmsg, because we need get src ip address 
 *				from packet.
 *
 * \param[in]     socket fd created by fnBfdRecvServer
 * \param[out]    buffer pointer to recv BFD
 * \param[out]     the number of we expected recv
 * \param[out]     the information of sender got from pkt message
 * \param[out]     the length of sender's infomation
 * \param[out]     the information of receiver got from pkt message
 * \param[out]     the length of receiver's infomation
 *
 * \retval      the number of bytes recv successful
 *				less Zero if failed
 *
 * \remarks     none
 *
 * \see         fnBfdRecvServer
 *
 * \warning     none
 */
int mhop_recvmsg(int sockfd, void *buf, size_t len, int flags,
        struct sockaddr *from, int *fromlen,
        struct sockaddr *to, int *tolen)
{
    struct msghdr msgh;
    struct cmsghdr *cmsg;
    struct iovec iov;
    char cbuf[MAX_IP_PKT_LEN];
	int err;
    /*
    *  If from or to are set, they must be big enough
    *  to store a struct sockaddr_in.
    */
    if ((from && (!fromlen || *fromlen < sizeof(struct sockaddr_in)))
         || (to && (!tolen || *tolen < sizeof(struct sockaddr_in)))) 
    {
        return -1;
    }
    if (tolen) *tolen = 0;

    /* Set MSG_DONTWAIT if O_NONBLOCK was set. */

    /* Set up iov and msgh structures. */
    iov.iov_base = buf;
    iov.iov_len = len;
    msgh.msg_control = cbuf;
    msgh.msg_controllen = sizeof(cbuf);
    msgh.msg_name = (caddr_t)from;
    msgh.msg_namelen = fromlen ? *fromlen : 0;
    msgh.msg_iov = &iov;
    msgh.msg_iovlen = 1;


    /* Receive one packet. */
    err = recvmsg(sockfd, &msgh, flags);
	if (err < 0)
	{
		return -1;
	}
	
    if (fromlen) 
		*fromlen = msgh.msg_namelen;

    /* Process auxiliary received data in msgh */
    for (cmsg = CMSG_FIRSTHDR(&msgh); cmsg != NULL && cmsg->cmsg_len >= sizeof(*cmsg); cmsg = CMSG_NXTHDR(&msgh,cmsg)) { 

#if defined(IP_RECVDSTADDR)  
      if (cmsg->cmsg_level == IPPROTO_IP && cmsg->cmsg_type == IP_RECVDSTADDR) {
         struct in_addr *i = (struct in_addr *)CMSG_DATA(cmsg);
         if (to) {
            ((struct sockaddr_in *)to)->sin_addr = *i;
            *tolen = sizeof(struct sockaddr_in);
         }
         break;
      } 
#elif defined(IP_PKTINFO)  
      if (cmsg->cmsg_level == SOL_IP && cmsg->cmsg_type == IP_PKTINFO) {
         struct in_pktinfo *in = (struct in_pktinfo *)CMSG_DATA(cmsg); 
         if (to) {
            ((struct sockaddr_in *)to)->sin_addr = in->ipi_addr;
            *tolen = sizeof(struct sockaddr_in);
         }
         break;
      }   
#endif 
		 
    }

    return err;
}

/**
 * \brief       create UDP server and wait for recving pkt, then 
 *				send the pkt to corresponsible function to deal 
 *				with.
 *
 * \param[in]   no
 *
 * \retval      the number of bytes recv successful
 *				less Zero if failed
 *
 * \remarks     none
 *
 * \see         fnBfdRecvServer
 *
 * \warning     none
 */
void* mhop_recv_thread(void *arg)
{
    struct sockaddr_in from, to;
    int n, fl, tl;
    
    int flags = 0;
    bfd_packet_t bfd;
    while (1) {
        fl = tl = sizeof(struct sockaddr_in);
        memset(&from, 0, sizeof(from));
        memset(&to, 0, sizeof(to));

        if (__create_bfd_recv_socket__r() != SUCCESS_EC) {
            Sleep(1000);
            continue;
        }
        
        if ((n = mhop_recvmsg(g_BfdRecvSocketId, (char*)&bfd, sizeof(bfd_packet_t), flags,
            		(struct sockaddr *)&from, &fl, (struct sockaddr *)&to, &tl)) < 0) {
            __delete_bfd_recv_socket__r();
            continue;
        }
        
        if(n == 0) {
            /* zero data, nothing to do */
            continue;    
        }
#ifdef DEBUG_BFD        
        fnSysLog(LOG_TYPE_T_TEXT_I_C, MHOP_RX_THREAD, "Received %d bytes ", n);
        fnSysLog(LOG_TYPE_T_TEXT_I_C, MHOP_RX_THREAD, " src ip:port %s:%d ",
                inet_ntoa(from.sin_addr), ntohs(from.sin_port));
        fnSysLog(LOG_TYPE_T_TEXT_I_C, MHOP_RX_THREAD, " dst ip:port %s:%d\n",
                inet_ntoa(to.sin_addr), ntohs(to.sin_port));
#endif
  
    }

    __delete_bfd_recv_socket__r();
    return 0;
}

