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
#include "if_arp.h"
#include "sbuf.h"
int packet_input(struct mbuf *m, int flag)
{
#if 0
    register struct mbuf *n;
    /* Step1: check the type of the packet, if LOOPBACK, drop it  */
    if (m->m_pkthdr.rcvif->if_flags & IFF_LOOPBACK)
        return 0;
    /* Step2: check the length of the ip packet (maybe don't need)
     * And copy the packet in case sb else should use it */
    n = m_copy(m, 0, (int)M_COPYALL);
    /* Step4: transfer the packet to be handled by the pr_input routine */
    if (n)
    {
        //	(*ipoptsw[ipopt_protox[j]].pr_input)(n, flag);
        packet_dhd_input(n, flag);
    }

    /* if the packet is local, leave it alone */
    if (flag == PACKET_LOCAL)
        return 0;

    m_freem(m);
#endif
    return -1;

}
