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
#include "tcp_var.h"
#include "ktime.h"
#include "tcp_ip.h"
#include "bsdip.h"
#include "bsdtcp.h"
#include "tcp_seq.h"
#include "tcp_fsm.h"
#include "tcp_timer.h"
#include "callout.h"
int	tcp_msl;

int	tcp_rexmit_min;

int	tcp_rexmit_slop;

static int	always_keepalive = 1;
int	tcp_keepinit;

int	tcp_keepidle;

int	tcp_keepintvl;

int	tcp_delacktime;

int	tcp_msl;

int	tcp_rexmit_min;

int	tcp_rexmit_slop;


static int	tcp_keepcnt = TCPTV_KEEPCNT;
	/* max idle probes */
int	tcp_maxpersistidle;
	/* max idle time in persist */
int	tcp_maxidle;

struct twlist {
	
	struct  {								
	   struct tcptw *lh_first;	/* first element */			
   }tw_list;
	struct tcptw	tw_tail;
};
#define TWLIST_NLISTS	2
static struct twlist twl_2msl[TWLIST_NLISTS];
static struct twlist *tw_2msl_list[] = { &twl_2msl[0], &twl_2msl[1], NULL };
int	tcp_syn_backoff[TCP_MAXRXTSHIFT + 1] =
    { 1, 1, 1, 1, 1, 2, 4, 8, 16, 32, 64, 64, 64 };

int	bsd_tcp_backoff[TCP_MAXRXTSHIFT + 1] =
    { 1, 2, 4, 8, 16, 32, 64, 128, 256, 512, 512, 512, 512 };

static int tcp_totbackoff = 2559;	/* sum of tcp_backoff[] */


void
tcp_timer_init(void)
{
	int i;
	struct twlist *twl;

	for (i = 0; i < TWLIST_NLISTS; i++) {
		twl = &twl_2msl[i];
		LIST_INIT(&twl->tw_list);
		LIST_INSERT_HEAD(&twl->tw_list, &twl->tw_tail, tw_2msl);
	}
}
#include <ktime.h>
extern struct timehands *volatile timehands;
void
getmicrouptime(struct timeval *tvp)
{
	
	struct timehands *th;
	u_int gen;

	//ngetmicrouptime++;
	do {
		th = timehands;
		gen = th->th_generation;
		bintime2timeval(&th->th_offset, tvp);
	} while (gen == 0 || gen != th->th_generation);
	
}

void
tcp_timer_2msl_stop(struct tcptw *tw)
{

	if (tw->tw_time != 0)
		LIST_REMOVE(tw, tw_2msl);
}

/*
 * TCP timer processing.
 */

void
tcp_timer_delack(xtp)
	void *xtp;
{
	struct tcpcb *tp = xtp;
	int s;
	struct inpcb *inp;

	s = splnet();
	INP_INFO_RLOCK(&tcbinfo);
	inp = tp->t_inpcb;
	if (!inp) {
		INP_INFO_RUNLOCK(&tcbinfo);
		splx(s);
		return;
	}
	INP_LOCK(inp);
	INP_INFO_RUNLOCK(&tcbinfo);
	if (callout_pending(tp->tt_delack) || !callout_active(tp->tt_delack)) {
		INP_UNLOCK(inp);
		splx(s);
		return;
	}
	callout_deactivate(tp->tt_delack);

	tp->t_flags |= TF_ACKNOW;
	tcpstat.tcps_delack++;
	(void) bsd_tcp_output(tp);
	INP_UNLOCK(inp);
	splx(s);
}

/*
 * Tcp protocol timeout routine called every 500 ms.
 * Updates timestamps used for TCP
 * causes finite state machine actions if timers expire.
 */
void
tcp_slowtimo()
{
	int s;

	s = splnet();
	tcp_maxidle = tcp_keepcnt * tcp_keepintvl;
	splx(s);
	INP_INFO_WLOCK(&tcbinfo);
	(void) tcp_timer_2msl_tw(0);
	INP_INFO_WUNLOCK(&tcbinfo);
}

void
tcp_timer_2msl(xtp)
	void *xtp;
{
	struct tcpcb *tp = xtp;
	int s;
	struct inpcb *inp;
#ifdef TCPDEBUG
	int ostate;

	ostate = tp->t_state;
#endif
	s = splnet();
	INP_INFO_WLOCK(&tcbinfo);
	inp = tp->t_inpcb;
	if (!inp) {
		INP_INFO_WUNLOCK(&tcbinfo);
		splx(s);
		return;
	}
	INP_LOCK(inp);
	tcp_free_sackholes(tp);
	if (callout_pending(tp->tt_2msl) || !callout_active(tp->tt_2msl)) {
		INP_UNLOCK(tp->t_inpcb);
		INP_INFO_WUNLOCK(&tcbinfo);
		splx(s);
		return;
	}
	callout_deactivate(tp->tt_2msl);
	/*
	 * 2 MSL timeout in shutdown went off.  If we're closed but
	 * still waiting for peer to close and connection has been idle
	 * too long, or if 2MSL time is up from TIME_WAIT, delete connection
	 * control block.  Otherwise, check again in a bit.
	 */
	if (tp->t_state != TCPS_TIME_WAIT &&
	    (ticks - tp->t_rcvtime) <= tcp_maxidle)
		callout_reset(tp->tt_2msl, tcp_keepintvl,
			      tcp_timer_2msl, tp);
	else
		tp = bsd_tcp_close(tp);

#ifdef TCPDEBUG
	if (tp && (tp->t_inpcb->inp_socket->so_options & SO_DEBUG))
		tcp_trace(TA_USER, ostate, tp, (void *)0, (struct tcphdr *)0,
			  PRU_SLOWTIMO);
#endif
	if (tp)
		INP_UNLOCK(inp);
	INP_INFO_WUNLOCK(&tcbinfo);
	splx(s);
}

void
tcp_timer_2msl_reset(struct tcptw *tw, int timeo)
{
	int i;
	struct tcptw *tw_tail;

	if (tw->tw_time != 0)
		LIST_REMOVE(tw, tw_2msl);
	tw->tw_time = timeo + ticks;
	i = timeo > tcp_msl ? 1 : 0;
	tw_tail = &twl_2msl[i].tw_tail;
	LIST_INSERT_BEFORE(tw_tail, tw, tw_2msl);
}

struct tcptw *
tcp_timer_2msl_tw(int reuse)
{
	struct tcptw *tw, *tw_tail;
	struct twlist *twl;
	int i;

	for (i = 0; i < 2; i++) {
		twl = tw_2msl_list[i];
		tw_tail = &twl->tw_tail;
		for (;;) {
			tw = LIST_FIRST(&twl->tw_list);
			if (tw == tw_tail || (!reuse && tw->tw_time > ticks))
				break;
			INP_LOCK(tw->tw_inpcb);
			if (tcp_twclose(tw, reuse) != NULL)
				return (tw);
		}
	}
	return (NULL);
}

void
tcp_timer_keep(xtp)
	void *xtp;
{
	struct tcpcb *tp = xtp;
	struct tcptemp *t_template;
	int s;
	struct inpcb *inp;
#ifdef TCPDEBUG
	int ostate;

	ostate = tp->t_state;
#endif
	s = splnet();
	INP_INFO_WLOCK(&tcbinfo);
	inp = tp->t_inpcb;
	if (!inp) {
		INP_INFO_WUNLOCK(&tcbinfo);
		splx(s);
		return;
	}
	INP_LOCK(inp);
	//if (callout_pending(tp->tt_keep) || !callout_active(tp->tt_keep)) {LUOYU
	//	INP_UNLOCK(inp);
	//	INP_INFO_WUNLOCK(&tcbinfo);
	//	splx(s);
	//	return;
	//}
	//callout_deactivate(tp->tt_keep);LUOYU
	/*
	 * Keep-alive timer went off; send something
	 * or drop connection if idle for too long.
	 */
	tcpstat.tcps_keeptimeo++;
	if (tp->t_state < TCPS_ESTABLISHED)
		goto dropit;
	if ((always_keepalive || inp->inp_socket->so_options & SO_KEEPALIVE) &&
	    tp->t_state <= TCPS_CLOSING) {
		if ((ticks - tp->t_rcvtime) >= tcp_keepidle + tcp_maxidle)
			goto dropit;
		/*
		 * Send a packet designed to force a response
		 * if the peer is up and reachable:
		 * either an ACK if the connection is still alive,
		 * or an RST if the peer has closed the connection
		 * due to timeout or reboot.
		 * Using sequence number tp->snd_una-1
		 * causes the transmitted zero-length segment
		 * to lie outside the receive window;
		 * by the protocol spec, this requires the
		 * correspondent TCP to respond.
		 */
		tcpstat.tcps_keepprobe++;
		t_template = tcpip_maketemplate(inp);
		if (t_template) {
			tcp_respond(tp, t_template->tt_ipgen,
				    &t_template->tt_t, (struct mbuf *)NULL,
				    tp->rcv_nxt, tp->snd_una - 1, 0);
			(void) m_free(dtom(t_template));
		}
		callout_reset(tp->tt_keep, tcp_keepintvl, tcp_timer_keep, tp);
	} else
		callout_reset(tp->tt_keep, tcp_keepidle, tcp_timer_keep, tp);

#ifdef TCPDEBUG
	if (inp->inp_socket->so_options & SO_DEBUG)
		tcp_trace(TA_USER, ostate, tp, (void *)0, (struct tcphdr *)0,
			  PRU_SLOWTIMO);
#endif
	INP_UNLOCK(inp);
	INP_INFO_WUNLOCK(&tcbinfo);
	splx(s);
	return;

dropit:
	tcpstat.tcps_keepdrops++;
	tp = tcp_drop(tp, ETIMEDOUT);

#ifdef TCPDEBUG
	if (tp && (tp->t_inpcb->inp_socket->so_options & SO_DEBUG))
		tcp_trace(TA_USER, ostate, tp, (void *)0, (struct tcphdr *)0,
			  PRU_SLOWTIMO);
#endif
	if (tp)
		INP_UNLOCK(tp->t_inpcb);
	INP_INFO_WUNLOCK(&tcbinfo);
	splx(s);
}

void
tcp_timer_persist(xtp)
	void *xtp;
{
	struct tcpcb *tp = xtp;
	int s;
	struct inpcb *inp;
#ifdef TCPDEBUG
	int ostate;

	ostate = tp->t_state;
#endif
	s = splnet();
	INP_INFO_WLOCK(&tcbinfo);
	inp = tp->t_inpcb;
	if (!inp) {
		INP_INFO_WUNLOCK(&tcbinfo);
		splx(s);
		return;
	}
	INP_LOCK(inp);
	//if (callout_pending(tp->tt_persist) || !callout_active(tp->tt_persist)){LUOYU
	//	INP_UNLOCK(inp);
	//	INP_INFO_WUNLOCK(&tcbinfo);
	//	splx(s);
	//	return;
	//}
	//callout_deactivate(tp->tt_persist);
	/*
	 * Persistance timer into zero window.
	 * Force a byte to be output, if possible.
	 */
	tcpstat.tcps_persisttimeo++;
	/*
	 * Hack: if the peer is dead/unreachable, we do not
	 * time out if the window is closed.  After a full
	 * backoff, drop the connection if the idle time
	 * (no responses to probes) reaches the maximum
	 * backoff that we would use if retransmitting.
	 */
	if (tp->t_rxtshift == TCP_MAXRXTSHIFT &&
	    ((ticks - tp->t_rcvtime) >= tcp_maxpersistidle ||
	     (ticks - tp->t_rcvtime) >= TCP_REXMTVAL(tp) * tcp_totbackoff)) {
		tcpstat.tcps_persistdrop++;
		tp = tcp_drop(tp, ETIMEDOUT);
		goto out;
	}
	tcp_setpersist(tp);
	tp->t_force = 1;
	(void) bsd_tcp_output(tp);
	tp->t_force = 0;

out:
#ifdef TCPDEBUG
	if (tp && tp->t_inpcb->inp_socket->so_options & SO_DEBUG)
		tcp_trace(TA_USER, ostate, tp, (void *)0, (struct tcphdr *)0,
			  PRU_SLOWTIMO);
#endif
	if (tp)
		INP_UNLOCK(inp);
	INP_INFO_WUNLOCK(&tcbinfo);
	splx(s);
}

void
tcp_timer_rexmt(xtp)
	void *xtp;
{
	struct tcpcb *tp = xtp;
	int s;
	int rexmt;
	int headlocked;
	struct inpcb *inp;
#ifdef TCPDEBUG
	int ostate;

	ostate = tp->t_state;
#endif
	s = splnet();
	INP_INFO_WLOCK(&tcbinfo);
	headlocked = 1;
	inp = tp->t_inpcb;
	if (!inp) {
		INP_INFO_WUNLOCK(&tcbinfo);
		splx(s);
		return;
	}
	INP_LOCK(inp);
	//if (callout_pending(tp->tt_rexmt) || !callout_active(tp->tt_rexmt)) {
	//	INP_UNLOCK(inp);
	//	INP_INFO_WUNLOCK(&tcbinfo);
	//	splx(s);
	//	return;
	//}
	//callout_deactivate(tp->tt_rexmt);
	tcp_free_sackholes(tp);
	/*
	 * Retransmission timer went off.  Message has not
	 * been acked within retransmit interval.  Back off
	 * to a longer retransmit interval and retransmit one segment.
	 */
	if (++tp->t_rxtshift > TCP_MAXRXTSHIFT) {
		tp->t_rxtshift = TCP_MAXRXTSHIFT;
		tcpstat.tcps_timeoutdrop++;
		tp = tcp_drop(tp, tp->t_softerror ?
			      tp->t_softerror : ETIMEDOUT);
		goto out;
	}
	INP_INFO_WUNLOCK(&tcbinfo);
	headlocked = 0;
	if (tp->t_rxtshift == 1) {
		/*
		 * first retransmit; record ssthresh and cwnd so they can
		 * be recovered if this turns out to be a "bad" retransmit.
		 * A retransmit is considered "bad" if an ACK for this
		 * segment is received within RTT/2 interval; the assumption
		 * here is that the ACK was already in flight.  See
		 * "On Estimating End-to-End Network Path Properties" by
		 * Allman and Paxson for more details.
		 */
		tp->snd_cwnd_prev = tp->snd_cwnd;
		tp->snd_ssthresh_prev = tp->snd_ssthresh;
		tp->snd_recover_prev = tp->snd_recover;
		if (IN_FASTRECOVERY(tp))
		  tp->t_flags |= TF_WASFRECOVERY;
		else
		  tp->t_flags &= ~TF_WASFRECOVERY;
		tp->t_badrxtwin = ticks + (tp->t_srtt >> (TCP_RTT_SHIFT + 1));
	}
	tcpstat.tcps_rexmttimeo++;
	if (tp->t_state == TCPS_SYN_SENT)
		rexmt = TCP_REXMTVAL(tp) * tcp_syn_backoff[tp->t_rxtshift];
	else
		rexmt = TCP_REXMTVAL(tp) * bsd_tcp_backoff[tp->t_rxtshift];
	TCPT_RANGESET(tp->t_rxtcur, rexmt,
		      tp->t_rttmin, TCPTV_REXMTMAX);
	/*
	 * Disable rfc1323 and rfc1644 if we havn't got any response to
	 * our third SYN to work-around some broken terminal servers
	 * (most of which have hopefully been retired) that have bad VJ
	 * header compression code which trashes TCP segments containing
	 * unknown-to-them TCP options.
	 */
	if ((tp->t_state == TCPS_SYN_SENT) && (tp->t_rxtshift == 3))
		tp->t_flags &= ~(TF_REQ_SCALE|TF_REQ_TSTMP|TF_REQ_CC);
	/*
	 * If we backed off this far, our srtt estimate is probably bogus.
	 * Clobber it so we'll take the next rtt measurement as our srtt;
	 * move the current srtt into rttvar to keep the current
	 * retransmit times until then.
	 */
	if (tp->t_rxtshift > TCP_MAXRXTSHIFT / 4) {
#ifdef INET6
		if ((tp->t_inpcb->inp_vflag & INP_IPV6) != 0)
			in6_losing(tp->t_inpcb);
		else
#endif
		tp->t_rttvar += (tp->t_srtt >> TCP_RTT_SHIFT);
		tp->t_srtt = 0;
	}
	tp->snd_nxt = tp->snd_una;
	tp->snd_recover = tp->snd_max;
	/*
	 * Force a segment to be sent.
	 */
	tp->t_flags |= TF_ACKNOW;
	/*
	 * If timing a segment in this window, stop the timer.
	 */
	tp->t_rtttime = 0;
	/*
	 * Close the congestion window down to one segment
	 * (we'll open it by one segment for each ack we get).
	 * Since we probably have a window's worth of unacked
	 * data accumulated, this "slow start" keeps us from
	 * dumping all that data as back-to-back packets (which
	 * might overwhelm an intermediate gateway).
	 *
	 * There are two phases to the opening: Initially we
	 * open by one mss on each ack.  This makes the window
	 * size increase exponentially with time.  If the
	 * window is larger than the path can handle, this
	 * exponential growth results in dropped packet(s)
	 * almost immediately.  To get more time between
	 * drops but still "push" the network to take advantage
	 * of improving conditions, we switch from exponential
	 * to linear window opening at some threshhold size.
	 * For a threshhold, we use half the current window
	 * size, truncated to a multiple of the mss.
	 *
	 * (the minimum cwnd that will give us exponential
	 * growth is 2 mss.  We don't allow the threshhold
	 * to go below this.)
	 */
	{
		u_int win = min(tp->snd_wnd, tp->snd_cwnd) / 2 / tp->t_maxseg;
		if (win < 2)
			win = 2;
		tp->snd_cwnd = tp->t_maxseg;
		tp->snd_ssthresh = win * tp->t_maxseg;
		tp->t_dupacks = 0;
	}
	EXIT_FASTRECOVERY(tp);
	(void) bsd_tcp_output(tp);

out:
#ifdef TCPDEBUG
	if (tp && (tp->t_inpcb->inp_socket->so_options & SO_DEBUG))
		tcp_trace(TA_USER, ostate, tp, (void *)0, (struct tcphdr *)0,
			  PRU_SLOWTIMO);
#endif
	if (tp)
		INP_UNLOCK(inp);
	if (headlocked)
		INP_INFO_WUNLOCK(&tcbinfo);
	splx(s);
}

