#include "bsdsys.h"
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
#include "bsdif.h"


MALLOC_DEFINE(M_CACHE, "cache", "Various Dynamically allocated caches");
MALLOC_DEFINE(M_DEVBUF, "devbuf", "device driver memory");
MALLOC_DEFINE(M_TEMP, "temp", "misc temporary data buffers");

/*
 * Zones.
 *
 * Mbuf Clusters (2K, contiguous) are allocated from the Cluster
 * Zone.  The Zone can be capped at kern.ipc.nmbclusters, if the
 * administrator so desires.
 *
 * Mbufs are allocated from a UMA Master Zone called the Mbuf
 * Zone.
 *
 * configures as a Secondary Zone to the Mbuf Master Zone,
 * thus sharing backend Slab kegs with the Mbuf Master Zone.
 *
 * Thus common-case allocations and locking are simplified:
 *
 *  m_clget()                m_getcl()
 *    |                         |
 *    |   .------------>[(Packet Cache)]    m_get(), m_gethdr()
 *    |   |             [     Packet   ]            |
 *  [(Cluster Cache)]   [    Secondary ]   [ (Mbuf Cache)     ]
 *  [ Cluster Zone  ]   [     Zone     ]   [ Mbuf Master Zone ]
 *        |                       \________         |
 *  [ Cluster Keg   ]                      \       /
 *        |    	                         [ Mbuf Keg   ]
 *  [ Cluster Slabs ]                         |
 *        |                              [ Mbuf Slabs ]
 *         \____________(VM)_________________/
 */
int nmbclusters = 1024 + 64;/* one user */
struct mbstat mbstat;

uma_zone_t	zone_mbuf;
uma_zone_t	zone_clust;
uma_zone_t	zone_pack;


/*
 * Local prototypes.
 */
static int	mb_ctor_mbuf(void *, int, void *, int);
static int	mb_ctor_clust(void *, int, void *, int);
static int	mb_ctor_pack(void *, int, void *, int);
static void	mb_dtor_mbuf(void *, int, void *);
static void	mb_dtor_clust(void *, int, void *);	/* XXX */
static void	mb_dtor_pack(void *, int, void *);	/* XXX */
static int	mb_init_pack(void *, int, int);
static void	mb_fini_pack(void *, int);

static void	mb_reclaim(void *);
void	mbuf_init(void *);

void
mbuf_init(void *dummy)
{
    struct mbuf *m;
    /*
     * Configure UMA zones for Mbufs, Clusters, and Packets.
     */
    zone_mbuf = uma_zcreate("Mbuf", MSIZE, 100, mb_ctor_mbuf, mb_dtor_mbuf,
                            UMA_ALIGN_PTR, UMA_ZONE_MAXBUCKET);
    zone_clust = uma_zcreate("MbufClust", MCLBYTES, 10, mb_ctor_clust,
                             mb_dtor_clust, UMA_ALIGN_PTR, UMA_ZONE_REFCNT);
    if (nmbclusters > 0)
        uma_zone_set_max(zone_clust, nmbclusters);
    zone_pack = uma_zsecond_create("Packet", 100, mb_ctor_pack, mb_dtor_pack,
                                   zone_mbuf);

    //MGET(m, M_NOWAIT, MT_DATA);
    //m_free(m);

    m = m_getcl(M_NOWAIT, M_NOWAIT, (MT_DATA & M_PKTHDR));
    /* uma_prealloc() goes here */

    /*
     * Hook event handler for low-memory situation, used to
     * drain protocols and push data back to the caches (UMA
     * later pushes it back to VM).
     */
    //EVENTHANDLER_REGISTER(vm_lowmem, mb_reclaim, NULL,
    //    EVENTHANDLER_PRI_FIRST);

    /*
     * [Re]set counters and local statistics knobs.
     * XXX Some of these should go and be replaced, but UMA stat
     * gathering needs to be revised.
     */
    mbstat.m_mbufs = 0;
    mbstat.m_mclusts = 0;
    mbstat.m_drain = 0;
    mbstat.m_msize = MSIZE;
    mbstat.m_mclbytes = MCLBYTES;
    mbstat.m_minclsize = MINCLSIZE;
    mbstat.m_mlen = MLEN;
    mbstat.m_mhlen = MHLEN;
    mbstat.m_numtypes = MT_NTYPES;

    mbstat.m_mcfail = mbstat.m_mpfail = 0;
    mbstat.sf_iocnt = 0;
    mbstat.sf_allocwait = mbstat.sf_allocfail = 0;
}
/*
 * Constructor for Mbuf master zone.
 *
 * The 'arg' pointer points to a mb_args structure which
 * contains call-specific information required to support the
 * mbuf allocation API.
 */
static int
mb_ctor_mbuf(void *mem, int size, void *arg, int how)
{
    struct mbuf *m;
    struct mb_args *args;
#ifdef MAC
    int error;
#endif
    int flags;
    short type;

    m = (struct mbuf *)mem;
    args = (struct mb_args *)arg;
    flags = args->flags;
    type = args->type;

    m->m_type = type;
    m->m_next = NULL;
    m->m_nextpkt = NULL;
    m->m_flags = flags;
    if (flags & M_PKTHDR)
    {
        m->m_data = m->m_pktdat;
        m->m_pkthdr.rcvif = NULL;
        m->m_pkthdr.csum_flags = 0;
        SLIST_INIT(&m->m_pkthdr.tags);
    }
    else
        m->m_data = m->m_dat;
    mbstat.m_mbufs += 1;	/* XXX */
    return (0);
}

/*
 * The Mbuf master zone and Packet secondary zone destructor.
 */
static void
mb_dtor_mbuf(void *mem, int size, void *arg)
{
    struct mbuf *m;

    m = (struct mbuf *)mem;
    if ((m->m_flags & M_PKTHDR) != 0)
        m_tag_delete_chain(m, NULL);
    mbstat.m_mbufs -= 1;	/* XXX */
}

/* XXX Only because of stats */
static void
mb_dtor_pack(void *mem, int size, void *arg)
{
    struct mbuf *m;

    m = (struct mbuf *)mem;
    if ((m->m_flags & M_PKTHDR) != 0)
        m_tag_delete_chain(m, NULL);
    mbstat.m_mbufs -= 1;	/* XXX */
    mbstat.m_mclusts -= 1;	/* XXX */
}

/*
 * The Cluster zone constructor.
 *
 * Here the 'arg' pointer points to the Mbuf which we
 * are configuring cluster storage for.
 */
static int
mb_ctor_clust(void *mem, int size, void *arg, int how)
{
    struct mbuf *m;

    m = (struct mbuf *)arg;
    m->m_ext.ext_buf = (caddr_t)mem;
    m->m_data = m->m_ext.ext_buf;
    m->m_flags |= M_EXT;
    m->m_ext.ext_free = NULL;
    m->m_ext.ext_args = NULL;
    m->m_ext.ext_size = MCLBYTES;
    m->m_ext.ext_type = EXT_CLUSTER;
    //m->m_ext.ref_cnt = (u_int *)uma_find_refcnt(zone_clust,
    //    m->m_ext.ext_buf);
    //*(m->m_ext.ref_cnt) = 1;
    m->m_ext.ref_cnt = 1;
    mbstat.m_mclusts += 1;	/* XXX */
    return (0);
}

/* XXX */
static void
mb_dtor_clust(void *mem, int size, void *arg)
{
    mbstat.m_mclusts -= 1;	/* XXX */
}

/*
 * The Packet secondary zone's init routine, executed on the
 * object's transition from keg slab to zone cache.
 */
static int
mb_init_pack(void *mem, int size, int how)
{
    struct mbuf *m;

    m = (struct mbuf *)mem;
    m->m_ext.ext_buf = NULL;
    uma_alloc_arg(zone_clust, m, how);
    if (m->m_ext.ext_buf == NULL)
        return (ENOMEM);
    mbstat.m_mclusts -= 1;	/* XXX */
    return (0);
}

/*
 * The Packet secondary zone's fini routine, executed on the
 * object's transition from zone cache to keg slab.
 */
static void
mb_fini_pack(void *mem, int size)
{
    struct mbuf *m;

    m = (struct mbuf *)mem;
    uma_free_arg(zone_clust, m->m_ext.ext_buf, NULL);
    m->m_ext.ext_buf = NULL;
    mbstat.m_mclusts += 1;	/* XXX */
}

/*
 * The "packet" keg constructor.
 */
static int
mb_ctor_pack(void *mem, int size, void *arg, int how)
{
    struct mbuf *m;
    struct mb_args *args;
    int flags;
    short type;
    mb_init_pack(mem, size, how);//LUOYU added for new Memory system
    m = (struct mbuf *)mem;
    args = (struct mb_args *)arg;
    flags = args->flags;
    type = args->type;

    m->m_type = type;
    m->m_next = NULL;
    m->m_nextpkt = NULL;
    m->m_data = m->m_ext.ext_buf;
    m->m_flags = flags | M_EXT;
    m->m_ext.ext_free = NULL;
    m->m_ext.ext_args = NULL;
    m->m_ext.ext_size = MCLBYTES;
    m->m_ext.ext_type = EXT_PACKET;
    m->m_ext.ref_cnt = 1;

    if (flags & M_PKTHDR)
    {
        m->m_pkthdr.rcvif = NULL;
        m->m_pkthdr.csum_flags = 0;
        SLIST_INIT(&m->m_pkthdr.tags);
    }
    mbstat.m_mbufs += 1;	/* XXX */
    mbstat.m_mclusts += 1;	/* XXX */
    return (0);
}

/*
 * This is the protocol drain routine.
 *
 * No locks should be held when this is called.  The drain routines have to
 * presently acquire some locks which raises the possibility of lock order
 * reversal.
 */
static void
mb_reclaim(void *junk)
{
    struct domain *dp;
    struct protosw *pr;


    mbstat.m_drain++;
    for (dp = domains; dp != NULL; dp = dp->dom_next)
        for (pr = dp->dom_protosw; pr < dp->dom_protoswNPROTOSW; pr++)
            if (pr->pr_drain != NULL)
                (*pr->pr_drain)();
}
