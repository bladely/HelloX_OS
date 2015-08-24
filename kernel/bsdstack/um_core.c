
#include "bsdsys.h"

#include "param.h"
//#include <sys/systm.h>
//#include <sys/kernel.h>
//#include <sys/types.h>
#include "kqueue.h"
#include "kmalloc.h"
#include "stdlib.h"
#include "priority.h"
//#include <sys/ktr.h>
//#include <sys/sysctl.h>
//#include <sys/proc.h>
//#include <sys/smp.h>
//#include <sys/vmmeter.h>

//#include <vm/vm.h>
//#include <vm/vm_object.h>
//#include <vm/vm_page.h>
//#include <vm/vm_param.h>
//#include <vm/vm_map.h>
//#include <vm/vm_kern.h>
//#include <vm/vm_extern.h>
//#include <vm/uma.h>
#include "uma.h"
//#include <vm/uma_dbg.h>

//#include <machine/vmparam.h>

///*
// * flags to malloc.
// */
//#define	M_NOWAIT	0x0001		/* do not block */
//#define	M_WAITOK	0x0002		/* ok to block */
//#define	M_ZERO		0x0100		/* bzero the allocation */
//#define	M_NOVM		0x0200		/* don't ask VM for pages */
/*
 * This is the zone and keg from which all zones are spawned.  The idea is that
 * even the zone & keg heads are allocated from the allocator, so we use the
 * bss section to bootstrap us.
 */
static struct uma_zone masterzone_k;
static struct uma_zone umzones;
static uma_zone_t kegs = &masterzone_k;
static uma_zone_t g_zones;// = &umzones;

/* This is the zone from which all of uma_slab_t's are allocated. */
static uma_zone_t slabzone;
static uma_zone_t slabrefzone;	/* With refcounters (for UMA_ZONE_REFCNT) */

/*
 * The initial hash tables come out of this zone so they can be allocated
 * prior to malloc coming up.
 */
static uma_zone_t hashzone;


/*
 * Are we allowed to allocate buckets?
 */
static int bucketdisable = 1;

/* Maximum number of allowed items-per-slab if the slab header is OFFPAGE */
static u_int uma_max_ipers;
static u_int uma_max_ipers_ref;

/*
 * This is the handle used to schedule events that need to happen
 * outside of the allocation fast path.
 */
//static struct callout uma_callout;
#define	UMA_TIMEOUT	20		/* Seconds for callout interval. */

/*
 * This structure is passed as the zone ctor arg so that I don't have to create
 * a special allocation function just for zones.
 */
struct uma_zctor_args
{
    char *name;
    size_t size;
    int number;
    uma_ctor ctor;
    uma_dtor dtor;
    int align;
    u_int16_t flags;
};

struct uma_kctor_args
{
    uma_zone_t zone;
    size_t size;
    int align;
    u_int16_t flags;
};

struct uma_bucket_zone
{
    uma_zone_t	ubz_zone;
    char		*ubz_name;
    int		ubz_entries;
};

static void *uma_zalloc_internal(uma_zone_t, void *, int);
static void uma_zfree_internal(uma_zone_t, void *, void *);
uma_zone_t	zone_mbuf;
uma_zone_t	zone_clust;
uma_zone_t	zone_pack;
#if 0
/*
 * Local prototypes.
 */
static int	mb_ctor_mbuf(void *, int, void *, int);
static int	mb_ctor_clust(void *, int, void *, int);
static int	mb_ctor_pack(void *, int, void *, int);
static void	mb_dtor_mbuf(void *, int, void *);
static void	mb_dtor_clust(void *, int, void *);	/* XXX */
static void	mb_dtor_pack(void *, int, void *);	/* XXX */
#endif
uma_zone_t
uma_zcreate_header_room(int maxZones)
{
    struct uma_zone *zone_base = (uma_zone_t)malloc(sizeof(struct uma_zone) * maxZones);
    bzero(zone_base, sizeof(struct uma_zone) * maxZones);
    return zone_base;
}
#define MAX_ZONES_NUM 50
void uma_startup(void *freeBase)
{
    g_zones = uma_zcreate_header_room(MAX_ZONES_NUM);
#if 0
    /*
     * Configure UMA zones for Mbufs, Clusters, and Packets.
     */
    zone_mbuf = uma_zcreate("Mbuf", MSIZE, 10, mb_ctor_mbuf, mb_dtor_mbuf,
                            UMA_ALIGN_PTR, UMA_ZONE_MAXBUCKET);
    zone_clust = uma_zcreate("MbufClust", MCLBYTES, 2, mb_ctor_clust,
                             mb_dtor_clust, UMA_ALIGN_PTR, UMA_ZONE_REFCNT);
    zone_pack = uma_zsecond_create("Packet", 10, mb_ctor_pack, mb_dtor_pack,
                                   zone_mbuf);
#endif
    return ;
}

uma_zone_t
uma_zcreate(char *name, size_t size, int num, uma_ctor ctor, uma_dtor dtor,
            int align, u_int16_t flags)

{
#if 1
    struct uma_zctor_args args;
    uma_zone_t cur = NULL;
    int i = 0;
    /* This stuff is essential for the zone ctor */
    if (strlen(name) > 16)
    {
        return NULL;
    }
    args.name = name;
    args.size = size;
    args.number = num;
    args.ctor = ctor;
    args.dtor = dtor;
    args.align = align;
    args.flags = flags | UMA_ZONE_SECONDARY;

    for (i = 0; i < MAX_ZONES_NUM; i ++)
    {
        cur = &g_zones[i];
        if (cur->bUsed)
        {
            continue;
        }
        if (i == MAX_ZONES_NUM)
        {
            printf("!!!!!!!!!!!!!!!!!    overused zones   !!!!!!!!!!!!!!");
            return NULL;
        }
        break;
    }
    return (uma_zone_t)uma_zalloc_internal(cur, &args, M_WAITOK);
#endif
}

/* See uma.h */
uma_zone_t
uma_zsecond_create(char *name, int num, uma_ctor ctor, uma_dtor dtor,
                   uma_zone_t master)
{
#if 1
    struct uma_zctor_args args;
    int i;
    uma_zone_t cur = NULL;
    args.name = name;
    args.size = master->uk_size;
    args.number = num;
    args.ctor = ctor;
    args.dtor = dtor;
    args.align = master->uk_align;
    args.flags = master->uk_flags | UMA_ZONE_SECONDARY;

    for (i = 0; i < MAX_ZONES_NUM; i ++)
    {
        cur = &g_zones[i];
        if (cur->bUsed)
        {
            continue;
        }
        if (i == MAX_ZONES_NUM)
        {
            printf("!!!!!!!!!!!!!!!!!    overused zones   !!!!!!!!!!!!!!");
            return NULL;
        }
        break;
    }
    return (uma_zone_t)uma_zalloc_internal(cur, &args, M_WAITOK);
#endif
}

/* See uma.h */
void
uma_zdestroy(uma_zone_t zone)
{
    uma_zfree_internal(g_zones, zone, NULL);
}
/*
 * Zone header ctor.  This initializes all fields, locks, etc.
 *
 * Arguments/Returns follow uma_ctor specifications
 *	udata  Actually uma_zctor_args
 */

static int
zone_ctor(void *mem, int size, void *udata, int flags)
{
    struct uma_zctor_args *arg = (struct uma_zctor_args *)udata;
    uma_zone_t zone = (uma_zone_t)mem;

    bzero(zone, sizeof(struct uma_zone));
    strncpy(zone->uz_name, arg->name, strlen(arg->name));
    zone->uz_name[strlen(arg->name)] = 0;
    zone->uz_ctor = arg->ctor;
    zone->uz_dtor = arg->dtor;
    zone->uk_size = arg->size;
    zone->uk_flags = flags;
    zone->uk_free = arg->number;
    zone->uk_align = arg->align;
    return (0);
}
/*
 * Allocates an item for an internal zone
 *
 * Arguments
 *	zone   The zone to alloc for.
 *	udata  The data to be passed to the constructor.
 *	flags  M_WAITOK, M_NOWAIT, M_ZERO.
 *
 * Returns
 *	NULL if there is no memory and M_NOWAIT is set
 *	An item if successful
 */

static void *
uma_zalloc_internal(uma_zone_t zone, void *udata, int flags)
{
    struct uma_zctor_args *args = (struct uma_zctor_args *)udata;
    size_t item_size = (sizeof(struct uma_item) + args->size) ;
    void *slotBase = malloc(item_size * args->number);
    uma_item_t *currentItem = (uma_item_t *)slotBase;
    int i;

    zone_ctor(zone, args->size, args, flags);
    zone->bUsed = TRUE;


    for (i = 0; i < args->number; i ++)
    {
        char *ptmp = NULL;
        strncpy(currentItem->memVerifyBelt, "UMA", 3);
        currentItem->memVerifyBelt[3] = 0;
        currentItem->data_ptr = (char *)currentItem + sizeof(uma_item_t);
        currentItem->item_link.le_next = NULL;
        currentItem->item_link.le_prev = NULL;
        LIST_INSERT_HEAD(&zone->free_item_header, currentItem, item_link);
        ptmp = (char *)currentItem;
        ptmp += item_size;
        currentItem = (uma_item_t *)ptmp;
    }
    return zone;
}
/* See uma.h */
void
uma_zone_set_max(uma_zone_t zone, int nitems)
{
    //NOTHING TO DO;
}

/* See uma.h */
void
uma_free_arg(uma_zone_t zone, void *data_ptr, void *udata)
{
    /* Move a node from used list to free list */
    uma_item_t *item = (uma_item_t *)((int)data_ptr - sizeof(uma_item_t));
    if (strncmp(item->memVerifyBelt, "UMA", 3) != 0)
    {
        /*******************    PANIC !!!    ***************/
        return;
    }
    LIST_REMOVE(item, item_link);
    LIST_INSERT_HEAD(&zone->free_item_header, item, item_link);

    if (zone->uz_ctor != NULL)
    {
        zone->uz_dtor(item->data_ptr, zone->uk_size, udata);
    }
    return;
}

/*
 * Frees an item to an INTERNAL zone or allocates a free bucket
 *
 * Arguments:
 *	zone   The zone to free to
 *	item   The item we're freeing
 *	udata  User supplied data for the dtor
 *	skip   Skip dtors and finis
 */
static void
uma_zfree_internal(uma_zone_t zone, void *item, void *udata)
{

}

/* See uma.h */
void *
uma_alloc_arg(uma_zone_t zone, void *udata, int flags)
{
    /* Move a node from free list to used list */
    uma_item_t *firstItem = LIST_FIRST(&zone->free_item_header);
    if (firstItem == NULL)
    {
        return NULL;
    }
    LIST_REMOVE(firstItem, item_link);
    LIST_INSERT_HEAD(&zone->used_item_header, firstItem, item_link);

    if (zone->uz_ctor != NULL)
    {
        if (zone->uz_ctor(firstItem->data_ptr, zone->uk_size, udata, flags) != 0)
        {
            uma_free(zone, firstItem->data_ptr);
        }
    }
    if (flags & M_ZERO)
        bzero(firstItem->data_ptr, zone->uk_size);
    return firstItem->data_ptr;
}


#if 0
struct mbstat mbstat;
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
    {
        //m_tag_delete_chain(m, NULL); LUOYU
    }
    mbstat.m_mbufs -= 1;	/* XXX */
}

/* XXX Only because of stats */
static void
mb_dtor_pack(void *mem, int size, void *arg)
{
    struct mbuf *m;

    m = (struct mbuf *)mem;
    if ((m->m_flags & M_PKTHDR) != 0)
    {
        //m_tag_delete_chain(m, NULL); LUOYU
    }
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
        return 12;// (ENOMEM);
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
    mb_init_pack(mem, size, how);
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



void *test_mbuf()
{
    mbuf *m;
    //MGET(m, M_NOWAIT, MT_DATA);
    //m_free(m);

    //m = m_getcl(M_NOWAIT, M_NOWAIT, (MT_DATA & M_PKTHDR));
    MGETHDR(m, M_DONTWAIT, MT_DATA);
    m->m_pkthdr.rcvif = NULL;

    m->m_pkthdr.len = m->m_len = MHLEN + 2;
    MCLGET(m, M_DONTWAIT);
    return m;
}
#endif