#ifndef __H_UM__
#define __H_UM__

/* 
 * Item constructor
 *
 * Arguments:
 *	item  A pointer to the memory which has been allocated.
 *	arg   The arg field passed to uma_zalloc_arg
 *	size  The size of the allocated item
 *	flags See zalloc flags
 * 
 * Returns:
 *	0      on success
 *      errno  on failure
 *
 * Discussion:
 *	The constructor is called just before the memory is returned
 *	to the user. It may block if necessary.
 */
typedef int (*uma_ctor)(void *mem, int size, void *arg, int flags);
/*
 * Item destructor
 *
 * Arguments:
 *	item  A pointer to the memory which has been allocated.
 *	size  The size of the item being destructed.
 *	arg   Argument passed through uma_zfree_arg
 * 
 * Returns:
 *	Nothing
 *
 * Discussion:
 *	The destructor may perform operations that differ from those performed
 *	by the initializer, but it must leave the object in the same state.
 *	This IS type stable storage.  This is called after EVERY zfree call.
 */
typedef void (*uma_dtor)(void *mem, int size, void *arg);
/* 
 * Item initializer
 *
 * Arguments:
 *	item  A pointer to the memory which has been allocated.
 *	size  The size of the item being initialized.
 *	flags See zalloc flags
 * 
 * Returns:
 *	0      on success
 *      errno  on failure
 *
 * Discussion:
 *	The initializer is called when the memory is cached in the uma zone. 
 *	this should be the same state that the destructor leaves the object in.
 */
//typedef int (*uma_init)(void *mem, int size, int flags);
/*
 * Item discard function
 *
 * Arguments:
 * 	item  A pointer to memory which has been 'freed' but has not left the 
 *	      zone's cache.
 *	size  The size of the item being discarded.
 *
 * Returns:
 *	Nothing
 *
 * Discussion:
 *	This routine is called when memory leaves a zone and is returned to the
 *	system for other uses.  It is the counter part to the init function.
 */
//typedef void (*uma_fini)(void *mem, int size);
typedef struct uma_item {
	char memVerifyBelt[4];    /* SHOULD BE "UMA\0" */
	struct {								\
		struct uma_item *le_next;	/* next element */			\
		struct uma_item **le_prev;	/* address of previous next element */	\
	}item_link;
	void *data_ptr;
}uma_item_t;
/*
 * Zone management structure 
 *
 * TODO: Optimize for cache line size
 *
 */
struct uma_zone {
	u_int32_t	bUsed;		
	char		uz_name[16];	/* Text name of the zone */
	struct mtx	*uz_lock;	/* Lock for the zone (keg's lock) */
	u_int32_t	uk_recurse;	/* Allocation recursion count */
	u_int32_t	uk_align;	/* Alignment mask */
	u_int32_t	uk_pages;	/* Total page count */
	u_int32_t	uk_free;	/* Count of items free in slabs */
	u_int32_t	uk_size;	/* Requested size of each item */
	u_int32_t	uk_rsize;	/* Real size of each item */
	u_int32_t	uk_maxpages;	/* Maximum number of pages to alloc */

	//u_int16_t	uk_pgoff;	/* Offset to uma_slab struct */
	//u_int16_t	uk_ppera;	/* pages per allocation from backend */
	//u_int16_t	uk_ipers;	/* Items per slab */
	u_int16_t	uk_flags;	/* Internal flags */
	//LIST_ENTRY(uma_zone)	uz_link;	/* List of all zones in keg */
	//struct {								\
	//	struct uma_zone *le_next;	/* next element */			\
	//	struct uma_zone **le_prev;	/* address of previous next element */	\
	//}uz_link;
	struct {								\
		struct uma_item *lh_first;	/* header element */			\
		
	}free_item_header;
	struct {								\
		struct uma_item *lh_first;	/* header element */			\
	}used_item_header;
	uma_ctor	uz_ctor;	/* Constructor for each allocation */
	uma_dtor	uz_dtor;	/* Destructor */

	//unsigned __int64	uz_allocs;	/* Total number of allocations */
	//unsigned short	uz_fills;	/* Outstanding bucket fills */
	//unsigned short	uz_count;	/* Highest value ub_ptr can have */
};
typedef struct uma_zone * uma_zone_t;

/* Sorry for the union, but space efficiency is important */
struct uma_slab_head {
	
	union {
		//LIST_ENTRY(uma_slab)	_us_link;	/* slabs in zone */
		struct {								\
		struct uma_slab *le_next;	/* next element */			\
		struct uma_slab **le_prev;	/* address of previous next element */	\
		}_us_link;

		unsigned long	_us_size;	/* Size of allocation */
	} us_type;
	//SLIST_ENTRY(uma_slab)	us_hlink;	/* Link for hash table */
	struct {								\
	struct uma_slab *sle_next;	/* next element */			\
	}us_hlink;

	u_int8_t	*us_data;		/* First item */
	u_int8_t	us_flags;		/* Page flags see uma.h */
	u_int8_t	us_freecount;	/* How many are free? */
	u_int8_t	us_firstfree;	/* First free item index */
};

/* The standard slab structure */
struct uma_slab {
	struct uma_slab_head	us_head;	/* slab header data */
	struct {
		u_int8_t	us_item;
	} us_freelist[1];			/* actual number bigger */
};
/* Function proto types */


/* 
 * Item constructor
 *
 * Arguments:
 *	item  A pointer to the memory which has been allocated.
 *	arg   The arg field passed to uma_zalloc_arg
 *	size  The size of the allocated item
 *	flags See zalloc flags
 * 
 * Returns:
 *	0      on success
 *      errno  on failure
 *
 * Discussion:
 *	The constructor is called just before the memory is returned
 *	to the user. It may block if necessary.
 */
typedef int (*uma_ctor)(void *mem, int size, void *arg, int flags);

/*
 * Item destructor
 *
 * Arguments:
 *	item  A pointer to the memory which has been allocated.
 *	size  The size of the item being destructed.
 *	arg   Argument passed through uma_zfree_arg
 * 
 * Returns:
 *	Nothing
 *
 * Discussion:
 *	The destructor may perform operations that differ from those performed
 *	by the initializer, but it must leave the object in the same state.
 *	This IS type stable storage.  This is called after EVERY zfree call.
 */
typedef void (*uma_dtor)(void *mem, int size, void *arg);

/* 
 * Item initializer
 *
 * Arguments:
 *	item  A pointer to the memory which has been allocated.
 *	size  The size of the item being initialized.
 *	flags See zalloc flags
 * 
 * Returns:
 *	0      on success
 *      errno  on failure
 *
 * Discussion:
 *	The initializer is called when the memory is cached in the uma zone. 
 *	this should be the same state that the destructor leaves the object in.
 */
typedef int (*uma_init)(void *mem, int size, int flags);

/*
 * Item discard function
 *
 * Arguments:
 * 	item  A pointer to memory which has been 'freed' but has not left the 
 *	      zone's cache.
 *	size  The size of the item being discarded.
 *
 * Returns:
 *	Nothing
 *
 * Discussion:
 *	This routine is called when memory leaves a zone and is returned to the
 *	system for other uses.  It is the counter part to the init function.
 */
typedef void (*uma_fini)(void *mem, int size);

/*
 * What's the difference between initializing and constructing?
 *
 * The item is initialized when it is cached, and this is the state that the 
 * object should be in when returned to the allocator. The purpose of this is
 * to remove some code which would otherwise be called on each allocation by
 * utilizing a known, stable state.  This differs from the constructor which
 * will be called on EVERY allocation.
 *
 * For example, in the initializer you may want to initialize embeded locks,
 * NULL list pointers, set up initial states, magic numbers, etc.  This way if
 * the object is held in the allocator and re-used it won't be necessary to
 * re-initialize it.
 *
 * The constructor may be used to lock a data structure, link it on to lists,
 * bump reference counts or total counts of outstanding structures, etc.
 *
 */


/* Function proto types */

/*
 * Create a new uma zone
 *
 * Arguments:
 *	name  The text name of the zone for debugging and stats, this memory
 *		should not be freed until the zone has been deallocated.
 *	size  The size of the object that is being created.
 *	ctor  The constructor that is called when the object is allocated
 *	dtor  The destructor that is called when the object is freed.
 *	init  An initializer that sets up the initial state of the memory.
 *	fini  A discard function that undoes initialization done by init.
 *		ctor/dtor/init/fini may all be null, see notes above.
 *	align A bitmask that corisponds to the requested alignment
 *		eg 4 would be 0x3
 *	flags A set of parameters that control the behavior of the zone
 *
 * Returns:
 *	A pointer to a structure which is intended to be opaque to users of
 *	the interface.  The value may be null if the wait flag is not set.
 */
uma_zone_t uma_zcreate(char *name, size_t size, int num, uma_ctor ctor, uma_dtor dtor,
			int align,
			u_int16_t flags);

/*
 * Create a secondary uma zone
 *
 * Arguments:
 *	name  The text name of the zone for debugging and stats, this memory
 *		should not be freed until the zone has been deallocated.
 *	ctor  The constructor that is called when the object is allocated
 *	dtor  The destructor that is called when the object is freed.
 *	zinit  An initializer that sets up the initial state of the memory
 *		as the object passes from the Keg's slab to the Zone's cache.
 *	zfini  A discard function that undoes initialization done by init
 *		as the object passes from the Zone's cache to the Keg's slab.
 *
 *		ctor/dtor/zinit/zfini may all be null, see notes above.
 *		Note that the zinit and zfini specified here are NOT
 *		exactly the same as the init/fini specified to uma_zcreate()
 *		when creating a master zone.  These zinit/zfini are called
 *		on the TRANSITION from keg to zone (and vice-versa). Once
 *		these are set, the primary zone may alter its init/fini
 *		(which are called when the object passes from VM to keg)
 *		using uma_zone_set_init/fini()) as well as its own
 *		zinit/zfini (unset by default for master zone) with
 *		uma_zone_set_zinit/zfini() (note subtle 'z' prefix).
 *
 *	master  A reference to this zone's Master Zone (Primary Zone),
 *		which contains the backing Keg for the Secondary Zone
 *		being added.
 *
 * Returns:
 *	A pointer to a structure which is intended to be opaque to users of
 *	the interface.  The value may be null if the wait flag is not set.
 */
uma_zone_t uma_zsecond_create(char *name, int num, uma_ctor ctor, uma_dtor dtor,
		    uma_zone_t master);

/*
 * Definitions for uma_zcreate flags
 *
 * These flags share space with UMA_ZFLAGs in uma_int.h.  Be careful not to
 * overlap when adding new features.  0xf000 is in use by uma_int.h.
 */
#define UMA_ZONE_PAGEABLE	0x0001	/* Return items not fully backed by
					   physical memory XXX Not yet */
#define UMA_ZONE_ZINIT		0x0002	/* Initialize with zeros */
#define UMA_ZONE_STATIC		0x0004	/* Staticly sized zone */
#define UMA_ZONE_OFFPAGE	0x0008	/* Force the slab structure allocation
					   off of the real memory */
#define UMA_ZONE_MALLOC		0x0010	/* For use by malloc(9) only! */
#define UMA_ZONE_NOFREE		0x0020	/* Do not free slabs of this type! */
#define UMA_ZONE_MTXCLASS	0x0040	/* Create a new lock class */
#define	UMA_ZONE_VM		0x0080	/*
					 * Used for internal vm datastructures
					 * only.
					 */
#define	UMA_ZONE_HASH		0x0100	/*
					 * Use a hash table instead of caching
					 * information in the vm_page.
					 */
#define	UMA_ZONE_SECONDARY	0x0200	/* Zone is a Secondary Zone */
#define	UMA_ZONE_REFCNT		0x0400	/* Allocate refcnts in slabs */
#define	UMA_ZONE_MAXBUCKET	0x0800	/* Use largest buckets */

/* Definitions for align */
#define UMA_ALIGN_PTR	(sizeof(void *) - 1)	/* Alignment fit for ptr */
#define UMA_ALIGN_LONG	(sizeof(long) - 1)	/* "" long */
#define UMA_ALIGN_INT	(sizeof(int) - 1)	/* "" int */
#define UMA_ALIGN_SHORT	(sizeof(short) - 1)	/* "" short */
#define UMA_ALIGN_CHAR	(sizeof(char) - 1)	/* "" char */
#define UMA_ALIGN_CACHE	(16 - 1)		/* Cache line size align */

/*
 * Destroys an empty uma zone.  If the zone is not empty uma complains loudly.
 *
 * Arguments:
 *	zone  The zone we want to destroy.
 *
 */
void uma_zdestroy(uma_zone_t zone);

/*
 * Allocates an item out of a zone
 *
 * Arguments:
 *	zone  The zone we are allocating from
 *	arg   This data is passed to the ctor function
 *	flags See sys/malloc.h for available flags.
 *
 * Returns:
 *	A non null pointer to an initialized element from the zone is
 *	garanteed if the wait flag is M_WAITOK, otherwise a null pointer may be
 *	returned if the zone is empty or the ctor failed.
 */

void *uma_alloc_arg(uma_zone_t zone, void *arg, int flags);

/*
 * Allocates an item out of a zone without supplying an argument
 *
 * This is just a wrapper for uma_zalloc_arg for convenience.
 *
 */
static __inline void *uma_alloc(uma_zone_t zone, int flags);

static __inline void *
uma_alloc(uma_zone_t zone, int flags)
{
	return uma_alloc_arg(zone, NULL, flags);
}

/*
 * Frees an item back into the specified zone.
 *
 * Arguments:
 *	zone  The zone the item was originally allocated out of.
 *	item  The memory to be freed.
 *	arg   Argument passed to the destructor
 *
 * Returns:
 *	Nothing.
 */

void uma_free_arg(uma_zone_t zone, void *item, void *arg);

/*
 * Frees an item back to a zone without supplying an argument
 *
 * This is just a wrapper for uma_zfree_arg for convenience.
 *
 */
static __inline void uma_free(uma_zone_t zone, void *item);

static __inline void
uma_free(uma_zone_t zone, void *item)
{
	uma_free_arg(zone, item, NULL);
}

/*
 * XXX The rest of the prototypes in this header are h0h0 magic for the VM.
 * If you think you need to use it for a normal zone you're probably incorrect.
 */



/*
 * Sets up the uma allocator. (Called by vm_mem_init)
 *
 * Arguments:
 *	bootmem  A pointer to memory used to bootstrap the system.
 *
 * Returns:
 *	Nothing
 *
 * Discussion:
 *	This memory is used for zones which allocate things before the
 *	backend page supplier can give us pages.  It should be
 *	UMA_SLAB_SIZE * UMA_BOOT_PAGES bytes. (see uma_int.h)
 *
 */

void uma_startup(void *bootmem);

/*
 * Finishes starting up the allocator.  This should
 * be called when kva is ready for normal allocs.
 *
 * Arguments:
 *	None
 *
 * Returns:
 *	Nothing
 *
 * Discussion:
 *	uma_startup2 is called by kmeminit() to enable us of uma for malloc.
 */
 
void uma_startup2(void);

/*
 * Sets a high limit on the number of items allowed in a zone
 *
 * Arguments:
 *	zone  The zone to limit
 *
 * Returns:
 *	Nothing
 */
void uma_zone_set_max(uma_zone_t zone, int nitems);

#endif /* __UM__ */
