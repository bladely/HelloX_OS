#include "bsdsys.h"
#include "uio.h"
#include "stdio.h"
#include "libkern.h"
#include "sysproto.h"
#include "kevent.h"
#include "priority.h"
#include "socketvar.h"
static struct mtx	knlist_lock;


void
knlist_init(struct knlist *knl, struct mtx *mtx)
{

    //if (mtx == NULL)
    //	knl->kl_lock = &knlist_lock;
    //else
    //	knl->kl_lock = mtx;

    SLIST_INIT(&knl->kl_list);
}

void
knlist_destroy(struct knlist *knl)
{


    //knl->kl_lock = NULL;
    SLIST_INIT(&knl->kl_list);
}
static void
knlist_remove_kq(struct knlist *knl, struct knote *kn, int knlislocked, int kqislocked)
{
    KASSERT(!(!!kqislocked && !knlislocked), ("kq locked w/o knl locked"));

    SLIST_REMOVE(&knl->kl_list, kn, knote, kn_selnext);
    kn->kn_knlist = NULL;
    kn->kn_status |= KN_DETACHED;
}

/*
 * Even if we are locked, we may need to drop the lock to allow any influx
 * knotes time to "settle".
 */
void
knlist_clear(struct knlist *knl, int islocked)
{
    struct knote *kn;
    struct kqueue *kq;

again:		/* need to reaquire lock since we have dropped it */

    SLIST_FOREACH(kn, &knl->kl_list, kn_selnext)
    {
        kq = kn->kn_kq;
        KQ_LOCK(kq);
        if ((kn->kn_status & KN_INFLUX) &&
                (kn->kn_status & KN_DETACHED) != KN_DETACHED)
        {
            KQ_UNLOCK(kq);
            continue;
        }
        /* Make sure cleared knotes disappear soon */
        kn->kn_flags |= (EV_EOF | EV_ONESHOT);
        knlist_remove_kq(knl, kn, 1, 1);
        KQ_UNLOCK(kq);
        kq = NULL;
    }

    if (!SLIST_EMPTY(&knl->kl_list))
    {
        /* there are still KN_INFLUX remaining */
        kn = SLIST_FIRST(&knl->kl_list);
        kq = kn->kn_kq;
        KQ_LOCK(kq);
        KASSERT(kn->kn_status & KN_INFLUX,
                ("knote removed w/o list lock"));
        mtx_unlock(knl->kl_lock);
        kq->kq_state |= KQ_FLUXWAIT;
        msleep(kq, &kq->kq_lock, PSOCK | PDROP, "kqkclr", 0);
        kq = NULL;
        goto again;
    }

    SLIST_INIT(&knl->kl_list);

}


