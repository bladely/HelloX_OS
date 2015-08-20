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
int
minor(struct cdev *x)
{
	if (x == NULL)
		return NODEV;
	//return(x->si_udev & 0xffff00ff);LUOYU
	return 1;
}

int
unit2minor(int unit)
{

	KASSERT(unit <= 0xffffff, ("Invalid unit (%d) in unit2minor", unit));
	return ((unit & 0xff) | ((unit << 8) & ~0xffff));
}

struct cdev *
make_dev_alias(struct cdev *pdev, const char *fmt, ...)
{
#if 0
	struct cdev *dev;
	va_list ap;
	int i;
	
	dev = allocdev();
	devlock();
	dev->si_flags |= SI_ALIAS;
	dev->si_flags |= SI_NAMED;
	va_start(ap, fmt);
	i = vsnrprintf(dev->__si_namebuf, sizeof dev->__si_namebuf, 32, fmt, ap);
	if (i > (sizeof dev->__si_namebuf - 1)) {
		printf("WARNING: Device name truncated! (%s)", 
			dev->__si_namebuf);
	}
	va_end(ap);
	
	//devfs_create(dev);LUOYU
	//devunlock();
	//dev_depends(pdev, dev);
	return (dev);
	#endif
	return NULL;
}


struct cdev *
make_dev(struct cdevsw *devsw, int minornr, uid_t uid, gid_t gid, int perms, const char *fmt, ...)
{
#if 0
	struct cdev *dev;
	va_list ap;
	int i;
	
	KASSERT((minornr & ~0xffff00ff) == 0,
		("Invalid minor (0x%x) in make_dev", minornr));
	
	if (!(devsw->d_flags & D_INIT))
		prep_cdevsw(devsw);
	dev = newdev(devsw->d_maj, minornr);
	if (dev->si_flags & SI_CHEAPCLONE &&
		dev->si_flags & SI_NAMED &&
		dev->si_devsw == devsw) {
		/*
		* This is allowed as it removes races and generally
		* simplifies cloning devices.
		* XXX: still ??
		*/
		return (dev);
	}
	devlock();
	KASSERT(!(dev->si_flags & SI_NAMED),
		("make_dev() by driver %s on pre-existing device (maj=%d, min=%d, name=%s)",
		devsw->d_name, major(dev), minor(dev), devtoname(dev)));
	
	va_start(ap, fmt);
	i = vsnrprintf(dev->__si_namebuf, sizeof dev->__si_namebuf, 32, fmt, ap);
	if (i > (sizeof dev->__si_namebuf - 1)) {
		printf("WARNING: Device name truncated! (%s)", 
			dev->__si_namebuf);
	}
	va_end(ap);
	dev->si_devsw = devsw;
	dev->si_uid = uid;
	dev->si_gid = gid;
	dev->si_mode = perms;
	dev->si_flags |= SI_NAMED;
	
	LIST_INSERT_HEAD(&devsw->d_devs, dev, si_list);
	devfs_create(dev);
	devunlock();
	return (dev);
#endif
	return NULL;
}
void
destroy_dev(struct cdev *dev)
{
#if 0
	devlock();
	idestroy_dev(dev);
	devunlock();
#endif	
}

