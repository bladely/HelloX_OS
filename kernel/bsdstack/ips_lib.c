/********************************************************/
/****************** AUTHOR LUOYU ************************/
/********************************************************/

#include "uio.h"
#include "sys.h"
#include "libkern.h"
#include "kin.h"
#include "ip.h"
#include "ip_icmp.h"
#include "socket.h"
#include "sockio.h"
#include "if.h"
#include "if_dl.h"
#include "ethernet.h"
#include "kroute.h"
#include "if_arp.h"
#include "if_ether.h"

//from Windows
#include <process.h>
//#include "ips_config.h"
extern int errno;
/*
* Check whether "cp" is a valid ascii representation
* of an Internet address and convert to a binary address.
* Returns 1 if the address is valid, 0 if not.
* This replaces inet_addr, the return value from which
* cannot distinguish between failure and a local broadcast address.
*/
#define _LIBC
in_addr_t
__inet_aton(const char *cp, struct in_addr *addr)
{
	static const in_addr_t max[4] = { 0xffffffff, 0xffffff, 0xffff, 0xff };
	in_addr_t val;
#ifndef _LIBC
	int base;
#endif
	char c;
	union iaddr {
		uint8_t bytes[4];
		uint32_t word;
	} res;
	uint8_t *pp = res.bytes;
	int digit;
	
#ifdef _LIBC
	int saved_errno = errno;
#endif
	
	res.word = 0;
	
	c = *cp;
	for (;;) {
	/*
	* Collect number up to ``.''.
	* Values are specified as for C:
	* 0x=hex, 0=octal, isdigit=decimal.
		*/
		if (!isdigit(c))
			goto ret_0;
		{
			char *endp;
			unsigned long ul = strtoul (cp, (char **) &endp, 0);
			if (ul == ULONG_MAX && errno == ERANGE)
				goto ret_0;
			if (ul > 0xfffffffful)
				goto ret_0;
			val = ul;
			digit = cp != endp;
			cp = endp;
		}
		c = *cp;
		
		if (c == '.') {
		/*
		* Internet format:
		*	a.b.c.d
		*	a.b.c	(with c treated as 16 bits)
		*	a.b	(with b treated as 24 bits)
			*/
			if (pp > res.bytes + 2 || val > 0xff)
				goto ret_0;
			*pp++ = val;
			c = *++cp;
		} else
			break;
	}
	/*
	* Check for trailing characters.
	*/
	if (c != '\0' && (!isascii(c) || !isspace(c)))
		goto ret_0;
		/*
		* Did we get a valid digit?
	*/
	if (!digit)
		goto ret_0;
	
		/* Check whether the last part is in its limits depending on
	   the number of parts in total.  */
	if (val > max[pp - res.bytes])
		goto ret_0;
	
	if (addr != NULL)
		addr->s_addr = res.word | htonl (val);
	
	
	return (1);
	
ret_0:
	
	return (0);
}

/*
* Ascii internet address interpretation routine.
* The value returned is in network order.
*/
in_addr_t
inet_addr(const char *cp) {
	struct in_addr val;
	
	if (__inet_aton(cp, &val))
		return (val.s_addr);
	return (INADDR_NONE);
}
/* 
 * Check whether "cp" is a valid ascii representation
 * of an Internet address and convert to a binary address.
 * Returns 1 if the address is valid, 0 if not.
 * This replaces inet_addr, the return value from which
 * cannot distinguish between failure and a local broadcast address.
 */
int
inet_aton(const char *cp, struct in_addr *addr)
{
	register u_int32_t val;
	register int base, n;
	register char c;
	unsigned int parts[4];
	register unsigned int *pp = parts;

	c = *cp;
	for (;;) {
		/*
		 * Collect number up to ``.''.
		 * Values are specified as for C:
		 * 0x=hex, 0=octal, isdigit=decimal.
		 */
		if (!isdigit(c))
			return (0);
		val = 0; base = 10;
		if (c == '0') {
			c = *++cp;
			if (c == 'x' || c == 'X')
				base = 16, c = *++cp;
			else
				base = 8;
		}
		for (;;) {
			if (isascii(c) && isdigit(c)) {
				val = (val * base) + (c - '0');
				c = *++cp;
			} else if (base == 16 && isascii(c) && isxdigit(c)) {
				val = (val << 4) |
					(c + 10 - (islower(c) ? 'a' : 'A'));
				c = *++cp;
			} else
				break;
		}
		if (c == '.') {
			/*
			 * Internet format:
			 *	a.b.c.d
			 *	a.b.c	(with c treated as 16 bits)
			 *	a.b	(with b treated as 24 bits)
			 */
			if (pp >= parts + 3)
				return (0);
			*pp++ = val;
			c = *++cp;
		} else
			break;
	}
	/*
	 * Check for trailing characters.
	 */
	if (c != '\0' && (!isascii(c) || !isspace(c)))
		return (0);
	/*
	 * Concoct the address according to
	 * the number of parts specified.
	 */
	n = pp - parts + 1;
	switch (n) {

	case 0:
		return (0);		/* initial nondigit */

	case 1:				/* a -- 32 bits */
		break;

	case 2:				/* a.b -- 8.24 bits */
		if ((val > 0xffffff) || (parts[0] > 0xff))
			return (0);
		val |= parts[0] << 24;
		break;

	case 3:				/* a.b.c -- 8.8.16 bits */
		if ((val > 0xffff) || (parts[0] > 0xff) || (parts[1] > 0xff))
			return (0);
		val |= (parts[0] << 24) | (parts[1] << 16);
		break;

	case 4:				/* a.b.c.d -- 8.8.8.8 bits */
		if ((val > 0xff) || (parts[0] > 0xff) || (parts[1] > 0xff) || (parts[2] > 0xff))
			return (0);
		val |= (parts[0] << 24) | (parts[1] << 16) | (parts[2] << 8);
		break;
	}
	if (addr)
		addr->s_addr = htonl(val);
	return (1);
}
