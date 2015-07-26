/******************************************************************************

  Copyright (c) 2001-2010, Intel Corporation 
  All rights reserved.
  
  Redistribution and use in source and binary forms, with or without 
  modification, are permitted provided that the following conditions are met:
  
   1. Redistributions of source code must retain the above copyright notice, 
      this list of conditions and the following disclaimer.
  
   2. Redistributions in binary form must reproduce the above copyright 
      notice, this list of conditions and the following disclaimer in the 
      documentation and/or other materials provided with the distribution.
  
   3. Neither the name of the Intel Corporation nor the names of its 
      contributors may be used to endorse or promote products derived from 
      this software without specific prior written permission.
  
  THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
  AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE 
  IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE 
  ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT OWNER OR CONTRIBUTORS BE 
  LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR 
  CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF 
  SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS 
  INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN 
  CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) 
  ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
  POSSIBILITY OF SUCH DAMAGE.

******************************************************************************/
/*$FreeBSD: release/9.0.0/sys/dev/e1000/e1000_osdep.h 210569 2010-07-28 16:24:06Z mdf $*/


#ifndef _FREEBSD_OS_H_
#define _FREEBSD_OS_H_

#include "sys.h"
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
#include "if.h"
#include "if_var.h"
#include "sockio.h"
#include "kroute.h"
#include "if_dl.h"
#include "if_arp.h"
#include "sbuf.h"
#include "ethernet.h"
#include "if_vlan_var.h"
#include "if_media.h"
#include "pcireg.h"
#define ASSERT(x) if(!(x)) panic("EM: x")

#define usec_delay(x) DELAY(x)
#define msec_delay(x) DELAY(1000*(x))
#define msec_delay_irq(x) DELAY(1000*(x))

#define MSGOUT(S, A, B)     printf(S "\n", A, B)
#define DEBUGFUNC(F)        DEBUGOUT(F);
#define DEBUGOUT(S)			do {} while (0)
#define DEBUGOUT1(S,A)			do {} while (0)
#define DEBUGOUT2(S,A,B)		do {} while (0)
#define DEBUGOUT3(S,A,B,C)		do {} while (0)
#define DEBUGOUT7(S,A,B,C,D,E,F,G)	do {} while (0)

#define STATIC			static
#define FALSE			0
#define false			FALSE 
#define TRUE			1
#define true			TRUE
#define CMD_MEM_WRT_INVALIDATE	0x0010  /* BIT_4 */
#define PCI_COMMAND_REGISTER	PCIR_COMMAND

/* Mutex used in the shared code */
#define E1000_MUTEX                     struct mtx
#define E1000_MUTEX_INIT(mutex)         mtx_init((mutex), #mutex, \
                                            MTX_NETWORK_LOCK, MTX_DEF)
#define E1000_MUTEX_DESTROY(mutex)      mtx_destroy(mutex)
#define E1000_MUTEX_LOCK(mutex)         mtx_lock(mutex)
#define E1000_MUTEX_TRYLOCK(mutex)      mtx_trylock(mutex)
#define E1000_MUTEX_UNLOCK(mutex)       mtx_unlock(mutex)

typedef __uint64_t	u64;
typedef __uint32_t	u32;
typedef __uint16_t	u16;
typedef __uint8_t		u8;
typedef __int64		s64;
typedef __int32_t		s32;
typedef __int16_t		s16;
typedef __int8_t		s8;
typedef __int32_t	bool;

#define __le16		u16
#define __le32		u32
#define __le64		u64

#if __FreeBSD_version < 800000 /* Now in HEAD */
#if defined(__i386__) || defined(__amd64__)
#define mb()	__asm volatile("mfence" ::: "memory")
#define wmb()	__asm volatile("sfence" ::: "memory")
#define rmb()	__asm volatile("lfence" ::: "memory")
#else
#define mb()
#define rmb()
#define wmb()
#endif
#endif /*__FreeBSD_version < 800000 */

#if defined(__i386__) || defined(__amd64__)
static __inline
void prefetch(void *x)
{
	__asm volatile("prefetcht0 %0" :: "m" (*(unsigned long *)x));
}
#else
#define prefetch(x)
#endif

struct e1000_osdep
{
	bus_space_tag_t    mem_bus_space_tag;
	bus_space_handle_t mem_bus_space_handle;
	bus_space_tag_t    io_bus_space_tag;
	bus_space_handle_t io_bus_space_handle;
	bus_space_tag_t    flash_bus_space_tag;
	bus_space_handle_t flash_bus_space_handle;
	struct device     *dev;
};

#define E1000_REGISTER(hw, reg) (((hw)->mac.type >= e1000_82543) \
    ? reg : e1000_translate_register_82542(reg))

#define E1000_WRITE_FLUSH(a) E1000_READ_REG(a, E1000_STATUS)

/* Read from an absolute offset in the adapter's memory space */
#define E1000_READ_OFFSET(hw, offset) \
    bus_space_read_4(((struct e1000_osdep *)(hw)->back)->mem_bus_space_tag, \
    ((struct e1000_osdep *)(hw)->back)->mem_bus_space_handle, offset)

/* Write to an absolute offset in the adapter's memory space */
#define E1000_WRITE_OFFSET(hw, offset, value) \
    bus_space_write_4(((struct e1000_osdep *)(hw)->back)->mem_bus_space_tag, \
    ((struct e1000_osdep *)(hw)->back)->mem_bus_space_handle, offset, value)

/* Register READ/WRITE macros */

#define E1000_READ_REG(hw, reg) \
    bus_space_read_4(((struct e1000_osdep *)(hw)->back)->mem_bus_space_tag, \
        ((struct e1000_osdep *)(hw)->back)->mem_bus_space_handle, \
        E1000_REGISTER(hw, reg))

#define E1000_WRITE_REG(hw, reg, value) \
    bus_space_write_4(((struct e1000_osdep *)(hw)->back)->mem_bus_space_tag, \
        ((struct e1000_osdep *)(hw)->back)->mem_bus_space_handle, \
        E1000_REGISTER(hw, reg), value)

#define E1000_READ_REG_ARRAY(hw, reg, index) \
    bus_space_read_4(((struct e1000_osdep *)(hw)->back)->mem_bus_space_tag, \
        ((struct e1000_osdep *)(hw)->back)->mem_bus_space_handle, \
        E1000_REGISTER(hw, reg) + ((index)<< 2))

#define E1000_WRITE_REG_ARRAY(hw, reg, index, value) \
    bus_space_write_4(((struct e1000_osdep *)(hw)->back)->mem_bus_space_tag, \
        ((struct e1000_osdep *)(hw)->back)->mem_bus_space_handle, \
        E1000_REGISTER(hw, reg) + ((index)<< 2), value)

#define E1000_READ_REG_ARRAY_DWORD E1000_READ_REG_ARRAY
#define E1000_WRITE_REG_ARRAY_DWORD E1000_WRITE_REG_ARRAY

#define E1000_READ_REG_ARRAY_BYTE(hw, reg, index) \
    bus_space_read_1(((struct e1000_osdep *)(hw)->back)->mem_bus_space_tag, \
        ((struct e1000_osdep *)(hw)->back)->mem_bus_space_handle, \
        E1000_REGISTER(hw, reg) + index)

#define E1000_WRITE_REG_ARRAY_BYTE(hw, reg, index, value) \
    bus_space_write_1(((struct e1000_osdep *)(hw)->back)->mem_bus_space_tag, \
        ((struct e1000_osdep *)(hw)->back)->mem_bus_space_handle, \
        E1000_REGISTER(hw, reg) + index, value)

#define E1000_WRITE_REG_ARRAY_WORD(hw, reg, index, value) \
    bus_space_write_2(((struct e1000_osdep *)(hw)->back)->mem_bus_space_tag, \
        ((struct e1000_osdep *)(hw)->back)->mem_bus_space_handle, \
        E1000_REGISTER(hw, reg) + (index << 1), value)

#define E1000_WRITE_REG_IO(hw, reg, value) do {\
    bus_space_write_4(((struct e1000_osdep *)(hw)->back)->io_bus_space_tag, \
        ((struct e1000_osdep *)(hw)->back)->io_bus_space_handle, \
        (hw)->io_base, reg); \
    bus_space_write_4(((struct e1000_osdep *)(hw)->back)->io_bus_space_tag, \
        ((struct e1000_osdep *)(hw)->back)->io_bus_space_handle, \
        (hw)->io_base + 4, value); } while (0)

#define E1000_READ_FLASH_REG(hw, reg) \
    bus_space_read_4(((struct e1000_osdep *)(hw)->back)->flash_bus_space_tag, \
        ((struct e1000_osdep *)(hw)->back)->flash_bus_space_handle, reg)

#define E1000_READ_FLASH_REG16(hw, reg) \
    bus_space_read_2(((struct e1000_osdep *)(hw)->back)->flash_bus_space_tag, \
        ((struct e1000_osdep *)(hw)->back)->flash_bus_space_handle, reg)

#define E1000_WRITE_FLASH_REG(hw, reg, value) \
    bus_space_write_4(((struct e1000_osdep *)(hw)->back)->flash_bus_space_tag, \
        ((struct e1000_osdep *)(hw)->back)->flash_bus_space_handle, reg, value)

#define E1000_WRITE_FLASH_REG16(hw, reg, value) \
    bus_space_write_2(((struct e1000_osdep *)(hw)->back)->flash_bus_space_tag, \
        ((struct e1000_osdep *)(hw)->back)->flash_bus_space_handle, reg, value)

#endif  /* _FREEBSD_OS_H_ */

