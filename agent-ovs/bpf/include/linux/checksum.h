/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * INET         An implementation of the TCP/IP protocol suite for the LINUX
 *              operating system.  INET is implemented using the  BSD Socket
 *              interface as the means of communication with the user level.
 *
 *              Checksumming functions for IP, TCP, UDP and so on
 *
 * Authors:     Jorge Cwik, <jorge@laser.satlink.net>
 *              Arnt Gulbrandsen, <agulbra@nvg.unit.no>
 *              Borrows very liberally from tcp.c and ip.c, see those
 *              files for more names.
 */

#ifndef __CHECKSUM_H__
#define __CHECKSUM_H__

#include <linux/types.h>

# define __force

static inline __wsum csum_add(__wsum csum, __wsum addend)
{
        __u32 res = (__force __u32)csum;
        res += (__force __u32)addend;
        return (__force __wsum)(res + (res < (__force __u32)addend));
}

static inline __wsum csum_sub(__wsum csum, __wsum addend)
{
        return csum_add(csum, ~addend);
}

static inline __sum16 csum16_add(__sum16 csum, __be16 addend)
{
        __u16 res = (__force __u16)csum;

        res += (__force __u16)addend;
        return (__force __sum16)(res + (res < (__force __u16)addend));
}

static inline __sum16 csum16_sub(__sum16 csum, __be16 addend)
{
        return csum16_add(csum, ~addend);
}

static inline __sum16 csum_fold(__wsum csum)
{
        __u32 sum = (__force __u32)csum;
        sum = (sum & 0xffff) + (sum >> 16);
        sum = (sum & 0xffff) + (sum >> 16);
        return (__force __sum16)~sum;
}

static inline __wsum csum_unfold(__sum16 n)
{
        return (__force __wsum)n;
}

#define CSUM_MANGLED_0 ((__force __sum16)0xffff)

static inline void csum_replace_by_diff(__sum16 *sum, __wsum diff)
{
        *sum = csum_fold(csum_add(diff, ~csum_unfold(*sum)));
}

static inline void csum_replace4(__sum16 *sum, __be32 from, __be32 to)
{
        __wsum tmp = csum_sub(~csum_unfold(*sum), (__force __wsum)from);

        *sum = csum_fold(csum_add(tmp, (__force __wsum)to));
}

/* Implements RFC 1624 (Incremental Internet Checksum)
 * 3. Discussion states :
 *     HC' = ~(~HC + ~m + m')
 *  m : old value of a 16bit field
 *  m' : new value of a 16bit field
 */
static inline void csum_replace2(__sum16 *sum, __be16 old, __be16 new)
{
        *sum = ~csum16_add(csum16_sub(~(*sum), old), new);
}

static inline unsigned short csum_block(__be16 *buf, int sz)
{
       __u32 sum = 0;

       while (sz > 1) {
                sum += *buf;
                buf++;
                sz -= 2;
        }

        if (sz == 1) {
                sum += *(unsigned char *)buf;
        }

        return csum_fold(sum);
}
#endif
