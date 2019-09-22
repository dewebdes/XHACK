/*
 *  This program is free software: you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation, either version 3 of the License, or
 *  (at your option) any later version.
 */

/* Copyright (C) 1997-2018 Free Software Foundation, Inc.
   This file is part of the GNU C Library.
   The GNU C Library is free software; you can redistribute it and/or
   modify it under the terms of the GNU Lesser General Public
   License as published by the Free Software Foundation; either
   version 2.1 of the License, or (at your option) any later version.
   The GNU C Library is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
   Lesser General Public License for more details.
   You should have received a copy of the GNU Lesser General Public
   License along with the GNU C Library; if not, see
   <http://www.gnu.org/licenses/>.  */
#ifndef _ARPA_INET_H
#define	_ARPA_INET_H	1
#include <features.h>
#include <netinet/in.h>		/* To define `struct in_addr'.  */
/* Type for length arguments in socket calls.  */
#ifndef __socklen_t_defined
typedef __socklen_t socklen_t;
# define __socklen_t_defined
#endif
__BEGIN_DECLS
/* Convert Internet host address from numbers-and-dots notation in CP
   into binary data in network byte order.  */
extern in_addr_t inet_addr (const char *__cp) __THROW;
/* Return the local host address part of the Internet address in IN.  */
extern in_addr_t inet_lnaof (struct in_addr __in) __THROW;
/* Make Internet host address in network byte order by combining the
   network number NET with the local address HOST.  */
extern struct in_addr inet_makeaddr (in_addr_t __net, in_addr_t __host)
     __THROW;
/* Return network number part of the Internet address IN.  */
extern in_addr_t inet_netof (struct in_addr __in) __THROW;
/* Extract the network number in network byte order from the address
   in numbers-and-dots natation starting at CP.  */
extern in_addr_t inet_network (const char *__cp) __THROW;
/* Convert Internet number in IN to ASCII representation.  The return value
   is a pointer to an internal array containing the string.  */
extern char *inet_ntoa (struct in_addr __in) __THROW;
/* Convert from presentation format of an Internet number in buffer
   starting at CP to the binary network format and store result for
   interface type AF in buffer starting at BUF.  */
extern int inet_pton (int __af, const char *__restrict __cp,
		      void *__restrict __buf) __THROW;
/* Convert a Internet address in binary network format for interface
   type AF in buffer starting at CP to presentation form and place
   result in buffer of length LEN astarting at BUF.  */
extern const char *inet_ntop (int __af, const void *__restrict __cp,
			      char *__restrict __buf, socklen_t __len)
     __THROW;
/* The following functions are not part of XNS 5.2.  */
#ifdef __USE_MISC
/* Convert Internet host address from numbers-and-dots notation in CP
   into binary data and store the result in the structure INP.  */
extern int inet_aton (const char *__cp, struct in_addr *__inp) __THROW;
/* Format a network number NET into presentation format and place result
   in buffer starting at BUF with length of LEN bytes.  */
extern char *inet_neta (in_addr_t __net, char *__buf, size_t __len) __THROW;
/* Convert network number for interface type AF in buffer starting at
   CP to presentation format.  The result will specifiy BITS bits of
   the number.  */
extern char *inet_net_ntop (int __af, const void *__cp, int __bits,
			    char *__buf, size_t __len) __THROW;
/* Convert network number for interface type AF from presentation in
   buffer starting at CP to network format and store result int
   buffer starting at BUF of size LEN.  */
extern int inet_net_pton (int __af, const char *__cp,
			  void *__buf, size_t __len) __THROW;
/* Convert ASCII representation in hexadecimal form of the Internet
   address to binary form and place result in buffer of length LEN
   starting at BUF.  */
extern unsigned int inet_nsap_addr (const char *__cp,
				    unsigned char *__buf, int __len) __THROW;
/* Convert internet address in binary form in LEN bytes starting at CP
   a presentation form and place result in BUF.  */
extern char *inet_nsap_ntoa (int __len, const unsigned char *__cp,
			     char *__buf) __THROW;
#endif
__END_DECLS
#endif /* arpa/inet.h */


/* SPDX-License-Identifier: GPL-2.0 WITH Linux-syscall-note */
#ifndef __LINUX_IF_PACKET_H
#define __LINUX_IF_PACKET_H

#include <linux/types.h>

struct sockaddr_pkt {
	unsigned short spkt_family;
	unsigned char spkt_device[14];
	__be16 spkt_protocol;
};

struct sockaddr_ll {
	unsigned short	sll_family;
	__be16		sll_protocol;
	int		sll_ifindex;
	unsigned short	sll_hatype;
	unsigned char	sll_pkttype;
	unsigned char	sll_halen;
	unsigned char	sll_addr[8];
};

/* Packet types */

#define PACKET_HOST		0		/* To us		*/
#define PACKET_BROADCAST	1		/* To all		*/
#define PACKET_MULTICAST	2		/* To group		*/
#define PACKET_OTHERHOST	3		/* To someone else 	*/
#define PACKET_OUTGOING		4		/* Outgoing of any type */
#define PACKET_LOOPBACK		5		/* MC/BRD frame looped back */
#define PACKET_USER		6		/* To user space	*/
#define PACKET_KERNEL		7		/* To kernel space	*/
/* Unused, PACKET_FASTROUTE and PACKET_LOOPBACK are invisible to user space */
#define PACKET_FASTROUTE	6		/* Fastrouted frame	*/

/* Packet socket options */

#define PACKET_ADD_MEMBERSHIP		1
#define PACKET_DROP_MEMBERSHIP		2
#define PACKET_RECV_OUTPUT		3
/* Value 4 is still used by obsolete turbo-packet. */
#define PACKET_RX_RING			5
#define PACKET_STATISTICS		6
#define PACKET_COPY_THRESH		7
#define PACKET_AUXDATA			8
#define PACKET_ORIGDEV			9
#define PACKET_VERSION			10
#define PACKET_HDRLEN			11
#define PACKET_RESERVE			12
#define PACKET_TX_RING			13
#define PACKET_LOSS			14
#define PACKET_VNET_HDR			15
#define PACKET_TX_TIMESTAMP		16
#define PACKET_TIMESTAMP		17
#define PACKET_FANOUT			18
#define PACKET_TX_HAS_OFF		19
#define PACKET_QDISC_BYPASS		20
#define PACKET_ROLLOVER_STATS		21
#define PACKET_FANOUT_DATA		22
#define PACKET_IGNORE_OUTGOING		23

#define PACKET_FANOUT_HASH		0
#define PACKET_FANOUT_LB		1
#define PACKET_FANOUT_CPU		2
#define PACKET_FANOUT_ROLLOVER		3
#define PACKET_FANOUT_RND		4
#define PACKET_FANOUT_QM		5
#define PACKET_FANOUT_CBPF		6
#define PACKET_FANOUT_EBPF		7
#define PACKET_FANOUT_FLAG_ROLLOVER	0x1000
#define PACKET_FANOUT_FLAG_UNIQUEID	0x2000
#define PACKET_FANOUT_FLAG_DEFRAG	0x8000

struct tpacket_stats {
	unsigned int	tp_packets;
	unsigned int	tp_drops;
};

struct tpacket_stats_v3 {
	unsigned int	tp_packets;
	unsigned int	tp_drops;
	unsigned int	tp_freeze_q_cnt;
};

struct tpacket_rollover_stats {
	__aligned_u64	tp_all;
	__aligned_u64	tp_huge;
	__aligned_u64	tp_failed;
};

union tpacket_stats_u {
	struct tpacket_stats stats1;
	struct tpacket_stats_v3 stats3;
};

struct tpacket_auxdata {
	__u32		tp_status;
	__u32		tp_len;
	__u32		tp_snaplen;
	__u16		tp_mac;
	__u16		tp_net;
	__u16		tp_vlan_tci;
	__u16		tp_vlan_tpid;
};

/* Rx ring - header status */
#define TP_STATUS_KERNEL		      0
#define TP_STATUS_USER			(1 << 0)
#define TP_STATUS_COPY			(1 << 1)
#define TP_STATUS_LOSING		(1 << 2)
#define TP_STATUS_CSUMNOTREADY		(1 << 3)
#define TP_STATUS_VLAN_VALID		(1 << 4) /* auxdata has valid tp_vlan_tci */
#define TP_STATUS_BLK_TMO		(1 << 5)
#define TP_STATUS_VLAN_TPID_VALID	(1 << 6) /* auxdata has valid tp_vlan_tpid */
#define TP_STATUS_CSUM_VALID		(1 << 7)

/* Tx ring - header status */
#define TP_STATUS_AVAILABLE	      0
#define TP_STATUS_SEND_REQUEST	(1 << 0)
#define TP_STATUS_SENDING	(1 << 1)
#define TP_STATUS_WRONG_FORMAT	(1 << 2)

/* Rx and Tx ring - header status */
#define TP_STATUS_TS_SOFTWARE		(1 << 29)
#define TP_STATUS_TS_SYS_HARDWARE	(1 << 30) /* deprecated, never set */
#define TP_STATUS_TS_RAW_HARDWARE	(1U << 31)

/* Rx ring - feature request bits */
#define TP_FT_REQ_FILL_RXHASH	0x1

struct tpacket_hdr {
	unsigned long	tp_status;
	unsigned int	tp_len;
	unsigned int	tp_snaplen;
	unsigned short	tp_mac;
	unsigned short	tp_net;
	unsigned int	tp_sec;
	unsigned int	tp_usec;
};

#define TPACKET_ALIGNMENT	16
#define TPACKET_ALIGN(x)	(((x)+TPACKET_ALIGNMENT-1)&~(TPACKET_ALIGNMENT-1))
#define TPACKET_HDRLEN		(TPACKET_ALIGN(sizeof(struct tpacket_hdr)) + sizeof(struct sockaddr_ll))

struct tpacket2_hdr {
	__u32		tp_status;
	__u32		tp_len;
	__u32		tp_snaplen;
	__u16		tp_mac;
	__u16		tp_net;
	__u32		tp_sec;
	__u32		tp_nsec;
	__u16		tp_vlan_tci;
	__u16		tp_vlan_tpid;
	__u8		tp_padding[4];
};

struct tpacket_hdr_variant1 {
	__u32	tp_rxhash;
	__u32	tp_vlan_tci;
	__u16	tp_vlan_tpid;
	__u16	tp_padding;
};

struct tpacket3_hdr {
	__u32		tp_next_offset;
	__u32		tp_sec;
	__u32		tp_nsec;
	__u32		tp_snaplen;
	__u32		tp_len;
	__u32		tp_status;
	__u16		tp_mac;
	__u16		tp_net;
	/* pkt_hdr variants */
	union {
		struct tpacket_hdr_variant1 hv1;
	};
	__u8		tp_padding[8];
};

struct tpacket_bd_ts {
	unsigned int ts_sec;
	union {
		unsigned int ts_usec;
		unsigned int ts_nsec;
	};
};

struct tpacket_hdr_v1 {
	__u32	block_status;
	__u32	num_pkts;
	__u32	offset_to_first_pkt;

	/* Number of valid bytes (including padding)
	 * blk_len <= tp_block_size
	 */
	__u32	blk_len;

	/*
	 * Quite a few uses of sequence number:
	 * 1. Make sure cache flush etc worked.
	 *    Well, one can argue - why not use the increasing ts below?
	 *    But look at 2. below first.
	 * 2. When you pass around blocks to other user space decoders,
	 *    you can see which blk[s] is[are] outstanding etc.
	 * 3. Validate kernel code.
	 */
	__aligned_u64	seq_num;

	/*
	 * ts_last_pkt:
	 *
	 * Case 1.	Block has 'N'(N >=1) packets and TMO'd(timed out)
	 *		ts_last_pkt == 'time-stamp of last packet' and NOT the
	 *		time when the timer fired and the block was closed.
	 *		By providing the ts of the last packet we can absolutely
	 *		guarantee that time-stamp wise, the first packet in the
	 *		next block will never precede the last packet of the
	 *		previous block.
	 * Case 2.	Block has zero packets and TMO'd
	 *		ts_last_pkt = time when the timer fired and the block
	 *		was closed.
	 * Case 3.	Block has 'N' packets and NO TMO.
	 *		ts_last_pkt = time-stamp of the last pkt in the block.
	 *
	 * ts_first_pkt:
	 *		Is always the time-stamp when the block was opened.
	 *		Case a)	ZERO packets
	 *			No packets to deal with but atleast you know the
	 *			time-interval of this block.
	 *		Case b) Non-zero packets
	 *			Use the ts of the first packet in the block.
	 *
	 */
	struct tpacket_bd_ts	ts_first_pkt, ts_last_pkt;
};

union tpacket_bd_header_u {
	struct tpacket_hdr_v1 bh1;
};

struct tpacket_block_desc {
	__u32 version;
	__u32 offset_to_priv;
	union tpacket_bd_header_u hdr;
};

#define TPACKET2_HDRLEN		(TPACKET_ALIGN(sizeof(struct tpacket2_hdr)) + sizeof(struct sockaddr_ll))
#define TPACKET3_HDRLEN		(TPACKET_ALIGN(sizeof(struct tpacket3_hdr)) + sizeof(struct sockaddr_ll))

enum tpacket_versions {
	TPACKET_V1,
	TPACKET_V2,
	TPACKET_V3
};

/*
   Frame structure:
   - Start. Frame must be aligned to TPACKET_ALIGNMENT=16
   - struct tpacket_hdr
   - pad to TPACKET_ALIGNMENT=16
   - struct sockaddr_ll
   - Gap, chosen so that packet data (Start+tp_net) alignes to TPACKET_ALIGNMENT=16
   - Start+tp_mac: [ Optional MAC header ]
   - Start+tp_net: Packet data, aligned to TPACKET_ALIGNMENT=16.
   - Pad to align to TPACKET_ALIGNMENT=16
 */

struct tpacket_req {
	unsigned int	tp_block_size;	/* Minimal size of contiguous block */
	unsigned int	tp_block_nr;	/* Number of blocks */
	unsigned int	tp_frame_size;	/* Size of frame */
	unsigned int	tp_frame_nr;	/* Total number of frames */
};

struct tpacket_req3 {
	unsigned int	tp_block_size;	/* Minimal size of contiguous block */
	unsigned int	tp_block_nr;	/* Number of blocks */
	unsigned int	tp_frame_size;	/* Size of frame */
	unsigned int	tp_frame_nr;	/* Total number of frames */
	unsigned int	tp_retire_blk_tov; /* timeout in msecs */
	unsigned int	tp_sizeof_priv; /* offset to private data area */
	unsigned int	tp_feature_req_word;
};

union tpacket_req_u {
	struct tpacket_req	req;
	struct tpacket_req3	req3;
};

struct packet_mreq {
	int		mr_ifindex;
	unsigned short	mr_type;
	unsigned short	mr_alen;
	unsigned char	mr_address[8];
};

#define PACKET_MR_MULTICAST	0
#define PACKET_MR_PROMISC	1
#define PACKET_MR_ALLMULTI	2
#define PACKET_MR_UNICAST	3

#endif
 /*
  * Copyright (c) 1990 The Regents of the University of California.
  * All rights reserved.
  *
  * Redistribution and use in source and binary forms are permitted
  * provided that the above copyright notice and this paragraph are
  * duplicated in all such forms and that any documentation,
  * advertising materials, and other materials related to such
  * distribution and use acknowledge that the software was developed
  * by the University of California, Berkeley.  The name of the
  * University may not be used to endorse or promote products derived
  * from this software without specific prior written permission.
  * THIS SOFTWARE IS PROVIDED ``AS IS'' AND WITHOUT ANY EXPRESS OR
  * IMPLIED WARRANTIES, INCLUDING, WITHOUT LIMITATION, THE IMPLIED
  * WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE.
  *
  *      @(#)stdio.h     5.3 (Berkeley) 3/15/86
  */
 
 /*
  * NB: to fit things in six character monocase externals, the
  * stdio code uses the prefix `__s' for stdio objects, typically
  * followed by a three-character attempt at a mnemonic.
  */
 
 #ifndef _STDIO_H_
 #ifdef __cplusplus
 extern "C" {
 #endif
 #define _STDIO_H_
 
 #define _FSTDIO                 /* ``function stdio'' */
 
 #define __need_size_t
 #include <stddef.h>
 
 #define __need___va_list
 #include <stdarg.h>
 
 /*
  * <sys/reent.h> defines __sFILE, _fpos_t.
  * They must be defined there because struct _reent needs them (and we don't
  * want reent.h to include this file.
  */
 
 struct __sFile 
 {
   int unused;
 };
   
 typedef struct __sFILE FILE;
 
 #define __SLBF  0x0001          /* line buffered */
 #define __SNBF  0x0002          /* unbuffered */
 #define __SRD   0x0004          /* OK to read */
 #define __SWR   0x0008          /* OK to write */
         /* RD and WR are never simultaneously asserted */
 #define __SRW   0x0010          /* open for reading & writing */
 #define __SEOF  0x0020          /* found EOF */
 #define __SERR  0x0040          /* found error */
 #define __SMBF  0x0080          /* _buf is from malloc */
 #define __SAPP  0x0100          /* fdopen()ed in append mode - so must  write to end */
 #define __SSTR  0x0200          /* this is an sprintf/snprintf string */
 #define __SOPT  0x0400          /* do fseek() optimisation */
 #define __SNPT  0x0800          /* do not do fseek() optimisation */
 #define __SOFF  0x1000          /* set iff _offset is in fact correct */
 #define __SMOD  0x2000          /* true => fgetline modified _p text */
 #if defined(__CYGWIN__) || defined(__CYGWIN__)
 #define __SCLE        0x4000          /* convert line endings CR/LF <-> NL */
 #endif
 
 /*
  * The following three definitions are for ANSI C, which took them
  * from System V, which stupidly took internal interface macros and
  * made them official arguments to setvbuf(), without renaming them.
  * Hence, these ugly _IOxxx names are *supposed* to appear in user code.
  *
  * Although these happen to match their counterparts above, the
  * implementation does not rely on that (so these could be renumbered).
  */
 #define _IOFBF  0               /* setvbuf should set fully buffered */
 #define _IOLBF  1               /* setvbuf should set line buffered */
 #define _IONBF  2               /* setvbuf should set unbuffered */
 
 #ifndef NULL
 #define NULL    0
 #endif
 
 #define BUFSIZ  1024
 #define EOF     (-1)
 
 #define FOPEN_MAX       20      /* must be <= OPEN_MAX <sys/syslimits.h> */
 #define FILENAME_MAX    1024    /* must be <= PATH_MAX <sys/syslimits.h> */
 #define L_tmpnam        1024    /* XXX must be == PATH_MAX */
 #ifndef __STRICT_ANSI__
 #define P_tmpdir        "/tmp"
 #endif
 
 #ifndef SEEK_SET
 #define SEEK_SET        0       /* set file offset to offset */
 #endif
 #ifndef SEEK_CUR
 #define SEEK_CUR        1       /* set file offset to current plus offset */
 #endif
 #ifndef SEEK_END
 #define SEEK_END        2       /* set file offset to EOF plus offset */
 #endif
 
 #define TMP_MAX         26
 
 #define stdin   (_impure_ptr->_stdin)
 #define stdout  (_impure_ptr->_stdout)
 #define stderr  (_impure_ptr->_stderr)
 
 #define _stdin_r(x)     ((x)->_stdin)
 #define _stdout_r(x)    ((x)->_stdout)
 #define _stderr_r(x)    ((x)->_stderr)
 
 /*
  * Functions defined in ANSI C standard.
  */
 
 #ifdef __GNUC__
 #define __VALIST __gnuc_va_list
 #else
 #define __VALIST char*
 #endif
 
 #ifndef _EXFUN
 # define _EXFUN(N,P) N P
 #endif
 
 int     _EXFUN(printf, (const char *, ...));
 int     _EXFUN(scanf, (const char *, ...));
 int     _EXFUN(sscanf, (const char *, const char *, ...));
 int     _EXFUN(vfprintf, (FILE *, const char *, __VALIST));
 int     _EXFUN(vprintf, (const char *, __VALIST));
 int     _EXFUN(vsprintf, (char *, const char *, __VALIST));
 int     _EXFUN(vsnprintf, (char *, size_t, const char *, __VALIST));
 int     _EXFUN(fgetc, (FILE *));
 char *  _EXFUN(fgets, (char *, int, FILE *));
 int     _EXFUN(fputc, (int, FILE *));
 int     _EXFUN(fputs, (const char *, FILE *));
 int     _EXFUN(getc, (FILE *));
 int     _EXFUN(getchar, (void));
 char *  _EXFUN(gets, (char *));
 int     _EXFUN(putc, (int, FILE *));
 int     _EXFUN(putchar, (int));
 int     _EXFUN(puts, (const char *));
 int     _EXFUN(ungetc, (int, FILE *));
 size_t  _EXFUN(fread, (void *, size_t _size, size_t _n, FILE *));
 size_t  _EXFUN(fwrite, (const void *, size_t _size, size_t _n, FILE *));
 
 int     _EXFUN(sprintf, (char *, const char *, ...));
 int     _EXFUN(snprintf, (char *, size_t, const char *, ...));
 
 #ifdef __cplusplus
 }
 #endif
 #endif /* _STDIO_H_ */
/*
 * string.h
 * This file has no copyright assigned and is placed in the Public Domain.
 * This file is a part of the mingw-runtime package.
 * No warranty is given; refer to the file DISCLAIMER within the package.
 *
 * Definitions for memory and string functions.
 *
 */
 
#ifndef _STRING_H_
#define	_STRING_H_
 
/* All the headers include this file. */
#include <_mingw.h>
 
/*
 * Define size_t, wchar_t and NULL
 */
#define __need_size_t
#define __need_wchar_t
#define	__need_NULL
#ifndef RC_INVOKED
#include <stddef.h>
#endif	/* Not RC_INVOKED */
 
#ifndef RC_INVOKED
 
#ifdef __cplusplus
extern "C" {
#endif
 
/*
 * Prototypes of the ANSI Standard C library string functions.
 */
_CRTIMP void* __cdecl	memchr (const void*, int, size_t) __MINGW_ATTRIB_PURE;
_CRTIMP int __cdecl 	memcmp (const void*, const void*, size_t) __MINGW_ATTRIB_PURE;
_CRTIMP void* __cdecl 	memcpy (void*, const void*, size_t);
_CRTIMP void* __cdecl	memmove (void*, const void*, size_t);
_CRTIMP void* __cdecl	memset (void*, int, size_t);
_CRTIMP char* __cdecl	strcat (char*, const char*);
_CRTIMP char* __cdecl	strchr (const char*, int)  __MINGW_ATTRIB_PURE;
_CRTIMP int __cdecl	strcmp (const char*, const char*)  __MINGW_ATTRIB_PURE;
_CRTIMP int __cdecl	strcoll (const char*, const char*);	/* Compare using locale */
_CRTIMP char* __cdecl	strcpy (char*, const char*);
_CRTIMP size_t __cdecl	strcspn (const char*, const char*)  __MINGW_ATTRIB_PURE;
_CRTIMP char* __cdecl	strerror (int); /* NOTE: NOT an old name wrapper. */
 
_CRTIMP size_t __cdecl	strlen (const char*)  __MINGW_ATTRIB_PURE;
_CRTIMP char* __cdecl	strncat (char*, const char*, size_t);
_CRTIMP int __cdecl	strncmp (const char*, const char*, size_t)  __MINGW_ATTRIB_PURE;
_CRTIMP char* __cdecl	strncpy (char*, const char*, size_t);
_CRTIMP char* __cdecl	strpbrk (const char*, const char*)  __MINGW_ATTRIB_PURE;
_CRTIMP char* __cdecl	strrchr (const char*, int)  __MINGW_ATTRIB_PURE;
_CRTIMP size_t __cdecl	strspn (const char*, const char*)  __MINGW_ATTRIB_PURE;
_CRTIMP char* __cdecl	strstr (const char*, const char*)  __MINGW_ATTRIB_PURE;
_CRTIMP char* __cdecl	strtok (char*, const char*);
_CRTIMP size_t __cdecl	strxfrm (char*, const char*, size_t);
 
#ifndef __STRICT_ANSI__
/*
 * Extra non-ANSI functions provided by the CRTDLL library
 */
_CRTIMP char* __cdecl	_strerror (const char *);
_CRTIMP void* __cdecl	_memccpy (void*, const void*, int, size_t);
_CRTIMP int __cdecl 	_memicmp (const void*, const void*, size_t);
_CRTIMP char* __cdecl 	_strdup (const char*) __MINGW_ATTRIB_MALLOC;
_CRTIMP int __cdecl	_strcmpi (const char*, const char*);
_CRTIMP int __cdecl	_stricmp (const char*, const char*);
_CRTIMP int __cdecl	_stricoll (const char*, const char*);
_CRTIMP char* __cdecl	_strlwr (char*);
_CRTIMP int __cdecl	_strnicmp (const char*, const char*, size_t);
_CRTIMP char* __cdecl	_strnset (char*, int, size_t);
_CRTIMP char* __cdecl	_strrev (char*);
_CRTIMP char* __cdecl	_strset (char*, int);
_CRTIMP char* __cdecl	_strupr (char*);
_CRTIMP void __cdecl	_swab (const char*, char*, size_t);
 
#ifdef __MSVCRT__
_CRTIMP int __cdecl  _strncoll(const char*, const char*, size_t);
_CRTIMP int __cdecl  _strnicoll(const char*, const char*, size_t);
#endif
 
#ifndef	_NO_OLDNAMES
/*
 * Non-underscored versions of non-ANSI functions. They live in liboldnames.a
 * and provide a little extra portability. Also a few extra UNIX-isms like
 * strcasecmp.
 */
_CRTIMP void* __cdecl	memccpy (void*, const void*, int, size_t);
_CRTIMP int __cdecl	memicmp (const void*, const void*, size_t);
_CRTIMP char* __cdecl	strdup (const char*) __MINGW_ATTRIB_MALLOC;
_CRTIMP int __cdecl	strcmpi (const char*, const char*);
_CRTIMP int __cdecl	stricmp (const char*, const char*);
__CRT_INLINE int __cdecl
strcasecmp (const char * __sz1, const char * __sz2)
  {return _stricmp (__sz1, __sz2);}
_CRTIMP int __cdecl	stricoll (const char*, const char*);
_CRTIMP char* __cdecl	strlwr (char*);
_CRTIMP int __cdecl	strnicmp (const char*, const char*, size_t);
__CRT_INLINE int __cdecl
strncasecmp (const char * __sz1, const char * __sz2, size_t __sizeMaxCompare)
  {return _strnicmp (__sz1, __sz2, __sizeMaxCompare);}
_CRTIMP char* __cdecl	strnset (char*, int, size_t);
_CRTIMP char* __cdecl	strrev (char*);
_CRTIMP char* __cdecl	strset (char*, int);
_CRTIMP char* __cdecl	strupr (char*);
#ifndef _UWIN
_CRTIMP void __cdecl	swab (const char*, char*, size_t);
#endif /* _UWIN */
#endif /* _NO_OLDNAMES */
 
#endif	/* Not __STRICT_ANSI__ */
 
#ifndef _WSTRING_DEFINED
/*
 * Unicode versions of the standard calls.
 * Also in wchar.h, where they belong according to ISO standard.
 */
_CRTIMP wchar_t* __cdecl wcscat (wchar_t*, const wchar_t*);
_CRTIMP wchar_t* __cdecl wcschr (const wchar_t*, wchar_t);
_CRTIMP int __cdecl	wcscmp (const wchar_t*, const wchar_t*);
_CRTIMP int __cdecl	wcscoll (const wchar_t*, const wchar_t*);
_CRTIMP wchar_t* __cdecl wcscpy (wchar_t*, const wchar_t*);
_CRTIMP size_t __cdecl	wcscspn (const wchar_t*, const wchar_t*);
/* Note:  _wcserror requires __MSVCRT_VERSION__ >= 0x0700.  */
_CRTIMP size_t __cdecl	wcslen (const wchar_t*);
_CRTIMP wchar_t* __cdecl wcsncat (wchar_t*, const wchar_t*, size_t);
_CRTIMP int __cdecl	wcsncmp(const wchar_t*, const wchar_t*, size_t);
_CRTIMP wchar_t* __cdecl wcsncpy(wchar_t*, const wchar_t*, size_t);
_CRTIMP wchar_t* __cdecl wcspbrk(const wchar_t*, const wchar_t*);
_CRTIMP wchar_t* __cdecl wcsrchr(const wchar_t*, wchar_t);
_CRTIMP size_t __cdecl	wcsspn(const wchar_t*, const wchar_t*);
_CRTIMP wchar_t* __cdecl wcsstr(const wchar_t*, const wchar_t*);
_CRTIMP wchar_t* __cdecl wcstok(wchar_t*, const wchar_t*);
_CRTIMP size_t __cdecl	wcsxfrm(wchar_t*, const wchar_t*, size_t);
 
#ifndef	__STRICT_ANSI__
/*
 * Unicode versions of non-ANSI string functions provided by CRTDLL.
 */
 
/* NOTE: _wcscmpi not provided by CRTDLL, this define is for portability */
#define		_wcscmpi	_wcsicmp
 
_CRTIMP wchar_t* __cdecl _wcsdup (const wchar_t*);
_CRTIMP int __cdecl	_wcsicmp (const wchar_t*, const wchar_t*);
_CRTIMP int __cdecl	_wcsicoll (const wchar_t*, const wchar_t*);
_CRTIMP wchar_t* __cdecl _wcslwr (wchar_t*);
_CRTIMP int __cdecl	_wcsnicmp (const wchar_t*, const wchar_t*, size_t);
_CRTIMP wchar_t* __cdecl _wcsnset (wchar_t*, wchar_t, size_t);
_CRTIMP wchar_t* __cdecl _wcsrev (wchar_t*);
_CRTIMP wchar_t* __cdecl _wcsset (wchar_t*, wchar_t);
_CRTIMP wchar_t* __cdecl _wcsupr (wchar_t*);
 
#ifdef __MSVCRT__
_CRTIMP int __cdecl  _wcsncoll(const wchar_t*, const wchar_t*, size_t);
_CRTIMP int   __cdecl _wcsnicoll(const wchar_t*, const wchar_t*, size_t);
#if __MSVCRT_VERSION__ >= 0x0700
_CRTIMP  wchar_t* __cdecl _wcserror(int);
_CRTIMP  wchar_t* __cdecl __wcserror(const wchar_t*);
#endif
#endif
 
#ifndef	_NO_OLDNAMES
/* NOTE: There is no _wcscmpi, but this is for compatibility. */
int __cdecl wcscmpi (const wchar_t * __ws1, const wchar_t * __ws2);
__CRT_INLINE int __cdecl
wcscmpi (const wchar_t * __ws1, const wchar_t * __ws2)
  {return _wcsicmp (__ws1, __ws2);}
_CRTIMP wchar_t* __cdecl wcsdup (const wchar_t*);
_CRTIMP int __cdecl	wcsicmp (const wchar_t*, const wchar_t*);
_CRTIMP int __cdecl	wcsicoll (const wchar_t*, const wchar_t*);
_CRTIMP wchar_t* __cdecl wcslwr (wchar_t*);
_CRTIMP int __cdecl	wcsnicmp (const wchar_t*, const wchar_t*, size_t);
_CRTIMP wchar_t* __cdecl wcsnset (wchar_t*, wchar_t, size_t);
_CRTIMP wchar_t* __cdecl wcsrev (wchar_t*);
_CRTIMP wchar_t* __cdecl wcsset (wchar_t*, wchar_t);
_CRTIMP wchar_t* __cdecl wcsupr (wchar_t*);
#endif	/* Not _NO_OLDNAMES */
 
#endif	/* Not strict ANSI */
 
#define _WSTRING_DEFINED
#endif  /* _WSTRING_DEFINED */
 
#ifdef __cplusplus
}
#endif
 
#endif	/* Not RC_INVOKED */
 
#endif	/* Not _STRING_H_ */
/* Copyright (C) 1991-2018 Free Software Foundation, Inc.
   This file is part of the GNU C Library.
   The GNU C Library is free software; you can redistribute it and/or
   modify it under the terms of the GNU Lesser General Public
   License as published by the Free Software Foundation; either
   version 2.1 of the License, or (at your option) any later version.
   The GNU C Library is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
   Lesser General Public License for more details.
   You should have received a copy of the GNU Lesser General Public
   License along with the GNU C Library; if not, see
   <http://www.gnu.org/licenses/>.  */
/*
 *	ISO C99 Standard: 7.20 General utilities	<stdlib.h>
 */
#ifndef	_STDLIB_H
#define __GLIBC_INTERNAL_STARTING_HEADER_IMPLEMENTATION
#include <bits/libc-header-start.h>
/* Get size_t, wchar_t and NULL from <stddef.h>.  */
#define __need_size_t
#define __need_wchar_t
#define __need_NULL
#include <stddef.h>
__BEGIN_DECLS
#define	_STDLIB_H	1
#if (defined __USE_XOPEN || defined __USE_XOPEN2K8) && !defined _SYS_WAIT_H
/* XPG requires a few symbols from <sys/wait.h> being defined.  */
# include <bits/waitflags.h>
# include <bits/waitstatus.h>
/* Define the macros <sys/wait.h> also would define this way.  */
# define WEXITSTATUS(status)	__WEXITSTATUS (status)
# define WTERMSIG(status)	__WTERMSIG (status)
# define WSTOPSIG(status)	__WSTOPSIG (status)
# define WIFEXITED(status)	__WIFEXITED (status)
# define WIFSIGNALED(status)	__WIFSIGNALED (status)
# define WIFSTOPPED(status)	__WIFSTOPPED (status)
# ifdef __WIFCONTINUED
#  define WIFCONTINUED(status)	__WIFCONTINUED (status)
# endif
#endif	/* X/Open or XPG7 and <sys/wait.h> not included.  */
/* _FloatN API tests for enablement.  */
#include <bits/floatn.h>
/* Returned by `div'.  */
typedef struct
  {
    int quot;			/* Quotient.  */
    int rem;			/* Remainder.  */
  } div_t;
/* Returned by `ldiv'.  */
#ifndef __ldiv_t_defined
typedef struct
  {
    long int quot;		/* Quotient.  */
    long int rem;		/* Remainder.  */
  } ldiv_t;
# define __ldiv_t_defined	1
#endif
#if defined __USE_ISOC99 && !defined __lldiv_t_defined
/* Returned by `lldiv'.  */
__extension__ typedef struct
  {
    long long int quot;		/* Quotient.  */
    long long int rem;		/* Remainder.  */
  } lldiv_t;
# define __lldiv_t_defined	1
#endif
/* The largest number rand will return (same as INT_MAX).  */
#define	RAND_MAX	2147483647
/* We define these the same for all machines.
   Changes from this to the outside world should be done in `_exit'.  */
#define	EXIT_FAILURE	1	/* Failing exit status.  */
#define	EXIT_SUCCESS	0	/* Successful exit status.  */
/* Maximum length of a multibyte character in the current locale.  */
#define	MB_CUR_MAX	(__ctype_get_mb_cur_max ())
extern size_t __ctype_get_mb_cur_max (void) __THROW __wur;
/* Convert a string to a floating-point number.  */
extern double atof (const char *__nptr)
     __THROW __attribute_pure__ __nonnull ((1)) __wur;
/* Convert a string to an integer.  */
extern int atoi (const char *__nptr)
     __THROW __attribute_pure__ __nonnull ((1)) __wur;
/* Convert a string to a long integer.  */
extern long int atol (const char *__nptr)
     __THROW __attribute_pure__ __nonnull ((1)) __wur;
#ifdef __USE_ISOC99
/* Convert a string to a long long integer.  */
__extension__ extern long long int atoll (const char *__nptr)
     __THROW __attribute_pure__ __nonnull ((1)) __wur;
#endif
/* Convert a string to a floating-point number.  */
extern double strtod (const char *__restrict __nptr,
		      char **__restrict __endptr)
     __THROW __nonnull ((1));
#ifdef	__USE_ISOC99
/* Likewise for `float' and `long double' sizes of floating-point numbers.  */
extern float strtof (const char *__restrict __nptr,
		     char **__restrict __endptr) __THROW __nonnull ((1));
extern long double strtold (const char *__restrict __nptr,
			    char **__restrict __endptr)
     __THROW __nonnull ((1));
#endif
/* Likewise for '_FloatN' and '_FloatNx'.  */
#if __HAVE_FLOAT16 && __GLIBC_USE (IEC_60559_TYPES_EXT)
extern _Float16 strtof16 (const char *__restrict __nptr,
			  char **__restrict __endptr)
     __THROW __nonnull ((1));
#endif
#if __HAVE_FLOAT32 && __GLIBC_USE (IEC_60559_TYPES_EXT)
extern _Float32 strtof32 (const char *__restrict __nptr,
			  char **__restrict __endptr)
     __THROW __nonnull ((1));
#endif
#if __HAVE_FLOAT64 && __GLIBC_USE (IEC_60559_TYPES_EXT)
extern _Float64 strtof64 (const char *__restrict __nptr,
			  char **__restrict __endptr)
     __THROW __nonnull ((1));
#endif
#if __HAVE_FLOAT128 && __GLIBC_USE (IEC_60559_TYPES_EXT)
extern _Float128 strtof128 (const char *__restrict __nptr,
			    char **__restrict __endptr)
     __THROW __nonnull ((1));
#endif
#if __HAVE_FLOAT32X && __GLIBC_USE (IEC_60559_TYPES_EXT)
extern _Float32x strtof32x (const char *__restrict __nptr,
			    char **__restrict __endptr)
     __THROW __nonnull ((1));
#endif
#if __HAVE_FLOAT64X && __GLIBC_USE (IEC_60559_TYPES_EXT)
extern _Float64x strtof64x (const char *__restrict __nptr,
			    char **__restrict __endptr)
     __THROW __nonnull ((1));
#endif
#if __HAVE_FLOAT128X && __GLIBC_USE (IEC_60559_TYPES_EXT)
extern _Float128x strtof128x (const char *__restrict __nptr,
			      char **__restrict __endptr)
     __THROW __nonnull ((1));
#endif
/* Convert a string to a long integer.  */
extern long int strtol (const char *__restrict __nptr,
			char **__restrict __endptr, int __base)
     __THROW __nonnull ((1));
/* Convert a string to an unsigned long integer.  */
extern unsigned long int strtoul (const char *__restrict __nptr,
				  char **__restrict __endptr, int __base)
     __THROW __nonnull ((1));
#ifdef __USE_MISC
/* Convert a string to a quadword integer.  */
__extension__
extern long long int strtoq (const char *__restrict __nptr,
			     char **__restrict __endptr, int __base)
     __THROW __nonnull ((1));
/* Convert a string to an unsigned quadword integer.  */
__extension__
extern unsigned long long int strtouq (const char *__restrict __nptr,
				       char **__restrict __endptr, int __base)
     __THROW __nonnull ((1));
#endif /* Use misc.  */
#ifdef __USE_ISOC99
/* Convert a string to a quadword integer.  */
__extension__
extern long long int strtoll (const char *__restrict __nptr,
			      char **__restrict __endptr, int __base)
     __THROW __nonnull ((1));
/* Convert a string to an unsigned quadword integer.  */
__extension__
extern unsigned long long int strtoull (const char *__restrict __nptr,
					char **__restrict __endptr, int __base)
     __THROW __nonnull ((1));
#endif /* ISO C99 or use MISC.  */
/* Convert a floating-point number to a string.  */
#if __GLIBC_USE (IEC_60559_BFP_EXT)
extern int strfromd (char *__dest, size_t __size, const char *__format,
		     double __f)
     __THROW __nonnull ((3));
extern int strfromf (char *__dest, size_t __size, const char *__format,
		     float __f)
     __THROW __nonnull ((3));
extern int strfroml (char *__dest, size_t __size, const char *__format,
		     long double __f)
     __THROW __nonnull ((3));
#endif
#if __HAVE_FLOAT16 && __GLIBC_USE (IEC_60559_TYPES_EXT)
extern int strfromf16 (char *__dest, size_t __size, const char * __format,
		       _Float16 __f)
     __THROW __nonnull ((3));
#endif
#if __HAVE_FLOAT32 && __GLIBC_USE (IEC_60559_TYPES_EXT)
extern int strfromf32 (char *__dest, size_t __size, const char * __format,
		       _Float32 __f)
     __THROW __nonnull ((3));
#endif
#if __HAVE_FLOAT64 && __GLIBC_USE (IEC_60559_TYPES_EXT)
extern int strfromf64 (char *__dest, size_t __size, const char * __format,
		       _Float64 __f)
     __THROW __nonnull ((3));
#endif
#if __HAVE_FLOAT128 && __GLIBC_USE (IEC_60559_TYPES_EXT)
extern int strfromf128 (char *__dest, size_t __size, const char * __format,
			_Float128 __f)
     __THROW __nonnull ((3));
#endif
#if __HAVE_FLOAT32X && __GLIBC_USE (IEC_60559_TYPES_EXT)
extern int strfromf32x (char *__dest, size_t __size, const char * __format,
			_Float32x __f)
     __THROW __nonnull ((3));
#endif
#if __HAVE_FLOAT64X && __GLIBC_USE (IEC_60559_TYPES_EXT)
extern int strfromf64x (char *__dest, size_t __size, const char * __format,
			_Float64x __f)
     __THROW __nonnull ((3));
#endif
#if __HAVE_FLOAT128X && __GLIBC_USE (IEC_60559_TYPES_EXT)
extern int strfromf128x (char *__dest, size_t __size, const char * __format,
			 _Float128x __f)
     __THROW __nonnull ((3));
#endif
#ifdef __USE_GNU
/* Parallel versions of the functions above which take the locale to
   use as an additional parameter.  These are GNU extensions inspired
   by the POSIX.1-2008 extended locale API.  */
# include <bits/types/locale_t.h>
extern long int strtol_l (const char *__restrict __nptr,
			  char **__restrict __endptr, int __base,
			  locale_t __loc) __THROW __nonnull ((1, 4));
extern unsigned long int strtoul_l (const char *__restrict __nptr,
				    char **__restrict __endptr,
				    int __base, locale_t __loc)
     __THROW __nonnull ((1, 4));
__extension__
extern long long int strtoll_l (const char *__restrict __nptr,
				char **__restrict __endptr, int __base,
				locale_t __loc)
     __THROW __nonnull ((1, 4));
__extension__
extern unsigned long long int strtoull_l (const char *__restrict __nptr,
					  char **__restrict __endptr,
					  int __base, locale_t __loc)
     __THROW __nonnull ((1, 4));
extern double strtod_l (const char *__restrict __nptr,
			char **__restrict __endptr, locale_t __loc)
     __THROW __nonnull ((1, 3));
extern float strtof_l (const char *__restrict __nptr,
		       char **__restrict __endptr, locale_t __loc)
     __THROW __nonnull ((1, 3));
extern long double strtold_l (const char *__restrict __nptr,
			      char **__restrict __endptr,
			      locale_t __loc)
     __THROW __nonnull ((1, 3));
# if __HAVE_FLOAT16
extern _Float16 strtof16_l (const char *__restrict __nptr,
			    char **__restrict __endptr,
			    locale_t __loc)
     __THROW __nonnull ((1, 3));
# endif
# if __HAVE_FLOAT32
extern _Float32 strtof32_l (const char *__restrict __nptr,
			    char **__restrict __endptr,
			    locale_t __loc)
     __THROW __nonnull ((1, 3));
# endif
# if __HAVE_FLOAT64
extern _Float64 strtof64_l (const char *__restrict __nptr,
			    char **__restrict __endptr,
			    locale_t __loc)
     __THROW __nonnull ((1, 3));
# endif
# if __HAVE_FLOAT128
extern _Float128 strtof128_l (const char *__restrict __nptr,
			      char **__restrict __endptr,
			      locale_t __loc)
     __THROW __nonnull ((1, 3));
# endif
# if __HAVE_FLOAT32X
extern _Float32x strtof32x_l (const char *__restrict __nptr,
			      char **__restrict __endptr,
			      locale_t __loc)
     __THROW __nonnull ((1, 3));
# endif
# if __HAVE_FLOAT64X
extern _Float64x strtof64x_l (const char *__restrict __nptr,
			      char **__restrict __endptr,
			      locale_t __loc)
     __THROW __nonnull ((1, 3));
# endif
# if __HAVE_FLOAT128X
extern _Float128x strtof128x_l (const char *__restrict __nptr,
				char **__restrict __endptr,
				locale_t __loc)
     __THROW __nonnull ((1, 3));
# endif
#endif /* GNU */
#ifdef __USE_EXTERN_INLINES
__extern_inline int
__NTH (atoi (const char *__nptr))
{
  return (int) strtol (__nptr, (char **) NULL, 10);
}
__extern_inline long int
__NTH (atol (const char *__nptr))
{
  return strtol (__nptr, (char **) NULL, 10);
}
# ifdef __USE_ISOC99
__extension__ __extern_inline long long int
__NTH (atoll (const char *__nptr))
{
  return strtoll (__nptr, (char **) NULL, 10);
}
# endif
#endif /* Optimizing and Inlining.  */
#if defined __USE_MISC || defined __USE_XOPEN_EXTENDED
/* Convert N to base 64 using the digits "./0-9A-Za-z", least-significant
   digit first.  Returns a pointer to static storage overwritten by the
   next call.  */
extern char *l64a (long int __n) __THROW __wur;
/* Read a number from a string S in base 64 as above.  */
extern long int a64l (const char *__s)
     __THROW __attribute_pure__ __nonnull ((1)) __wur;
#endif	/* Use misc || extended X/Open.  */
#if defined __USE_MISC || defined __USE_XOPEN_EXTENDED
# include <sys/types.h>	/* we need int32_t... */
/* These are the functions that actually do things.  The `random', `srandom',
   `initstate' and `setstate' functions are those from BSD Unices.
   The `rand' and `srand' functions are required by the ANSI standard.
   We provide both interfaces to the same random number generator.  */
/* Return a random long integer between 0 and RAND_MAX inclusive.  */
extern long int random (void) __THROW;
/* Seed the random number generator with the given number.  */
extern void srandom (unsigned int __seed) __THROW;
/* Initialize the random number generator to use state buffer STATEBUF,
   of length STATELEN, and seed it with SEED.  Optimal lengths are 8, 16,
   32, 64, 128 and 256, the bigger the better; values less than 8 will
   cause an error and values greater than 256 will be rounded down.  */
extern char *initstate (unsigned int __seed, char *__statebuf,
			size_t __statelen) __THROW __nonnull ((2));
/* Switch the random number generator to state buffer STATEBUF,
   which should have been previously initialized by `initstate'.  */
extern char *setstate (char *__statebuf) __THROW __nonnull ((1));
# ifdef __USE_MISC
/* Reentrant versions of the `random' family of functions.
   These functions all use the following data structure to contain
   state, rather than global state variables.  */
struct random_data
  {
    int32_t *fptr;		/* Front pointer.  */
    int32_t *rptr;		/* Rear pointer.  */
    int32_t *state;		/* Array of state values.  */
    int rand_type;		/* Type of random number generator.  */
    int rand_deg;		/* Degree of random number generator.  */
    int rand_sep;		/* Distance between front and rear.  */
    int32_t *end_ptr;		/* Pointer behind state table.  */
  };
extern int random_r (struct random_data *__restrict __buf,
		     int32_t *__restrict __result) __THROW __nonnull ((1, 2));
extern int srandom_r (unsigned int __seed, struct random_data *__buf)
     __THROW __nonnull ((2));
extern int initstate_r (unsigned int __seed, char *__restrict __statebuf,
			size_t __statelen,
			struct random_data *__restrict __buf)
     __THROW __nonnull ((2, 4));
extern int setstate_r (char *__restrict __statebuf,
		       struct random_data *__restrict __buf)
     __THROW __nonnull ((1, 2));
# endif	/* Use misc.  */
#endif	/* Use extended X/Open || misc. */
/* Return a random integer between 0 and RAND_MAX inclusive.  */
extern int rand (void) __THROW;
/* Seed the random number generator with the given number.  */
extern void srand (unsigned int __seed) __THROW;
#ifdef __USE_POSIX199506
/* Reentrant interface according to POSIX.1.  */
extern int rand_r (unsigned int *__seed) __THROW;
#endif
#if defined __USE_MISC || defined __USE_XOPEN
/* System V style 48-bit random number generator functions.  */
/* Return non-negative, double-precision floating-point value in [0.0,1.0).  */
extern double drand48 (void) __THROW;
extern double erand48 (unsigned short int __xsubi[3]) __THROW __nonnull ((1));
/* Return non-negative, long integer in [0,2^31).  */
extern long int lrand48 (void) __THROW;
extern long int nrand48 (unsigned short int __xsubi[3])
     __THROW __nonnull ((1));
/* Return signed, long integers in [-2^31,2^31).  */
extern long int mrand48 (void) __THROW;
extern long int jrand48 (unsigned short int __xsubi[3])
     __THROW __nonnull ((1));
/* Seed random number generator.  */
extern void srand48 (long int __seedval) __THROW;
extern unsigned short int *seed48 (unsigned short int __seed16v[3])
     __THROW __nonnull ((1));
extern void lcong48 (unsigned short int __param[7]) __THROW __nonnull ((1));
# ifdef __USE_MISC
/* Data structure for communication with thread safe versions.  This
   type is to be regarded as opaque.  It's only exported because users
   have to allocate objects of this type.  */
struct drand48_data
  {
    unsigned short int __x[3];	/* Current state.  */
    unsigned short int __old_x[3]; /* Old state.  */
    unsigned short int __c;	/* Additive const. in congruential formula.  */
    unsigned short int __init;	/* Flag for initializing.  */
    __extension__ unsigned long long int __a;	/* Factor in congruential
						   formula.  */
  };
/* Return non-negative, double-precision floating-point value in [0.0,1.0).  */
extern int drand48_r (struct drand48_data *__restrict __buffer,
		      double *__restrict __result) __THROW __nonnull ((1, 2));
extern int erand48_r (unsigned short int __xsubi[3],
		      struct drand48_data *__restrict __buffer,
		      double *__restrict __result) __THROW __nonnull ((1, 2));
/* Return non-negative, long integer in [0,2^31).  */
extern int lrand48_r (struct drand48_data *__restrict __buffer,
		      long int *__restrict __result)
     __THROW __nonnull ((1, 2));
extern int nrand48_r (unsigned short int __xsubi[3],
		      struct drand48_data *__restrict __buffer,
		      long int *__restrict __result)
     __THROW __nonnull ((1, 2));
/* Return signed, long integers in [-2^31,2^31).  */
extern int mrand48_r (struct drand48_data *__restrict __buffer,
		      long int *__restrict __result)
     __THROW __nonnull ((1, 2));
extern int jrand48_r (unsigned short int __xsubi[3],
		      struct drand48_data *__restrict __buffer,
		      long int *__restrict __result)
     __THROW __nonnull ((1, 2));
/* Seed random number generator.  */
extern int srand48_r (long int __seedval, struct drand48_data *__buffer)
     __THROW __nonnull ((2));
extern int seed48_r (unsigned short int __seed16v[3],
		     struct drand48_data *__buffer) __THROW __nonnull ((1, 2));
extern int lcong48_r (unsigned short int __param[7],
		      struct drand48_data *__buffer)
     __THROW __nonnull ((1, 2));
# endif	/* Use misc.  */
#endif	/* Use misc or X/Open.  */
/* Allocate SIZE bytes of memory.  */
extern void *malloc (size_t __size) __THROW __attribute_malloc__ __wur;
/* Allocate NMEMB elements of SIZE bytes each, all initialized to 0.  */
extern void *calloc (size_t __nmemb, size_t __size)
     __THROW __attribute_malloc__ __wur;
/* Re-allocate the previously allocated block
   in PTR, making the new block SIZE bytes long.  */
/* __attribute_malloc__ is not used, because if realloc returns
   the same pointer that was passed to it, aliasing needs to be allowed
   between objects pointed by the old and new pointers.  */
extern void *realloc (void *__ptr, size_t __size)
     __THROW __attribute_warn_unused_result__;
#ifdef __USE_GNU
/* Re-allocate the previously allocated block in PTR, making the new
   block large enough for NMEMB elements of SIZE bytes each.  */
/* __attribute_malloc__ is not used, because if reallocarray returns
   the same pointer that was passed to it, aliasing needs to be allowed
   between objects pointed by the old and new pointers.  */
extern void *reallocarray (void *__ptr, size_t __nmemb, size_t __size)
     __THROW __attribute_warn_unused_result__;
#endif
/* Free a block allocated by `malloc', `realloc' or `calloc'.  */
extern void free (void *__ptr) __THROW;
#ifdef __USE_MISC
# include <alloca.h>
#endif /* Use misc.  */
#if (defined __USE_XOPEN_EXTENDED && !defined __USE_XOPEN2K) \
    || defined __USE_MISC
/* Allocate SIZE bytes on a page boundary.  The storage cannot be freed.  */
extern void *valloc (size_t __size) __THROW __attribute_malloc__ __wur;
#endif
#ifdef __USE_XOPEN2K
/* Allocate memory of SIZE bytes with an alignment of ALIGNMENT.  */
extern int posix_memalign (void **__memptr, size_t __alignment, size_t __size)
     __THROW __nonnull ((1)) __wur;
#endif
#ifdef __USE_ISOC11
/* ISO C variant of aligned allocation.  */
extern void *aligned_alloc (size_t __alignment, size_t __size)
     __THROW __attribute_malloc__ __attribute_alloc_size__ ((2)) __wur;
#endif
/* Abort execution and generate a core-dump.  */
extern void abort (void) __THROW __attribute__ ((__noreturn__));
/* Register a function to be called when `exit' is called.  */
extern int atexit (void (*__func) (void)) __THROW __nonnull ((1));
#if defined __USE_ISOC11 || defined __USE_ISOCXX11
/* Register a function to be called when `quick_exit' is called.  */
# ifdef __cplusplus
extern "C++" int at_quick_exit (void (*__func) (void))
     __THROW __asm ("at_quick_exit") __nonnull ((1));
# else
extern int at_quick_exit (void (*__func) (void)) __THROW __nonnull ((1));
# endif
#endif
#ifdef	__USE_MISC
/* Register a function to be called with the status
   given to `exit' and the given argument.  */
extern int on_exit (void (*__func) (int __status, void *__arg), void *__arg)
     __THROW __nonnull ((1));
#endif
/* Call all functions registered with `atexit' and `on_exit',
   in the reverse of the order in which they were registered,
   perform stdio cleanup, and terminate program execution with STATUS.  */
extern void exit (int __status) __THROW __attribute__ ((__noreturn__));
#if defined __USE_ISOC11 || defined __USE_ISOCXX11
/* Call all functions registered with `at_quick_exit' in the reverse
   of the order in which they were registered and terminate program
   execution with STATUS.  */
extern void quick_exit (int __status) __THROW __attribute__ ((__noreturn__));
#endif
#ifdef __USE_ISOC99
/* Terminate the program with STATUS without calling any of the
   functions registered with `atexit' or `on_exit'.  */
extern void _Exit (int __status) __THROW __attribute__ ((__noreturn__));
#endif
/* Return the value of envariable NAME, or NULL if it doesn't exist.  */
extern char *getenv (const char *__name) __THROW __nonnull ((1)) __wur;
#ifdef __USE_GNU
/* This function is similar to the above but returns NULL if the
   programs is running with SUID or SGID enabled.  */
extern char *secure_getenv (const char *__name)
     __THROW __nonnull ((1)) __wur;
#endif
#if defined __USE_MISC || defined __USE_XOPEN
/* The SVID says this is in <stdio.h>, but this seems a better place.	*/
/* Put STRING, which is of the form "NAME=VALUE", in the environment.
   If there is no `=', remove NAME from the environment.  */
extern int putenv (char *__string) __THROW __nonnull ((1));
#endif
#ifdef __USE_XOPEN2K
/* Set NAME to VALUE in the environment.
   If REPLACE is nonzero, overwrite an existing value.  */
extern int setenv (const char *__name, const char *__value, int __replace)
     __THROW __nonnull ((2));
/* Remove the variable NAME from the environment.  */
extern int unsetenv (const char *__name) __THROW __nonnull ((1));
#endif
#ifdef	__USE_MISC
/* The `clearenv' was planned to be added to POSIX.1 but probably
   never made it.  Nevertheless the POSIX.9 standard (POSIX bindings
   for Fortran 77) requires this function.  */
extern int clearenv (void) __THROW;
#endif
#if defined __USE_MISC \
    || (defined __USE_XOPEN_EXTENDED && !defined __USE_XOPEN2K8)
/* Generate a unique temporary file name from TEMPLATE.
   The last six characters of TEMPLATE must be "XXXXXX";
   they are replaced with a string that makes the file name unique.
   Always returns TEMPLATE, it's either a temporary file name or a null
   string if it cannot get a unique file name.  */
extern char *mktemp (char *__template) __THROW __nonnull ((1));
#endif
#if defined __USE_XOPEN_EXTENDED || defined __USE_XOPEN2K8
/* Generate a unique temporary file name from TEMPLATE.
   The last six characters of TEMPLATE must be "XXXXXX";
   they are replaced with a string that makes the filename unique.
   Returns a file descriptor open on the file for reading and writing,
   or -1 if it cannot create a uniquely-named file.
   This function is a possible cancellation point and therefore not
   marked with __THROW.  */
# ifndef __USE_FILE_OFFSET64
extern int mkstemp (char *__template) __nonnull ((1)) __wur;
# else
#  ifdef __REDIRECT
extern int __REDIRECT (mkstemp, (char *__template), mkstemp64)
     __nonnull ((1)) __wur;
#  else
#   define mkstemp mkstemp64
#  endif
# endif
# ifdef __USE_LARGEFILE64
extern int mkstemp64 (char *__template) __nonnull ((1)) __wur;
# endif
#endif
#ifdef __USE_MISC
/* Similar to mkstemp, but the template can have a suffix after the
   XXXXXX.  The length of the suffix is specified in the second
   parameter.
   This function is a possible cancellation point and therefore not
   marked with __THROW.  */
# ifndef __USE_FILE_OFFSET64
extern int mkstemps (char *__template, int __suffixlen) __nonnull ((1)) __wur;
# else
#  ifdef __REDIRECT
extern int __REDIRECT (mkstemps, (char *__template, int __suffixlen),
		       mkstemps64) __nonnull ((1)) __wur;
#  else
#   define mkstemps mkstemps64
#  endif
# endif
# ifdef __USE_LARGEFILE64
extern int mkstemps64 (char *__template, int __suffixlen)
     __nonnull ((1)) __wur;
# endif
#endif
#ifdef __USE_XOPEN2K8
/* Create a unique temporary directory from TEMPLATE.
   The last six characters of TEMPLATE must be "XXXXXX";
   they are replaced with a string that makes the directory name unique.
   Returns TEMPLATE, or a null pointer if it cannot get a unique name.
   The directory is created mode 700.  */
extern char *mkdtemp (char *__template) __THROW __nonnull ((1)) __wur;
#endif
#ifdef __USE_GNU
/* Generate a unique temporary file name from TEMPLATE similar to
   mkstemp.  But allow the caller to pass additional flags which are
   used in the open call to create the file..
   This function is a possible cancellation point and therefore not
   marked with __THROW.  */
# ifndef __USE_FILE_OFFSET64
extern int mkostemp (char *__template, int __flags) __nonnull ((1)) __wur;
# else
#  ifdef __REDIRECT
extern int __REDIRECT (mkostemp, (char *__template, int __flags), mkostemp64)
     __nonnull ((1)) __wur;
#  else
#   define mkostemp mkostemp64
#  endif
# endif
# ifdef __USE_LARGEFILE64
extern int mkostemp64 (char *__template, int __flags) __nonnull ((1)) __wur;
# endif
/* Similar to mkostemp, but the template can have a suffix after the
   XXXXXX.  The length of the suffix is specified in the second
   parameter.
   This function is a possible cancellation point and therefore not
   marked with __THROW.  */
# ifndef __USE_FILE_OFFSET64
extern int mkostemps (char *__template, int __suffixlen, int __flags)
     __nonnull ((1)) __wur;
# else
#  ifdef __REDIRECT
extern int __REDIRECT (mkostemps, (char *__template, int __suffixlen,
				   int __flags), mkostemps64)
     __nonnull ((1)) __wur;
#  else
#   define mkostemps mkostemps64
#  endif
# endif
# ifdef __USE_LARGEFILE64
extern int mkostemps64 (char *__template, int __suffixlen, int __flags)
     __nonnull ((1)) __wur;
# endif
#endif
/* Execute the given line as a shell command.
   This function is a cancellation point and therefore not marked with
   __THROW.  */
extern int system (const char *__command) __wur;
#ifdef	__USE_GNU
/* Return a malloc'd string containing the canonical absolute name of the
   existing named file.  */
extern char *canonicalize_file_name (const char *__name)
     __THROW __nonnull ((1)) __wur;
#endif
#if defined __USE_MISC || defined __USE_XOPEN_EXTENDED
/* Return the canonical absolute name of file NAME.  If RESOLVED is
   null, the result is malloc'd; otherwise, if the canonical name is
   PATH_MAX chars or more, returns null with `errno' set to
   ENAMETOOLONG; if the name fits in fewer than PATH_MAX chars,
   returns the name in RESOLVED.  */
extern char *realpath (const char *__restrict __name,
		       char *__restrict __resolved) __THROW __wur;
#endif
/* Shorthand for type of comparison functions.  */
#ifndef __COMPAR_FN_T
# define __COMPAR_FN_T
typedef int (*__compar_fn_t) (const void *, const void *);
# ifdef	__USE_GNU
typedef __compar_fn_t comparison_fn_t;
# endif
#endif
#ifdef __USE_GNU
typedef int (*__compar_d_fn_t) (const void *, const void *, void *);
#endif
/* Do a binary search for KEY in BASE, which consists of NMEMB elements
   of SIZE bytes each, using COMPAR to perform the comparisons.  */
extern void *bsearch (const void *__key, const void *__base,
		      size_t __nmemb, size_t __size, __compar_fn_t __compar)
     __nonnull ((1, 2, 5)) __wur;
#ifdef __USE_EXTERN_INLINES
# include <bits/stdlib-bsearch.h>
#endif
/* Sort NMEMB elements of BASE, of SIZE bytes each,
   using COMPAR to perform the comparisons.  */
extern void qsort (void *__base, size_t __nmemb, size_t __size,
		   __compar_fn_t __compar) __nonnull ((1, 4));
#ifdef __USE_GNU
extern void qsort_r (void *__base, size_t __nmemb, size_t __size,
		     __compar_d_fn_t __compar, void *__arg)
  __nonnull ((1, 4));
#endif
/* Return the absolute value of X.  */
extern int abs (int __x) __THROW __attribute__ ((__const__)) __wur;
extern long int labs (long int __x) __THROW __attribute__ ((__const__)) __wur;
#ifdef __USE_ISOC99
__extension__ extern long long int llabs (long long int __x)
     __THROW __attribute__ ((__const__)) __wur;
#endif
/* Return the `div_t', `ldiv_t' or `lldiv_t' representation
   of the value of NUMER over DENOM. */
/* GCC may have built-ins for these someday.  */
extern div_t div (int __numer, int __denom)
     __THROW __attribute__ ((__const__)) __wur;
extern ldiv_t ldiv (long int __numer, long int __denom)
     __THROW __attribute__ ((__const__)) __wur;
#ifdef __USE_ISOC99
__extension__ extern lldiv_t lldiv (long long int __numer,
				    long long int __denom)
     __THROW __attribute__ ((__const__)) __wur;
#endif
#if (defined __USE_XOPEN_EXTENDED && !defined __USE_XOPEN2K8) \
    || defined __USE_MISC
/* Convert floating point numbers to strings.  The returned values are
   valid only until another call to the same function.  */
/* Convert VALUE to a string with NDIGIT digits and return a pointer to
   this.  Set *DECPT with the position of the decimal character and *SIGN
   with the sign of the number.  */
extern char *ecvt (double __value, int __ndigit, int *__restrict __decpt,
		   int *__restrict __sign) __THROW __nonnull ((3, 4)) __wur;
/* Convert VALUE to a string rounded to NDIGIT decimal digits.  Set *DECPT
   with the position of the decimal character and *SIGN with the sign of
   the number.  */
extern char *fcvt (double __value, int __ndigit, int *__restrict __decpt,
		   int *__restrict __sign) __THROW __nonnull ((3, 4)) __wur;
/* If possible convert VALUE to a string with NDIGIT significant digits.
   Otherwise use exponential representation.  The resulting string will
   be written to BUF.  */
extern char *gcvt (double __value, int __ndigit, char *__buf)
     __THROW __nonnull ((3)) __wur;
#endif
#ifdef __USE_MISC
/* Long double versions of above functions.  */
extern char *qecvt (long double __value, int __ndigit,
		    int *__restrict __decpt, int *__restrict __sign)
     __THROW __nonnull ((3, 4)) __wur;
extern char *qfcvt (long double __value, int __ndigit,
		    int *__restrict __decpt, int *__restrict __sign)
     __THROW __nonnull ((3, 4)) __wur;
extern char *qgcvt (long double __value, int __ndigit, char *__buf)
     __THROW __nonnull ((3)) __wur;
/* Reentrant version of the functions above which provide their own
   buffers.  */
extern int ecvt_r (double __value, int __ndigit, int *__restrict __decpt,
		   int *__restrict __sign, char *__restrict __buf,
		   size_t __len) __THROW __nonnull ((3, 4, 5));
extern int fcvt_r (double __value, int __ndigit, int *__restrict __decpt,
		   int *__restrict __sign, char *__restrict __buf,
		   size_t __len) __THROW __nonnull ((3, 4, 5));
extern int qecvt_r (long double __value, int __ndigit,
		    int *__restrict __decpt, int *__restrict __sign,
		    char *__restrict __buf, size_t __len)
     __THROW __nonnull ((3, 4, 5));
extern int qfcvt_r (long double __value, int __ndigit,
		    int *__restrict __decpt, int *__restrict __sign,
		    char *__restrict __buf, size_t __len)
     __THROW __nonnull ((3, 4, 5));
#endif	/* misc */
/* Return the length of the multibyte character
   in S, which is no longer than N.  */
extern int mblen (const char *__s, size_t __n) __THROW;
/* Return the length of the given multibyte character,
   putting its `wchar_t' representation in *PWC.  */
extern int mbtowc (wchar_t *__restrict __pwc,
		   const char *__restrict __s, size_t __n) __THROW;
/* Put the multibyte character represented
   by WCHAR in S, returning its length.  */
extern int wctomb (char *__s, wchar_t __wchar) __THROW;
/* Convert a multibyte string to a wide char string.  */
extern size_t mbstowcs (wchar_t *__restrict  __pwcs,
			const char *__restrict __s, size_t __n) __THROW;
/* Convert a wide char string to multibyte string.  */
extern size_t wcstombs (char *__restrict __s,
			const wchar_t *__restrict __pwcs, size_t __n)
     __THROW;
#ifdef __USE_MISC
/* Determine whether the string value of RESPONSE matches the affirmation
   or negative response expression as specified by the LC_MESSAGES category
   in the program's current locale.  Returns 1 if affirmative, 0 if
   negative, and -1 if not matching.  */
extern int rpmatch (const char *__response) __THROW __nonnull ((1)) __wur;
#endif
#if defined __USE_XOPEN_EXTENDED || defined __USE_XOPEN2K8
/* Parse comma separated suboption from *OPTIONP and match against
   strings in TOKENS.  If found return index and set *VALUEP to
   optional value introduced by an equal sign.  If the suboption is
   not part of TOKENS return in *VALUEP beginning of unknown
   suboption.  On exit *OPTIONP is set to the beginning of the next
   token or at the terminating NUL character.  */
extern int getsubopt (char **__restrict __optionp,
		      char *const *__restrict __tokens,
		      char **__restrict __valuep)
     __THROW __nonnull ((1, 2, 3)) __wur;
#endif
/* X/Open pseudo terminal handling.  */
#ifdef __USE_XOPEN2KXSI
/* Return a master pseudo-terminal handle.  */
extern int posix_openpt (int __oflag) __wur;
#endif
#ifdef __USE_XOPEN_EXTENDED
/* The next four functions all take a master pseudo-tty fd and
   perform an operation on the associated slave:  */
/* Chown the slave to the calling user.  */
extern int grantpt (int __fd) __THROW;
/* Release an internal lock so the slave can be opened.
   Call after grantpt().  */
extern int unlockpt (int __fd) __THROW;
/* Return the pathname of the pseudo terminal slave associated with
   the master FD is open on, or NULL on errors.
   The returned storage is good until the next call to this function.  */
extern char *ptsname (int __fd) __THROW __wur;
#endif
#ifdef __USE_GNU
/* Store at most BUFLEN characters of the pathname of the slave pseudo
   terminal associated with the master FD is open on in BUF.
   Return 0 on success, otherwise an error number.  */
extern int ptsname_r (int __fd, char *__buf, size_t __buflen)
     __THROW __nonnull ((2));
/* Open a master pseudo terminal and return its file descriptor.  */
extern int getpt (void);
#endif
#ifdef __USE_MISC
/* Put the 1 minute, 5 minute and 15 minute load averages into the first
   NELEM elements of LOADAVG.  Return the number written (never more than
   three, but may be less than NELEM), or -1 if an error occurred.  */
extern int getloadavg (double __loadavg[], int __nelem)
     __THROW __nonnull ((1));
#endif
#if defined __USE_XOPEN_EXTENDED && !defined __USE_XOPEN2K
/* Return the index into the active-logins file (utmp) for
   the controlling terminal.  */
extern int ttyslot (void) __THROW;
#endif
#include <bits/stdlib-float.h>
/* Define some macros helping to catch buffer overflows.  */
#if __USE_FORTIFY_LEVEL > 0 && defined __fortify_function
# include <bits/stdlib.h>
#endif
#ifdef __LDBL_COMPAT
# include <bits/stdlib-ldbl.h>
#endif
__END_DECLS
#endif /* stdlib.h  */

/* Copyright (C) 1991-2018 Free Software Foundation, Inc.
   This file is part of the GNU C Library.
   The GNU C Library is free software; you can redistribute it and/or
   modify it under the terms of the GNU Lesser General Public
   License as published by the Free Software Foundation; either
   version 2.1 of the License, or (at your option) any later version.
   The GNU C Library is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
   Lesser General Public License for more details.
   You should have received a copy of the GNU Lesser General Public
   License along with the GNU C Library; if not, see
   <http://www.gnu.org/licenses/>.  */
#ifndef	_SYS_IOCTL_H
#define	_SYS_IOCTL_H	1
#include <features.h>
__BEGIN_DECLS
/* Get the list of `ioctl' requests and related constants.  */
#include <bits/ioctls.h>
/* Define some types used by `ioctl' requests.  */
#include <bits/ioctl-types.h>
/* On a Unix system, the system <sys/ioctl.h> probably defines some of
   the symbols we define in <sys/ttydefaults.h> (usually with the same
   values).  The code to generate <bits/ioctls.h> has omitted these
   symbols to avoid the conflict, but a Unix program expects <sys/ioctl.h>
   to define them, so we must include <sys/ttydefaults.h> here.  */
#include <sys/ttydefaults.h>
/* Perform the I/O control operation specified by REQUEST on FD.
   One argument may follow; its presence and type depend on REQUEST.
   Return value depends on REQUEST.  Usually -1 indicates error.  */
extern int ioctl (int __fd, unsigned long int __request, ...) __THROW;
__END_DECLS
#endif /* sys/ioctl.h */
/* Declarations of socket constants, types, and functions.
   Copyright (C) 1991-2018 Free Software Foundation, Inc.
   This file is part of the GNU C Library.
   The GNU C Library is free software; you can redistribute it and/or
   modify it under the terms of the GNU Lesser General Public
   License as published by the Free Software Foundation; either
   version 2.1 of the License, or (at your option) any later version.
   The GNU C Library is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
   Lesser General Public License for more details.
   You should have received a copy of the GNU Lesser General Public
   License along with the GNU C Library; if not, see
   <http://www.gnu.org/licenses/>.  */
#ifndef	_SYS_SOCKET_H
#define	_SYS_SOCKET_H	1
#include <features.h>
__BEGIN_DECLS
#include <bits/types/struct_iovec.h>
#define	__need_size_t
#include <stddef.h>
/* This operating system-specific header file defines the SOCK_*, PF_*,
   AF_*, MSG_*, SOL_*, and SO_* constants, and the `struct sockaddr',
   `struct msghdr', and `struct linger' types.  */
#include <bits/socket.h>
#ifdef __USE_MISC
# include <bits/types/struct_osockaddr.h>
#endif
/* The following constants should be used for the second parameter of
   `shutdown'.  */
enum
{
  SHUT_RD = 0,		/* No more receptions.  */
#define SHUT_RD		SHUT_RD
  SHUT_WR,		/* No more transmissions.  */
#define SHUT_WR		SHUT_WR
  SHUT_RDWR		/* No more receptions or transmissions.  */
#define SHUT_RDWR	SHUT_RDWR
};
/* This is the type we use for generic socket address arguments.
   With GCC 2.7 and later, the funky union causes redeclarations or
   uses with any of the listed types to be allowed without complaint.
   G++ 2.7 does not support transparent unions so there we want the
   old-style declaration, too.  */
#if defined __cplusplus || !__GNUC_PREREQ (2, 7) || !defined __USE_GNU
# define __SOCKADDR_ARG		struct sockaddr *__restrict
# define __CONST_SOCKADDR_ARG	const struct sockaddr *
#else
/* Add more `struct sockaddr_AF' types here as necessary.
   These are all the ones I found on NetBSD and Linux.  */
# define __SOCKADDR_ALLTYPES \
  __SOCKADDR_ONETYPE (sockaddr) \
  __SOCKADDR_ONETYPE (sockaddr_at) \
  __SOCKADDR_ONETYPE (sockaddr_ax25) \
  __SOCKADDR_ONETYPE (sockaddr_dl) \
  __SOCKADDR_ONETYPE (sockaddr_eon) \
  __SOCKADDR_ONETYPE (sockaddr_in) \
  __SOCKADDR_ONETYPE (sockaddr_in6) \
  __SOCKADDR_ONETYPE (sockaddr_inarp) \
  __SOCKADDR_ONETYPE (sockaddr_ipx) \
  __SOCKADDR_ONETYPE (sockaddr_iso) \
  __SOCKADDR_ONETYPE (sockaddr_ns) \
  __SOCKADDR_ONETYPE (sockaddr_un) \
  __SOCKADDR_ONETYPE (sockaddr_x25)
# define __SOCKADDR_ONETYPE(type) struct type *__restrict __##type##__;
typedef union { __SOCKADDR_ALLTYPES
	      } __SOCKADDR_ARG __attribute__ ((__transparent_union__));
# undef __SOCKADDR_ONETYPE
# define __SOCKADDR_ONETYPE(type) const struct type *__restrict __##type##__;
typedef union { __SOCKADDR_ALLTYPES
	      } __CONST_SOCKADDR_ARG __attribute__ ((__transparent_union__));
# undef __SOCKADDR_ONETYPE
#endif
#ifdef __USE_GNU
/* For `recvmmsg' and `sendmmsg'.  */
struct mmsghdr
  {
    struct msghdr msg_hdr;	/* Actual message header.  */
    unsigned int msg_len;	/* Number of received or sent bytes for the
				   entry.  */
  };
#endif
/* Create a new socket of type TYPE in domain DOMAIN, using
   protocol PROTOCOL.  If PROTOCOL is zero, one is chosen automatically.
   Returns a file descriptor for the new socket, or -1 for errors.  */
extern int socket (int __domain, int __type, int __protocol) __THROW;
/* Create two new sockets, of type TYPE in domain DOMAIN and using
   protocol PROTOCOL, which are connected to each other, and put file
   descriptors for them in FDS[0] and FDS[1].  If PROTOCOL is zero,
   one will be chosen automatically.  Returns 0 on success, -1 for errors.  */
extern int socketpair (int __domain, int __type, int __protocol,
		       int __fds[2]) __THROW;
/* Give the socket FD the local address ADDR (which is LEN bytes long).  */
extern int bind (int __fd, __CONST_SOCKADDR_ARG __addr, socklen_t __len)
     __THROW;
/* Put the local address of FD into *ADDR and its length in *LEN.  */
extern int getsockname (int __fd, __SOCKADDR_ARG __addr,
			socklen_t *__restrict __len) __THROW;
/* Open a connection on socket FD to peer at ADDR (which LEN bytes long).
   For connectionless socket types, just set the default address to send to
   and the only address from which to accept transmissions.
   Return 0 on success, -1 for errors.
   This function is a cancellation point and therefore not marked with
   __THROW.  */
extern int connect (int __fd, __CONST_SOCKADDR_ARG __addr, socklen_t __len);
/* Put the address of the peer connected to socket FD into *ADDR
   (which is *LEN bytes long), and its actual length into *LEN.  */
extern int getpeername (int __fd, __SOCKADDR_ARG __addr,
			socklen_t *__restrict __len) __THROW;
/* Send N bytes of BUF to socket FD.  Returns the number sent or -1.
   This function is a cancellation point and therefore not marked with
   __THROW.  */
extern ssize_t send (int __fd, const void *__buf, size_t __n, int __flags);
/* Read N bytes into BUF from socket FD.
   Returns the number read or -1 for errors.
   This function is a cancellation point and therefore not marked with
   __THROW.  */
extern ssize_t recv (int __fd, void *__buf, size_t __n, int __flags);
/* Send N bytes of BUF on socket FD to peer at address ADDR (which is
   ADDR_LEN bytes long).  Returns the number sent, or -1 for errors.
   This function is a cancellation point and therefore not marked with
   __THROW.  */
extern ssize_t sendto (int __fd, const void *__buf, size_t __n,
		       int __flags, __CONST_SOCKADDR_ARG __addr,
		       socklen_t __addr_len);
/* Read N bytes into BUF through socket FD.
   If ADDR is not NULL, fill in *ADDR_LEN bytes of it with tha address of
   the sender, and store the actual size of the address in *ADDR_LEN.
   Returns the number of bytes read or -1 for errors.
   This function is a cancellation point and therefore not marked with
   __THROW.  */
extern ssize_t recvfrom (int __fd, void *__restrict __buf, size_t __n,
			 int __flags, __SOCKADDR_ARG __addr,
			 socklen_t *__restrict __addr_len);
/* Send a message described MESSAGE on socket FD.
   Returns the number of bytes sent, or -1 for errors.
   This function is a cancellation point and therefore not marked with
   __THROW.  */
extern ssize_t sendmsg (int __fd, const struct msghdr *__message,
			int __flags);
#ifdef __USE_GNU
/* Send a VLEN messages as described by VMESSAGES to socket FD.
   Returns the number of datagrams successfully written or -1 for errors.
   This function is a cancellation point and therefore not marked with
   __THROW.  */
extern int sendmmsg (int __fd, struct mmsghdr *__vmessages,
		     unsigned int __vlen, int __flags);
#endif
/* Receive a message as described by MESSAGE from socket FD.
   Returns the number of bytes read or -1 for errors.
   This function is a cancellation point and therefore not marked with
   __THROW.  */
extern ssize_t recvmsg (int __fd, struct msghdr *__message, int __flags);
#ifdef __USE_GNU
/* Receive up to VLEN messages as described by VMESSAGES from socket FD.
   Returns the number of messages received or -1 for errors.
   This function is a cancellation point and therefore not marked with
   __THROW.  */
extern int recvmmsg (int __fd, struct mmsghdr *__vmessages,
		     unsigned int __vlen, int __flags,
		     struct timespec *__tmo);
#endif
/* Put the current value for socket FD's option OPTNAME at protocol level LEVEL
   into OPTVAL (which is *OPTLEN bytes long), and set *OPTLEN to the value's
   actual length.  Returns 0 on success, -1 for errors.  */
extern int getsockopt (int __fd, int __level, int __optname,
		       void *__restrict __optval,
		       socklen_t *__restrict __optlen) __THROW;
/* Set socket FD's option OPTNAME at protocol level LEVEL
   to *OPTVAL (which is OPTLEN bytes long).
   Returns 0 on success, -1 for errors.  */
extern int setsockopt (int __fd, int __level, int __optname,
		       const void *__optval, socklen_t __optlen) __THROW;
/* Prepare to accept connections on socket FD.
   N connection requests will be queued before further requests are refused.
   Returns 0 on success, -1 for errors.  */
extern int listen (int __fd, int __n) __THROW;
/* Await a connection on socket FD.
   When a connection arrives, open a new socket to communicate with it,
   set *ADDR (which is *ADDR_LEN bytes long) to the address of the connecting
   peer and *ADDR_LEN to the address's actual length, and return the
   new socket's descriptor, or -1 for errors.
   This function is a cancellation point and therefore not marked with
   __THROW.  */
extern int accept (int __fd, __SOCKADDR_ARG __addr,
		   socklen_t *__restrict __addr_len);
#ifdef __USE_GNU
/* Similar to 'accept' but takes an additional parameter to specify flags.
   This function is a cancellation point and therefore not marked with
   __THROW.  */
extern int accept4 (int __fd, __SOCKADDR_ARG __addr,
		    socklen_t *__restrict __addr_len, int __flags);
#endif
/* Shut down all or part of the connection open on socket FD.
   HOW determines what to shut down:
     SHUT_RD   = No more receptions;
     SHUT_WR   = No more transmissions;
     SHUT_RDWR = No more receptions or transmissions.
   Returns 0 on success, -1 for errors.  */
extern int shutdown (int __fd, int __how) __THROW;
#ifdef __USE_XOPEN2K
/* Determine wheter socket is at a out-of-band mark.  */
extern int sockatmark (int __fd) __THROW;
#endif
#ifdef __USE_MISC
/* FDTYPE is S_IFSOCK or another S_IF* macro defined in <sys/stat.h>;
   returns 1 if FD is open on an object of the indicated type, 0 if not,
   or -1 for errors (setting errno).  */
extern int isfdtype (int __fd, int __fdtype) __THROW;
#endif
/* Define some macros helping to catch buffer overflows.  */
#if __USE_FORTIFY_LEVEL > 0 && defined __fortify_function
# include <bits/socket2.h>
#endif
__END_DECLS
#endif /* sys/socket.h */

/* net/if.h -- declarations for inquiring about network interfaces
   Copyright (C) 1997-2018 Free Software Foundation, Inc.
   This file is part of the GNU C Library.
   The GNU C Library is free software; you can redistribute it and/or
   modify it under the terms of the GNU Lesser General Public
   License as published by the Free Software Foundation; either
   version 2.1 of the License, or (at your option) any later version.
   The GNU C Library is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
   Lesser General Public License for more details.
   You should have received a copy of the GNU Lesser General Public
   License along with the GNU C Library; if not, see
   <http://www.gnu.org/licenses/>.  */
#ifndef _NET_IF_H
#define _NET_IF_H	1
#include <features.h>
#ifdef __USE_MISC
# include <sys/types.h>
# include <sys/socket.h>
#endif
/* Length of interface name.  */
#define IF_NAMESIZE	16
struct if_nameindex
  {
    unsigned int if_index;	/* 1, 2, ... */
    char *if_name;		/* null terminated name: "eth0", ... */
  };
#ifdef __USE_MISC
/* Standard interface flags. */
enum
  {
    IFF_UP = 0x1,		/* Interface is up.  */
# define IFF_UP	IFF_UP
    IFF_BROADCAST = 0x2,	/* Broadcast address valid.  */
# define IFF_BROADCAST	IFF_BROADCAST
    IFF_DEBUG = 0x4,		/* Turn on debugging.  */
# define IFF_DEBUG	IFF_DEBUG
    IFF_LOOPBACK = 0x8,		/* Is a loopback net.  */
# define IFF_LOOPBACK	IFF_LOOPBACK
    IFF_POINTOPOINT = 0x10,	/* Interface is point-to-point link.  */
# define IFF_POINTOPOINT IFF_POINTOPOINT
    IFF_NOTRAILERS = 0x20,	/* Avoid use of trailers.  */
# define IFF_NOTRAILERS	IFF_NOTRAILERS
    IFF_RUNNING = 0x40,		/* Resources allocated.  */
# define IFF_RUNNING	IFF_RUNNING
    IFF_NOARP = 0x80,		/* No address resolution protocol.  */
# define IFF_NOARP	IFF_NOARP
    IFF_PROMISC = 0x100,	/* Receive all packets.  */
# define IFF_PROMISC	IFF_PROMISC
    /* Not supported */
    IFF_ALLMULTI = 0x200,	/* Receive all multicast packets.  */
# define IFF_ALLMULTI	IFF_ALLMULTI
    IFF_MASTER = 0x400,		/* Master of a load balancer.  */
# define IFF_MASTER	IFF_MASTER
    IFF_SLAVE = 0x800,		/* Slave of a load balancer.  */
# define IFF_SLAVE	IFF_SLAVE
    IFF_MULTICAST = 0x1000,	/* Supports multicast.  */
# define IFF_MULTICAST	IFF_MULTICAST
    IFF_PORTSEL = 0x2000,	/* Can set media type.  */
# define IFF_PORTSEL	IFF_PORTSEL
    IFF_AUTOMEDIA = 0x4000,	/* Auto media select active.  */
# define IFF_AUTOMEDIA	IFF_AUTOMEDIA
    IFF_DYNAMIC = 0x8000	/* Dialup device with changing addresses.  */
# define IFF_DYNAMIC	IFF_DYNAMIC
  };
/* The ifaddr structure contains information about one address of an
   interface.  They are maintained by the different address families,
   are allocated and attached when an address is set, and are linked
   together so all addresses for an interface can be located.  */
struct ifaddr
  {
    struct sockaddr ifa_addr;	/* Address of interface.  */
    union
      {
	struct sockaddr	ifu_broadaddr;
	struct sockaddr	ifu_dstaddr;
      } ifa_ifu;
    struct iface *ifa_ifp;	/* Back-pointer to interface.  */
    struct ifaddr *ifa_next;	/* Next address for interface.  */
  };
# define ifa_broadaddr	ifa_ifu.ifu_broadaddr	/* broadcast address	*/
# define ifa_dstaddr	ifa_ifu.ifu_dstaddr	/* other end of link	*/
/* Device mapping structure. I'd just gone off and designed a
   beautiful scheme using only loadable modules with arguments for
   driver options and along come the PCMCIA people 8)
   Ah well. The get() side of this is good for WDSETUP, and it'll be
   handy for debugging things. The set side is fine for now and being
   very small might be worth keeping for clean configuration.  */
struct ifmap
  {
    unsigned long int mem_start;
    unsigned long int mem_end;
    unsigned short int base_addr;
    unsigned char irq;
    unsigned char dma;
    unsigned char port;
    /* 3 bytes spare */
  };
/* Interface request structure used for socket ioctl's.  All interface
   ioctl's must have parameter definitions which begin with ifr_name.
   The remainder may be interface specific.  */
struct ifreq
  {
# define IFHWADDRLEN	6
# define IFNAMSIZ	IF_NAMESIZE
    union
      {
	char ifrn_name[IFNAMSIZ];	/* Interface name, e.g. "en0".  */
      } ifr_ifrn;
    union
      {
	struct sockaddr ifru_addr;
	struct sockaddr ifru_dstaddr;
	struct sockaddr ifru_broadaddr;
	struct sockaddr ifru_netmask;
	struct sockaddr ifru_hwaddr;
	short int ifru_flags;
	int ifru_ivalue;
	int ifru_mtu;
	struct ifmap ifru_map;
	char ifru_slave[IFNAMSIZ];	/* Just fits the size */
	char ifru_newname[IFNAMSIZ];
	__caddr_t ifru_data;
      } ifr_ifru;
  };
# define ifr_name	ifr_ifrn.ifrn_name	/* interface name 	*/
# define ifr_hwaddr	ifr_ifru.ifru_hwaddr	/* MAC address 		*/
# define ifr_addr	ifr_ifru.ifru_addr	/* address		*/
# define ifr_dstaddr	ifr_ifru.ifru_dstaddr	/* other end of p-p lnk	*/
# define ifr_broadaddr	ifr_ifru.ifru_broadaddr	/* broadcast address	*/
# define ifr_netmask	ifr_ifru.ifru_netmask	/* interface net mask	*/
# define ifr_flags	ifr_ifru.ifru_flags	/* flags		*/
# define ifr_metric	ifr_ifru.ifru_ivalue	/* metric		*/
# define ifr_mtu	ifr_ifru.ifru_mtu	/* mtu			*/
# define ifr_map	ifr_ifru.ifru_map	/* device map		*/
# define ifr_slave	ifr_ifru.ifru_slave	/* slave device		*/
# define ifr_data	ifr_ifru.ifru_data	/* for use by interface	*/
# define ifr_ifindex	ifr_ifru.ifru_ivalue    /* interface index      */
# define ifr_bandwidth	ifr_ifru.ifru_ivalue	/* link bandwidth	*/
# define ifr_qlen	ifr_ifru.ifru_ivalue	/* queue length		*/
# define ifr_newname	ifr_ifru.ifru_newname	/* New name		*/
# define _IOT_ifreq	_IOT(_IOTS(char),IFNAMSIZ,_IOTS(char),16,0,0)
# define _IOT_ifreq_short _IOT(_IOTS(char),IFNAMSIZ,_IOTS(short),1,0,0)
# define _IOT_ifreq_int	_IOT(_IOTS(char),IFNAMSIZ,_IOTS(int),1,0,0)
/* Structure used in SIOCGIFCONF request.  Used to retrieve interface
   configuration for machine (useful for programs which must know all
   networks accessible).  */
struct ifconf
  {
    int	ifc_len;			/* Size of buffer.  */
    union
      {
	__caddr_t ifcu_buf;
	struct ifreq *ifcu_req;
      } ifc_ifcu;
  };
# define ifc_buf	ifc_ifcu.ifcu_buf	/* Buffer address.  */
# define ifc_req	ifc_ifcu.ifcu_req	/* Array of structures.  */
# define _IOT_ifconf _IOT(_IOTS(struct ifconf),1,0,0,0,0) /* not right */
#endif	/* Misc.  */
__BEGIN_DECLS
/* Convert an interface name to an index, and vice versa.  */
extern unsigned int if_nametoindex (const char *__ifname) __THROW;
extern char *if_indextoname (unsigned int __ifindex, char *__ifname) __THROW;
/* Return a list of all interfaces and their indices.  */
extern struct if_nameindex *if_nameindex (void) __THROW;
/* Free the data returned from if_nameindex.  */
extern void if_freenameindex (struct if_nameindex *__ptr) __THROW;
__END_DECLS
#endif /* net/if.h */
/* Copyright (C) 1996-2018 Free Software Foundation, Inc.
   This file is part of the GNU C Library.
   The GNU C Library is free software; you can redistribute it and/or
   modify it under the terms of the GNU Lesser General Public
   License as published by the Free Software Foundation; either
   version 2.1 of the License, or (at your option) any later version.
   The GNU C Library is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
   Lesser General Public License for more details.
   You should have received a copy of the GNU Lesser General Public
   License along with the GNU C Library; if not, see
   <http://www.gnu.org/licenses/>.  */
#ifndef __NETINET_IF_ETHER_H
#define __NETINET_IF_ETHER_H	1
#include <features.h>
#include <sys/types.h>
/* Get definitions from kernel header file.  */
#include <linux/if_ether.h>
#ifdef __USE_MISC
/*
 * Copyright (c) 1982, 1986, 1993
 *	The Regents of the University of California.  All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 4. Neither the name of the University nor the names of its contributors
 *    may be used to endorse or promote products derived from this software
 *    without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE REGENTS AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE REGENTS OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 *
 *	@(#)if_ether.h	8.3 (Berkeley) 5/2/95
 *	$FreeBSD$
 */
#include <net/ethernet.h>
#include <net/if_arp.h>
__BEGIN_DECLS
/*
 * Ethernet Address Resolution Protocol.
 *
 * See RFC 826 for protocol description.  Structure below is adapted
 * to resolving internet addresses.  Field names used correspond to
 * RFC 826.
 */
struct	ether_arp {
	struct	arphdr ea_hdr;		/* fixed-size header */
	uint8_t arp_sha[ETH_ALEN];	/* sender hardware address */
	uint8_t arp_spa[4];		/* sender protocol address */
	uint8_t arp_tha[ETH_ALEN];	/* target hardware address */
	uint8_t arp_tpa[4];		/* target protocol address */
};
#define	arp_hrd	ea_hdr.ar_hrd
#define	arp_pro	ea_hdr.ar_pro
#define	arp_hln	ea_hdr.ar_hln
#define	arp_pln	ea_hdr.ar_pln
#define	arp_op	ea_hdr.ar_op
/*
 * Macro to map an IP multicast address to an Ethernet multicast address.
 * The high-order 25 bits of the Ethernet address are statically assigned,
 * and the low-order 23 bits are taken from the low end of the IP address.
 */
#define ETHER_MAP_IP_MULTICAST(ipaddr, enaddr) \
	/* struct in_addr *ipaddr; */ \
	/* uint8_t enaddr[ETH_ALEN]; */ \
{ \
	(enaddr)[0] = 0x01; \
	(enaddr)[1] = 0x00; \
	(enaddr)[2] = 0x5e; \
	(enaddr)[3] = ((uint8_t *)ipaddr)[1] & 0x7f; \
	(enaddr)[4] = ((uint8_t *)ipaddr)[2]; \
	(enaddr)[5] = ((uint8_t *)ipaddr)[3]; \
}
__END_DECLS
#endif /* __USE_MISC */
#endif /* netinet/if_ether.h */

#define MY_DEST_MAC0 0x00
#define MY_DEST_MAC1 0x00
#define MY_DEST_MAC2 0x00
#define MY_DEST_MAC3 0x00
#define MY_DEST_MAC4 0x00
#define MY_DEST_MAC5 0x00

#define DEFAULT_IF "eth0"
#define BUF_SIZ  1024

int main(int argc, char *argv[])
{
 int sockfd;
 struct ifreq if_idx;
 struct ifreq if_mac;
 int tx_len = 0;
 char sendbuf[BUF_SIZ];
 struct ether_header *eh = (struct ether_header *) sendbuf;
 struct iphdr *iph = (struct iphdr *) (sendbuf + sizeof(struct ether_header));
 struct sockaddr_ll socket_address;
 char ifName[IFNAMSIZ];
 
 /* Get interface name */
 if (argc > 1)
  strcpy(ifName, argv[1]);
 else
  strcpy(ifName, DEFAULT_IF);

 /* Open RAW socket to send on */
 if ((sockfd = socket(AF_PACKET, SOCK_RAW, IPPROTO_RAW)) == -1) {
     perror("socket");
 }

 /* Get the index of the interface to send on */
 memset(&if_idx, 0, sizeof(struct ifreq));
 strncpy(if_idx.ifr_name, ifName, IFNAMSIZ-1);
 if (ioctl(sockfd, SIOCGIFINDEX, &if_idx) < 0)
     perror("SIOCGIFINDEX");
 /* Get the MAC address of the interface to send on */
 memset(&if_mac, 0, sizeof(struct ifreq));
 strncpy(if_mac.ifr_name, ifName, IFNAMSIZ-1);
 if (ioctl(sockfd, SIOCGIFHWADDR, &if_mac) < 0)
     perror("SIOCGIFHWADDR");

 /* Construct the Ethernet header */
 memset(sendbuf, 0, BUF_SIZ);
 /* Ethernet header */
 eh->ether_shost[0] = ((uint8_t *)&if_mac.ifr_hwaddr.sa_data)[0];
 eh->ether_shost[1] = ((uint8_t *)&if_mac.ifr_hwaddr.sa_data)[1];
 eh->ether_shost[2] = ((uint8_t *)&if_mac.ifr_hwaddr.sa_data)[2];
 eh->ether_shost[3] = ((uint8_t *)&if_mac.ifr_hwaddr.sa_data)[3];
 eh->ether_shost[4] = ((uint8_t *)&if_mac.ifr_hwaddr.sa_data)[4];
 eh->ether_shost[5] = ((uint8_t *)&if_mac.ifr_hwaddr.sa_data)[5];
 eh->ether_dhost[0] = MY_DEST_MAC0;
 eh->ether_dhost[1] = MY_DEST_MAC1;
 eh->ether_dhost[2] = MY_DEST_MAC2;
 eh->ether_dhost[3] = MY_DEST_MAC3;
 eh->ether_dhost[4] = MY_DEST_MAC4;
 eh->ether_dhost[5] = MY_DEST_MAC5;
 /* Ethertype field */
 eh->ether_type = htons(ETH_P_IP);
 tx_len += sizeof(struct ether_header);

 /* Packet data */
 sendbuf[tx_len++] = 0xde;
 sendbuf[tx_len++] = 0xad;
 sendbuf[tx_len++] = 0xbe;
 sendbuf[tx_len++] = 0xef;

 /* Index of the network device */
 socket_address.sll_ifindex = if_idx.ifr_ifindex;
 /* Address length*/
 socket_address.sll_halen = ETH_ALEN;
 /* Destination MAC */
 socket_address.sll_addr[0] = MY_DEST_MAC0;
 socket_address.sll_addr[1] = MY_DEST_MAC1;
 socket_address.sll_addr[2] = MY_DEST_MAC2;
 socket_address.sll_addr[3] = MY_DEST_MAC3;
 socket_address.sll_addr[4] = MY_DEST_MAC4;
 socket_address.sll_addr[5] = MY_DEST_MAC5;

 /* Send packet */
 if (sendto(sockfd, sendbuf, tx_len, 0, (struct sockaddr*)&socket_address, sizeof(struct sockaddr_ll)) < 0)
     printf("Send failed\n");

 return 0;
}
