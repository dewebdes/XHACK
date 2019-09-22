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
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <net/if.h>
#include <netinet/ether.h>

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
