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


#include <linux/if_packet.h>
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
