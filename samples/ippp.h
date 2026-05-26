#ifndef _IPPP_H
#define _IPPP_H

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>           // close()
#include <string.h>           // strcpy, memset(), and memcpy()
#include <netdb.h>            // struct addrinfo
#include <sys/types.h>        // needed for socket(), uint8_t, uint16_t, uint32_t
#include <sys/socket.h>       // needed for socket()
#include <netinet/in.h>       // IPPROTO_ICMP, INET_ADDRSTRLEN/*in_addr结构*/
#include <netinet/ip.h>       // struct ip and IP_MAXPACKET (which is 65535)/*iphdr 结构*/
#include <netinet/ip_icmp.h>  // struct icmp, ICMP_ECHO
#include <arpa/inet.h>        // inet_pton() and inet_ntop()
#include <sys/ioctl.h>        // macro ioctl is defined/*ioctl 命令*/
#include <bits/ioctls.h>      // defines values for argument "request" of ioctl.
#include <net/if.h>           // struct ifreq/*ifreq 结构*/
#include <linux/if_ether.h>   // ETH_P_IP = 0x0800, ETH_P_IPV6 = 0x86DD/*ethhdr 结构*/
#include <linux/if_packet.h>  // struct sockaddr_ll (see man 7 packet)
#include <net/ethernet.h>
#include <netinet/udp.h>					/*udphdr 结构*/
#include <netinet/tcp.h>					/*tcphdr 结构*/
#include <string>

/*由于linux内核源码中没有为新协议族预留协议号，所以原则上需修改内核源码，
这样不太方便。因此这里选择借用已基本不用的AF_IPX的协议族号*/
#define AF_INETPP 4
#define PF_INETPP AF_INETPP
#define ETH_P_IPPP 0x0810 /* Internet Protocol Plus Plus packet */
#define NFPROTO_IPPP 11

#pragma pack(1)
struct ippp_addr {
	__u8    type;
	__u8	len:4,
			base:4;
	__be32  addr[16];
};

struct sockaddr_ippp {
	sa_family_t family;
  __be16 port;				// Port number
  struct ippp_addr addr;	// Internet address
};
#pragma pack()

int inetpp_aton(const std::string& str, struct ippp_addr *addrptr)
{
	if(str[0] == '/')
		addrptr->type = 0;
	else if(str[0] == '.')
		addrptr->type = 1;
	else
		return -1;
	int base;
	if(str.find('#') == str.npos) {			// 简写方式

	} else if(str.find('#') == 1)
		base = 0;
	else
		base = stoi(str.substr(1, str.find('#') - 1));
	if(addrptr->type == 1)
		base = -base;
	addrptr->base = base;
	int start = str.find('#') + 1;
	addrptr->len = 0;
	while(true) {
		std::string::size_type position = str.find_first_of('-', start);
		if(position != str.npos)
		{
			addrptr->addr[addrptr->len] = inet_addr(str.substr(start, position - start).c_str());
			if(addrptr->addr[addrptr->len] == 0x00000006) {		// IPv6

			}
			start = position + 1;
			(addrptr->len)++;
		} else {
			addrptr->addr[addrptr->len] = inet_addr(str.substr(start).c_str());
			return 0;
		}
	}
}

// char *inetpp_ntoa(struct ippp_addr addr)
// {

// }

#endif	/* _IPPP_H */