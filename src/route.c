#include <linux/module.h>
#include <linux/uaccess.h>
#include <linux/bitops.h>
#include <linux/types.h>
#include <linux/kernel.h>
#include <linux/mm.h>
#include <linux/string.h>
#include <linux/socket.h>
#include <linux/sockios.h>
#include <linux/errno.h>
#include <linux/in.h>
#include <linux/inet.h>
#include <linux/netdevice.h>
#include <linux/proc_fs.h>
#include <linux/init.h>
#include <linux/skbuff.h>
#include <linux/inetdevice.h>
#include <linux/igmp.h>
#include <linux/pkt_sched.h>
#include <linux/mroute.h>
#include <linux/netfilter_ipv4.h>
#include <linux/random.h>
#include <linux/rcupdate.h>
#include <linux/times.h>
#include <linux/slab.h>
#include <linux/jhash.h>
#include <net/dst.h>
#include <net/dst_metadata.h>
#include <net/net_namespace.h>
#include <net/protocol.h>
#include <net/ip.h>
#include <net/route.h>
#include <net/inetpeer.h>
#include <net/sock.h>
#include <net/ip_fib.h>
#include <net/nexthop.h>
#include <net/arp.h>
#include <net/tcp.h>
#include <net/icmp.h>
#include <net/xfrm.h>
#include <net/lwtunnel.h>
#include <net/netevent.h>
#include <net/rtnetlink.h>
#include <net/secure_seq.h>
#include <net/ip_tunnels.h>
#include <net/l3mdev.h>
#include "ipppk.h"

struct rtable *ippp_route_output_ports(struct net *net, struct flowi4 *fl4,
						   struct sock *sk,
						   __be32 daddr, __be32 saddr,
						   __be16 dport, __be16 sport,
						   __u8 proto, __u8 tos, int oif)
{
	DEBUG_LOG("%X %X %d %d %d %d", ntohl(daddr), ntohl(saddr), ntohs(dport), ntohs(sport), tos, oif);
	flowi4_init_output(fl4, oif, sk ? sk->sk_mark : 0, tos,
			   RT_SCOPE_UNIVERSE, proto,
			   sk ? inet_sk_flowi_flags(sk) : 0,
			   daddr, saddr, dport, sport, sock_net_uid(net, sk));
	if (sk)
		security_sk_classify_flow(sk, flowi4_to_flowi_common(fl4));
	return ippp_route_output_flow(net, (struct flowipp*)fl4, sk, NULL, true);
}

struct rtable *ippp_route_connect(struct flowipp *flpp,
					      struct ippp_addr dst, struct ippp_addr src,
					      int oif, u8 protocol,
					      __be16 sport, __be16 dport,
					      struct sock *sk)
{
	struct net *net = sock_net(sk);
	DEBUG_LOG("%X %X %d %d %d", ntohl(leafAddr(&dst)), ntohl(leafAddr(&src)), ntohs(dport), ntohs(sport), oif);
	// struct rtable *rt;

	flpp->rmtaddr = dst;
	flpp->fl4.saddr = leafAddr(&(flpp->locaddr));
	char *name = __ip_dev_find(net, flpp->fl4.saddr, true)->name;
	struct if_ *if__ = (struct if_*)findNode(if_global_list.head, name, 1);
	flpp->un = (if__)->un;
	ip_route_connect_init(&flpp->fl4, leafAddr(&dst), leafAddr(&src), oif, protocol, sport, dport, sk);

	// if (!dst || !src) {
	// 	rt = __ip_route_output_key(net, fl4);
	// 	if (IS_ERR(rt))
	// 		return rt;
	// 	ip_rt_put(rt);
	// 	flowi4_update_output(fl4, oif, fl4->flowi4_tos, fl4->daddr,
	// 			     fl4->saddr);
	// }
	security_sk_classify_flow(sk, flowi4_to_flowi_common(&flpp->fl4));
	return ippp_route_output_flow(net, flpp, sk, NULL, true);
}

struct rtable *ippp_route_newports(struct flowipp *flpp, struct rtable *rt,
					       __be16 orig_sport, __be16 orig_dport,
					       __be16 sport, __be16 dport,
					       struct sock *sk)
{
	DEBUG_LOG("%d %d", ntohs(dport), ntohs(sport));
    return ip_route_newports(&flpp->fl4, rt, orig_sport, orig_dport, sport, dport, sk);
	if (sport != orig_sport || dport != orig_dport) {
		flpp->fl4.fl4_dport = dport;
		flpp->fl4.fl4_sport = sport;
		ip_rt_put(rt);
		flowi4_update_output(&flpp->fl4, sk->sk_bound_dev_if,
			/* RT_CONN_FLAGS(sk),  */flpp->fl4.daddr,
			flpp->fl4.saddr);
		security_sk_classify_flow(sk, flowi4_to_flowi_common(&flpp->fl4));
		return ippp_route_output_flow(sock_net(sk), flpp, sk, NULL, true);
	}
	return rt;
}

inline bool match(__be32* addr_, struct unitnet** pun, int i) {
	if((*pun)->type == 0) {
		struct listNode* if_ =(*pun)->if_list.head;
		if(if_) {
			do {																		// 逐接口匹配
				struct listNode* addr =((struct if_ *)(if_))->ifaddr_list.head;
				if(addr) {
					do {																// 逐地址匹配
						if(((struct ifAddr*)addr)->addr == *(addr_+i)) {					// 匹配上
							(*pun) = ((struct ifAddr*)addr)->gate_->supnet;
							return true;
						}
						addr = addr->next;
					} while(addr != ((struct if_ *)(if_))->ifaddr_list.head);
				}
				if_ = if_->next;
			} while(if_ != (*pun)->if_list.head);
		}
	} else {
		struct listNode* g = ((struct external_unitnet*)(*pun))->subgateway_list.head;
		if(g) {
			do {																		// 逐地址匹配
				if(((struct external_gate*)g)->upaddr == *(addr_+i)) {					// 匹配上
					(*pun) = (struct unitnet*)(((struct external_gate*)g)->down);
					return true;
				}
				g = g->next;
			} while(g != ((struct external_unitnet*)(*pun))->subgateway_list.head);
		}
	}
	return false;
}

int ippp_route_input_noref(struct sk_buff *skb, struct net_device *dev)
{
	// 为方便处理，规定gate接口只能有一个地址。
	struct if_* if_ = (struct if_*)findNode(if_global_list.head, dev->name, 1);
	if(!if_)
		return -1;
	struct ifAddr* addr = (struct ifAddr*)(if_->ifaddr_list.head);
	if(!addr)
		return -1;
    struct ippphdr *iph = ippp_hdr(skb);
	bool matched = false;
	struct unitnet* un = ((struct if_*)findNode(if_global_list.head, dev->name, 1))->un;
	if(iph->dst_type == 0) {
		if(((iph->dst_base + iph->dst_len) == if_->un->level) && (iph->addr[iph->dst_len] == addr->addr)){		// 本地 查找地址?
			matched = true;
			struct unitnet* un_ = rootUnitnet;
			for(int i = 0; i < un->level; i++) {												// 逐级匹配
				if(match(iph->addr, &un_, i)) {
					continue;
				} else {
					matched = false;
					break;
				}
			}
			if(un_ != un) {
				matched = false;
			}
		}
	} else {
		if((iph->dst_base == 0) && (iph->dst_len == 0) && (iph->addr[0] == addr->addr))
			matched = true;
	}
	if(matched) {
		struct rtable *rt = rt_dst_alloc(dev, RTCF_LOCAL, RTN_UNICAST, false);
		skb_dst_set(skb, &rt->dst);
		skb_dst(skb)->input = ippp_local_deliver;
	} else if(addr->type == 1) {				// supgate
		struct net_device *dev_ = addr->gate_->subaddr->ifa->ifa_dev->dev;
		struct rtable *rt = rt_dst_alloc(dev_, RTCF_LOCAL, RTN_UNICAST, false);
		skb_dst_set(skb, &rt->dst);
		skb_dst(skb)->input = ippp_forward;
		// 相对地址要相应变化
		if(iph->dst_type == 1) {
			if(iph->dst_base != 0) {
				iph->dst_base -= 1;
			} else {
				for(int i = iph->dst_len + iph->src_len + 2; i > 0; i--) {
					iph->addr[i] = iph->addr[i - 1];
				}
				iph->addr[0] = addr->gate_->subaddr->addr;
				iph->dst_len += 1;
			}
		}
		if(iph->src_type == 1) {
			if(iph->src_base != 0) {
				iph->src_base -= 1;
			} else {
				for(int i = iph->dst_len + iph->src_len + 2; i > iph->dst_len + 1; i--) {
					iph->addr[i] = iph->addr[i - 1];
				}
				iph->addr[iph->dst_len + 1] = addr->gate_->subaddr->addr;
				iph->src_len += 1;
			}
		}
	} else if(addr->type == 2) {		// subgate
		struct net_device *dev_ = addr->gate_->supaddr->ifa->ifa_dev->dev;
		struct rtable *rt = rt_dst_alloc(dev_, RTCF_LOCAL, RTN_UNICAST, false);
		skb_dst_set(skb, &rt->dst);
		skb_dst(skb)->input = ippp_forward;
		// 相对地址要相应变化
		if(iph->dst_type == 1) {
			if((iph->dst_base == 0) && (iph->addr[0] == addr->addr)) {
				for(int i = 0; i <= iph->dst_len + iph->src_len; i++) {
					iph->addr[i] = iph->addr[i + 1];
				}
				iph->dst_len -= 1;
			} else {
				iph->dst_base += 1;
			}
		}
		if(iph->src_type == 1) {
			if((iph->src_base == 0) && (iph->addr[iph->dst_len + 1] == addr->addr)) {
				for(int i = iph->dst_len + 1; i <= iph->dst_len + iph->src_len; i++) {
					iph->addr[i] = iph->addr[i + 1];
				}
				iph->src_len -= 1;
			} else {
				iph->src_base += 1;
			}
		}
	} else if(addr->type == 0) {
		struct rtable *rt = rt_dst_alloc(dev, RTCF_LOCAL, RTN_UNICAST, false);
		skb_dst_set(skb, &rt->dst);
		skb_dst(skb)->input = ippp_forward;
	}
	return 0;
	// rt->dst.output = ippp_local_out;
	// skb->protocol = htons(ETH_P_IP);
	// 会造成ping中断，但ssh(TCP)还通。原因未知
    //ip_route_input_noref(skb, iph->addr[iph->dst_len], iph->addr[iph->dst_len + iph->src_len + 1], iph->tos, dev);
	// skb->protocol = htons(ETH_P_IPPP);
}

struct rtable *ippp_route_output_flow(struct net *net, struct flowipp *flpp, const struct sock *sk, struct sk_buff *skb, bool src)
{
	if(flpp->rmtaddr.type && (flpp->rmtaddr.base == 0)) {
		flpp->fl4.daddr = flpp->rmtaddr.addr[0];
	} else if(rootUnitnet == NULL || (flpp->rmtaddr.type ?
	( flpp->un->level - flpp->rmtaddr.base + flpp->rmtaddr.len) :
	(flpp->rmtaddr.base + flpp->rmtaddr.len)) < flpp->un->level) {
		flpp->fl4.daddr = ((struct gate*)(flpp->un->supgateway_list.head))->supgate;			// 向上
	} else if(flpp->un == rootUnitnet) {
		flpp->fl4.daddr = flpp->rmtaddr.addr[0];												// 向边
	} else if(flpp->rmtaddr.type == 1) {														// 目标地址为相对地址
		if(flpp->rmtaddr.base == 0) {
			flpp->fl4.daddr = flpp->rmtaddr.addr[0];
		} else {
			flpp->fl4.daddr = ((struct gate*)(flpp->un->supgateway_list.head))->supgate;		// 向上
		}
	} else {																					// 核对目标地址与根结构
		bool matched = true;
		struct unitnet* un = rootUnitnet;
		for(int i = 0; i < flpp->un->level; i++) {												// 逐级匹配
			if(match(flpp->rmtaddr.addr, &un, i)) {
				continue;
			} else {
				matched = false;
				break;
			}
		}
		if(un != flpp->un) {
			matched = false;
		}
		if(matched) {
			flpp->fl4.daddr = flpp->rmtaddr.addr[flpp->un->level - flpp->rmtaddr.base];			// 向边
		} else {
			flpp->fl4.daddr = ((struct gate*)(flpp->un->supgateway_list.head))->supgate;		// 向上
		}
	}
	struct rtable* rt;
	if(src) {
		rt = ip_route_output_flow(net, &flpp->fl4, sk);
	} else {
		if(flpp->fl4.saddr == 0)
			flpp->fl4.saddr = ((struct ifAddr*)(((struct if_*)findNode(if_global_list.head, skb_dst(skb)->dev->name, 1))->ifaddr_list.head))->addr;
		rt = __ip_route_output_key(net, &flpp->fl4);
	}
	rt->rt_gw_family = AF_INET;
	if(rt->rt_uses_gateway == 0) {
		rt->rt_gw4 = flpp->fl4.daddr;
	}
	return rt;
}