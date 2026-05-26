/* 
 * To Fix:
 *		完善is_last_unitnet
*/

#include <linux/capability.h>
#include <linux/types.h>
#include <linux/slab.h>
#include <linux/uaccess.h>
#include <linux/netdevice.h>
#include <linux/in.h>
#include <linux/if_arp.h>
#include <linux/init.h>
#include <net/sock.h>
#include <net/ip.h>
#include <net/icmp.h>
#include <net/ip_tunnels.h>
#include <net/inet_ecn.h>
#include <net/xfrm.h>
#include <net/net_namespace.h>
#include <net/netns/generic.h>
#include <net/dst_metadata.h>
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/sched.h>
#include <linux/netfilter.h>
#include <linux/netfilter_arp.h>
#include <linux/netfilter_ipv4.h>
#include <linux/skbuff.h> 
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <net/tcp.h>
#include <linux/udp.h>
#include "../ipppk.h"

#define EXPIRE_PERIOD HZ * 30

struct nat_config {
	struct listNode node;
	struct ifAddr* ifa;
	__be32 prefix;
	__u8 prefix_len;
};

struct nat_node {
	struct listNode node;
	u8 protocol;	// 传输层协议
	__be32 server_addr;
	__be16 server_port;
	struct ippp_addr client_addr;
	__be16 client_port;
	__be32 nat_addr;
	__be16 nat_port;
	unsigned long last_time;
};

struct nat_net {
	struct nat_config* nat_configs;
	struct nat_node* nat_nodes;
};

static unsigned int nat_net_id __read_mostly;

int nat_newlink(struct net *net, struct ifAddr* ifa, __be32 prefix, __u8 prefix_len) {
	rtnl_lock();
	struct nat_net* nat_net = net_generic(net, nat_net_id);
	struct nat_config* nat_config = (struct nat_config*)kmalloc(sizeof(struct nat_config), GFP_KERNEL);
	nat_config->ifa = ifa;
	nat_config->prefix = prefix;
	nat_config->prefix_len = prefix_len;
	nat_net->nat_configs = (struct nat_config*)addNode((struct listNode*)nat_net->nat_configs, (struct listNode*)nat_config);
	rtnl_unlock();
	return 0;
}

inline bool compare_prefix(__be32 prefix1, __be32 prefix2, __u8 prefix_len) {
		__be32 mask = 0xFFFF;
		mask = mask << (32 - prefix_len);
		if((prefix1 & mask) == (prefix2 & mask))
			return true;
		else
			return false;
}

int nat_dellink(struct net *net, struct ifAddr* ifa, __be32 prefix, __u8 prefix_len) {
	rtnl_lock();
	struct nat_net* nat_net = net_generic(net, nat_net_id);
	struct nat_config* nat_config = nat_net->nat_configs;
	while(nat_config) {
		if( nat_config->ifa == ifa &&
			nat_config->prefix_len == prefix_len &&
			compare_prefix(nat_config->prefix, prefix, prefix_len)) {
			nat_net->nat_configs = (struct nat_config*)delNode((struct listNode*)(nat_net->nat_configs), (struct listNode*)nat_config);
			break;
		}
		nat_config = (struct nat_config*)(((struct listNode*)nat_config)->next);
		if(nat_config == nat_net->nat_configs)
			break;
	}
	rtnl_unlock();
	return 0;
}

static void del_timeout_nat_node(struct nat_node** pnat_node) {
	struct nat_node* nat_node = *pnat_node;
	struct nat_node* nat_node_next;
	while(nat_node) {
		if((jiffies - nat_node->last_time) > EXPIRE_PERIOD) {
			nat_node_next = (struct nat_node*)(((struct listNode*)nat_node)->next);
			if(nat_node_next == *pnat_node)
				nat_node_next = NULL;
			*pnat_node = (struct nat_node*)delNode((struct listNode*)(*pnat_node), (struct listNode*)nat_node);
			nat_node = nat_node_next;
		}
		if(!nat_node)
			break;
		nat_node = (struct nat_node*)(((struct listNode*)nat_node)->next);
		if(nat_node == *pnat_node)
			break;
	}
}

static unsigned int nf_nat_ippp_pre_routing_handler(void* priv, struct sk_buff* skb, const struct nf_hook_state* state) {
	// 查看是否为网际接口地址-----------------------------------------------
	struct ifAddr* ifa = (struct ifAddr*)(((struct if_*)findNode(if_global_list.head, skb->dev->name, 1))->ifaddr_list.head);
	if(ifa->type == 0)
		return NF_ACCEPT;
	// 删除过期nat_node-----------------------------------------------
	struct nat_net* nat_net = net_generic(dev_net(skb->dev), nat_net_id);
	del_timeout_nat_node(&(nat_net->nat_nodes));
	// 查看是否在本单元网内传输-------------------------------------------------
	struct ippp_addr daddr, saddr;
	getAddrFromSkb(skb, &daddr, &saddr, 0);
	if(daddr.type != 1 || daddr.base != 0 || daddr.len != 0 || saddr.type != 1 || saddr.base != 0 || saddr.len != 0)
		return NF_ACCEPT;
	// 查看是否属于nat_node-----------------------------------------------
	struct ippphdr *ippph = ippp_hdr(skb);
	struct nat_node* nat_node = nat_net->nat_nodes;
	bool belong_nat_nodes = false;
	__be16 server_port, client_port;
	if(ippph->protocol == IPPROTO_TCP) {
		struct tcphdr *th = tcp_hdr(skb);
		server_port = th->source;
		client_port = th->dest;
	} else if(ippph->protocol == IPPROTO_UDP) {
		struct udphdr *uh = udp_hdr(skb);
		server_port = uh->source;
		client_port = uh->dest;
	}
	while(nat_node) {
		if( nat_node->server_addr == saddr.addr[0] &&
			nat_node->server_port == server_port &&
			nat_node->nat_addr == daddr.addr[0] &&
			nat_node->nat_port == client_port) {
			belong_nat_nodes = true;
			break;
		}
		nat_node = (struct nat_node*)(((struct listNode*)nat_node)->next);
		if(nat_node == nat_net->nat_nodes)
			break;
	}
	if(belong_nat_nodes) { // 属于nat_nodes
		// nat转换-----------------------------------------------
		// 计算头部长度
		__u8 hdrlen = getHdrLen(&(nat_node->client_addr), &saddr, ifa->if_->un->level);
		// 扩展头部
		__u8 ippphdr_len = 8 + (8 << hdrlen);
		unsigned int max_headroom = LL_RESERVED_SPACE(skb->dev) + ippphdr_len;

		if (skb_cow_head(skb, max_headroom)) {
			kfree_skb(skb);
			return NF_DROP;
		}
		skb_push(skb, ippphdr_len - 16);
		skb_reset_network_header(skb);
		struct ippphdr *nippph = ippp_hdr(skb);
		memcpy(nippph, ippph, 16);
		// 修改头部
		nippph->ihl = hdrlen;
		if(nat_node->client_addr.len != 0) {
			nippph->addr[nat_node->client_addr.len + 1] = saddr.addr[0];
		}
		nippph->dst_type	= nat_node->client_addr.type;
		nippph->dst_base	= nat_node->client_addr.base;
		nippph->dst_len	= nat_node->client_addr.len;
		memcpy(nippph->addr, nat_node->client_addr.addr, (nat_node->client_addr.len + 1) * 4);
		if(nippph->protocol == IPPROTO_TCP) {
			struct tcphdr *th = tcp_hdr(skb);
			th->dest = nat_node->client_port;
		} else if(nippph->protocol == IPPROTO_UDP) {
			struct udphdr *uh = udp_hdr(skb);
			uh->dest = nat_node->client_port;
			__wsum csum = 0;
			if (skb->ip_summed == CHECKSUM_PARTIAL) {
				udp4_hwcsum(skb, nippph->addr[nat_node->client_addr.len + 1], nippph->addr[nat_node->client_addr.len]);
			} else {
				csum = udp_csum(skb);
				uh->check = csum_tcpudp_magic(nippph->addr[nat_node->client_addr.len + 1], nippph->addr[nat_node->client_addr.len], ntohs(uh->len), IPPROTO_UDP, csum);
			}
		}
	}
	return NF_ACCEPT;
}

inline bool is_last_unitnet(struct ippp_addr* daddr) {
	if(daddr->type == 0) {
		return true;
	} else {
		if(daddr->len == 0) {
			return true;
		} else {
			if(daddr->base != daddr->len) {
				return false;
			}
			return true;
		}
	}
}
inline __be16 udp_get_port(void) {
	// DECLARE_BITMAP(bitmap, PORTS_PER_CHAIN);
	// unsigned short first, last;
	// int low, high, remaining;
	// unsigned int rand;

	// inet_sk_get_local_port_range(sk, &low, &high);
	// remaining = (high - low) + 1;

	// rand = get_random_u32();
	// first = reciprocal_scale(rand, remaining) + low;
	// /*
	// 	* force rand to be an odd multiple of UDP_HTABLE_SIZE
	// 	*/
	// rand = (rand | 1) * (udptable->mask + 1);
	// last = first + udptable->mask + 1;
	// do {
	// 	hslot = udp_hashslot(udptable, net, first);
	// 	bitmap_zero(bitmap, PORTS_PER_CHAIN);
	// 	spin_lock_bh(&hslot->lock);
	// 	udp_lib_lport_inuse(net, snum, hslot, bitmap, sk, udptable->log);

	// 	snum = first;
	// 	/*
	// 		* Iterate on all possible values of snum for this hash.
	// 		* Using steps of an odd multiple of UDP_HTABLE_SIZE
	// 		* give us randomization and full range coverage.
	// 		*/
	// 	do {
	// 		if (low <= snum && snum <= high &&
	// 			!test_bit(snum >> udptable->log, bitmap) &&
	// 			!inet_is_local_reserved_port(net, snum))
	// 			goto found;
	// 		snum += rand;
	// 	} while (snum != first);
	// 	spin_unlock_bh(&hslot->lock);
	// 	cond_resched();
	// } while (++first != last);
	// goto fail;
	return htons(9000);
}

inline __be16 tcp_get_port(void) {

	return htons(9000);
}

static unsigned int nf_nat_ippp_post_routing_handler(void* priv, struct sk_buff* skb, const struct nf_hook_state* state) {
	// 查看是否为网际接口地址-----------------------------------------------
	struct net_device* dev = skb->dev;
	struct translate_node* translate_node = netdev_priv(dev);
	struct net* net = dev_net(dev);
	struct net_device* real_dev;
	if(is_translate_dev(net, dev))
		real_dev = translate_node->base_dev;
	else
		real_dev = dev;
	struct ifAddr* ifa = (struct ifAddr*)(((struct if_*)findNode(if_global_list.head, real_dev->name, 1))->ifaddr_list.head);
	if(ifa->type == 0)
		return NF_ACCEPT;
	// 删除过期nat_node-----------------------------------------------
	struct nat_net* nat_net = net_generic(dev_net(skb->dev), nat_net_id);
	del_timeout_nat_node(&(nat_net->nat_nodes));
	// 查看是否到达末单元网-------------------------------------------------
	struct ippp_addr daddr, saddr;
	getAddrFromSkb(skb, &daddr, &saddr, 0);
	if(!is_last_unitnet(&daddr))// 未到达末单元网
		return NF_ACCEPT;
	// 查看是否属于nat_config-----------------------------------------------
	__be32 _daddr = leafAddr(&daddr);
	struct nat_config* nat_config = nat_net->nat_configs;
	bool belong_nat_configs = false;
	while(nat_config) {
		__be32 mask = 0xFFFF;
		mask = mask << (32 - nat_config->prefix_len);
		if((ifa == nat_config->ifa) && (((_daddr & mask) == (nat_config->prefix & mask)) || (nat_config->prefix_len == 0))) {
			belong_nat_configs = true;
			break;
		}
		nat_config = (struct nat_config*)(((struct listNode*)nat_config)->next);
		if(nat_config == nat_net->nat_configs)
			break;
	}
	if(!belong_nat_configs)		// 不属于nat_configs
		return NF_ACCEPT;
	// 查看是否已经有nat_node-----------------------------------------------
	struct ippphdr *ippph = ippp_hdr(skb);
	struct nat_node* nat_node = nat_net->nat_nodes;
	bool belong_nat_nodes = false;
	__be16 server_port, client_port;
	if(ippph->protocol == IPPROTO_TCP) {
		struct tcphdr *th = tcp_hdr(skb);
		server_port = th->dest;
		client_port = th->source;
	} else if(ippph->protocol == IPPROTO_UDP) {
		struct udphdr *uh = udp_hdr(skb);
		server_port = uh->dest;
		client_port = uh->source;
	}
	while(nat_node) {
		if( nat_node->server_addr == _daddr &&
			nat_node->server_port == server_port &&
			addr_equal(&(nat_node->client_addr), &saddr) &&
			nat_node->client_port == client_port) {
			belong_nat_nodes = true;
			break;
		}
		nat_node = (struct nat_node*)(((struct listNode*)nat_node)->next);
		if(nat_node == nat_net->nat_nodes)
			break;
	}
	if(!belong_nat_nodes) { // 不属于nat_nodes
		// 插入nat_nodes
		nat_node = (struct nat_node*)kmalloc(sizeof(struct nat_node), GFP_KERNEL);
		nat_node->protocol = ippph->protocol;
		nat_node->server_addr = _daddr;
		nat_node->server_port = server_port;
		nat_node->client_addr = saddr;
		nat_node->client_port = client_port;
		nat_node->nat_addr = ifa->addr;
		if(nat_node->protocol == IPPROTO_TCP) {
			nat_node->nat_port = tcp_get_port();
		} else if(nat_node->protocol == IPPROTO_UDP) {
			nat_node->nat_port = udp_get_port();
		}
		nat_node->last_time = jiffies;

		nat_net->nat_nodes = (struct nat_node*)addNode((struct listNode*)(nat_net->nat_nodes), (struct listNode*)nat_node);
	}
	// nat转换-----------------------------------------------
	ippph->dst_type		=	1;
	ippph->dst_base		=	0;
	ippph->dst_len		=	0;
	ippph->addr[0]		=	_daddr;
	ippph->src_type		=	1;
	ippph->src_base		=	0;
	ippph->src_len		=	0;
	ippph->addr[1]		=	nat_node->nat_addr;
	nat_node->last_time = jiffies;
	if(ippph->protocol == IPPROTO_TCP) {
		struct tcphdr *th = tcp_hdr(skb);
		th->source = nat_node->nat_port;
	} else if(ippph->protocol == IPPROTO_UDP) {
		struct udphdr *uh = udp_hdr(skb);
		uh->source = nat_node->nat_port;
		__wsum csum = 0;
		if (skb->ip_summed == CHECKSUM_PARTIAL) {
			udp4_hwcsum(skb, ippph->addr[1], ippph->addr[0]);
		} else {
			csum = udp_csum(skb);
			uh->check = csum_tcpudp_magic(ippph->addr[1], ippph->addr[0], ntohs(uh->len), IPPROTO_UDP, csum);
		}
	}
	return NF_ACCEPT;
}

struct nf_hook_ops nat_hook_ops[] = {
	{
		.hook = nf_nat_ippp_pre_routing_handler,
		.hooknum = NF_INET_PRE_ROUTING,
		.pf = NFPROTO_IPPP,
		.priority = NF_IP_PRI_SELINUX_LAST + 1
	},
	{
		.hook = nf_nat_ippp_post_routing_handler,
		.hooknum = NF_INET_POST_ROUTING,
		.pf = NFPROTO_IPPP,
		.priority = NF_IP_PRI_NAT_SRC
	},
};

static int __net_init nat_init_net(struct net *net) {
	struct nat_net* nat_net = net_generic(net, nat_net_id);
	nat_net->nat_configs = NULL;
	nat_net->nat_nodes = NULL;

	nf_register_net_hooks_pp(net, nat_hook_ops, ARRAY_SIZE(nat_hook_ops));

	return 0;
}

static void __net_exit nat_exit_net(struct net *net) {
	struct nat_net* nat_net = net_generic(net, nat_net_id);
	while(nat_net->nat_configs) {
		nat_net->nat_configs = (struct nat_config*)delNode((struct listNode*)(nat_net->nat_configs), (struct listNode*)(nat_net->nat_configs));
	}
	while(nat_net->nat_nodes) {
		nat_net->nat_nodes = (struct nat_node*)delNode((struct listNode*)(nat_net->nat_nodes), (struct listNode*)(nat_net->nat_nodes));
	}

	nf_unregister_net_hooks_pp(net, nat_hook_ops, ARRAY_SIZE(nat_hook_ops));
}

static struct pernet_operations nat_net_ops = {
	.init = nat_init_net,
	.exit = nat_exit_net,
	.id   = &nat_net_id,
	.size = sizeof(struct nat_net),
};

int __init nf_nat_init(void) {
	int err;

	err = register_pernet_device(&nat_net_ops);
	if (err < 0)
		return err;

	return err;
}

void nf_nat_exit(void) {
	unregister_pernet_device(&nat_net_ops);
}