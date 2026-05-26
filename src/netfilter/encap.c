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

struct temporary_route_node {
	struct listNode node;
	__be32 prefix;
	u8 prefixlen;
	__be32 nh;
	struct net_device *dev;
	unsigned long last_time;
};

struct encap_node {
	struct listNode node;
	struct net_device *base_dev;
	struct net_device *dev;
};

struct encap_net {
	struct encap_node* encap_nodes;
	struct temporary_route_node* temporary_route_nodes;
};

static unsigned int encap_net_id __read_mostly;

inline bool is_encap_dev(struct net* net, struct net_device *dev) {
	struct encap_net* encap_net = net_generic(net, encap_net_id);
// 在encap_nodes中搜索与dev匹配的
	struct encap_node* en = encap_net->encap_nodes;
	while(en) {
		if(en->dev == dev)
			return true;
		en = (struct encap_node*)(((struct listNode*)en)->next);
		if(en == encap_net->encap_nodes)
			return false;
	}
	return false;
}

static netdev_tx_t encap_tunnel_xmit(struct sk_buff *skb, struct net_device *dev) {
	// if (!pskb_inet_may_pull(skb))
	// 	goto tx_error;

	u8 ipproto;
	// switch (skb->protocol) {
	// case htons(ETH_P_IPPP):
		ipproto = IPPROTO_IPPPIP;
	// 	break;
	// default:
	// 	goto tx_error;
	// }

	// if (tiph->protocol != ipproto && tiph->protocol != 0)
	// 	goto tx_error;

	// if (iptunnel_handle_offloads(skb, SKB_GSO_IPXIP4))
	// 	goto tx_error;

	skb_set_inner_ipproto(skb, ipproto);
	// const struct iphdr *inner_iph = (const struct iphdr *)skb_inner_network_header(skb);
	// __be16 payload_protocol = skb_protocol(skb, true);
	memset(&(IPCB(skb)->opt), 0, sizeof(IPCB(skb)->opt));

	struct encap_node* encap_node = netdev_priv(dev);
    struct net* net = dev_net(dev);
	struct net_device* real_dev;
	if(is_encap_dev(net, dev))
		real_dev = encap_node->base_dev;
	else
		real_dev = dev;
    struct flowipp flpp;
	struct flowi4 *fl4 = &flpp.fl4;
    getAddrFromSkb(skb, &(flpp.rmtaddr), &(flpp.locaddr), 0);
    fl4->saddr = ((struct ifAddr*)(((struct if_*)findNode(if_global_list.head, real_dev->name, 1))->ifaddr_list.head))->addr;
	fl4->flowi4_oif = real_dev->ifindex;
    flpp.un = ((struct if_*)findNode(if_global_list.head, real_dev->name, 1))->un;
    struct rtable *rt = ippp_route_output_flow(net, &flpp, NULL, skb, false);
	rt->dst.dev = real_dev;
    skb_dst_set(skb, &rt->dst);
	// skb->dev = real_dev;

	if (IS_ERR(rt)) {
		DEV_STATS_INC(dev, tx_carrier_errors);
		goto tx_error;
	}

	// __be16 df = 0;
	// if (payload_protocol == htons(ETH_P_IP) && !tunnel->ignore_df)
	// 	df |= (inner_iph->frag_off & htons(IP_DF));

	// if (tnl_update_pmtu(dev, skb, rt, df, inner_iph, 0, 0, false)) {
	// 	ip_rt_put(rt);
	// 	goto tx_error;
	// }

	struct ippphdr *ippph = ippp_hdr(skb);
	unsigned int ippphdr_len = 8 + (8 << ippph->ihl);
	unsigned int max_headroom = LL_RESERVED_SPACE(rt->dst.dev) + sizeof(struct iphdr) + ippphdr_len
			+ rt->dst.header_len /* + ip_encap_hlen(&tunnel->encap) */;

	if (skb_cow_head(skb, max_headroom)) {
		ip_rt_put(rt);
		DEV_STATS_INC(dev, tx_dropped);
		kfree_skb(skb);
		return NETDEV_TX_OK;
	}

	static const unsigned int max_allowed = 512;
	if (max_headroom > max_allowed)
		max_headroom = max_allowed;
	if (max_headroom > READ_ONCE(dev->needed_headroom))
		WRITE_ONCE(dev->needed_headroom, max_headroom);

	int pkt_len = skb->len - skb_inner_network_offset(skb);
	net = dev_net(rt->dst.dev);
	struct net_device *dev_ = skb->dev;
	int err;

	skb_scrub_packet(skb, false/* !net_eq(tunnel->net, dev_net(dev_)) */);

	skb_clear_hash_if_not_l4(skb);
	skb_dst_set(skb, &rt->dst);
	memset(IPCB(skb), 0, sizeof(*IPCB(skb)));

	/* Push down and install the IP header. */
	skb_push(skb, sizeof(struct iphdr));
	skb_reset_network_header(skb);

	/* 设置新的IP头字段 */
	struct iphdr *iph = ip_hdr(skb);
	iph->version	=	4;
	iph->ihl		=	sizeof(struct iphdr) >> 2;
	iph->frag_off	=	0/* ip_mtu_locked(&rt->dst) ? 0 : df */;
	iph->protocol	=	ipproto;
	iph->tos		=	ippph->tos;
	// if (ip_dont_fragment(sk, &rt->dst) && !skb->ignore_df)
	// 	iph->frag_off = htons(IP_DF);
	// else
	// 	iph->frag_off = 0;
	iph->daddr		=	ippph->addr[ippph->dst_len];
	iph->saddr		=	ippph->addr[ippph->dst_len + ippph->src_len + 1];
	iph->ttl		=	ippph->ttl;
	__ip_select_ident(net, iph, skb_shinfo(skb)->gso_segs ?: 1);

	err = ip_local_out(net, NULL, skb);

	if (dev_) {
		if (unlikely(net_xmit_eval(err)))
			pkt_len = 0;
		iptunnel_xmit_stats(dev_, pkt_len);
	}

	return NETDEV_TX_OK;

tx_error:
	kfree_skb(skb);

	DEV_STATS_INC(dev, tx_errors);
	return NETDEV_TX_OK;
}

// static bool encap_tunnel_ioctl_verify_protocol(u8 ipproto)
// {
// 	switch (ipproto) {
// 	case 0:
// 	case IPPROTO_IPIP:
// 		return true;
// 	}

// 	return false;
// }

static int encap_tunnel_ctl(struct net_device *dev, struct ip_tunnel_parm_kern *p, int cmd) {
// 	if (cmd == SIOCADDTUNNEL || cmd == SIOCCHGTUNNEL) {
// 		if (p->iph.version != 4 ||
// 		    !encap_tunnel_ioctl_verify_protocol(p->iph.protocol) ||
// 		    p->iph.ihl != 5 || (p->iph.frag_off & htons(~IP_DF)))
// 			return -EINVAL;
// 	}

// 	p->i_key = p->o_key = 0;
// 	p->i_flags = p->o_flags = 0;
	return 0/* ip_tunnel_ctl(dev, p, cmd) */;
}

static int encap_tunnel_init(struct net_device *dev) {
	// struct encap_node *encap_node = netdev_priv(dev);

	// __dev_addr_set(dev, &tunnel->parms.iph.saddr, 4);
	// memcpy(dev->broadcast, &tunnel->parms.iph.daddr, 4);

	// tunnel->tun_hlen = 0;
	// tunnel->hlen = tunnel->tun_hlen + tunnel->encap_hlen;
	return 0/* ip_tunnel_init(dev) */;
}

static void encap_tunnel_uninit(struct net_device *dev) {

}

static const struct net_device_ops encap_netdev_ops = {
	.ndo_init       = encap_tunnel_init,
	.ndo_uninit     = encap_tunnel_uninit,
	.ndo_start_xmit	= encap_tunnel_xmit,
	// .ndo_siocdevprivate = ip_tunnel_siocdevprivate,
	// .ndo_change_mtu = ip_tunnel_change_mtu,
	.ndo_get_stats64 = dev_get_tstats64,
	// .ndo_get_iflink = ip_tunnel_get_iflink,
	.ndo_tunnel_ctl	= encap_tunnel_ctl,
};

static void encap_setup(struct net_device *dev) {
	dev->netdev_ops		= &encap_netdev_ops;
}

int encap_newlink(struct net *net, struct net_device *base_dev, char* name) {
	rtnl_lock();
	struct encap_net* encap_net = net_generic(net, encap_net_id);
	struct net_device* dev = alloc_netdev(sizeof(struct encap_node), name, NET_NAME_UNKNOWN, encap_setup);
	dev_net_set(dev, net);
	int err = register_netdevice(dev);
	dev->mtu = base_dev->mtu;
	struct encap_node* encap_node = netdev_priv(dev);
	encap_node->base_dev = base_dev;
	encap_node->dev = dev;
	encap_net->encap_nodes = (struct encap_node*)addNode((struct listNode*)encap_net->encap_nodes, (struct listNode*)encap_node);
	rtnl_unlock();
	return err;
}

int encap_dellink(struct net *net, struct net_device *dev) {
	unregister_netdevice(dev);
	free_netdev(dev);
	return 0;
}

static unsigned int nf_encap_ipv4_pre_routing_handler(void* priv, struct sk_buff* skb, const struct nf_hook_state* state) {
	struct iphdr *iph = ip_hdr(skb);
	struct net* net = dev_net(skb->dev);
	struct encap_net* encap_net = net_generic(net, encap_net_id);
	struct temporary_route_node* trn;
	struct rtable *rt;
	// read_lock(&ipip_lock);
	if(((struct sysctl_net*)net_generic(net, sysctl_net_id))->forwarding &&
	iph->protocol == IPPROTO_IPPPIP) {	// 为封装数据包
		// 整理条目
		trn = encap_net->temporary_route_nodes;
		struct temporary_route_node* _trn;
		while(trn) {
			_trn = (struct temporary_route_node*)(((struct listNode*)trn)->next);
			if((jiffies - trn->last_time) > EXPIRE_PERIOD) {
				encap_net->temporary_route_nodes = (struct temporary_route_node*)delNode((struct listNode*)(encap_net->temporary_route_nodes), (struct listNode*)trn);
			}
			trn = _trn;
			if(trn == encap_net->temporary_route_nodes)
				break;
		}
		// 查反向路由，判别是否为封装路由
		struct flowipp flpp;
		struct flowi4 *fl4 = &flpp.fl4;
		getAddrFromSkb(skb, &(flpp.locaddr), &(flpp.rmtaddr), iph->ihl << 2);
		struct ifAddr* ifa = (struct ifAddr*)(((struct if_*)findNode(if_global_list.head, skb->dev->name, 1))->ifaddr_list.head);
		fl4->saddr = ifa->addr;
		flpp.un = ((struct if_*)findNode(if_global_list.head, skb->dev->name, 1))->un;
		struct net* net = dev_net(skb->dev);
		rt = ippp_route_output_flow(net, &flpp, NULL, skb, false);
		if(is_encap_dev(net, rt->dst.dev))			// 反向路由是封装的
			goto decap;
		// 查反向虚拟路由
		trn = encap_net->temporary_route_nodes;
		while(trn) {
			_trn = (struct temporary_route_node*)(((struct listNode*)trn)->next);
			__be32 mask = 0xFFFF >> trn->prefixlen;
			if((iph->saddr & mask) == (trn->prefix & mask)) {
				// 更新last_time
				trn->last_time = jiffies;
				goto decap;
			}
			trn = _trn;
			if(trn == encap_net->temporary_route_nodes)
				break;
		}
		// 查前向路由，判别是否为封装路由
		// struct flowi4 fl4_2;
		// fl4_2.daddr = iph->daddr;
		// fl4_2.saddr = iph->saddr;
		// struct rtable *rt2 = __ip_route_output_key(net, &fl4_2);
		struct flowipp flpp2;
		struct flowi4 *fl4_2 = &flpp2.fl4;
		flpp2.locaddr = flpp.rmtaddr;
		flpp2.rmtaddr = flpp.locaddr;
		fl4_2->saddr = fl4->saddr;
		flpp2.un = flpp.un;
		struct rtable *rt2 = ippp_route_output_flow(net, &flpp2, NULL, skb, false);
		if(!is_encap_dev(net, rt2->dst.dev))
			goto additem;
		// 到达本单元网目的地
		if(ifa->type != 0)
			goto additem;
		if(ifa->addr == leafAddr(&(flpp.rmtaddr)))
			goto additem;
	}
	// 	read_unlock(&ipip_lock);
	return NF_ACCEPT;
additem:	// 添加条目
// 查反向路由 fiblookup  添加虚拟路由条目
	rcu_read_lock();
	struct flowi4 fl4;
	fl4.daddr = iph->saddr;
	// __be32 saddr = iph->daddr;
	fl4.saddr = ((struct ifAddr*)(((struct if_*)findNode(if_global_list.head, skb->dev->name, 1))->ifaddr_list.head))->addr;
	// fl4.flowi4_iif = LOOPBACK_IFINDEX;
	// ip_rt_fix_tos(&fl4);
	struct fib_result res = {
		.type		= RTN_UNSPEC,
		.fi		= NULL,
		.table		= NULL,
		.tclassid	= 0,
	};
	struct hlist_node *tb_hlist = rcu_dereference_rtnl(hlist_first_rcu( &net->ipv4.fib_table_hash[RT_TABLE_MAIN  & (FIB_TABLE_HASHSZ - 1)]));
	struct fib_table *tb = hlist_entry(tb_hlist, struct fib_table, tb_hlist);
	if (tb)
		fib_table_lookup(tb, &fl4, &res, FIB_LOOKUP_NOREF);
	
	struct temporary_route_node* ntrn = (struct temporary_route_node*)kmalloc(sizeof(struct temporary_route_node), GFP_KERNEL);
	ntrn->prefix = res.prefix;
	ntrn->prefixlen = res.prefixlen;
	ntrn->nh = rt->rt_gw4;
	// struct net_device *dev;
	ntrn->last_time = jiffies;
	encap_net->temporary_route_nodes = (struct temporary_route_node*)addNode((struct listNode*)(encap_net->temporary_route_nodes), (struct listNode*)ntrn);
	rcu_read_unlock();
decap:		// 解封装
	// 	read_unlock(&ipip_lock);

	if (iptunnel_pull_header(skb, iph->ihl << 2, ETH_P_IPPP, false))
		goto drop;
	skb_reset_mac_header(skb);
	skb_set_network_header(skb, 0);
	ippp_rcv_finish(net, NULL, skb);
	return NF_STOLEN;
drop:
	kfree_skb(skb);
	return NF_DROP;
}

static unsigned int nf_encap_ippp_post_routing_handler(void* priv, struct sk_buff* skb, const struct nf_hook_state* state) {
	// 循环检查条目
	struct encap_net* encap_net = net_generic(dev_net(skb->dev), encap_net_id);
	struct temporary_route_node* trn = encap_net->temporary_route_nodes;
	while(trn) {
		__be32 mask = 0xFFFF >> trn->prefixlen;
		if((((struct rtable*)skb_dst(skb))->rt_gw4 & mask) == (trn->prefix & mask) &&
			((struct rtable*)skb_dst(skb))->rt_gw4 == trn->nh) {		// 如命中，则封装
			trn->last_time = jiffies;
			encap_tunnel_xmit(skb, skb->dev);
			return NF_STOLEN;
		}
		trn = (struct temporary_route_node*)(((struct listNode*)trn)->next);
		if(trn == encap_net->temporary_route_nodes)
			return NF_ACCEPT;
	}
	return NF_ACCEPT;
}

struct nf_hook_ops encap_hook_ops[] = {
	{
		.hook = nf_encap_ipv4_pre_routing_handler,
		.hooknum = NF_INET_PRE_ROUTING,
		.pf = NFPROTO_INET,
		.priority = NF_IP_PRI_SELINUX_LAST
	},
	{
		.hook = nf_encap_ippp_post_routing_handler,
		.hooknum = NF_INET_POST_ROUTING,
		.pf = NFPROTO_IPPP,
		.priority = NF_IP_PRI_SELINUX_LAST
	},
};

static int __net_init encap_init_net(struct net *net) {
	struct encap_net* encap_net = net_generic(net, encap_net_id);
	encap_net->encap_nodes = NULL;
	encap_net->temporary_route_nodes = NULL;

	nf_register_net_hooks_pp(net, encap_hook_ops, ARRAY_SIZE(encap_hook_ops));

	return 0;
}

static void __net_exit encap_exit_net(struct net *net) {
	struct encap_net* encap_net = net_generic(net, encap_net_id);
	while(encap_net->encap_nodes) {
		struct encap_node* encap_node = encap_net->encap_nodes;
		encap_dellink(net, encap_node->dev);
		encap_net->encap_nodes = (struct encap_node*)delNode((struct listNode*)(encap_net->encap_nodes), (struct listNode*)(encap_net->encap_nodes));
	}
	while(encap_net->temporary_route_nodes) {
		encap_net->temporary_route_nodes = (struct temporary_route_node*)delNode((struct listNode*)(encap_net->temporary_route_nodes), (struct listNode*)(encap_net->temporary_route_nodes));
	}

	nf_unregister_net_hooks_pp(net, encap_hook_ops, ARRAY_SIZE(encap_hook_ops));
}

static struct pernet_operations encap_net_ops = {
	.init = encap_init_net,
	.exit = encap_exit_net,
	.id   = &encap_net_id,
	.size = sizeof(struct encap_net),
};

int __init nf_encap_init(void) {
	int err;

	err = register_pernet_device(&encap_net_ops);
	if (err < 0)
		return err;

	return err;
}

void nf_encap_exit(void) {
	unregister_pernet_device(&encap_net_ops);
}