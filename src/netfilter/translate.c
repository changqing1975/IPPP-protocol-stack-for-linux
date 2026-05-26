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

struct translate_net {
	struct translate_node* translate_nodes;
};

static unsigned int translate_net_id __read_mostly;

bool is_translate_dev(struct net* net, struct net_device *dev) {
	struct translate_net* translate_net = net_generic(net, translate_net_id);
	if(translate_net) {
		// 在translate_nodes中搜索与dev匹配的
		struct translate_node* en = translate_net->translate_nodes;
		while(en) {
			if(en->dev == dev)
				return true;
			en = (struct translate_node*)(((struct listNode*)en)->next);
			if(en == translate_net->translate_nodes)
				return false;
		}
	}
	return false;
}

static netdev_tx_t translate_tunnel_xmit(struct sk_buff *skb, struct net_device *dev) {
	struct translate_node* translate_node = netdev_priv(dev);
    struct net* net = dev_net(dev);
	struct net_device* real_dev;
	if(is_translate_dev(net, dev))
		real_dev = translate_node->base_dev;
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

	struct ippphdr *ippph = ippp_hdr(skb);
	unsigned int ippphdr_len = 8 + (8 << ippph->ihl);
	unsigned int max_headroom = LL_RESERVED_SPACE(rt->dst.dev) + sizeof(struct iphdr) + rt->dst.header_len;
	__u8 protocol = ippph->protocol;
	__u8 tos = ippph->tos;
	__be32 daddr = ippph->addr[ippph->dst_len];
	__be32 saddr = ippph->addr[ippph->dst_len + ippph->src_len + 1];
	__u8 ttl = ippph->ttl;
	

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

	skb_scrub_packet(skb, false);

	skb_clear_hash_if_not_l4(skb);
	skb_dst_set(skb, &rt->dst);
	memset(IPCB(skb), 0, sizeof(*IPCB(skb)));

	/* Push down and install the IP header. */
	if(ippphdr_len > sizeof(struct iphdr))
		skb_pull(skb, ippphdr_len - sizeof(struct iphdr));
	else
		skb_push(skb, sizeof(struct iphdr) - ippphdr_len);
	skb_reset_network_header(skb);

	/* 设置新的IP头字段 */
	struct iphdr *iph = ip_hdr(skb);
	iph->version	=	4;
	iph->ihl		=	sizeof(struct iphdr) >> 2;
	iph->frag_off	=	0/* ip_mtu_locked(&rt->dst) ? 0 : df */;
	iph->protocol	=	protocol;
	iph->tos		=	tos;
	// if (ip_dont_fragment(sk, &rt->dst) && !skb->ignore_df)
	// 	iph->frag_off = htons(IP_DF);
	// else
	// 	iph->frag_off = 0;
	iph->daddr		=	daddr;
	iph->saddr		=	saddr;
	iph->ttl		=	ttl;
	__ip_select_ident(net, iph, skb_shinfo(skb)->gso_segs ?: 1);

	int err = ip_local_out(net, NULL, skb);

	if (dev_) {
		if (unlikely(net_xmit_eval(err)))
			pkt_len = 0;
		iptunnel_xmit_stats(dev_, pkt_len);
	}

	return NETDEV_TX_OK;
}

// // static bool translate_tunnel_ioctl_verify_protocol(u8 ipproto)
// // {
// // 	switch (ipproto) {
// // 	case 0:
// // 	case IPPROTO_IPIP:
// // 		return true;
// // 	}

// // 	return false;
// // }

static int translate_tunnel_ctl(struct net_device *dev, struct ip_tunnel_parm_kern *p, int cmd) {
// 	if (cmd == SIOCADDTUNNEL || cmd == SIOCCHGTUNNEL) {
// 		if (p->iph.version != 4 ||
// 		    !translate_tunnel_ioctl_verify_protocol(p->iph.protocol) ||
// 		    p->iph.ihl != 5 || (p->iph.frag_off & htons(~IP_DF)))
// 			return -EINVAL;
// 	}

// 	p->i_key = p->o_key = 0;
// 	p->i_flags = p->o_flags = 0;
	return 0/* ip_tunnel_ctl(dev, p, cmd) */;
}

static int translate_tunnel_init(struct net_device *dev) {
	// struct translate_node *translate_node = netdev_priv(dev);

	// __dev_addr_set(dev, &tunnel->parms.iph.saddr, 4);
	// memcpy(dev->broadcast, &tunnel->parms.iph.daddr, 4);

	// tunnel->tun_hlen = 0;
	// tunnel->hlen = tunnel->tun_hlen + tunnel->translate_hlen;
	return 0/* ip_tunnel_init(dev) */;
}

static void translate_tunnel_uninit(struct net_device *dev) {

}

static const struct net_device_ops translate_netdev_ops = {
	.ndo_init       = translate_tunnel_init,
	.ndo_uninit     = translate_tunnel_uninit,
	.ndo_start_xmit	= translate_tunnel_xmit,
	// .ndo_siocdevprivate = ip_tunnel_siocdevprivate,
	// .ndo_change_mtu = ip_tunnel_change_mtu,
	.ndo_get_stats64 = dev_get_tstats64,
	// .ndo_get_iflink = ip_tunnel_get_iflink,
	.ndo_tunnel_ctl	= translate_tunnel_ctl,
};

static void translate_setup(struct net_device *dev) {
	dev->netdev_ops		= &translate_netdev_ops;
}

int translate_newlink(struct net *net, struct net_device *base_dev, char* name) {
	rtnl_lock();
	struct translate_net* translate_net = net_generic(net, translate_net_id);
	struct net_device* dev = alloc_netdev(sizeof(struct translate_node), name, NET_NAME_UNKNOWN, translate_setup);
	dev_net_set(dev, net);
	int err = register_netdevice(dev);
	dev->mtu = base_dev->mtu;
	struct translate_node* translate_node = netdev_priv(dev);
	translate_node->base_dev = base_dev;
	translate_node->dev = dev;
	translate_net->translate_nodes = (struct translate_node*)addNode((struct listNode*)translate_net->translate_nodes, (struct listNode*)translate_node);
	rtnl_unlock();
	return err;
}

int translate_dellink(struct net *net, struct net_device *dev) {
	unregister_netdevice(dev);
	free_netdev(dev);
	return 0;
}

static unsigned int nf_translate_ipv4_pre_routing_handler(void* priv, struct sk_buff* skb, const struct nf_hook_state* state) {
	struct net* net = dev_net(skb->dev);
	// 查反向路由，判别是否为翻译
	struct flowi4 fl4;
	struct iphdr *iph = ip_hdr(skb);
	fl4.daddr = iph->saddr;
	if(net) {
		struct rtable* rt = __ip_route_output_key(net, &fl4);
		if(!(IS_ERR(rt)) && is_translate_dev(net, rt->dst.dev)) {			// 反向路由是封装的
			// 回翻译
			__u8 tos		=	iph->tos;
			__be16 len		=	iph->tot_len;
			__u8 ttl		=	iph->ttl;
			__u8 protocol	=	iph->protocol;
			__be32 daddr	=	iph->daddr;
			__be32 saddr	=	iph->saddr;
			if (iptunnel_pull_header(skb, 4, ETH_P_IPPP, false)) {
				kfree_skb(skb);
				return NF_DROP;
			}
			skb_reset_mac_header(skb);
			skb_set_network_header(skb, 0);
			struct ippphdr *ippph = ippp_hdr(skb);
			ippph->ihl			=	0;
			ippph->has_ext_hdr	=	0;
			ippph->tos			=	tos;
			ippph->tot_len		=	len;
			ippph->ttl			=	ttl;
			ippph->protocol		=	protocol;
			ippph->dst_type		=	1;
			ippph->dst_base		=	0;
			ippph->dst_len		=	0;
			ippph->addr[0]		=	daddr;
			ippph->src_type		=	1;
			ippph->src_base		=	0;
			ippph->src_len		=	0;
			ippph->addr[1]		=	saddr;
			NF_HOOK_PP(NF_INET_PRE_ROUTING,net, NULL, skb, skb->dev, NULL, ippp_rcv_finish);
			return NF_STOLEN;
		}
	}
	return NF_ACCEPT;
}

struct nf_hook_ops translate_hook_ops[] = {
	{
		.hook = nf_translate_ipv4_pre_routing_handler,
		.hooknum = NF_INET_PRE_ROUTING,
		.pf = NFPROTO_INET,
		.priority = NF_IP_PRI_SELINUX_LAST
	},
};

static int __net_init translate_init_net(struct net *net) {
	struct translate_net* translate_net = net_generic(net, translate_net_id);
	translate_net->translate_nodes = NULL;

	nf_register_net_hooks_pp(net, translate_hook_ops, ARRAY_SIZE(translate_hook_ops));

	return 0;
}

static void __net_exit translate_exit_net(struct net *net) {
	struct translate_net* translate_net = net_generic(net, translate_net_id);
	while(translate_net->translate_nodes) {
		struct translate_node* translate_node = translate_net->translate_nodes;
		translate_dellink(net, translate_node->dev);
		translate_net->translate_nodes = (struct translate_node*)delNode((struct listNode*)(translate_net->translate_nodes), (struct listNode*)(translate_net->translate_nodes));
	}

	nf_unregister_net_hooks_pp(net, translate_hook_ops, ARRAY_SIZE(translate_hook_ops));
}

static struct pernet_operations translate_net_ops = {
	.init = translate_init_net,
	.exit = translate_exit_net,
	.id   = &translate_net_id,
	.size = sizeof(struct translate_net),
};

int __init nf_translate_init(void) {
	int err = register_pernet_subsys(&translate_net_ops);
	if (err < 0)
		return err;

	return err;
}

void nf_translate_exit(void) {
	unregister_pernet_subsys(&translate_net_ops);
}