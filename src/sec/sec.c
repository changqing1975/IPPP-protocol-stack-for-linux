#ifdef SEC
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
#include <linux/memblock.h>
#include <net/tcp.h>
#include <linux/udp.h>
#include <../net/xfrm/xfrm_hash.h>
#include "../ipppk.h"

#define EXPIRE_PERIOD HZ * 30

struct sec_node {
	struct listNode node;
	u8 protocol;	// 传输层协议
	__be32 server_addr;
	__be16 server_port;
	struct ippp_addr client_addr;
	__be16 client_port;
	__be32 sec_addr;
	__be16 sec_port;
	unsigned long last_time;
};

unsigned int sec_net_id __read_mostly;
static DEFINE_SPINLOCK(xfrm_state_afinfo_lock);
static struct xfrm_state_afinfo __rcu xfrm_state_afinfo;

int xfrmpp_register_type(const struct xfrm_type *type, unsigned short family) {
	if(family != AF_INETPP)
		return xfrmpp_register_type(type, family);
	else {
		int err = 0;
		rcu_read_lock();
		#define X(afi, T, name) do {			\
			(afi).type_ ## name = (T);	\
		} while (0)

		switch (type->proto) {
		case IPPROTO_COMP:
			X(xfrm_state_afinfo, type, comp);
			break;
		case IPPROTO_AH:
			X(xfrm_state_afinfo, type, ah);
			break;
		case IPPROTO_ESP:
			X(xfrm_state_afinfo, type, esp);
			break;
		case IPPROTO_IPIP:
			X(xfrm_state_afinfo, type, ipip);
			break;
		case IPPROTO_DSTOPTS:
			X(xfrm_state_afinfo, type, dstopts);
			break;
		case IPPROTO_ROUTING:
			X(xfrm_state_afinfo, type, routing);
			break;
		case IPPROTO_IPV6:
			X(xfrm_state_afinfo, type, ipip6);
			break;
		default:
			WARN_ON(1);
			err = -EPROTONOSUPPORT;
			break;
		}
		#undef X
		rcu_read_unlock();
		return err;
	}
}
void xfrmpp_unregister_type(const struct xfrm_type *type, unsigned short family) {
	if(family != AF_INETPP)
		return xfrm_unregister_type(type, family);
	else {
		rcu_read_lock();
		#define X(afi, T, name) do {			\
			(afi).type_ ## name = NULL;	\
		} while (0)

		switch (type->proto) {
		case IPPROTO_COMP:
			X(xfrm_state_afinfo, type, comp);
			break;
		case IPPROTO_AH:
			X(xfrm_state_afinfo, type, ah);
			break;
		case IPPROTO_ESP:
			X(xfrm_state_afinfo, type, esp);
			break;
		case IPPROTO_IPIP:
			X(xfrm_state_afinfo, type, ipip);
			break;
		case IPPROTO_DSTOPTS:
			X(xfrm_state_afinfo, type, dstopts);
			break;
		case IPPROTO_ROUTING:
			X(xfrm_state_afinfo, type, routing);
			break;
		case IPPROTO_IPV6:
			X(xfrm_state_afinfo, type, ipip6);
			break;
		default:
			WARN_ON(1);
			break;
		}
		#undef X
		rcu_read_unlock();
	}
}

const struct xfrm_type *xfrmpp_get_type(u8 proto, unsigned short family) {
	if(family != AF_INETPP)
		return xfrmpp_get_type(proto, family);
	else {
		rcu_read_lock();
		const struct xfrm_type *type = NULL;
		switch (proto) {
		case IPPROTO_AH:
			type = xfrm_state_afinfo.type_ah;
			break;
		case IPPROTO_ESP:
			type = xfrm_state_afinfo.type_esp;
			break;
		default:
			break;
		}
		rcu_read_unlock();
		return type;
	}
}

struct xfrmpp_state *xfrmpp_state_alloc(struct net *net) {
	struct xfrmpp_state *x = kmalloc(sizeof(struct xfrmpp_state), GFP_ATOMIC);

	if (x) {
		struct xfrm_state *_x = (struct xfrm_state *)x;
		_x->props.family = AF_INETPP;
		write_pnet(&_x->xs_net, net);
		refcount_set(&_x->refcnt, 1);
		atomic_set(&_x->tunnel_users, 0);
		INIT_LIST_HEAD(&_x->km.all);
		INIT_HLIST_NODE(&_x->bydst);
		INIT_HLIST_NODE(&_x->bysrc);
		INIT_HLIST_NODE(&_x->byspi);
		INIT_HLIST_NODE(&_x->byseq);
		hrtimer_init(&_x->mtimer, CLOCK_BOOTTIME, HRTIMER_MODE_ABS_SOFT);
		// _x->mtimer.function = xfrm_timer_handler;
		// timer_setup(&_x->rtimer, xfrm_replay_timer_handler, 0);
		_x->curlft.add_time = ktime_get_real_seconds();
		_x->lft.soft_byte_limit = XFRM_INF;
		_x->lft.soft_packet_limit = XFRM_INF;
		_x->lft.hard_byte_limit = XFRM_INF;
		_x->lft.hard_packet_limit = XFRM_INF;
		_x->replay_maxage = 0;
		_x->replay_maxdiff = 0;
		spin_lock_init(&_x->lock);
	}
	return x;
}

inline bool compare_addr(struct ippp_addr* a, struct ippp_addr* b, __u8 prefix_len) {
	if(a->type != b->type)
		return false;
	if(a->base != b->base)
		return false;
	if(a->len > b->len)
		return false;
	for(int i = 0; i <= a->len; i++) {
		if(i == a->len) {
			__be32 mask = 0xFFFF << (32 - prefix_len);
			if((a->addr[i] & mask) != (b->addr[i] & mask))
				return false;
		} else {
			if(a->addr[i] != b->addr[i])
				return false;
		}
	}
	return true;
}

static unsigned int sec_ippp_pre_routing_handler(void* priv, struct sk_buff* skb, const struct nf_hook_state* state) {
	struct net* net = (struct net*)priv;
	struct sec_net* sec_net = net_generic(net, sec_net_id);
	struct ippp_addr daddr, saddr;
    getAddrFromSkb(skb, &daddr, &saddr, 0);
	struct xfrm_state *x = NULL;
	struct xfrm_state *ah_sa = NULL;
	struct xfrm_state *esp_sa = NULL;
    struct listNode* ln = sec_net->xfrmpp_states?&(sec_net->xfrmpp_states->node):NULL;
    while(ln) {
		struct xfrmpp_state *x = container_of(ln, struct xfrmpp_state, node);
		struct xfrm_state *_x = (struct xfrm_state *)x;
		if(x->direction != 0) {
			// 地址匹配，要求严格匹配
			if(compare_addr(&(x->daddr), &daddr, x->daddr_prefix_len) && compare_addr(&(x->saddr), &saddr, x->saddr_prefix_len)) {
				if(_x->id.proto == IPPROTO_AH) {
					if(!ah_sa) {
						ah_sa = _x;
					}
				} else if(_x->id.proto == IPPROTO_ESP) {
					if(!esp_sa) {
						esp_sa = _x;
					}
				}
			}
		}
		if(ah_sa && esp_sa)
			break;
        ln = ln->next;
        if(ln == &(sec_net->xfrmpp_states->node))
            break;
	}
	if(esp_sa) {
		esp_sa->type->input(esp_sa, skb);
	}
	if(ah_sa) {
		ah_sa->type->input(ah_sa, skb);		
	}
	if(ah_sa || esp_sa) {
		ippp_rcv_finish(net, NULL, skb);
		return NF_STOLEN;
	} else
		return NF_ACCEPT;
}

static unsigned int sec_ippp_post_routing_handler(void* priv, struct sk_buff* skb, const struct nf_hook_state* state) {
	struct net* net = (struct net*)priv;
	struct sec_net* sec_net = net_generic(net, sec_net_id);
	struct ippp_addr daddr, saddr;
    getAddrFromSkb(skb, &daddr, &saddr, 0);
	struct xfrm_state *x = NULL;
	struct xfrm_state *ah_sa = NULL;
	struct xfrm_state *esp_sa = NULL;
    struct listNode* ln = sec_net->xfrmpp_states?&(sec_net->xfrmpp_states->node):NULL;
    while(ln) {
		struct xfrmpp_state *x = container_of(ln, struct xfrmpp_state, node);
		struct xfrm_state *_x = (struct xfrm_state *)x;
		if(x->direction != 1) {
			// 地址匹配，要求严格匹配
			if(compare_addr(&(x->daddr), &daddr, x->daddr_prefix_len) && compare_addr(&(x->saddr), &saddr, x->saddr_prefix_len)) {
				if(_x->id.proto == IPPROTO_AH) {
					if(!ah_sa) {
						ah_sa = _x;
					}
				} else if(_x->id.proto == IPPROTO_ESP) {
					if(!esp_sa) {
						esp_sa = _x;
					}
				}
			}
		}
		if(ah_sa && esp_sa)
			break;
        ln = ln->next;
        if(ln == &(sec_net->xfrmpp_states->node))
            break;
	}
	if(esp_sa) {
		esp_sa->type->output(esp_sa, skb);
	}
	if(ah_sa) {
		ah_sa->type->output(ah_sa, skb);		
	}
	if(ah_sa || esp_sa) {
		ippp_finish_output(net, NULL, skb);
		return NF_STOLEN;
	} else
		return NF_ACCEPT;
}

struct nf_hook_ops sec_hook_ops[] = {
	// {
	// 	.hook = sec_ippp_pre_routing_handler,
	// 	.hooknum = NF_INET_PRE_ROUTING,
	// 	.pf = NFPROTO_IPPP,
	// 	.priority = NF_IP_PRI_SELINUX_LAST + 1
	// },
	{
		.hook = sec_ippp_post_routing_handler,
		.hooknum = NF_INET_POST_ROUTING,
		.pf = NFPROTO_IPPP,
		.priority = NF_IP_PRI_NAT_SRC
	},
};

static struct hlist_head *_xfrm_hash_alloc(unsigned int sz)
{
	struct hlist_head *n;

	if (sz <= PAGE_SIZE)
		n = kzalloc(sz, GFP_KERNEL);
	else if (hashdist)
		n = vzalloc(sz);
	else
		n = (struct hlist_head *)
			__get_free_pages(GFP_KERNEL | __GFP_NOWARN | __GFP_ZERO,
					 get_order(sz));

	return n;
}

static int __net_init sec_init_net(struct net *net) {
	struct sec_net* sec_net = net_generic(net, sec_net_id);
	sec_net->xfrmpp_states = NULL;
	sec_hook_ops[0].priv = (void*)net;
	sec_hook_ops[1].priv = (void*)net;
	nf_register_net_hooks_pp(net, sec_hook_ops, ARRAY_SIZE(sec_hook_ops));
	return 0;
}

static void __net_exit sec_exit_net(struct net *net) {
	struct sec_net* sec_net = net_generic(net, sec_net_id);
	while(sec_net->xfrmpp_states) {
		sec_net->xfrmpp_states = container_of(delNode(&(sec_net->xfrmpp_states->node), &((sec_net->xfrmpp_states)->node)), struct xfrmpp_state , node);
	}

	nf_unregister_net_hooks_pp(net, sec_hook_ops, ARRAY_SIZE(sec_hook_ops));
}

static struct pernet_operations sec_net_ops = {
	.init = sec_init_net,
	.exit = sec_exit_net,
	.id   = &sec_net_id,
	.size = sizeof(struct sec_net),
};

int __init sec_init(void) {
	int err;

	err = register_pernet_device(&sec_net_ops);
	if (err < 0)
		return err;

	return err;
}

void sec_exit(void) {
	unregister_pernet_device(&sec_net_ops);
}

#endif