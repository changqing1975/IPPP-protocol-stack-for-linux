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
#include <net/netns/generic.h>
#include <linux/udp.h>
#include "../ipppk.h"

struct remote_node {
	struct listNode node;
	__be16 proto;
	union{
		struct ippp_addr remote_addr;
		__be32 remote_addr_;
	};
	__be16 remote_port;
	__be32 nat_addr;
	__be16 nat_port;
	unsigned long last_time;
};

struct local_node {
	struct listNode node;
	u8 protocol;	// 传输层协议
	__be32 local_addr;
	__be16 local_port;
	__be16 proto;	// IPv4 | IP++
	/* 	超过一定时间(30秒)不活动的local_node需要被清除。此处的定时机制没采用定时器触发，而是在数据接收处理时触发。
		有数据收发时，如命中某local_node，则查看其是否超时，如不超时则将此local_node放置至链表尾并更新last_time,
		如超时则清除。清除所有超时local_node */
	unsigned long last_time;
	struct remote_node* remote_nodes;
};

// 存储网络命名空间的扩展信息
struct dstack_net {
	struct local_node* local_nodes;
};

#define EXPIRE_PERIOD HZ * 30

static unsigned int dstack_net_id __read_mostly;

inline struct local_node* find_local_node(struct dstack_net* dstack_net, u8 protocol, __be16 port) {

	if(dstack_net) {
		struct local_node* local_node = dstack_net->local_nodes;
		while(local_node) {
			if((local_node->protocol == protocol) && (local_node->local_port == port)) {
				return local_node;
			}
			local_node = (struct local_node*)(((struct listNode*)local_node)->next);
			if(local_node == dstack_net->local_nodes)
				return NULL;
		}
	}
	return NULL;
}

inline struct remote_node* find_remote_node(struct local_node* local_node, __be32 addr, __be16 port) {
	if(local_node) {
		struct remote_node* remote_node = local_node->remote_nodes;
		while(remote_node) {
			if((remote_node->remote_addr_ == addr) && (remote_node->remote_port == port)) {
				return remote_node;
			}
			remote_node = (struct remote_node*)(((struct listNode*)remote_node)->next);
			if(remote_node == local_node->remote_nodes)
				return NULL;
		}
	}
	return NULL;
}

inline struct remote_node* find_remote_node2(struct local_node* local_node, __be32 addr, __be16 port) {
	if(local_node) {
		struct remote_node* remote_node = local_node->remote_nodes;
		while(remote_node) {
			if((remote_node->nat_addr == addr) && (remote_node->remote_port == port)) {
				return remote_node;
			}
			remote_node = (struct remote_node*)(((struct listNode*)remote_node)->next);
			if(remote_node == local_node->remote_nodes)
				return NULL;
		}
	}
	return NULL;
}

inline struct remote_node* find_remote_node3(struct local_node* local_node, struct ippp_addr* addr, __be16 port) {
	if(local_node) {
		struct remote_node* remote_node = local_node->remote_nodes;
		while(remote_node) {
			if((remote_node->remote_addr.type == addr->type) &&
			(remote_node->remote_addr.base == addr->base) &&
			(remote_node->remote_addr.len == addr->len) &&
			(remote_node->remote_addr.addr == addr->addr) && (remote_node->nat_port == port)) {
				return remote_node;
			}
			remote_node = (struct remote_node*)(((struct listNode*)remote_node)->next);
			if(remote_node == local_node->remote_nodes)
				return NULL;
		}
	}
	return NULL;
}

// 清除超时记录
inline void clear_timeout_local_nodes(struct dstack_net* dstack_net) {
	if(dstack_net && dstack_net->local_nodes) {
		struct listNode* local_node_ = ((struct listNode*)(dstack_net->local_nodes))->prev;
		while(true) {
			if((jiffies - ((struct local_node*)local_node_)->last_time) > EXPIRE_PERIOD) {
				// 删除所有remote_node
				while(((struct local_node*)local_node_)->remote_nodes) {
					((struct local_node*)local_node_)->remote_nodes = (struct remote_node*)delNode(
						(struct listNode*)(((struct local_node*)local_node_)->remote_nodes),
						(struct listNode*)(((struct local_node*)local_node_)->remote_nodes));
				}
				dstack_net->local_nodes = (struct local_node*)delNode((struct listNode*)(dstack_net->local_nodes), local_node_);
				if(dstack_net->local_nodes) {
					local_node_ = ((struct listNode*)(dstack_net->local_nodes))->prev;
				} else {
					break;
				}
			} else {
				break;
			}
		}
	}
}

inline void clear_timeout_remote_nodes(struct local_node* local_node) {
	if(local_node && local_node->remote_nodes) {
		struct listNode* remote_node_ = ((struct listNode*)(((struct local_node*)local_node)->remote_nodes))->prev;
		while(true) {
			if((jiffies - ((struct remote_node*)remote_node_)->last_time) > EXPIRE_PERIOD) {
				((struct local_node*)local_node)->remote_nodes = (struct remote_node*)delNode((struct listNode*)(((struct local_node*)local_node)->remote_nodes), remote_node_);
				if(((struct local_node*)local_node)->remote_nodes) {
					remote_node_ = ((struct listNode*)(((struct local_node*)local_node)->remote_nodes))->prev;
				} else {
					break;
				}
			} else {
				break;
			}
		}
	}
}

static unsigned int nf_dstack_ipv4_local_in_handler(void* priv, struct sk_buff* skb, const struct nf_hook_state* state) {
	struct iphdr * iph = ip_hdr(skb);
	if(iph) {
		struct net* net = dev_net(skb->dev);
		struct dstack_net* dstack_net = net_generic(net, dstack_net_id);
		u8 protocol = iph->protocol;
		__be16 local_port = 0;
		__be16 remote_port = 0;
		if(protocol == IPPROTO_TCP) {
			struct tcphdr *th = tcp_hdr(skb);
			local_port = th->dest;
			remote_port = th->source;
		} else if(protocol == IPPROTO_UDP) {
			struct udphdr* uh = udp_hdr(skb);
			local_port = uh->dest;
			remote_port = uh->source;
		}

		clear_timeout_local_nodes(dstack_net);

		// 在local_nodes中查询是否已被记录
		struct local_node* local_node = find_local_node(dstack_net, protocol, local_port);
		if(local_node && (local_node->proto == ETH_P_IPPP)) {
			local_node->last_time = jiffies;
			// 移至队首
			if(local_node != dstack_net->local_nodes) {
				rmNode((struct listNode*)(dstack_net->local_nodes), (struct listNode*)(local_node));
				dstack_net->local_nodes = (struct local_node*)addNode((struct listNode*)(dstack_net->local_nodes), (struct listNode*)local_node);
			}
		} else {
			if(protocol == IPPROTO_TCP) {
				// struct tcphdr *th = tcp_hdr(skb);
				// DEBUG_LOG("TCP source : %pI4:%hu | dest : %pI4:%hu | seq : %u | ack_seq : %u | window : %hu | csum : 0x%hx | urg_ptr %hu\n",
				// 	&(iph->saddr),ntohs(th->source),&(iph->daddr),ntohs(th->dest),
				// 	ntohl(th->seq), ntohl(th->ack_seq), ntohs(th->window), ntohs(th->check), ntohs(th->urg_ptr));
			} else if(protocol == IPPROTO_UDP) {
				struct udphdr* uh = udp_hdr(skb);
				struct sock *sk = __udp4_lib_lookup(dev_net(skb->dev),
					iph->saddr, uh->source, iph->daddr, uh->dest,
					inet_iif(skb), inet_sdif(skb), dev_net(skb->dev)->ipv4.udp_table, skb);
				if(sk && (sk->sk_family == AF_INETPP)) {
					// 记录信息给后续数据包和返程数据包使用
					local_node = (struct local_node*)kmalloc(sizeof(struct local_node), GFP_KERNEL);
					local_node->protocol = protocol;
					local_node->local_port = local_port;
					local_node->proto = ETH_P_IPPP;
					local_node->last_time = jiffies;
					local_node->remote_nodes = NULL;
					dstack_net->local_nodes = (struct local_node*)addNode((struct listNode*)(dstack_net->local_nodes), (struct listNode*)local_node);
				}
			}
		}
		if(local_node) {
			// 清除超时记录
			clear_timeout_remote_nodes(local_node);

			__be32 remote_addr = iph->saddr;
			struct remote_node* remote_node = find_remote_node(local_node, remote_addr, remote_port);
			if(remote_node) {
				remote_node->last_time = jiffies;
				// 移至队首
				if(remote_node != local_node->remote_nodes) {
					rmNode((struct listNode*)(local_node->remote_nodes), (struct listNode*)(remote_node));
					local_node->remote_nodes = (struct remote_node*)addNode((struct listNode*)(local_node->remote_nodes), (struct listNode*)remote_node);
				}
			} else {
				// 记录信息给后续数据包和返程数据包使用
				remote_node = (struct remote_node*)kmalloc(sizeof(struct remote_node), GFP_KERNEL);
				remote_node->remote_addr_ = remote_addr;
				remote_node->remote_port = remote_port;
				remote_node->proto = ETH_P_IP;
				remote_node->last_time = jiffies;
				local_node->remote_nodes = (struct remote_node*)addNode((struct listNode*)(local_node->remote_nodes), (struct listNode*)remote_node);
			}

			// 切换到IPPP协议栈
			u8 tos = iph->tos;
			u8 ttl = iph->ttl;
			u8 protocol = iph->protocol;
			__be32 daddr = iph->daddr;
			__be32 saddr = iph->saddr;
			struct ippphdr* ippph = ippp_hdr(skb);
			ippph->ihl = 0;
			ippph->tos = tos;
			ippph->ttl = ttl;
			ippph->protocol = protocol;
			ippph->dst_type = 1;
			ippph->dst_base = 0;
			ippph->dst_len  = 0;
			ippph->addr[0] = daddr;
			ippph->src_type = 1;
			ippph->src_base = 0;
			ippph->src_len  = 0;
			ippph->addr[1] = saddr;
			
			ippp_local_deliver_finish(net, NULL, skb);
			return NF_STOLEN;
		}
	}
	return NF_ACCEPT;
}

static unsigned int nf_dstack_ippp_local_out_handler(void* priv, struct sk_buff* skb, const struct nf_hook_state* state) {
	struct ippphdr * ippph = ippp_hdr(skb);
	if(ippph) {
		__be16 local_port = 0;
		__be16 remote_port = 0;
		u8 protocol = ippph->protocol;
		if(protocol == IPPROTO_TCP) {
			struct tcphdr *th = tcp_hdr(skb);
			local_port = th->source;
			remote_port = th->dest;
		} else if(protocol == IPPROTO_UDP) {
			struct udphdr *uh = udp_hdr(skb);
			local_port = uh->source;
			remote_port = uh->dest;
		}
		struct net* net;
		if(skb->sk)
			net = sock_net(skb->sk);
		else
			net = dev_net(skb->dev);
		struct dstack_net* dstack_net = net_generic(net, dstack_net_id);
		struct local_node* local_node = find_local_node(dstack_net, protocol, local_port);
		if(local_node) {
			local_node->last_time = jiffies;
			// 移至队首
			if(local_node != dstack_net->local_nodes) {
				rmNode((struct listNode*)(dstack_net->local_nodes), (struct listNode*)(local_node));
				dstack_net->local_nodes = (struct local_node*)addNode((struct listNode*)(dstack_net->local_nodes), (struct listNode*)local_node);
			}
			__be32 remote_addr = ippph->addr[0];
			struct remote_node* remote_node = find_remote_node(local_node, remote_addr, remote_port);
			if(remote_node && (remote_node->proto == ETH_P_IP)) {
				remote_node->last_time = jiffies;
				// 移至队首
				if(remote_node != local_node->remote_nodes) {
					rmNode((struct listNode*)(local_node->remote_nodes), (struct listNode*)(remote_node));
					local_node->remote_nodes = (struct remote_node*)addNode((struct listNode*)(local_node->remote_nodes), (struct listNode*)remote_node);
				}
				// 切换到IPv4协议栈
				u8 tos = ippph->tos;
				u8 ttl = ippph->ttl;
				u8 protocol = ippph->protocol;
				__be32 daddr = ippph->addr[0];
				__be32 saddr = ippph->addr[1];

				// unsigned int max_headroom = LL_RESERVED_SPACE(skb->dev) + 20 + 20;
				// if (skb_cow_head(skb, max_headroom)) {
				// 	kfree_skb(skb);
				// 	return NF_DROP;
				// }
				// skb_scrub_packet(skb, false/* !net_eq(tunnel->net, dev_net(dev_)) */);
				// skb_clear_hash_if_not_l4(skb);
				// skb_dst_set(skb, &rt->dst);
				// memset(IPCB(skb), 0, sizeof(*IPCB(skb)));
				skb_push(skb, 20 - 16);
				skb_reset_network_header(skb);

				struct iphdr* iph = ip_hdr(skb);
				iph->version = 4;
				iph->ihl = 5;
				iph->tos = tos;
				iph->ttl = ttl;
				iph->frag_off = 0;
				iph->protocol = protocol;
				iph->daddr = daddr;
				iph->saddr = saddr;
				__ip_select_ident(net, iph, skb_shinfo(skb)->gso_segs ?: 1);
				ip_local_out(net, NULL, skb);
				return NF_STOLEN;
			}
		}
	}
	return NF_ACCEPT;
}

static unsigned int nf_dstack_ippp_local_in_handler(void* priv, struct sk_buff* skb, const struct nf_hook_state* state) {
	struct ippphdr * ippph = ippp_hdr(skb);
	if(ippph) {
		u8 protocol = ippph->protocol;
		__be16 local_port = 0;
		__be16 remote_port = 0;
		if(protocol == IPPROTO_TCP) {
			struct tcphdr *th = tcp_hdr(skb);
			local_port = th->dest;
			remote_port = th->source;
		} else if(protocol == IPPROTO_UDP) {
			struct udphdr* uh = udp_hdr(skb);
			local_port = uh->dest;
			remote_port = uh->source;
		}

		struct net* net = dev_net(skb->dev);
		struct dstack_net* dstack_net = net_generic(net, dstack_net_id);
		clear_timeout_local_nodes(dstack_net);

		// 在local_nodes中查询是否已被记录
		struct local_node* local_node = find_local_node(dstack_net, protocol, local_port);
		if(local_node && (local_node->proto == ETH_P_IP)) {
			local_node->last_time = jiffies;
			// 移至队首
			if(local_node != dstack_net->local_nodes) {
				rmNode((struct listNode*)(dstack_net->local_nodes), (struct listNode*)(local_node));
				dstack_net->local_nodes = (struct local_node*)addNode((struct listNode*)(dstack_net->local_nodes), (struct listNode*)local_node);
			}
		} else {
			if(protocol == IPPROTO_TCP) {
				// struct tcphdr *th = tcp_hdr(skb);

			} else if(protocol == IPPROTO_UDP) {
				struct udphdr* uh = udp_hdr(skb);
				struct sock *sk = __udp4_lib_lookup(dev_net(skb->dev),
					ippph->addr[ippph->dst_len + ippph->src_len + 1], uh->source,
					ippph->addr[ippph->dst_len], uh->dest,
					inet_iif(skb), inet_sdif(skb), dev_net(skb->dev)->ipv4.udp_table, skb);
				if(sk && (sk->sk_family == AF_INET)) {
					// 记录信息给后续数据包和返程数据包使用
					local_node = (struct local_node*)kmalloc(sizeof(struct local_node), GFP_KERNEL);
					local_node->protocol = protocol;
					local_node->local_port = local_port;
					local_node->proto = ETH_P_IP;
					local_node->last_time = jiffies;
					local_node->remote_nodes = NULL;
					dstack_net->local_nodes = (struct local_node*)addNode((struct listNode*)(dstack_net->local_nodes), (struct listNode*)local_node);
				}
			}
		}
		if(local_node) {
			// 清除超时记录
			clear_timeout_remote_nodes(local_node);
			struct ippp_addr remote_addr;
			getAddrFromSkb(skb, NULL, &remote_addr, 0);
			struct remote_node* remote_node = find_remote_node3(local_node, &remote_addr, remote_port);
			if(remote_node) {
				remote_node->last_time = jiffies;
				// 移至队首
				if(remote_node != local_node->remote_nodes) {
					rmNode((struct listNode*)(local_node->remote_nodes), (struct listNode*)(remote_node));
					local_node->remote_nodes = (struct remote_node*)addNode((struct listNode*)(local_node->remote_nodes), (struct listNode*)remote_node);
				}
			} else {
				// 记录信息给后续数据包和返程数据包使用
				remote_node = (struct remote_node*)kmalloc(sizeof(struct remote_node), GFP_KERNEL);
				remote_node->remote_addr = remote_addr;
				remote_node->remote_port = remote_port;
				remote_node->nat_addr = leafAddr(&remote_addr);
				__be16 nat_port = remote_port;
				while(find_remote_node2(local_node, remote_node->nat_addr, nat_port)) {
					nat_port++;
					if(nat_port == remote_port)
						return NF_DROP;
				}
				remote_node->nat_port = nat_port;
				remote_node->proto = ETH_P_IPPP;
				remote_node->last_time = jiffies;
				local_node->remote_nodes = (struct remote_node*)addNode((struct listNode*)(local_node->remote_nodes), (struct listNode*)remote_node);
			}

			// 切换到IPv4协议栈
			u8 tos = ippph->tos;
			u8 ttl = ippph->ttl;
			u8 protocol = ippph->protocol;
			__be32 daddr = ippph->addr[ippph->dst_len];
			__be32 saddr = ippph->addr[ippph->dst_len + ippph->src_len + 1];

			__u8 realLen = 8 + (8 << (ippph->ihl));
			if(realLen > sizeof(struct iphdr))
				skb_pull(skb, realLen - sizeof(struct iphdr));
			else
				skb_push(skb, sizeof(struct iphdr) - realLen);
			skb_reset_network_header(skb);

			struct iphdr* iph = ip_hdr(skb);
			iph->version = 4;
			iph->ihl = 5;
			iph->tos = tos;
			iph->ttl = ttl;
			iph->frag_off = 0;
			iph->protocol = protocol;
			iph->daddr = daddr;
			iph->saddr = saddr;
			if(remote_node->nat_port != remote_node->remote_port) {
				if(ippph->protocol == IPPROTO_TCP) {
					struct tcphdr *th = tcp_hdr(skb);
					th->source = remote_node->nat_port;
				} else if(ippph->protocol == IPPROTO_UDP) {
					struct udphdr *uh = udp_hdr(skb);
					uh->source = remote_node->nat_port;
					__wsum csum = 0;
					if (skb->ip_summed == CHECKSUM_PARTIAL) {
						udp4_hwcsum(skb, saddr, daddr);
					} else {
						csum = udp_csum(skb);
						uh->check = csum_tcpudp_magic(saddr, daddr, ntohs(uh->len), IPPROTO_UDP, csum);
					}
				}
			}
			skb_pull(skb, sizeof(struct iphdr));
			skb_reset_transport_header(skb);
			const struct net_protocol *ipprot = rcu_dereference(inet_protos[ip_hdr(skb)->protocol]);
			ipprot->handler(skb);

			// ip_local_deliver(skb);
			return NF_STOLEN;
		}
	}
	return NF_ACCEPT;
}

static unsigned int nf_dstack_ipv4_local_out_handler(void* priv, struct sk_buff* skb, const struct nf_hook_state* state) {
	struct iphdr * iph = ip_hdr(skb);
	if(iph) {
		__be16 local_port = 0;
		__be16 remote_port = 0;
		u8 protocol = iph->protocol;
		if(protocol == IPPROTO_TCP) {
			struct tcphdr *th = tcp_hdr(skb);
			local_port = th->source;
			remote_port = th->dest;
		} else if(protocol == IPPROTO_UDP) {
			struct udphdr *uh = udp_hdr(skb);
			local_port = uh->source;
			remote_port = uh->dest;
		}
		struct net* net = (struct net*)priv;
		if(!net)
			return NF_ACCEPT;
		struct dstack_net* dstack_net = net_generic(net, dstack_net_id);
		struct local_node* local_node = find_local_node(dstack_net, protocol, local_port);
		if(local_node) {
			local_node->last_time = jiffies;
			// 移至队首
			if(local_node != dstack_net->local_nodes) {
				rmNode((struct listNode*)(dstack_net->local_nodes), (struct listNode*)(local_node));
				dstack_net->local_nodes = (struct local_node*)addNode((struct listNode*)(dstack_net->local_nodes), (struct listNode*)local_node);
			}
			__be32 daddr = iph->daddr;
			struct remote_node* remote_node = find_remote_node2(local_node, daddr, remote_port);
			if(remote_node && (remote_node->proto == ETH_P_IPPP)) {
				remote_node->last_time = jiffies;
				// 移至队首
				if(remote_node != local_node->remote_nodes) {
					rmNode((struct listNode*)(local_node->remote_nodes), (struct listNode*)(remote_node));
					local_node->remote_nodes = (struct remote_node*)addNode((struct listNode*)(local_node->remote_nodes), (struct listNode*)remote_node);
				}
				// 切换到IPv4协议栈
				u8 tos = iph->tos;
				u8 ttl = iph->ttl;
				__be32 saddr = iph->saddr;

				struct flowipp flpp;
				struct ippp_addr remote_addr = {
					.type = remote_node->remote_addr.type,
					.base = remote_node->remote_addr.base,
					.len = remote_node->remote_addr.len,
				};
				struct ippp_addr local_addr = {
					.type = 1,
					.base = 0,
					.len = 0,
				};
				flpp.un = ((struct if_*)findNode(if_global_list.head, first_net_device(net)->name, 1))->un;
				__u8 level = flpp.un->level;
				__u8 hdrlen = getHdrLen(&remote_addr, &local_addr, level);
				__u8 realLen = 8 + (8 << hdrlen);
				unsigned int max_headroom = 14 + realLen;
				if (skb_cow_head(skb, max_headroom)) {
					kfree_skb(skb);
					return NF_DROP;
				}
				if(realLen > sizeof(struct iphdr))
					skb_push(skb, realLen - sizeof(struct iphdr));
				else
					skb_pull(skb, sizeof(struct iphdr) - realLen);
				skb_reset_network_header(skb);

				struct ippphdr* ippph = ippp_hdr(skb);
				ippph->ihl = hdrlen;
				ippph->has_ext_hdr = 0;
				ippph->tos = tos;
				ippph->ttl = ttl;
				ippph->protocol = protocol;
				ippph->dst_type = remote_addr.type;
				ippph->dst_base = remote_addr.base;
				ippph->dst_len = remote_addr.len;
				for(int i = 0; i <= ippph->dst_len; i++) {
					ippph->addr[i] = remote_node->remote_addr.addr[i];
				}
				ippph->src_type = 1;
				ippph->src_base = 0;
				ippph->src_len = 0;
				ippph->addr[ippph->dst_len + 1] = saddr;
				if(remote_node->nat_port != remote_node->remote_port) {
					if(protocol == IPPROTO_TCP) {
						struct tcphdr *th = tcp_hdr(skb);
						th->dest = remote_node->remote_port;
					} else if(protocol == IPPROTO_UDP) {
						struct udphdr *uh = udp_hdr(skb);
						uh->dest = remote_node->remote_port;
						__wsum csum = 0;
						if (skb->ip_summed == CHECKSUM_PARTIAL) {
							udp4_hwcsum(skb, saddr, daddr);
						} else {
							csum = udp_csum(skb);
							uh->check = csum_tcpudp_magic(saddr, daddr, ntohs(uh->len), IPPROTO_UDP, csum);
						}
					}
				}

    			getAddrFromSkb(skb, &(flpp.rmtaddr), &(flpp.locaddr), 0);
				struct flowi4 *fl4 = &flpp.fl4;
				fl4->saddr = 0;
				struct dst_entry *dst = skb_dst(skb);
				struct rtable *rt = (struct rtable *)dst;
				struct rtable *nrt = ippp_route_output_flow(net, &flpp, NULL, skb, false);
				kfree(rt);
				skb_dst_set(skb, &nrt->dst);
				ippph->tot_len = htons(skb->len);

				ippp_output(net, NULL, skb);
				return NF_STOLEN;
			}
		}
	}
	return NF_ACCEPT;
}

struct nf_hook_ops hook_ops[] = {
	{
		.hook = nf_dstack_ipv4_local_in_handler,
		.hooknum = NF_INET_LOCAL_IN,
		.pf = NFPROTO_INET,
		.priority = NF_IP_PRI_SELINUX_LAST
	},
	{
		.hook = nf_dstack_ippp_local_out_handler,
		.hooknum = NF_INET_LOCAL_OUT,
		.pf = NFPROTO_IPPP,
		.priority = NF_IP_PRI_SELINUX_LAST
	},
	{
		.hook = nf_dstack_ippp_local_in_handler,
		.hooknum = NF_INET_LOCAL_IN,
		.pf = NFPROTO_IPPP,
		.priority = NF_IP_PRI_SELINUX_LAST
	},
	{
		.hook = nf_dstack_ipv4_local_out_handler,
		.hooknum = NF_INET_LOCAL_OUT,
		.pf = NFPROTO_INET,
		.priority = NF_IP_PRI_SELINUX_LAST
	},
};

static int __net_init dstack_init_net(struct net *net) {
	struct dstack_net* dstack_net = net_generic(net, dstack_net_id);
	dstack_net->local_nodes = NULL;
	hook_ops[3].priv = (void*)net;
	return nf_register_net_hooks_pp(net, hook_ops,  ARRAY_SIZE(hook_ops));
}

static void __net_exit dstack_exit_net(struct net *net) {
	struct dstack_net* dstack_net = net_generic(net, dstack_net_id);
	while(dstack_net->local_nodes) {
		while(dstack_net->local_nodes->remote_nodes) {
			dstack_net->local_nodes->remote_nodes = (struct remote_node*)delNode((struct listNode*)(dstack_net->local_nodes->remote_nodes), (struct listNode*)(dstack_net->local_nodes->remote_nodes));
		}
		dstack_net->local_nodes = (struct local_node*)delNode((struct listNode*)(dstack_net->local_nodes), (struct listNode*)(dstack_net->local_nodes));
	}
	nf_unregister_net_hooks_pp(net, hook_ops, ARRAY_SIZE(hook_ops));
}

static struct pernet_operations dstack_ops = {
	.init = dstack_init_net,
	.exit = dstack_exit_net,
	.id   = &dstack_net_id,
	.size = sizeof(struct dstack_net),
};

int nf_dstack_init(void) {
	int err;

	err = register_pernet_device(&dstack_ops);
	if (err < 0)
		return err;

	return 0;
}

void nf_dstack_exit(void) {
	unregister_pernet_device(&dstack_ops);
}