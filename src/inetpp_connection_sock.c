#include <linux/module.h>
#include <linux/jhash.h>
#include <linux/slab.h>
#include <net/addrconf.h>
#include <net/inet_connection_sock.h>
#include <net/inet_ecn.h>
#include <net/inet_hashtables.h>
#include <net/sock.h>
#include <net/sock_reuseport.h>
#include "ipppk.h"

struct dst_entry *inetpp_csk_route_child_sock(const struct sock *sk,
		struct sock *newsk,
		const struct request_sock *req) {
	const struct inet_request_sock *ireq = inet_rsk(req);
	struct net *net = read_pnet(&ireq->ireq_net);
	struct ip_options_rcu *opt = rcu_dereference(ireq->ireq_opt);
	struct flowipp flpp;
	struct flowi4 *fl4 = &flpp.fl4;
	struct tcp_pp_request_sock *treqpp = (struct tcp_pp_request_sock *)req;
	flpp.locaddr = treqpp->flpp.locaddr;
	flpp.rmtaddr = treqpp->flpp.rmtaddr;
	flpp.fl4.saddr = leafAddr(&(flpp.locaddr));
	flpp.un = ((struct if_*)findNode(if_global_list.head, __ip_dev_find(net, flpp.fl4.saddr, true)->name, 1))->un;

	flowi4_init_output(fl4, ireq->ir_iif, ireq->ir_mark,
		ip_sock_rt_tos(sk), ip_sock_rt_scope(sk),
		sk->sk_protocol, inet_sk_flowi_flags(sk),
		(opt && opt->opt.srr) ? opt->opt.faddr : ireq->ir_rmt_addr,
		ireq->ir_loc_addr, ireq->ir_rmt_port,
		htons(ireq->ir_num), sk->sk_uid);
	security_req_classify_flow(req, flowi4_to_flowi_common(fl4));
	struct rtable *rt = ippp_route_output_flow(net, &flpp, sk, NULL, true);
	if (IS_ERR(rt))
		goto no_route;
	if (opt && opt->opt.is_strictroute && rt->rt_uses_gateway)
		goto route_err;
	return &rt->dst;

route_err:
	ip_rt_put(rt);
no_route:
	__IP_INC_STATS(net, IPSTATS_MIB_OUTNOROUTES);
	return NULL;
}

struct dst_entry *inetpp_csk_route_req(const struct sock *sk,
				     struct flowipp *flpp,
				     const struct tcp_pp_request_sock *treqpp)
{
	struct request_sock *req = (struct request_sock *)treqpp;
	const struct inet_request_sock *ireq = inet_rsk(req);
	struct net *net = read_pnet(&ireq->ireq_net);
	struct ip_options_rcu *opt;
	struct rtable *rt;

	rcu_read_lock();
	opt = rcu_dereference(ireq->ireq_opt);

	flowi4_init_output(&flpp->fl4, ireq->ir_iif, ireq->ir_mark,
				ip_sock_rt_tos(sk), ip_sock_rt_scope(sk),
			   sk->sk_protocol, inet_sk_flowi_flags(sk),
			   (opt && opt->opt.srr) ? opt->opt.faddr : ireq->ir_rmt_addr, ireq->ir_loc_addr,
			   ireq->ir_rmt_port, htons(ireq->ir_num), sock_net_uid(net, sk));
	security_req_classify_flow(req, flowi4_to_flowi_common(&flpp->fl4));
	rt = ippp_route_output_flow(net, flpp, sk, NULL, true);
	if (IS_ERR(rt))
		goto no_route;
	if (opt && opt->opt.is_strictroute && rt->rt_uses_gateway)
		goto route_err;
	rcu_read_unlock();
	return &rt->dst;

route_err:
	ip_rt_put(rt);
no_route:
	rcu_read_unlock();
	__IP_INC_STATS(net, IPSTATS_MIB_OUTNOROUTES);
	return NULL;
}

static inline int ip_select_ttl(int ttl, struct dst_entry *dst)
{
	int _ttl = ttl;

	if (_ttl < 0)
		_ttl = ip4_dst_hoplimit(dst);
	return _ttl;
}

int ippp_xmit(struct sock *sk, struct sk_buff *skb, struct rtable *rt, int tos,
					struct ippp_addr *daddrpp, struct ippp_addr *saddrpp, bool sock_type)
{
	struct net *net = sock_net(sk);
	struct ippphdr *iph;
	__u8 hdrlen4B, hdrlen;

	hdrlen4B = daddrpp->len + saddrpp->len + 2;
	for(int i = 0; i < 5; i++){
		if(hdrlen4B <= 2<<i){
			hdrlen = i;
			break;
		}
	}
	skb_push(skb, 8 + (8 << hdrlen));
	skb_reset_network_header(skb);
	iph = ippp_hdr(skb);
	iph->ihl         = hdrlen;
	iph->tos         = tos;
	iph->ttl         = ip_select_ttl(sock_type?64:inet_sk(sk)->uc_ttl, &rt->dst);
	iph->protocol    = sock_type?6:sk->sk_protocol;
	iph->has_ext_hdr = 0;
	/* copy addr */
	iph->dst_type = daddrpp->type;
	iph->dst_base = daddrpp->base;
	iph->dst_len  = daddrpp->len;
	for(int i = 0; i <= iph->dst_len; i++){
		iph->addr[i] = daddrpp->addr[i];
	}
	iph->src_type = saddrpp->type;
	iph->src_base = saddrpp->base;
	iph->src_len  = saddrpp->len;
	for(int i = 0; i <= iph->src_len; i++){
		iph->addr[iph->dst_len + 1 + i] = saddrpp->addr[i];
	}

	/* Transport layer set skb->h.foo itself. */

	// if (inet_opt && inet_opt->opt.optlen) {
	// 	iph->ihl += inet_opt->opt.optlen >> 2;
	// 	// ip_options_build(skb, &inet_opt->opt, inet->inet_daddr, rt, 0);
	// }

	// ip_select_ident_segs(net, skb, sk,
	// 		     skb_shinfo(skb)->gso_segs ?: 1);

	skb->priority = sk->sk_priority;
	skb->mark = sk->sk_mark;

	return ippp_local_out(net, sk, skb);
}

int ippp_queue_xmit(struct sock *sk, struct sk_buff *skb, struct flowi *fl)
{
	int tos = inet_sk(sk)->tos;
	struct inet_sock *inet = inet_sk(sk);
	struct net *net = sock_net(sk);
	struct ip_options_rcu *inet_opt;
	struct flowi4 *fl4;
	struct rtable *rt;
	int res;
	struct l4pp_sock *l4ppsk = l4pp_sk(sk);
	struct ippp_addr *daddrpp;
	struct ippp_addr *saddrpp;
	daddrpp = &(l4ppsk->flpp.rmtaddr);
	saddrpp = &(l4ppsk->flpp.locaddr);

	/* Skip all of this if the packet is already routed,
	 * f.e. by something like SCTP.
	 */
	rcu_read_lock();
	inet_opt = rcu_dereference(inet->inet_opt);
	fl4 = &fl->u.ip4;
	rt = skb_rtable(skb);
	if (rt)
		goto packet_routed;

	/* Make sure we can route this packet. */
	rt = (struct rtable *)__sk_dst_check(sk, 0);
	if (!rt) {
		__be32 daddr;

		/* Use correct destination address if we have options. */
		daddr = inet->inet_daddr;
		if (inet_opt && inet_opt->opt.srr)
			daddr = inet_opt->opt.faddr;

		/* If this fails, retransmit mechanism of transport layer will
		 * keep trying until route appears or the connection times
		 * itself out.
		 */
		rt = ippp_route_output_ports(net, fl4, sk,
					   daddr, inet->inet_saddr,
					   inet->inet_dport,
					   inet->inet_sport,
					   sk->sk_protocol,
					   tos & INET_DSCP_MASK,
					   sk->sk_bound_dev_if);
		if (IS_ERR(rt))
			goto no_route;
		sk_setup_caps(sk, &rt->dst);
	}
	skb_dst_set_noref(skb, &rt->dst);

packet_routed:
	if (inet_opt && inet_opt->opt.is_strictroute && rt->rt_uses_gateway)
		goto no_route;

	res = ippp_xmit(sk, skb, rt, tos, daddrpp, saddrpp, false);
	rcu_read_unlock();
	return res;

no_route:
	rcu_read_unlock();
	IP_INC_STATS(net, IPSTATS_MIB_OUTNOROUTES);
	kfree_skb(skb);
	return -EHOSTUNREACH;
}