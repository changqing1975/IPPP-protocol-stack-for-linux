/*
 *	TCP over IPPP
 *	Linux INETPP implementation
 *
 *	Authors:
 *	changqing		<cq@ippp.xyz>
 *	
 *	to-do:
 *		MD5、AO
 *		syncookie
 */

#include <linux/bottom_half.h>
#include <linux/types.h>
#include <linux/fcntl.h>
#include <linux/module.h>
#include <linux/random.h>
#include <linux/cache.h>
#include <linux/jhash.h>
#include <linux/init.h>
#include <linux/times.h>
#include <linux/slab.h>
#include <net/net_namespace.h>
#include <net/icmp.h>
#include <net/inet_hashtables.h>
#include <net/tcp.h>
#include <net/mptcp.h>
#include <net/inet_common.h>
#include <net/timewait_sock.h>
#include <net/xfrm.h>
#include <net/secure_seq.h>
#include <net/aligned_data.h>
#include <net/busy_poll.h>
#include <net/psp/functions.h>
#include <linux/inet.h>
#include <linux/stddef.h>
#include <linux/proc_fs.h>
#include <linux/seq_file.h>
#include <crypto/hash.h>
#include <linux/scatterlist.h>
#include <trace/events/tcp.h>
#include <linux/indirect_call_wrapper.h>
#include "ipppk.h"

static void tcp_pp_send_reset(const struct sock *sk, struct sk_buff *skb, enum sk_rst_reason reason);
static void tcp_pp_reqsk_send_ack(const struct sock *sk, struct sk_buff *skb, struct request_sock *req);

#if defined(CONFIG_TCP_MD5SIG) || defined(CONFIG_TCP_AO)
static const struct tcp_sock_af_ops tcp_sock_ippp_specific;
static const struct tcp_sock_af_ops tcp_sock_ippp_mapped_specific;
#endif

static DEFINE_PER_CPU(struct sock_bh_locked, ippp_tcp_sk) = {
	.bh_lock = INIT_LOCAL_LOCK(bh_lock),
};

static void inetpp_sk_rx_dst_set(struct sock *sk, const struct sk_buff *skb) {
	struct dst_entry *dst = skb_dst(skb);

	if (dst && dst_hold_safe(dst)) {
		rcu_assign_pointer(sk->sk_rx_dst, dst);
		sk->sk_rx_dst_ifindex = skb->skb_iif;
	}
}

static u32 tcp_pp_init_seq(const struct sk_buff *skb) {
	struct ippphdr *iph = ippp_hdr(skb);
	return secure_tcp_seq(iph->addr[iph->dst_len],
			      iph->addr[iph->dst_len + iph->src_len],
			      tcp_hdr(skb)->dest,
			      tcp_hdr(skb)->source);
}

static u32 tcp_pp_init_ts_off(const struct net *net, const struct sk_buff *skb) {
	struct ippphdr *iph = ippp_hdr(skb);
	return _secure_tcp_ts_off(net,
					iph->addr[iph->dst_len],
					iph->addr[iph->dst_len + iph->src_len]);
}

static int tcp_pp_pre_connect(struct sock *sk, struct sockaddr *uaddr, int addr_len) {

	if (addr_len < 10)
		return -EINVAL;

	struct ippp_addr *ippp_addr = (struct ippp_addr *)(&(((struct sockaddr_in *)uaddr)->sin_addr));
	if (addr_len < (6 + (ippp_addr->len + 1) * 4))
		return -EINVAL;

	sock_owned_by_me(sk);

	return 0;
}

static int tcp_pp_connect(struct sock *sk, struct sockaddr *uaddr, int addr_len) {
	DEBUG_LOG("%d", module_refcount(THIS_MODULE));

	struct sockaddr_ippp *usin = (struct sockaddr_ippp *) uaddr;
	if (usin->family != AF_INETPP)
		return -EAFNOSUPPORT;

	struct ippp_addr daddr, nexthop;
	nexthop = daddr = usin->addr;
	struct inet_sock *inet = inet_sk(sk);
	// struct ip_options_rcu *inet_opt;
	// inet_opt = rcu_dereference_protected(inet->inet_opt,
	// 				     lockdep_sock_is_held(sk));
	// if (inet_opt && inet_opt->opt.srr) {
	// 	if (!daddr)
	// 		return -EINVAL;
	// 	nexthop = inet_opt->opt.faddr;
	// }

	__be16 orig_sport = inet->inet_sport;
	__be16 orig_dport = usin->port;
	struct flowipp *flpp = &(l4pp_sk(sk)->flpp);
	struct rtable *rt = ippp_route_connect(flpp, nexthop, flpp->locaddr,
			      sk->sk_bound_dev_if, IPPROTO_TCP, orig_sport, orig_dport, sk);
	int err;
	if (IS_ERR(rt)) {
		err = PTR_ERR(rt);
		if (err == -ENETUNREACH)
			IP_INC_STATS(sock_net(sk), IPSTATS_MIB_OUTNOROUTES);
		return err;
	}

	if (rt->rt_flags & (RTCF_MULTICAST | RTCF_BROADCAST)) {
		ip_rt_put(rt);
		return -ENETUNREACH;
	}

	/* 获取本地绑定地址
	struct ippp_addr *get_default_addr(net) {
		struct ippp_addr *default_addr;
	}
	struct ippp_addr *default_addr;
	if(net->default_addr)
		default_addr = net->default_addr;
	else
		default_addr = get_default_addr(net);
	 */
	struct net *net = sock_net(sk);
	struct net_device *dev;
    struct in_device *in_dev;
	__be32 default_local_addr = 0;
	rcu_read_lock();
	for_each_netdev_rcu(net, dev) {
        // 检查设备是否处于UP状态
        if (!(dev->flags & IFF_UP))
            continue;
        // 获取设备的IPv4地址信息
        in_dev = __in_dev_get_rcu(dev);
        if (!in_dev)
            continue;
		default_local_addr = in_dev->ifa_list->ifa_local;
		break;
	}
	rcu_read_unlock();

	if (!inet->inet_saddr)
		inet->inet_saddr = default_local_addr;
	sk_rcv_saddr_set(sk, inet->inet_saddr);

	struct tcp_sock *tp = tcp_sk(sk);
	// if (tp->rx_opt.ts_recent_stamp && inet->inet_daddr != daddr) {
		/* Reset inherited state */
	// 	tp->rx_opt.ts_recent	   = 0;
	// 	tp->rx_opt.ts_recent_stamp = 0;
	// 	if (likely(!tp->repair))
	// 		WRITE_ONCE(tp->write_seq, 0);
	// }

	l4pp_sk(sk)->flpp.rmtaddr = usin->addr;
	struct ippp_addr *local_addr = &(l4pp_sk(sk)->flpp.locaddr);
	memset(local_addr, 0, sizeof(struct ippp_addr));
    local_addr->base = 0;
    local_addr->len = 0;
    local_addr->type = 1;
    local_addr->addr[0] = default_local_addr;
	inet->inet_dport = usin->port;
	sk_daddr_set(sk, leafAddr(&daddr));

	inet_csk(sk)->icsk_ext_hdr_len = 0;
	// if (inet_opt)
	// 	inet_csk(sk)->icsk_ext_hdr_len = inet_opt->opt.optlen;

	// tp->rx_opt.mss_clamp = TCP_MSS_DEFAULT;

	tcp_set_state(sk, TCP_SYN_SENT);
	struct inet_timewait_death_row *tcp_death_row = &sock_net(sk)->ipv4.tcp_death_row;
	err = inet_hash_connect(tcp_death_row, sk);
	if (err)
		goto failure;

	sk_set_txhash(sk);

	rt = ippp_route_newports(flpp, rt, orig_sport, orig_dport,
			       inet->inet_sport, inet->inet_dport, sk);

	if (IS_ERR(rt)) {
		err = PTR_ERR(rt);
		rt = NULL;
		goto failure;
	}
	/* OK, now commit destination to socket.  */
	sk->sk_gso_type = SKB_GSO_TCPV4;
	sk_setup_caps(sk, &rt->dst);
	rt = NULL;

	if (likely(!tp->repair)) {
		if (!tp->write_seq)
			WRITE_ONCE(tp->write_seq,
				   secure_tcp_seq(inet->inet_saddr,
						  inet->inet_daddr,
						  inet->inet_sport,
						  usin->port));
		tp->tsoffset = _secure_tcp_ts_off(sock_net(sk),
						 inet->inet_saddr,
						 inet->inet_daddr);
	}

	atomic_set(&inet->inet_id, get_random_u16());

	if (tcp_fastopen_defer_connect(sk, &err))
		return err;
	if (err)
		goto failure;

	err = tcp_connect(sk);
	if (err)
		goto failure;
	DEBUG_LOG("%d", module_refcount(THIS_MODULE));
	return 0;

failure:
	tcp_set_state(sk, TCP_CLOSE);
	ip_rt_put(rt);
	sk->sk_route_caps = 0;
	inet->inet_dport = 0;
	return err;
}

static void tcp_pp_mtu_reduced(struct sock *sk) {

	if ((1 << sk->sk_state) & (TCPF_LISTEN | TCPF_CLOSE))
		return;

	u32 mtu = READ_ONCE(tcp_sk(sk)->mtu_info);

	if (tcp_mtu_to_mss(sk, mtu) >= tcp_sk(sk)->mss_cache)
		return;

	// struct dst_entry *dst = inet_csk_update_pmtu(sk, mtu);
	// if (!dst)
	// 	return;

	// if (inet_csk(sk)->icsk_pmtu_cookie > dst_mtu(dst)) {
	// 	tcp_sync_mss(sk, dst_mtu(dst));
	// 	tcp_simple_retransmit(sk);
	// }
}

static int tcp_pp_err(struct sk_buff *skb, __be32 info) {

	const struct ippphdr *ippph = (const struct ippphdr *)skb->data;
	struct tcphdr *th = (struct tcphdr *)(skb->data + hdr_len(ippph));
	struct net *net = dev_net_rcu(skb->dev);
	const int type = icmp_hdr(skb)->type;
	const int code = icmp_hdr(skb)->code;
	int err;

	struct ippp_addr daddr, saddr;
	getAddrFromSkb(skb, &daddr, &saddr, 0);

	struct sock *sk = __inetpp_lookup_established(net, &daddr, th->dest,
										  &saddr, ntohs(th->source), inet_iif(skb), 0);
	if (!sk) {
		__ICMP_INC_STATS(net, ICMP_MIB_INERRORS);
		return -ENOENT;
	}
	if (sk->sk_state == TCP_TIME_WAIT) {
		/* To increase the counter of ignored icmps for TCP-AO */
		tcp_ao_ignore_icmp(sk, AF_INET, type, code);
		inet_twsk_put(inet_twsk(sk));
		return 0;
	}
	u32 seq = ntohl(th->seq);
	if (sk->sk_state == TCP_NEW_SYN_RECV) {
		tcp_req_err(sk, seq, type == ICMP_PARAMETERPROB ||
				     type == ICMP_TIME_EXCEEDED ||
				     (type == ICMP_DEST_UNREACH &&
				      (code == ICMP_NET_UNREACH ||
				       code == ICMP_HOST_UNREACH)));
		return 0;
	}

	if (tcp_ao_ignore_icmp(sk, AF_INET, type, code)) {
		sock_put(sk);
		return 0;
	}

	bh_lock_sock(sk);
	if (sock_owned_by_user(sk)) {
		if (!(type == ICMP_DEST_UNREACH && code == ICMP_FRAG_NEEDED))
			__NET_INC_STATS(net, LINUX_MIB_LOCKDROPPEDICMPS);
	}
	if (sk->sk_state == TCP_CLOSE)
		goto out;

	// if (static_branch_unlikely(&ip4_min_ttl)) {
	// 	/* min_ttl can be changed concurrently from do_ip_setsockopt() */
	// 	if (unlikely(iph->ttl < READ_ONCE(inet_sk(sk)->min_ttl))) {
	// 		__NET_INC_STATS(net, LINUX_MIB_TCPMINTTLDROP);
	// 		goto out;
	// 	}
	// }

	struct tcp_sock *tp = tcp_sk(sk);
	/* XXX (TFO) - tp->snd_una should be ISN (tcp_create_openreq_child() */
	struct request_sock *fastopen = rcu_dereference(tp->fastopen_rsk);
	u32 snd_una = fastopen ? tcp_rsk(fastopen)->snt_isn : tp->snd_una;
	if (sk->sk_state != TCP_LISTEN &&
	    !between(seq, snd_una, tp->snd_nxt)) {
		__NET_INC_STATS(net, LINUX_MIB_OUTOFWINDOWICMPS);
		goto out;
	}

	switch (type) {
	case ICMP_REDIRECT:
		if (!sock_owned_by_user(sk))
			// do_redirect(skb, sk);
		goto out;
	case ICMP_SOURCE_QUENCH:
		/* Just silently ignore these. */
		goto out;
	case ICMP_PARAMETERPROB:
		err = EPROTO;
		break;
	case ICMP_DEST_UNREACH:
		if (code > NR_ICMP_UNREACH)
			goto out;

		if (code == ICMP_FRAG_NEEDED) { /* PMTU discovery (RFC1191) */
			/* We are not interested in TCP_LISTEN and open_requests
			 * (SYN-ACKs send out by Linux are always <576bytes so
			 * they should go through unfragmented).
			 */
			if (sk->sk_state == TCP_LISTEN)
				goto out;

			WRITE_ONCE(tp->mtu_info, info);
			if (!sock_owned_by_user(sk)) {
				tcp_v4_mtu_reduced(sk);
			} else {
				if (!test_and_set_bit(TCP_MTU_REDUCED_DEFERRED, &sk->sk_tsq_flags))
					sock_hold(sk);
			}
			goto out;
		}

		err = icmp_err_convert[code].errno;
		/* check if this ICMP message allows revert of backoff.
		 * (see RFC 6069)
		 */
		if (!fastopen &&
		    (code == ICMP_NET_UNREACH || code == ICMP_HOST_UNREACH))
			tcp_ld_RTO_revert(sk, seq);
		break;
	case ICMP_TIME_EXCEEDED:
		err = EHOSTUNREACH;
		break;
	default:
		goto out;
	}

	switch (sk->sk_state) {
	case TCP_SYN_SENT:
	case TCP_SYN_RECV:
		/* Only in fast or simultaneous open. If a fast open socket is
		 * already accepted it is treated as a connected one below.
		 */
		if (fastopen && !fastopen->sk)
			break;

		ip_icmp_error(sk, skb, err, th->dest, info, (u8 *)th);

		if (!sock_owned_by_user(sk))
			tcp_done_with_error(sk, err);
		else
			WRITE_ONCE(sk->sk_err_soft, err);
		goto out;
	}

	if (!sock_owned_by_user(sk) && inet_test_bit(RECVERR, sk)) {
		WRITE_ONCE(sk->sk_err, err);
		sk_error_report(sk);
	} else {
		WRITE_ONCE(sk->sk_err_soft, err);
	}
out:
	bh_unlock_sock(sk);
	sock_put(sk);
	return 0;
}

static int tcp_pp_send_synack(const struct sock *sk, struct dst_entry *dst,
			      struct flowi *fl,
			      struct request_sock *req,
			      struct tcp_fastopen_cookie *foc,
			      enum tcp_synack_type synack_type,
			      struct sk_buff *syn_skb) {

	struct flowipp flpp;
	int err = -1;

	/* First, grab a route. */
	if (!dst && (dst = inetpp_csk_route_req(sk, &flpp, (struct tcp_pp_request_sock *)req)) == NULL)
		return -1;

	struct sk_buff *skb = tcp_make_synack(sk, dst, req, foc, synack_type, syn_skb);

	if (skb) {
		const struct inet_request_sock *ireq = inet_rsk(req);
		__tcp_pp_send_check(skb, ireq->ir_loc_addr, ireq->ir_rmt_addr);

		u8 tos;

		rcu_read_lock();
		struct tcp_pp_request_sock *treqpp = (struct tcp_pp_request_sock *)req;
		struct ippp_addr *daddrpp = &(treqpp->flpp.rmtaddr);
		struct ippp_addr *saddrpp = &(treqpp->flpp.locaddr);
		err = ippp_xmit((struct sock *)sk, skb, skb_rtable(skb), tos, daddrpp, saddrpp, false);
		rcu_read_unlock();
		err = net_xmit_eval(err);
	}

	return err;
}

static void tcp_pp_reqsk_destructor(struct request_sock *req) {
	kfree(rcu_dereference_protected(inet_rsk(req)->ireq_opt, 1));
}

#ifdef CONFIG_TCP_MD5SIG
static struct tcp_md5sig_key *tcp_pp_md5_do_lookup(const struct sock *sk,
						   const struct ippp_addr *addr,
						   int l3index) {
	return tcp_md5_do_lookup(sk, l3index,
				 (union tcp_md5_addr *)addr, AF_INETPP);
}

static struct tcp_md5sig_key *tcp_pp_md5_lookup(const struct sock *sk,
						const struct sock *addr_sk) {
	int l3index;

	l3index = l3mdev_master_ifindex_by_index(sock_net(sk),
						 addr_sk->sk_bound_dev_if);
	return tcp_pp_md5_do_lookup(sk, &(((struct l4pp_sock *)addr_sk)->flpp.locaddr),
				    l3index);
}

static int tcp_pp_parse_md5_keys(struct sock *sk, int optname,
				 sockptr_t optval, int optlen) {
	struct tcp_md5sig cmd;
	struct sockaddr_in *sin = (struct sockaddr_in *)&cmd.tcpm_addr;
	const union tcp_md5_addr *addr;
	u8 prefixlen = 32;
	int l3index = 0;
	u8 flags;

	if (optlen < sizeof(cmd))
		return -EINVAL;

	if (copy_from_sockptr(&cmd, optval, sizeof(cmd)))
		return -EFAULT;

	if (sin->sin_family != AF_INET)
		return -EINVAL;

	flags = cmd.tcpm_flags & TCP_MD5SIG_FLAG_IFINDEX;

	if (optname == TCP_MD5SIG_EXT &&
	    cmd.tcpm_flags & TCP_MD5SIG_FLAG_PREFIX) {
		prefixlen = cmd.tcpm_prefixlen;
		if (prefixlen > 32)
			return -EINVAL;
	}

	if (optname == TCP_MD5SIG_EXT && cmd.tcpm_ifindex &&
	    cmd.tcpm_flags & TCP_MD5SIG_FLAG_IFINDEX) {
		struct net_device *dev;

		rcu_read_lock();
		dev = dev_get_by_index_rcu(sock_net(sk), cmd.tcpm_ifindex);
		if (dev && netif_is_l3_master(dev))
			l3index = dev->ifindex;

		rcu_read_unlock();

		/* ok to reference set/not set outside of rcu;
		 * right now device MUST be an L3 master
		 */
		if (!dev || !l3index)
			return -EINVAL;
	}

	addr = (union tcp_md5_addr *)&sin->sin_addr.s_addr;

	if (!cmd.tcpm_keylen)
		return tcp_md5_do_del(sk, addr, AF_INET, prefixlen, l3index, flags);

	if (cmd.tcpm_keylen > TCP_MD5SIG_MAXKEYLEN)
		return -EINVAL;

	return tcp_md5_do_add(sk, addr, AF_INET, prefixlen, l3index, flags,
			      cmd.tcpm_key, cmd.tcpm_keylen/* , GFP_KERNEL */);
}

static int tcp_pp_md5_hash_headers(struct tcp_sigpool *hp,
				   __be32 daddr, __be32 saddr,
				   const struct tcphdr *th, int nbytes) {
	struct tcp4_pseudohdr *bp;
	struct scatterlist sg;
	struct tcphdr *_th;

	bp = hp->scratch;
	bp->saddr = saddr;
	bp->daddr = daddr;
	bp->pad = 0;
	bp->protocol = IPPROTO_TCP;
	bp->len = cpu_to_be16(nbytes);

	_th = (struct tcphdr *)(bp + 1);
	memcpy(_th, th, sizeof(*th));
	_th->check = 0;

	sg_init_one(&sg, bp, sizeof(*bp) + sizeof(*th));
	ahash_request_set_crypt(hp->req, &sg, NULL,
				sizeof(*bp) + sizeof(*th));
	return crypto_ahash_update(hp->req);
	
}

static int __attribute__((unused)) tcp_pp_md5_hash_hdr(char *md5_hash, const struct tcp_md5sig_key *key,
			       __be32 daddr, __be32 saddr, const struct tcphdr *th) {
	struct tcp_sigpool hp;

	if (tcp_sigpool_start(tcp_md5_sigpool_id, &hp))
		goto clear_hash_nostart;

	if (crypto_ahash_init(hp.req))
		goto clear_hash;
	if (tcp_pp_md5_hash_headers(&hp, daddr, saddr, th, th->doff << 2))
		goto clear_hash;
	if (tcp_md5_hash_key(&hp, key))
		goto clear_hash;
	ahash_request_set_crypt(hp.req, NULL, md5_hash, 0);
	if (crypto_ahash_final(hp.req))
		goto clear_hash;

	tcp_sigpool_end(&hp);
	return 0;

clear_hash:
	tcp_sigpool_end(&hp);
clear_hash_nostart:
	memset(md5_hash, 0, 16);
	return 1;

}

static int tcp_pp_md5_hash_skb(char *md5_hash,
			       const struct tcp_md5sig_key *key,
			       const struct sock *sk,
			       const struct sk_buff *skb) {

	return 0;

}

#endif

static void tcp_pp_init_req(struct tcp_pp_request_sock *treqpp,
			    const struct sock *sk_listener,
			    struct sk_buff *skb) {
	const struct ippphdr *iph = ippp_hdr(skb);

	struct request_sock *req = (struct request_sock *)treqpp;
	struct inet_request_sock *ireq = inet_rsk(req);
	ireq->ir_loc_addr = iph->addr[iph->dst_len];
    ireq->ir_rmt_addr = iph->addr[iph->dst_len + iph->src_len + 1];

	treqpp->flpp.locaddr = l4pp_sk(sk_listener)->flpp.locaddr;
	struct ippp_addr *rmtaddrpp;
	rmtaddrpp = &(treqpp->flpp.rmtaddr);
	rmtaddrpp->type = iph->src_type;
	rmtaddrpp->base = iph->src_base;
	rmtaddrpp->len  = iph->src_len;
	for(int i = 0; i <= iph->src_len; i++){
		rmtaddrpp->addr[i] = iph->addr[iph->dst_len + 1 + i];
	}

	struct net *net = sock_net(sk_listener);
	RCU_INIT_POINTER(ireq->ireq_opt, tcp_pp_save_options(net, skb));
}

static struct dst_entry *tcp_pp_route_req(const struct sock *sk,
					  struct sk_buff *skb,
					  struct flowi *fl,
					  struct request_sock *req,
					  u32 tw_isn) {
	struct tcp_pp_request_sock *treqpp = (struct tcp_pp_request_sock *)req;
	tcp_pp_init_req(treqpp, sk, skb);

	if (security_inet_conn_request(sk, skb, req))
		return NULL;

	struct net *net = sock_net(sk);
	struct flowipp flpp;
	flpp.fl4 = fl->u.ip4;
	flpp.locaddr = treqpp->flpp.locaddr;
	flpp.rmtaddr = treqpp->flpp.rmtaddr;
	flpp.fl4.saddr = leafAddr(&(flpp.locaddr));
	flpp.un = ((struct if_*)findNode(if_global_list.head, __ip_dev_find(net, flpp.fl4.saddr, true)->name, 1))->un;
	return inetpp_csk_route_req(sk, &flpp, treqpp);
}

struct request_sock_ops tcppp_request_sock_ops __read_mostly = {
	.family		=	PF_INETPP,
	.obj_size	=	sizeof(struct tcp_pp_request_sock),
	.send_ack	=	tcp_pp_reqsk_send_ack,
	.destructor	=	tcp_pp_reqsk_destructor,
	.send_reset	=	tcp_pp_send_reset,
	.syn_ack_timeout =	tcp_syn_ack_timeout,
};

const struct tcp_request_sock_ops tcp_request_sock_ippp_ops = {
	.mss_clamp	=	TCP_MSS_DEFAULT,
#ifdef CONFIG_TCP_MD5SIG
	.req_md5_lookup	=	tcp_pp_md5_lookup,
	.calc_md5_hash	=	tcp_pp_md5_hash_skb,
#endif
#ifdef CONFIG_TCP_AO
	.ao_lookup	=	tcp_pp_ao_lookup_rsk,
	.ao_calc_key	=	tcp_pp_ao_calc_key_rsk,
	.ao_synack_hash	=	tcp_pp_ao_synack_hash,
#endif
#ifdef CONFIG_SYN_COOKIES
	.cookie_init_seq =	cookie_pp_init_sequence,
#endif
	.route_req	=	tcp_pp_route_req,
	.init_seq	=	tcp_pp_init_seq,
	.init_ts_off	=	tcp_pp_init_ts_off,
	.send_synack	=	tcp_pp_send_synack,
};

static void tcp_pp_send_response(const struct sock *sk, struct sk_buff *skb, u32 seq,
				u32 ack, u32 win, u32 tsval, u32 tsecr,
				int oif, int rst, u8 tclass, __be32 label,
				u32 priority, u32 txhash, struct tcp_key *key) {
	struct net *net = sk ? sock_net(sk) : skb_dst_dev_net_rcu(skb);
	unsigned int tot_len = sizeof(struct tcphdr);
	const struct tcphdr *th = tcp_hdr(skb);
	__be32 mrst = 0, *topt;
	struct sk_buff *buff;
	struct tcphdr *t1;
	struct inet_timewait_sock *inet = (struct inet_timewait_sock *)sk;
	int tos = inet->tw_tos;
	// struct ip_options_rcu *inet_opt;
	struct rtable *rt;
	struct tcp_pp_timewait_sock *tcp_pp_twskk = (struct tcp_pp_timewait_sock *)sk;
	struct ippp_addr *daddrpp = &(tcp_pp_twskk->flpp.rmtaddr);
	struct ippp_addr *saddrpp = &(tcp_pp_twskk->flpp.locaddr);

	if (tsecr)
		tot_len += TCPOLEN_TSTAMP_ALIGNED;
	if (tcp_key_is_md5(key))
		tot_len += TCPOLEN_MD5SIG_ALIGNED;
	if (tcp_key_is_ao(key))
		tot_len += tcp_ao_len_aligned(key->ao_key);

#ifdef CONFIG_MPTCP
	// if (rst && !key) {
	// 	mrst = mptcp_reset_option(skb);

	// 	if (mrst)
	// 		tot_len += sizeof(__be32);
	// }
#endif

	__u8 hdrlen4B, hdrlen;

	hdrlen4B = daddrpp->len + saddrpp->len + 2;
	for(int i = 0; i < 5; i++){
		if(hdrlen4B <= 2<<i){
			hdrlen = i;
			break;
		}
	}
	buff = alloc_skb(8 + (8 << hdrlen) + MAX_TCP_HEADER, GFP_ATOMIC);
	if (!buff)
		return;

	skb_reserve(buff,  8 + (8 << hdrlen) + MAX_TCP_HEADER);

	t1 = skb_push(buff, tot_len);
	skb_reset_transport_header(buff);

	/* Swap the send and the receive. */
	memset(t1, 0, sizeof(*t1));
	t1->dest = th->source;
	t1->source = th->dest;
	t1->doff = tot_len / 4;
	t1->seq = htonl(seq);
	t1->ack_seq = htonl(ack);
	t1->ack = !rst || !th->ack;
	t1->rst = rst;
	t1->window = htons(win);

	topt = (__be32 *)(t1 + 1);

	if (tsecr) {
		*topt++ = htonl((TCPOPT_NOP << 24) | (TCPOPT_NOP << 16) |
				(TCPOPT_TIMESTAMP << 8) | TCPOLEN_TIMESTAMP);
		*topt++ = htonl(tsval);
		*topt++ = htonl(tsecr);
	}

	if (mrst)
		*topt++ = mrst;

	#ifdef CONFIG_TCP_MD5SIG
	if (key) {
	// 	*topt++ = htonl((TCPOPT_NOP << 24) | (TCPOPT_NOP << 16) |
	// 			(TCPOPT_MD5SIG << 8) | TCPOLEN_MD5SIG);
		// tcp_pp_md5_hash_hdr((__u8 *)topt, key,
		// 		    &ippp_hdr(skb)->saddr,
		// 		    &ippp_hdr(skb)->daddr, t1);
	}
#endif
#ifdef CONFIG_TCP_AO
	// if (tcp_key_is_ao(key)) {
	// *topt++ = htonl((TCPOPT_AO << 24) |
	//    (tcp_ao_len(key->ao_key) << 16) |
	//    (key->ao_key->sndid << 8) |
	//    (key->rcv_next));

	// tcp_ao_hash_hdr(AF_INET6, (char *)topt, key->ao_key,
	//    key->traffic_key,
	//    (union tcp_ao_addr *)&ipv6_hdr(skb)->saddr,
	//    (union tcp_ao_addr *)&ipv6_hdr(skb)->daddr,
	//    t1, key->sne);
	// }
#endif

	buff->ip_summed = CHECKSUM_PARTIAL;
	__tcp_pp_send_check(buff, inet->tw_rcv_saddr, inet->tw_daddr);
	rcu_read_lock();
	// inet_opt = rcu_dereference(inet->inet_opt);
	rt = skb_rtable(buff);
	if (!rt) {
		/* Make sure we can route this packet. */
		rt = (struct rtable *)__sk_dst_check((struct sock *)sk, 0);
		if (!rt) {
			__be32 daddr = inet->tw_daddr;

			// if (inet_opt && inet_opt->opt.srr)
			// 	daddr = inet_opt->opt.faddr;

			/* If this fails, retransmit mechanism of transport layer will
			* keep trying until route appears or the connection times
			* itself out.
			*/
			struct flowi4 fl4;
			rt = ippp_route_output_ports(net, &fl4, (struct sock *)sk,
						daddr, inet->tw_rcv_saddr,
						inet->tw_dport,
						inet->tw_sport,
						IPPROTO_TCP,
						ip_sock_rt_tos(sk),
						sk->sk_bound_dev_if);
			// if (IS_ERR(rt))
			// 	goto no_route;
			sk_setup_caps((struct sock *)sk, &rt->dst);
		}
		skb_dst_set_noref(buff, &rt->dst);
	}

	ippp_xmit((struct sock *)sk, buff, rt, tos, daddrpp, saddrpp, true);
	rcu_read_unlock();printk(KERN_NOTICE"tcp_pp_send_response -- %d\n", module_refcount(THIS_MODULE));
	/* 模块引用计数错乱，导致无法remove模块。详细情况还未理清楚，暂时先强行修正。
	Module reference count is corrupted, making it impossible to remove the module. 
	The details are not yet clear; a forced fix is applied temporarily. */
	module_put(THIS_MODULE);module_put(THIS_MODULE);
}

#define REPLY_OPTIONS_LEN      (MAX_TCP_OPTION_SPACE / sizeof(__be32))

static void tcp_pp_send_reset(const struct sock *sk, struct sk_buff *skb, enum sk_rst_reason reason) {
	const struct tcphdr *th = tcp_hdr(skb);
	struct ippphdr *ippph = ippp_hdr(skb);
	const __u8 *md5_hash_location = NULL;
#if defined(CONFIG_TCP_MD5SIG) || defined(CONFIG_TCP_AO)
	bool allocated_traffic_key = false;
#endif
	const struct tcp_ao_hdr *aoh;
	struct tcp_key key = {};
	u32 seq = 0, ack_seq = 0;
	u32 priority = 0;
	struct net *net;
	u32 txhash = 0;
	int oif = 0;
#ifdef CONFIG_TCP_MD5SIG
	// unsigned char newhash[16];
	// int genhash;
	struct sock *sk1 = NULL;
#endif

	if (th->rst)
		return;

	/* If sk not NULL, it means we did a successful lookup and incoming
	 * route had to be correct. prequeue might have dropped our dst.
	 */
	if (!sk && skb_rtable(skb)->rt_type != RTN_LOCAL)
		return;

	net = sk ? sock_net(sk) : skb_dst_dev_net_rcu(skb);
	/* Invalid TCP option size or twice included auth */
	if (tcp_parse_auth_options(th, &md5_hash_location, &aoh))
		return;
#if defined(CONFIG_TCP_MD5SIG) || defined(CONFIG_TCP_AO)
	rcu_read_lock();
#endif
#ifdef CONFIG_TCP_MD5SIG
	if (sk && sk_fullsock(sk)) {
		int l3index;

		/* sdif set, means packet ingressed via a device
		 * in an L3 domain and inet_iif is set to it.
		 */
		struct net_device *dev;
		dev = dev_get_by_index_rcu(sock_net(sk), 0);
		if (dev && netif_is_l3_master(dev))
			l3index = dev->ifindex;
		// key.md5_key = tcp_pp_md5_do_lookup(sk, &ipv6h->saddr, l3index);
		// if (key.md5_key)
		// 	key.type = TCP_KEY_MD5;
	} else if (md5_hash_location) {
		// int dif = tcp_v6_iif_l3_slave(skb);
		// int sdif = tcp_v6_sdif(skb);
		// int l3index;

		/*
		 * active side is lost. Try to find listening socket through
		 * source port, and then find md5 key through listening socket.
		 * we are not loose security here:
		 * Incoming packet is checked with md5 hash with finding key,
		 * no RST generated if md5 hash doesn't match.
		 */
		// sk1 = inet6_lookup_listener(net, NULL, 0, &ipv6h->saddr, th->source,
		// 			    &ipv6h->daddr, ntohs(th->source),
		// 			    dif, sdif);
		if (!sk1)
			goto out;

		/* sdif set, means packet ingressed via a device
		 * in an L3 domain and dif is set to it.
		 */
		// l3index = tcp_v6_sdif(skb) ? dif : 0;

		// key.md5_key = tcp_v6_md5_do_lookup(sk1, &ipv6h->saddr, l3index);
		// if (!key.md5_key)
		// 	goto out;
		// key.type = TCP_KEY_MD5;

		// genhash = tcp_v6_md5_hash_skb(newhash, key.md5_key, NULL, skb);
		// if (genhash || memcmp(md5_hash_location, newhash, 16) != 0)
		// 	goto out;
	}
#endif

	if (th->ack)
		seq = ntohl(th->ack_seq);
	else
		ack_seq = ntohl(th->seq) + th->syn + th->fin + skb->len -
			  (th->doff << 2);

#ifdef CONFIG_TCP_AO
	if (aoh) {
		int l3index;

		// l3index = tcp_v6_sdif(skb) ? tcp_v6_iif_l3_slave(skb) : 0;
		// if (tcp_ao_prepare_reset(sk, skb, aoh, l3index, seq,
		// 			 &key.ao_key, &key.traffic_key,
		// 			 &allocated_traffic_key,
		// 			 &key.rcv_next, &key.sne))
			goto out;
		key.type = TCP_KEY_AO;
	}
#endif

	if (sk) {
		oif = sk->sk_bound_dev_if;
		if (sk_fullsock(sk)) {
			priority = READ_ONCE(sk->sk_priority);
			txhash = sk->sk_txhash;
		}
		if (sk->sk_state == TCP_TIME_WAIT) {
			priority = inet_twsk(sk)->tw_priority;
			txhash = inet_twsk(sk)->tw_txhash;
		}
	}

	trace_tcp_send_reset(sk, skb, reason);

	tcp_pp_send_response(sk, skb, seq, ack_seq, 0, 0, 0, oif, 1,
				ippph->tos & ~INET_ECN_MASK,
				0, priority, txhash,
				&key);

#if defined(CONFIG_TCP_MD5SIG) || defined(CONFIG_TCP_AO)
out:
	if (allocated_traffic_key)
		kfree(key.traffic_key);
	rcu_read_unlock();
#endif
}

static void tcp_pp_send_ack(const struct sock *sk, struct sk_buff *skb, u32 seq,
			    u32 ack, u32 win, u32 tsval, u32 tsecr, int oif,
			    struct tcp_key *key, u8 tclass,
			    __be32 label, u32 priority, u32 txhash) {
	tcp_pp_send_response(sk, skb, seq, ack, win, tsval, tsecr, oif, 0,
			     tclass, label, priority, txhash, key);
}

static void tcp_pp_timewait_ack(struct sock *sk, struct sk_buff *skb, enum tcp_tw_status tw_status) {
	struct inet_timewait_sock *tw = inet_twsk(sk);
	struct tcp_timewait_sock *tcptw = tcp_twsk(sk);
	u8 tclass = tw->tw_tclass;
	struct tcp_key key = {};

	if (tw_status == TCP_TW_ACK_OOW)
		tclass &= ~INET_ECN_MASK;

	tcp_pp_send_ack(sk, skb, tcptw->tw_snd_nxt,
		READ_ONCE(tcptw->tw_rcv_nxt),
		tcptw->tw_rcv_wnd >> tw->tw_rcv_wscale,
		tcp_tw_tsval(tcptw),
		READ_ONCE(tcptw->tw_ts_recent), tw->tw_bound_dev_if,
		&key, tclass, cpu_to_be32(tw->tw_flowlabel),
		tw->tw_priority, tw->tw_txhash);

	inet_twsk_put(tw);
}

static void tcp_pp_reqsk_send_ack(const struct sock *sk, struct sk_buff *skb, struct request_sock *req) {

}

static struct sock *tcp_pp_cookie_check(struct sock *sk, struct sk_buff *skb) {
#ifdef CONFIG_SYN_COOKIES
	const struct tcphdr *th = tcp_hdr(skb);

	if (!th->syn)
		sk = cookie_pp_check(sk, skb);
#endif
	return sk;
}

static int tcp_pp_conn_request(struct sock *sk, struct sk_buff *skb) {
	// 因未执行ininput_noref，skb_rtable未初始化
	/* Never answer to SYNs send to broadcast or multicast */
	if (skb_rtable(skb) && skb_rtable(skb)->rt_flags & (RTCF_BROADCAST | RTCF_MULTICAST))
		goto drop;

	return tcp_conn_request(&tcppp_request_sock_ops,
				&tcp_request_sock_ippp_ops, sk, skb);

drop:
	tcp_listendrop(sk);
	return 0;
}

static void tcp_pp_restore_cb(struct sk_buff *skb) {
	memmove(IPCB(skb), &TCP_SKB_CB(skb)->header.h4, sizeof(struct inet_skb_parm));
}

static struct sock *tcp_pp_syn_recv_sock(const struct sock *sk, struct sk_buff *skb,
				  struct request_sock *req,
				  struct dst_entry *dst,
				  struct request_sock *req_unhash,
				  bool *own_req) {
	struct inet_request_sock *ireq;
	struct tcp_pp_request_sock *treqpp = (struct tcp_pp_request_sock *)req;
	bool found_dup_sk = false;
	struct inet_sock *newinet;
	struct tcp_sock *newtp;
	struct l4pp_sock *newl4ppsk;
	struct sock *newsk;
#ifdef CONFIG_TCP_MD5SIG
	const union tcp_md5_addr *addr;
	struct tcp_md5sig_key *key;
	int l3index;
#endif
	struct ip_options_rcu *inet_opt;

	if (sk_acceptq_is_full(sk))
		goto exit_overflow;

	newsk = tcp_create_openreq_child(sk, req, skb);
	if (!newsk)
		goto exit_nonewsk;

	newsk->sk_gso_type = SKB_GSO_TCPV4;
	inet_sk_rx_dst_set(newsk, skb);

	newtp		      = tcp_sk(newsk);
	newinet		      = inet_sk(newsk);
	newl4ppsk         = l4pp_sk(newsk);
	ireq		      = inet_rsk(req);
	sk_daddr_set(newsk, ireq->ir_rmt_addr);
	sk_rcv_saddr_set(newsk, ireq->ir_loc_addr);
	newl4ppsk->flpp.locaddr = treqpp->flpp.locaddr;
	newl4ppsk->flpp.rmtaddr = treqpp->flpp.rmtaddr;
	newsk->sk_bound_dev_if = ireq->ir_iif;
	newinet->inet_saddr   = ireq->ir_loc_addr;
	inet_opt	      = rcu_dereference(ireq->ireq_opt);
	RCU_INIT_POINTER(newinet->inet_opt, inet_opt);
	newinet->mc_index     = inet_iif(skb);
	newinet->mc_ttl	      = ip_hdr(skb)->ttl;
	newinet->rcv_tos      = ip_hdr(skb)->tos;
	inet_csk(newsk)->icsk_ext_hdr_len = 0;
	if (inet_opt)
		inet_csk(newsk)->icsk_ext_hdr_len = inet_opt->opt.optlen;
	atomic_set(&newinet->inet_id, get_random_u16());

	if (READ_ONCE(sock_net(sk)->ipv4.sysctl_tcp_reflect_tos))
		newinet->tos = tcp_rsk(req)->syn_tos & ~INET_ECN_MASK;

	if (!dst) {
		dst = inetpp_csk_route_child_sock(sk, newsk, req);
		if (!dst)
			goto put_and_exit;
	} else {
		/* syncookie case : see end of cookie_v4_check() */
	}
	sk_setup_caps(newsk, dst);

	tcp_ca_openreq_child(newsk, dst);

	tcp_sync_mss(newsk, dst_mtu(dst));
	newtp->advmss = tcp_mss_clamp(tcp_sk(sk), dst_metric_advmss(dst));

	tcp_initialize_rcv_mss(newsk);

#ifdef CONFIG_TCP_MD5SIG
	l3index = l3mdev_master_ifindex_by_index(sock_net(sk), ireq->ir_iif);
	/* Copy over the MD5 key from the original socket */
	addr = (union tcp_md5_addr *)&newinet->inet_daddr;
	key = tcp_md5_do_lookup(sk, l3index, addr, AF_INET);
	if (key && !tcp_rsk_used_ao(req)) {
		if (tcp_md5_key_copy(newsk, addr, AF_INET, 32, l3index, key))
		goto put_and_exit;
		sk_gso_disable(newsk);
	}
#endif
#ifdef CONFIG_TCP_AO

#endif

	if (__inet_inherit_port(sk, newsk) < 0)
		goto put_and_exit;
	*own_req = inet_ehash_nolisten(newsk, req_to_sk(req_unhash),
				       &found_dup_sk);
	if (likely(*own_req)) {
		tcp_move_syn(newtp, req);
		ireq->ireq_opt = NULL;
	} else {
		newinet->inet_opt = NULL;

		if (!req_unhash && found_dup_sk) {
			bh_unlock_sock(newsk);
			sock_put(newsk);
			newsk = NULL;
		}
	}
	return newsk;

exit_overflow:
	NET_INC_STATS(sock_net(sk), LINUX_MIB_LISTENOVERFLOWS);
exit_nonewsk:
	dst_release(dst);
exit:
	tcp_listendrop(sk);
	return NULL;
put_and_exit:
	newinet->inet_opt = NULL;
	inet_csk_prepare_forced_close(newsk);
	tcp_done(newsk);
	goto exit;
}

static int tcp_pp_rcv_state_process(struct sock *sk, struct sk_buff *skb) {
	int res = tcp_rcv_state_process(sk, skb);
	if(sk->sk_state == TCP_FIN_WAIT1) {
		struct net *net = sock_net(sk);
		struct ippp_addr rmtaddr = l4pp_sk(sk)->flpp.rmtaddr;
		struct ippp_addr locaddr = l4pp_sk(sk)->flpp.locaddr;
		__be16 dport = inet_sk(sk)->inet_dport;
		__be16 sport = inet_sk(sk)->inet_sport;
		int dif = inet_iif(skb);
		int sdif = inet_sdif(skb);
		struct tcp_pp_timewait_sock *tcp_pp_twsk = 
		(struct tcp_pp_timewait_sock *)__inetpp_lookup_established(net,
			&rmtaddr, dport, &locaddr, ntohs(sport), dif, sdif);
		if(tcp_pp_twsk != NULL) {
			tcp_pp_twsk->flpp.locaddr = locaddr;
			tcp_pp_twsk->flpp.rmtaddr = rmtaddr;
		}
	}		
	return res;
}

static int tcp_pp_do_rcv(struct sock *sk, struct sk_buff *skb) {
	enum skb_drop_reason reason;
	struct sock *rsk;

	reason = psp_sk_rx_policy_check(sk, skb);
	if (reason)
		goto err_discard;

	if (sk->sk_state == TCP_ESTABLISHED) { /* Fast path */
		struct dst_entry *dst;

		dst = rcu_dereference_protected(sk->sk_rx_dst,
						lockdep_sock_is_held(sk));

		sock_rps_save_rxhash(sk, skb);
		sk_mark_napi_id(sk, skb);
		if (dst) {
			if (sk->sk_rx_dst_ifindex != skb->skb_iif ||
			    !INDIRECT_CALL_1(dst->ops->check, ipv4_dst_check,
					     dst, 0)) {
				RCU_INIT_POINTER(sk->sk_rx_dst, NULL);
				dst_release(dst);
			}
		}
		tcp_rcv_established(sk, skb);
		return 0;
	}

	if (tcp_checksum_complete(skb))
		goto csum_err;

	if (sk->sk_state == TCP_LISTEN) {
		struct sock *nsk = tcp_pp_cookie_check(sk, skb);

		if (!nsk)
			return 0;
		if (nsk != sk) {
			reason = tcp_child_process(sk, nsk, skb);
			if (reason) {
				rsk = nsk;
				goto reset;
			}
			return 0;
		}
	} else
		sock_rps_save_rxhash(sk, skb);

	reason = tcp_pp_rcv_state_process(sk, skb);
	if (reason) {
		rsk = sk;
		goto reset;
	}
	return 0;

reset:
	tcp_pp_send_reset(rsk, skb, sk_rst_convert_drop_reason(reason));
discard:
	sk_skb_reason_drop(sk, skb, reason);
	return 0;

csum_err:
	reason = SKB_DROP_REASON_TCP_CSUM;
	trace_tcp_bad_csum(skb);
	TCP_INC_STATS(sock_net(sk), TCP_MIB_CSUMERRORS);
err_discard:
	TCP_INC_STATS(sock_net(sk), TCP_MIB_INERRS);
	goto discard;
}

static void tcp_pp_fill_cb(struct sk_buff *skb, const struct ippphdr *iph,
			   const struct tcphdr *th) {
	memmove(&TCP_SKB_CB(skb)->header.h4, IPCB(skb),
		sizeof(struct inet_skb_parm));
	barrier();

	TCP_SKB_CB(skb)->seq = ntohl(th->seq);
	TCP_SKB_CB(skb)->end_seq = (TCP_SKB_CB(skb)->seq + th->syn + th->fin +
				    skb->len - th->doff * 4);
	TCP_SKB_CB(skb)->ack_seq = ntohl(th->ack_seq);
	TCP_SKB_CB(skb)->tcp_flags = tcp_flags_ntohs(th);
	TCP_SKB_CB(skb)->ip_dsfield = iph->tos;
	TCP_SKB_CB(skb)->sacked	 = 0;
	TCP_SKB_CB(skb)->has_rxtstamp =
			skb->tstamp || skb_hwtstamps(skb)->hwtstamp;
}

int tcp_pp_rcv(struct sk_buff *skb) {
	struct net *net = dev_net_rcu(skb->dev);
	enum skb_drop_reason drop_reason;
	int sdif = inet_sdif(skb);
	int dif = inet_iif(skb);
	const struct ippphdr *iph;
	const struct tcphdr *th;
	bool refcounted;
	struct sock *sk;
	int ret;
	u32 isn;

	drop_reason = SKB_DROP_REASON_NOT_SPECIFIED;
	if (skb->pkt_type != PACKET_HOST)
		goto discard_it;

	/* Count it even if it's bad */
	__TCP_INC_STATS(net, TCP_MIB_INSEGS);

	if (!pskb_may_pull(skb, sizeof(struct tcphdr)))
		goto discard_it;

	th = (const struct tcphdr *)skb->data;

	if (unlikely(th->doff < sizeof(struct tcphdr) / 4)) {
		drop_reason = SKB_DROP_REASON_PKT_TOO_SMALL;
		goto bad_packet;
	}
	if (!pskb_may_pull(skb, th->doff * 4))
		goto discard_it;

	if (skb_checksum_init(skb, IPPROTO_TCP, inetpp_compute_pseudo))
		goto csum_error;

	th = (const struct tcphdr *)skb->data;
	iph = ippp_hdr(skb);

	lookup:
	sk = __inetpp_lookup_skb(skb, __tcp_hdrlen(th), th->source, th->dest, dif, sdif, &refcounted);
	if (!sk)
		goto no_tcp_socket;

	if (sk->sk_state == TCP_TIME_WAIT)
		goto do_time_wait;

	if (sk->sk_state == TCP_NEW_SYN_RECV) {
		struct request_sock *req = inet_reqsk(sk);
		bool req_stolen = false;
		struct sock *nsk;

		sk = req->rsk_listener;

		if (tcp_checksum_complete(skb)) {
			reqsk_put(req);
			goto csum_error;
		}
		if (unlikely(sk->sk_state != TCP_LISTEN)) {
			nsk = reuseport_migrate_sock(sk, req_to_sk(req), skb);
			if (!nsk) {
				inet_csk_reqsk_queue_drop_and_put(sk, req);
				goto lookup;
			}
			sk = nsk;
		} else {
			sock_hold(sk);
		}
		refcounted = true;
		nsk = NULL;
		if (!tcp_filter(sk, skb, &drop_reason)) {
			th = (const struct tcphdr *)skb->data;
			iph = ippp_hdr(skb);
			tcp_pp_fill_cb(skb, iph, th);
			nsk = tcp_check_req(sk, skb, req, false, &req_stolen, &drop_reason);
			/* 模块引用计数错乱，导致无法remove模块。详细情况还未理清楚，暂时先强行修正。 */
			module_put(THIS_MODULE);
		}
		if (!nsk) {
			reqsk_put(req);
			if (req_stolen) {
				tcp_pp_restore_cb(skb);
				sock_put(sk);
				goto lookup;
			}
			goto discard_and_relse;
		}
		nf_reset_ct(skb);
		if (nsk == sk) {
			reqsk_put(req);
			tcp_pp_restore_cb(skb);
		} else {
            drop_reason = tcp_child_process(sk, nsk, skb);
			if (drop_reason) {
				tcp_pp_send_reset(nsk, skb, sk_rst_convert_drop_reason(drop_reason));
				goto discard_and_relse;
			}
			sock_put(sk);
			return 0;
		}
	}

process:

    nf_reset_ct(skb);

    if (tcp_filter(sk, skb, &drop_reason))
        goto discard_and_relse;

	th = (const struct tcphdr *)skb->data;
	iph = ippp_hdr(skb);
	tcp_pp_fill_cb(skb, iph, th);

	skb->dev = NULL;

	if (sk->sk_state == TCP_LISTEN) {
		ret = tcp_pp_do_rcv(sk, skb);
		goto put_and_return;
	}

	sk_incoming_cpu_update(sk);

	bh_lock_sock_nested(sk);
	tcp_segs_in(tcp_sk(sk), skb);
	ret = 0;
	if (!sock_owned_by_user(sk)) {
		ret = tcp_pp_do_rcv(sk, skb);
	} else {
		if (tcp_add_backlog(sk, skb, &drop_reason))
			goto discard_and_relse;
	}
	bh_unlock_sock(sk);
put_and_return:
	if (refcounted)
		sock_put(sk);
	return ret ? -1 : 0;

no_tcp_socket:
	drop_reason = SKB_DROP_REASON_NO_SOCKET;
	if (!xfrm4_policy_check(NULL, XFRM_POLICY_IN, skb))
		goto discard_it;

	tcp_pp_fill_cb(skb, iph, th);

	if (tcp_checksum_complete(skb)) {
csum_error:
	drop_reason = SKB_DROP_REASON_TCP_CSUM;
	trace_tcp_bad_csum(skb);
		__TCP_INC_STATS(net, TCP_MIB_CSUMERRORS);
bad_packet:
		__TCP_INC_STATS(net, TCP_MIB_INERRS);
	} else {
		tcp_pp_send_reset(NULL, skb, sk_rst_convert_drop_reason(drop_reason));
	}

discard_it:
	SKB_DR_OR(drop_reason, NOT_SPECIFIED);
	sk_skb_reason_drop(sk, skb, drop_reason);
	return 0;

discard_and_relse:
	sk_drops_skbadd(sk, skb);
	if (refcounted)
		sock_put(sk);
	goto discard_it;

do_time_wait:
	if (!xfrm4_policy_check(NULL, XFRM_POLICY_IN, skb)) {
		drop_reason = SKB_DROP_REASON_XFRM_POLICY;
		inet_twsk_put(inet_twsk(sk));
		goto discard_it;
	}

	tcp_pp_fill_cb(skb, iph, th);

	if (tcp_checksum_complete(skb)) {
		inet_twsk_put(inet_twsk(sk));
		goto csum_error;
	}
	enum tcp_tw_status tw_status = tcp_timewait_state_process(inet_twsk(sk), skb, th, &isn, &drop_reason);
	switch (tw_status) {
	case TCP_TW_SYN: {
		struct sock *sk2 = NULL/* inet_lookup_listener(net, skb, __tcp_hdrlen(th),
		&ipv6_hdr(skb)->saddr, th->source,
		&ipv6_hdr(skb)->daddr,
		ntohs(th->dest),
		tcp_v6_iif_l3_slave(skb),
		sdif) */;
		if (sk2) {
			inet_twsk_deschedule_put(inet_twsk(sk));
			sk = sk2;
			tcp_pp_restore_cb(skb);
			refcounted = false;
			__this_cpu_write(tcp_tw_isn, isn);
			goto process;
		}

		drop_reason = psp_twsk_rx_policy_check(inet_twsk(sk), skb);
		if (drop_reason)
			break;
	}
		/* to ACK */
		fallthrough;
	case TCP_TW_ACK:
	case TCP_TW_ACK_OOW:
		tcp_pp_timewait_ack(sk, skb, tw_status);
		break;
	case TCP_TW_RST:
		tcp_pp_send_reset(sk, skb, SK_RST_REASON_TCP_TIMEWAIT_SOCKET);
		inet_twsk_deschedule_put(inet_twsk(sk));
		goto discard_it;
	case TCP_TW_SUCCESS:;
	}
	goto discard_it;
}

void tcppp_early_demux(struct sk_buff *skb) {

	if (skb->pkt_type != PACKET_HOST)
		return;

	if (!pskb_may_pull(skb, skb_transport_offset(skb) + sizeof(struct tcphdr)))
		return;

	const struct tcphdr *th = tcp_hdr(skb);
	if (th->doff < sizeof(struct tcphdr) / 4)
		return;

	struct net *net = dev_net(skb->dev);
	struct ippp_addr daddr, saddr;
	getAddrFromSkb(skb, &daddr, &saddr, 0);
	struct sock *sk = __inetpp_lookup_established(net, &saddr, th->source,
		&daddr, ntohs(th->dest), skb->skb_iif, inet_sdif(skb));
	if (sk) {
		skb->sk = sk;
		skb->destructor = sock_edemux;
		if (sk_fullsock(sk)) {
			struct dst_entry *dst = rcu_dereference(sk->sk_rx_dst);

			if (dst)
				dst = dst_check(dst, 0);
			if (dst && sk->sk_rx_dst_ifindex == skb->skb_iif)
				skb_dst_set_noref(skb, dst);
		}
	}
}

static struct timewait_sock_ops tcppp_timewait_sock_ops = {
	.twsk_obj_size	= sizeof(struct tcp_pp_timewait_sock),
};

static void tcp_pp_send_check(struct sock *sk, struct sk_buff *skb) {
	const struct inet_sock *inet = inet_sk(sk);

	__tcp_pp_send_check(skb, inet->inet_saddr, inet->inet_daddr);
}

const struct inet_connection_sock_af_ops ippp_specific = {
	.queue_xmit			 = ippp_queue_xmit,
	.send_check			 = tcp_pp_send_check,
	.rebuild_header		 = inetpp_sk_rebuild_header,
	.sk_rx_dst_set		 = inetpp_sk_rx_dst_set,
	.conn_request		 = tcp_pp_conn_request,
	.syn_recv_sock		 = tcp_pp_syn_recv_sock,
	.net_header_len		 = sizeof(struct ippphdr),
	.setsockopt          = ippp_setsockopt,
	.getsockopt          = ippp_getsockopt,
	.mtu_reduced		 = tcp_pp_mtu_reduced,
};

#if defined(CONFIG_TCP_MD5SIG) || defined(CONFIG_TCP_AO)
static const struct tcp_sock_af_ops tcp_sock_ippp_specific = {
#ifdef CONFIG_TCP_MD5SIG
	.md5_lookup		= tcp_pp_md5_lookup,
	.calc_md5_hash	= tcp_pp_md5_hash_skb,
	.md5_parse		= tcp_pp_parse_md5_keys,
#endif
#ifdef CONFIG_TCP_AO
	.ao_lookup	=	tcp_pp_ao_lookup,
	.calc_ao_hash	=	tcp_pp_ao_hash_skb,
	.ao_parse	=	tcp_pp_parse_ao,
	.ao_calc_key_sk	=	tcp_pp_ao_calc_key_sk,
#endif
};
#endif

/*
 *	TCP over IPv4 via INETPP API
 */
static const struct inet_connection_sock_af_ops ippp_mapped = {
	.queue_xmit        = ip_queue_xmit,
	.send_check        = tcp_v4_send_check,
	.rebuild_header	   = inet_sk_rebuild_header,
	.sk_rx_dst_set	   = inet_sk_rx_dst_set,
	.conn_request	   = tcp_pp_conn_request,
	.syn_recv_sock	   = tcp_pp_syn_recv_sock,
	.net_header_len	   = sizeof(struct iphdr),
	.setsockopt        = ippp_setsockopt,
	.getsockopt        = ippp_getsockopt,
	.mtu_reduced	   = tcp_v4_mtu_reduced,
};

#if defined(CONFIG_TCP_MD5SIG) || defined(CONFIG_TCP_AO)
static const struct tcp_sock_af_ops tcp_sock_ippp_mapped_specific = {
#ifdef CONFIG_TCP_MD5SIG
	.md5_lookup	=	tcp_v4_md5_lookup,
	.calc_md5_hash	=	tcp_v4_md5_hash_skb,
	.md5_parse	=	tcp_pp_parse_md5_keys,
#endif
#ifdef CONFIG_TCP_AO
	.ao_lookup	=	tcp_pp_ao_lookup,
	.calc_ao_hash	=	tcp_v4_ao_hash_skb,
	.ao_parse	=	tcp_pp_parse_ao,
	.ao_calc_key_sk	=	tcp_v4_ao_calc_key_sk,
#endif
};

static void tcppp_destruct_sock(struct sock *sk) {
	tcp_md5_destruct_sock(sk);
	tcp_ao_destroy_sock(sk, false);
	inetpp_sock_destruct(sk);
}
#endif

static int tcp_pp_init_sock(struct sock *sk) {
	struct inet_connection_sock *icsk = inet_csk(sk);

	tcp_init_sock(sk);

	icsk->icsk_af_ops = &ippp_specific;

#if defined(CONFIG_TCP_MD5SIG) || defined(CONFIG_TCP_AO)
	tcp_sk(sk)->af_specific = &tcp_sock_ippp_specific;
	sk->sk_destruct = tcppp_destruct_sock;
#endif

	return 0;
}

#ifdef CONFIG_PROC_FS
/* Proc filesystem TCPpp sock list dumping. */
static void get_openreqpp(struct seq_file *seq,
			 const struct request_sock *req, int i) {
	long ttd = req->rsk_timer.expires - jiffies;
	if (ttd < 0)
		ttd = 0;

	seq_printf(seq,
		   "%4d: :%04X :%04X "
		   "%02X %08X:%08X %02X:%08lX %08X %8d %d %d %pK\n",
		   i,
		   inet_rsk(req)->ir_num,
		   ntohs(inet_rsk(req)->ir_rmt_port),
		   TCP_SYN_RECV,
		   0, 0, /* could print option size, but that is af dependent. */
		   1,   /* timers active (only the expire timer) */
		   jiffies_to_clock_t(ttd),
		   req->num_timeout,
		   0,  /* non standard timer */
		   0, /* open_requests have no inode */
		   0, req);
}

static void get_tcppp_sock(struct seq_file *seq, struct sock *sp, int i) {
	__u16 destp, srcp;
	int timer_active;
	const struct inet_sock *inet = inet_sk(sp);
	const struct tcp_sock *tp = tcp_sk(sp);
	const struct inet_connection_sock *icsk = inet_csk(sp);
	const struct fastopen_queue *fastopenq = &icsk->icsk_accept_queue.fastopenq;
	int rx_queue;
	int state;

	destp = ntohs(inet->inet_dport);
	srcp  = ntohs(inet->inet_sport);

	if (icsk->icsk_pending == ICSK_TIME_RETRANS ||
	    icsk->icsk_pending == ICSK_TIME_REO_TIMEOUT ||
	    icsk->icsk_pending == ICSK_TIME_LOSS_PROBE) {
		timer_active	= 1;
	} else if (icsk->icsk_pending == ICSK_TIME_PROBE0) {
		timer_active	= 4;
	} else if (timer_pending(&sp->sk_timer)) {
		timer_active	= 2;
	} else {
		timer_active	= 0;
	}

	state = inet_sk_state_load(sp);
	if (state == TCP_LISTEN)
		rx_queue = READ_ONCE(sp->sk_ack_backlog);
	else
		/* Because we don't lock the socket,
		 * we might find a transient negative value.
		 */
		rx_queue = max_t(int, READ_ONCE(tp->rcv_nxt) -
				      READ_ONCE(tp->copied_seq), 0);

	seq_printf(seq,
		   "%4d: :%04X :%04X "
		   "%02X %08X:%08X %02X %08X %8d %lu %d %pK %lu %lu %u %u %d\n",
		   i,
		   srcp,
		   destp,
		   state,
		   READ_ONCE(tp->write_seq) - tp->snd_una,
		   rx_queue,
		   timer_active,
		   icsk->icsk_retransmits,
		   icsk->icsk_probes_out,
		   sock_i_ino(sp),
		   refcount_read(&sp->sk_refcnt), sp,
		   jiffies_to_clock_t(icsk->icsk_rto),
		   jiffies_to_clock_t(icsk->icsk_ack.ato),
		   (icsk->icsk_ack.quick << 1) | inet_csk_in_pingpong_mode(sp),
		   tcp_snd_cwnd(tp),
		   state == TCP_LISTEN ?
			fastopenq->max_qlen :
			(tcp_in_initial_slowstart(tp) ? -1 : tp->snd_ssthresh)
		   );
}

static void get_timewaitpp_sock(struct seq_file *seq,
			       struct inet_timewait_sock *tw, int i) {
	long delta = tw->tw_timer.expires - jiffies;
	__u16 destp, srcp;

	destp = ntohs(tw->tw_dport);
	srcp  = ntohs(tw->tw_sport);

	seq_printf(seq,
		   "%4d: %04X :%04X "
		   "%02X %08X:%08X %02X:%08lX %08X %5d %8d %d %d %pK\n",
		   i,
		   srcp,
		   destp,
		   tw->tw_substate, 0, 0,
		   3, jiffies_delta_to_clock_t(delta), 0, 0, 0, 0,
		   refcount_read(&tw->tw_refcnt), tw);
}

static int tcppp_seq_show(struct seq_file *seq, void *v) {
	struct tcp_iter_state *st;
	struct sock *sk = v;

	if (v == SEQ_START_TOKEN) {
		seq_puts(seq,
			 "  sl  "
			 "local_address                         "
			 "remote_address                        "
			 "st tx_queue rx_queue tr tm->when retrnsmt"
			 "   uid  timeout inode\n");
		goto out;
	}
	st = seq->private;

	if (sk->sk_state == TCP_TIME_WAIT)
		get_timewaitpp_sock(seq, v, st->num);
	else if (sk->sk_state == TCP_NEW_SYN_RECV)
		get_openreqpp(seq, v, st->num);
	else
		get_tcppp_sock(seq, v, st->num);
out:
	return 0;
}

static const struct seq_operations tcppp_seq_ops = {
	.show		= tcppp_seq_show,
	.start		= tcp_seq_start,
	.next		= tcp_seq_next,
	.stop		= tcp_seq_stop,
};

static struct tcp_seq_afinfo tcppp_seq_afinfo = {
	.family		= AF_INETPP,
};

int __net_init tcppp_proc_init(struct net *net) {
	if (!proc_create_net_data("tcppp", 0444, net->proc_net, &tcppp_seq_ops,
			sizeof(struct tcp_iter_state), &tcppp_seq_afinfo))
		return -ENOMEM;
	return 0;
}

void tcppp_proc_exit(struct net *net) {
	remove_proc_entry("tcppp", net->proc_net);
}
#endif

struct proto tcppp_prot = {
	.name					= "TCPPP",
	.owner					= THIS_MODULE,
	.close					= tcp_close,
	.pre_connect			= tcp_pp_pre_connect,
	.connect				= tcp_pp_connect,
	.disconnect				= tcp_disconnect,
	.accept					= inet_csk_accept,
	.ioctl					= tcp_ioctl,
	.init					= tcp_pp_init_sock,
	.destroy				= tcp_v4_destroy_sock,
	.shutdown				= tcp_shutdown,
	.setsockopt				= tcp_setsockopt,
	.getsockopt				= tcp_getsockopt,
	.bpf_bypass_getsockopt	= tcp_bpf_bypass_getsockopt,
	.keepalive				= tcp_set_keepalive,
	.recvmsg				= tcp_recvmsg,
	.sendmsg				= tcp_sendmsg,
	.splice_eof				= tcp_splice_eof,
	.backlog_rcv			= tcp_pp_do_rcv,
	.release_cb				= tcp_release_cb,
	.hash					= inet_hash,
	.unhash					= inet_unhash,
	.get_port				= inet_csk_get_port,
	.put_port				= inet_put_port,
#ifdef CONFIG_BPF_SYSCALL
	.psock_update_sk_prot	= tcp_bpf_update_proto,
#endif
	.enter_memory_pressure	= tcp_enter_memory_pressure,
	.leave_memory_pressure	= tcp_leave_memory_pressure,
	.stream_memory_free		= tcp_stream_memory_free,
	.sockets_allocated		= &tcp_sockets_allocated,

	.memory_allocated		= &net_aligned_data.tcp_memory_allocated,
	.per_cpu_fw_alloc		= &tcp_memory_per_cpu_fw_alloc,

	.memory_pressure		= &tcp_memory_pressure,
	.sysctl_mem				= sysctl_tcp_mem,
	.sysctl_wmem_offset		= offsetof(struct net, ipv4.sysctl_tcp_wmem),
	.sysctl_rmem_offset		= offsetof(struct net, ipv4.sysctl_tcp_rmem),
	.max_header				= MAX_TCP_HEADER,
	.obj_size				= sizeof(struct l4pp_sock),
	.slab_flags				= SLAB_TYPESAFE_BY_RCU,
	.twsk_prot				= &tcppp_timewait_sock_ops,
	.rsk_prot				= &tcppp_request_sock_ops,
	.h.hashinfo				= NULL,
	.no_autobind			= true,
	.diag_destroy			= tcp_abort,
};
EXPORT_SYMBOL_GPL(tcppp_prot);

static struct net_protocol tcppp_protocol = {
	.handler		=	tcp_pp_rcv,
	.err_handler	=	tcp_pp_err,
	.no_policy		=	1,
};

static struct inet_protosw tcppp_protosw = {
	.type		= SOCK_STREAM,
	.protocol	= IPPROTO_TCP,
	.prot		= &tcppp_prot,
	.ops		= &inetpp_stream_ops,
	.flags		= INET_PROTOSW_PERMANENT | INET_PROTOSW_ICSK
};

static int __net_init tcppp_net_init(struct net *net) {
	return 0;
}

static void __net_exit tcppp_net_exit(struct net *net) {

}

static struct pernet_operations tcppp_net_ops = {
	.init	    = tcppp_net_init,
	.exit	    = tcppp_net_exit,
};

int __init tcppp_init(void) {
	int cpu, res;

	for_each_possible_cpu(cpu) {
		struct sock *sk;

		res = inet_ctl_sock_create(&sk, PF_INET, SOCK_RAW,
					   IPPROTO_TCP, &init_net);
		if (res)
			panic("Failed to create the TCP control socket.\n");
		sock_set_flag(sk, SOCK_USE_WRITE_QUEUE);

		inet_sk(sk)->pmtudisc = IP_PMTUDISC_DO;

		sk->sk_clockid = CLOCK_MONOTONIC;

		per_cpu(ippp_tcp_sk.sock, cpu) = sk;
	}

	int ret = inetpp_add_protocol(&tcppp_protocol, IPPROTO_TCP);
	if (ret)
		goto out;

	ret = inetpp_register_protosw(&tcppp_protosw);
	if (ret)
		goto out_tcp_pp_protocol;

	ret = register_pernet_subsys(&tcppp_net_ops);
	if (ret)
		goto out_tcp_pp_protosw;

out:
	return ret;

out_tcp_pp_protosw:
	inetpp_unregister_protosw(&tcppp_protosw);
out_tcp_pp_protocol:
	inetpp_del_protocol(&tcppp_protocol, IPPROTO_TCP);
	goto out;
}

void tcppp_exit(void) {
	unregister_pernet_subsys(&tcppp_net_ops);
	inetpp_unregister_protosw(&tcppp_protosw);
	inetpp_del_protocol(&tcppp_protocol, IPPROTO_TCP);
}