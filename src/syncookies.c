#include <linux/tcp.h>
#include <linux/random.h>
#include <linux/siphash.h>
#include <linux/kernel.h>
#include <net/secure_seq.h>
#include <net/ipv6.h>
#include <net/tcp.h>
#include "ipppk.h"

__u32 cookie_pp_init_sequence(const struct sk_buff *skb, __u16 *mssp) {
	const struct iphdr *iph = ip_hdr(skb);
	const struct tcphdr *th = tcp_hdr(skb);

	return __cookie_v4_init_sequence(iph, th, mssp);
}

/* On input, sk is a listener.
 * Output is listener if incoming packet would not create a child
 *           NULL if memory could not be allocated.
 */
struct sock *cookie_pp_check(struct sock *sk, struct sk_buff *skb) {
	struct ip_options *opt = &TCP_SKB_CB(skb)->header.h4.opt;
	struct tcp_options_received tcp_opt;
	struct inet_request_sock *ireq;
	struct net *net = sock_net(sk);
	struct tcp_request_sock *treq;
	struct tcp_sock *tp = tcp_sk(sk);
	const struct tcphdr *th = tcp_hdr(skb);
	__u32 cookie = ntohl(th->ack_seq) - 1;
	struct sock *ret = sk;
	struct request_sock *req;
	int full_space, mss;
	struct rtable *rt;
	__u8 rcv_wscale;
	struct flowi4 fl4;
	u32 tsoff = 0;

	if (!READ_ONCE(net->ipv4.sysctl_tcp_syncookies) ||
		!th->ack || th->rst)
		goto out;

	if (tcp_synq_no_recent_overflow(sk))
		goto out;

	mss = __cookie_v4_check(ip_hdr(skb), th/* , cookie */);
	if (mss == 0) {
		__NET_INC_STATS(sock_net(sk), LINUX_MIB_SYNCOOKIESFAILED);
		goto out;
	}

	__NET_INC_STATS(sock_net(sk), LINUX_MIB_SYNCOOKIESRECV);

	/* check for timestamp cookie support */
	memset(&tcp_opt, 0, sizeof(tcp_opt));
	tcp_parse_options(sock_net(sk), skb, &tcp_opt, 0, NULL);

	if (tcp_opt.saw_tstamp && tcp_opt.rcv_tsecr) {
		tsoff = _secure_tcp_ts_off(sock_net(sk),
					ip_hdr(skb)->daddr,
					ip_hdr(skb)->saddr);
		tcp_opt.rcv_tsecr -= tsoff;
	}

	if (!cookie_timestamp_decode(sock_net(sk), &tcp_opt))
		goto out;

	ret = NULL;
	req = cookie_tcp_reqsk_alloc(&tcppp_request_sock_ops, sk, skb, &tcp_opt, mss, tsoff);
	if (!req)
		goto out;

	ireq = inet_rsk(req);
	treq = tcp_rsk(req);
	treq->rcv_isn		= ntohl(th->seq) - 1;
	treq->snt_isn		= cookie;
	treq->ts_off		= 0;
	treq->txhash		= net_tx_rndhash();
	req->mss		= mss;
	ireq->ir_num		= ntohs(th->dest);
	ireq->ir_rmt_port	= th->source;
	sk_rcv_saddr_set(req_to_sk(req), ip_hdr(skb)->daddr);
	sk_daddr_set(req_to_sk(req), ip_hdr(skb)->saddr);
	ireq->ir_mark		= inet_request_mark(sk, skb);
	ireq->snd_wscale	= tcp_opt.snd_wscale;
	ireq->sack_ok		= tcp_opt.sack_ok;
	ireq->wscale_ok		= tcp_opt.wscale_ok;
	ireq->tstamp_ok		= tcp_opt.saw_tstamp;
	req->ts_recent		= tcp_opt.saw_tstamp ? tcp_opt.rcv_tsval : 0;
	treq->snt_synack	= 0;
	treq->tfo_listener	= false;

	if (IS_ENABLED(CONFIG_SMC))
		ireq->smc_ok = 0;

	ireq->ir_iif = inet_request_bound_dev_if(sk, skb);

	/* We throwed the options of the initial SYN away, so we hope
	* the ACK carries the same options again (see RFC1122 4.2.3.8)
	*/
	// RCU_INIT_POINTER(ireq->ireq_opt, tcp_v4_save_options(sock_net(sk), skb));

	if (security_inet_conn_request(sk, skb, req)) {
		reqsk_free(req);
		goto out;
	}

	req->num_retrans = 0;

	/*
	* We need to lookup the route here to get at the correct
	* window size. We should better make sure that the window size
	* hasn't changed since we received the original syn, but I see
	* no easy way to do this.
	*/
	flowi4_init_output(&fl4, ireq->ir_iif, ireq->ir_mark,
			ip_sock_rt_tos(sk), ip_sock_rt_scope(sk), IPPROTO_TCP,
			inet_sk_flowi_flags(sk),
			opt->srr ? opt->faddr : ireq->ir_rmt_addr,
			ireq->ir_loc_addr, th->source, th->dest, sk->sk_uid);
	security_req_classify_flow(req, flowi4_to_flowi_common(&fl4));
	rt = ippp_route_output_flow(net, (struct flowipp*)(&fl4), NULL, NULL,true);
	if (IS_ERR(rt)) {
		reqsk_free(req);
		goto out;
	}

	/* Try to redo what tcp_v4_send_synack did. */
	req->rsk_window_clamp = READ_ONCE(tp->window_clamp) ? :dst_metric(&rt->dst, RTAX_WINDOW);
	/* limit the window selection if the user enforce a smaller rx buffer */
	full_space = tcp_full_space(sk);
	if (sk->sk_userlocks & SOCK_RCVBUF_LOCK &&
		(req->rsk_window_clamp > full_space || req->rsk_window_clamp == 0))
		req->rsk_window_clamp = full_space;

	tcp_select_initial_window(sk, full_space, req->mss,
				&req->rsk_rcv_wnd, &req->rsk_window_clamp,
				ireq->wscale_ok, &rcv_wscale,
				dst_metric(&rt->dst, RTAX_INITRWND));

	ireq->rcv_wscale  = rcv_wscale;
	ireq->ecn_ok = cookie_ecn_ok(sock_net(sk), &rt->dst);

	ret = tcp_get_cookie_sock(sk, skb, req, &rt->dst);
	/* ip_queue_xmit() depends on our flow being setup
	* Normal sockets get it right from inet_csk_route_child_sock()
	*/
	if (ret)
		inet_sk(ret)->cork.fl.u.ip4 = fl4;
out:	return ret;
}