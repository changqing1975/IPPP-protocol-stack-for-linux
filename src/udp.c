/*
 *	UDP over IPPP
 *	Linux INETPP implementation
 *
 *	UDPlite is not supported
 *
 *	Authors:
 *	changqing		<cq@ippp.xyz>
 *	
 *	to-do:
 *		compute_score
 *		__udppp_lib_demux_lookup
 */

#include <linux/errno.h>
#include <linux/types.h>
#include <linux/socket.h>
#include <linux/sockios.h>
#include <linux/net.h>
#include <linux/netdevice.h>
#include <linux/if_arp.h>
#include <linux/init.h>
#include <linux/module.h>
#include <linux/skbuff.h>
#include <linux/slab.h>
#include <linux/uaccess.h>
#include <net/addrconf.h>
#include <net/ndisc.h>
#include <net/protocol.h>
#include <net/raw.h>
#include <net/tcp_states.h>
#include <net/xfrm.h>
#include <net/inet_hashtables.h>
#include <net/busy_poll.h>
#include <net/sock_reuseport.h>
#include <net/aligned_data.h>
#include <net/udp.h>
#include <net/udp_tunnel.h>
#include <net/icmp.h>
#include <linux/proc_fs.h>
#include <linux/seq_file.h>
#include <linux/inetdevice.h>
#include <trace/events/skb.h>
#include "ipppk.h"

static void udppp_destruct_sock(struct sock *sk) {
	udp_destruct_common(sk);
	inetpp_sock_destruct(sk);
}

static int udppp_init_sock(struct sock *sk) {
	int res = udp_lib_init_sock(sk);
	sk->sk_destruct = udppp_destruct_sock;
	set_bit(SOCK_SUPPORT_ZC, &sk->sk_socket->flags);
	return res;
}

static u32 udppp_ehashfn(const struct net *net, const __be32 laddr, const __u16 lport, const __be32 faddr, const __be16 fport) {
	net_get_random_once(&udp_ehash_secret, sizeof(udp_ehash_secret));

	return __inet_ehashfn(laddr, lport, faddr, fport, udp_ehash_secret + net_hash_mix(net));
}

static int udppp_get_port(struct sock *sk, unsigned short snum) {
	unsigned int hash2_nulladdr =
		ipv4_portaddr_hash(sock_net(sk), htonl(INADDR_ANY), snum);
	unsigned int hash2_partial =
		ipv4_portaddr_hash(sock_net(sk), inet_sk(sk)->inet_rcv_saddr, 0);

	/* precompute partial secondary hash */
	udp_sk(sk)->udp_portaddr_hash = hash2_partial;
	return udp_lib_get_port(sk, snum, hash2_nulladdr);
}

static void udppp_rehash(struct sock *sk) {
	u16 new_hash = ipv4_portaddr_hash(sock_net(sk),
					inet_sk(sk)->inet_rcv_saddr,
					inet_sk(sk)->inet_num);
	u16 new_hash4 = udppp_ehashfn(sock_net(sk),
					sk->sk_rcv_saddr, sk->sk_num,
					sk->sk_daddr, sk->sk_dport);
  
	udp_lib_rehash(sk, new_hash, new_hash4);
}

static int compute_score(struct sock *sk, const struct net *net,
			struct ippp_addr *saddr, __be16 sport,
			struct ippp_addr *daddr, unsigned short hnum,
			int dif, int sdif) {
	int score;

	if (!net_eq(sock_net(sk), net) ||
	udp_sk(sk)->udp_port_hash != hnum ||
	sk->sk_family != PF_INETPP)
		return -1;

	// if (!addr_equal(daddr, &(l4pp_sk(sk)->flpp.locaddr)))
	if (sk->sk_rcv_saddr != leafAddr(daddr))
		return -1;

	score = (sk->sk_family == PF_INETPP) ? 2 : 1;

	struct inet_sock *inet = inet_sk(sk);
	if (inet->inet_daddr) {
		// if (addr_equal(saddr, &(l4pp_sk(sk)->flpp.rmtaddr)))
		if (inet->inet_daddr != leafAddr(saddr))
			return -1;
		score += 4;
	}

	if (inet->inet_dport) {
		if (inet->inet_dport != sport)
			return -1;
		score += 4;
	}

	bool dev_match = udp_sk_bound_dev_eq(net, sk->sk_bound_dev_if, dif, sdif);
	if (!dev_match)
		return -1;
	if (sk->sk_bound_dev_if)
		score += 4;

	if (READ_ONCE(sk->sk_incoming_cpu) == raw_smp_processor_id())
		score++;

	return score;
}

/* called with rcu_read_lock() */
static struct sock *udppp_lib_lookup2(struct net *net,
		struct ippp_addr *saddr, __be16 sport,
		struct ippp_addr *daddr, unsigned int hnum,
		int dif, int sdif, struct udp_hslot *hslot2, struct sk_buff *skb) {
	struct sock *sk, *result;
	int score, badness;
	u32 hash = 0;

	result = NULL;
	badness = 0;
	udp_portaddr_for_each_entry_rcu(sk, &hslot2->head) {
		score = compute_score(sk, net, saddr, sport, daddr, hnum, dif, sdif);
		if (score > badness) {
			if (sk->sk_reuseport &&
			    sk->sk_state != TCP_ESTABLISHED) {
				hash = udppp_ehashfn(net, leafAddr(daddr), hnum,
										  leafAddr(saddr), sport);
				result = reuseport_select_sock(sk, hash, skb, sizeof(struct udphdr));
				if (result && !reuseport_has_conns(sk))
					return result;
			}
			badness = score;
			result = sk;
		}
	}
	return result;
}

static struct sock *__udppp_lib_lookup(struct net *net,
		struct ippp_addr *saddr, __be16 sport,
		struct ippp_addr *daddr, __be16 dport,
		int dif, int sdif, struct udp_table *udptable, struct sk_buff *skb) {
	unsigned short hnum = ntohs(dport);
	unsigned int hash2 = ipv4_portaddr_hash(net, leafAddr(daddr), hnum);
	struct udp_hslot *hslot2 =  udp_hashslot2(udptable, hash2);

	struct sock *result = udppp_lib_lookup2(net, saddr, sport, daddr, hnum, dif, sdif, hslot2, skb);
	if (!result) {
		hash2 = ipv4_portaddr_hash(net, htonl(INADDR_ANY), hnum);
		hslot2 = udp_hashslot2(udptable, hash2);
		struct ippp_addr addr_any = IPPPADDR_ANY;
		result = udppp_lib_lookup2(net, saddr, sport, &addr_any, hnum, dif, sdif, hslot2, skb);
	}
	if (IS_ERR(result))
		return NULL;
	return result;
}

static inline struct sock *__udppp_lib_lookup_skb(struct sk_buff *skb,
				__be16 sport, __be16 dport, struct udp_table *udptable) {
	struct ippp_addr daddr, saddr;
	getAddrFromSkb(skb, &daddr, &saddr, 0);
	return __udppp_lib_lookup(dev_net(skb->dev), &saddr, sport,
				&daddr, dport, inet_iif(skb), inet_sdif(skb), udptable, skb);
}

static int udppp_skb_len(struct sk_buff *skb) {
	return udp_skb_len(skb);
}

int udppp_recvmsg(struct sock *sk, struct msghdr *msg, size_t len, int flags, int *addr_len) {
	struct inet_sock *inet = inet_sk(sk);
	DECLARE_SOCKADDR(struct sockaddr_ippp *, sin, msg->msg_name);
	struct sk_buff *skb;
	unsigned int ulen, copied;
	int off, err, peeking = flags & MSG_PEEK;
	bool checksum_valid = false;

	if (flags & MSG_ERRQUEUE)
		return ippp_recv_error(sk, msg, len, addr_len);

try_again:
	off = sk_peek_offset(sk, flags);
	skb = __skb_recv_udp(sk, flags, &off, &err);
	if (!skb)
		return err;

	ulen = udppp_skb_len(skb);
	copied = len;
	if (copied > ulen - off)
		copied = ulen - off;
	else if (copied < ulen)
		msg->msg_flags |= MSG_TRUNC;

	/*
	 * If checksum is needed at all, try to do it while copying the
	 * data.  If the data is truncated, do it before the copy.
	 */

	if (copied < ulen || peeking) {
		checksum_valid = udp_skb_csum_unnecessary(skb) || !__udp_lib_checksum_complete(skb);
		if (!checksum_valid)
			goto csum_copy_err;
	}

	if (checksum_valid || udp_skb_csum_unnecessary(skb)) {
		if (udp_skb_is_linear(skb))
			err = copy_linear_skb(skb, copied, off, &msg->msg_iter);
		else
			err = skb_copy_datagram_msg(skb, off, msg, copied);
	} else {
		err = skb_copy_and_csum_datagram_msg(skb, off, msg);
		if (err == -EINVAL)
			goto csum_copy_err;
	}

	if (unlikely(err)) {
		if (!peeking) {
			udp_drops_inc(sk);
			UDP_INC_STATS(sock_net(sk), UDP_MIB_INERRORS, false);
		}
		kfree_skb(skb);
		return err;
	}

	if (!peeking)
		UDP_INC_STATS(sock_net(sk), UDP_MIB_INDATAGRAMS, false);

	sock_recv_cmsgs(msg, sk, skb);

	/* Copy the address. */
	if (sin) {
		struct ippphdr *_ippphdr;
		sin->family = AF_INETPP;
		sin->port = udp_hdr(skb)->source;
		_ippphdr = ippp_hdr(skb);
		sin->addr.type = _ippphdr->src_type;
		sin->addr.base = _ippphdr->src_base;
		sin->addr.len = _ippphdr->src_len;
		memset(sin->addr.addr, 0, 4 * 16);
		memcpy(sin->addr.addr, (unsigned char *)&_ippphdr->addr + (_ippphdr->dst_len + 1) * 4, (_ippphdr->src_len + 1) * 4);
		*addr_len = 6 + (_ippphdr->src_len + 1) * 4;
	}

	if (udp_test_bit(GRO_ENABLED, sk))
		udp_cmsg_recv(msg, sk, skb);

	if (inet_cmsg_flags(inet))
		ip_cmsg_recv_offset(msg, sk, skb, sizeof(struct udphdr), off);

	err = copied;
	if (flags & MSG_TRUNC)
		err = ulen;

	skb_consume_udp(sk, skb, peeking ? -err : err);
	return err;

csum_copy_err:
	if (!__sk_queue_drop_skb(sk, &udp_sk(sk)->reader_queue, skb, flags, udp_skb_destructor)) {
		UDP_INC_STATS(sock_net(sk), UDP_MIB_CSUMERRORS, false);
		UDP_INC_STATS(sock_net(sk), UDP_MIB_INERRORS, false);
	}
	kfree_skb_reason(skb, SKB_DROP_REASON_UDP_CSUM);

	/* starting over for a new packet, but check if we need to yield */
	cond_resched();
	msg->msg_flags &= ~MSG_TRUNC;
	goto try_again;
}

DEFINE_STATIC_KEY_FALSE(udppp_encap_needed_key);
static void __attribute__((unused)) udppp_encap_enable(void) {
	static_branch_inc(&udppp_encap_needed_key);
}

static int __udppp_lib_err_encap_no_sk(struct sk_buff *skb, u32 info) {
	int i;

	for (i = 0; i < MAX_IPTUN_ENCAP_OPS; i++) {
		const struct ip_tunnel_encap_ops *encap = rcu_dereference(iptun_encaps[i]);
		if (!encap)
			continue;
		int (*handler)(struct sk_buff *skb, u32 info);
		handler = encap->err_handler;
		if (handler && !handler(skb, info))
			return 0;
	}

	return -ENOENT;
}

static struct sock *__udppp_lib_err_encap(struct net *net,
					 const struct ippphdr *hdr,
					 struct udphdr *uh,
					 struct udp_table *udptable,
					 struct sock *sk,
					 struct sk_buff *skb, u32 info) {
	int (*lookup)(struct sock *sk, struct sk_buff *skb);
	struct udp_sock *up;

	int network_offset = skb_network_offset(skb);
	int transport_offset = skb_transport_offset(skb);

	/* Network header needs to point to the outer IPv6 header inside ICMP */
	skb_reset_network_header(skb);

	/* Transport header needs to point to the UDP header */
	skb_set_transport_header(skb, hdr_len(hdr));

	if (sk) {
		up = udp_sk(sk);

		lookup = READ_ONCE(up->encap_err_lookup);
		if (lookup && lookup(sk, skb))
			sk = NULL;

		goto out;
	}

	struct ippp_addr daddr, saddr;
	getAddrFromSkb(skb, &daddr, &saddr, 0);
	sk = __udppp_lib_lookup(net, &daddr, uh->dest, &saddr, uh->source,
			inet_iif(skb), inet_sdif(skb), dev_net(skb->dev)->ipv4.udp_table, NULL);

	if (sk) {
		up = udp_sk(sk);

		lookup = READ_ONCE(up->encap_err_lookup);
		if (!lookup || lookup(sk, skb))
			sk = NULL;
	}

out:
	if (!sk)
		sk = ERR_PTR(__udppp_lib_err_encap_no_sk(skb, info));

	skb_set_transport_header(skb, transport_offset);
	skb_set_network_header(skb, network_offset);

	return sk;
}

static int __udppp_lib_err(struct sk_buff *skb, u32 info, struct udp_table *udptable) {
	const struct ippphdr *hdr = ippp_hdr(skb);
	struct ippp_addr daddr, saddr;
	getAddrFromSkb(skb, &daddr, &saddr, 0);
	struct udphdr *uh = (struct udphdr *)(skb->data);
	bool tunnel = false;
	struct net *net = dev_net(skb->dev);

	struct sock *sk = __udppp_lib_lookup(net, &daddr, uh->dest, &saddr, uh->source,
			       inet_iif(skb), inet_sdif(skb), dev_net(skb->dev)->ipv4.udp_table, NULL);

	if (!sk || udp_sk(sk)->encap_type) {
		/* No socket for error: try tunnels before discarding */
		if (static_branch_unlikely(&udppp_encap_needed_key)) {
			sk = __udppp_lib_err_encap(net, hdr, uh,
				dev_net(skb->dev)->ipv4.udp_table, sk, skb, info);
			if (!sk)
				return 0;
		} else
			sk = ERR_PTR(-ENOENT);

		if (IS_ERR(sk)) {
			__ICMP_INC_STATS(net, ICMP_MIB_INERRORS);
			return PTR_ERR(sk);
		}

		tunnel = true;
	}

	int err = 0;
	int harderr = 0;
	const int type = icmp_hdr(skb)->type;
	const int code = icmp_hdr(skb)->code;

	switch (type) {
	default:
	case ICMP_TIME_EXCEEDED:
		err = EHOSTUNREACH;
		break;
	case ICMP_SOURCE_QUENCH:
		goto out;
	case ICMP_PARAMETERPROB:
		err = EPROTO;
		harderr = 1;
		break;
	case ICMP_DEST_UNREACH:
		if (code == ICMP_FRAG_NEEDED) {
			/* Path MTU discovery */
			// update_pmtu
			if (READ_ONCE(inet_sk(sk)->pmtudisc) != IP_PMTUDISC_DONT) {
				err = EMSGSIZE;
				harderr = 1;
				break;
			}
			goto out;
		}
		err = EHOSTUNREACH;
		if (code <= NR_ICMP_UNREACH) {
			harderr = icmp_err_convert[code].fatal;
			err = icmp_err_convert[code].errno;
		}
		break;
	case ICMP_REDIRECT:
		// redirect(skb, sk);
		goto out;
	}

	/*
	 *      RFC1122: OK.  Passes ICMP errors back to application, as per
	 *	4.1.3.3.
	 */
	if (tunnel) {
		/* ...not for tunnels though: we don't have a sending socket */
		if (udp_sk(sk)->encap_err_rcv)
			udp_sk(sk)->encap_err_rcv(sk, skb, err, uh->dest, info,
						  (u8 *)(uh+1));
		goto out;
	}
	if (!inet_test_bit(RECVERR, sk)) {
		if (!harderr || sk->sk_state != TCP_ESTABLISHED)
			goto out;
	} else {
		// icmp_error();
	}

	sk->sk_err = err;
	sk_error_report(sk);
out:
	return 0;
}

__inline__ int udppp_err(struct sk_buff *skb, u32 info) {
	return __udppp_lib_err(skb, info, dev_net(skb->dev)->ipv4.udp_table);
}

static int __udppp_queue_rcv_skb(struct sock *sk, struct sk_buff *skb) {
	int rc;

	if (inet_sk(sk)->inet_daddr) {
		sock_rps_save_rxhash(sk, skb);
		sk_mark_napi_id(sk, skb);
		sk_incoming_cpu_update(sk);
	} else {
		sk_mark_napi_id_once(sk, skb);
	}

	rc = __udp_enqueue_schedule_skb(sk, skb);
	if (rc < 0) {
		int drop_reason;

		/* Note that an ENOMEM error is charged twice */
		if (rc == -ENOMEM) {
			UDP_INC_STATS(sock_net(sk), UDP_MIB_RCVBUFERRORS, false);
			drop_reason = SKB_DROP_REASON_SOCKET_RCVBUFF;
		} else {
			UDP_INC_STATS(sock_net(sk), UDP_MIB_MEMERRORS, false);
			drop_reason = SKB_DROP_REASON_PROTO_MEM;
		}
		UDP_INC_STATS(sock_net(sk), UDP_MIB_INERRORS, false);
		sk_skb_reason_drop(sk, skb, drop_reason);
		return -1;
	}

	return 0;
}

/* returns:
 *  -1: error
 *   0: success
 *  >0: "udp encap" protocol resubmission
 *
 * Note that in the success and error cases, the skb is assumed to
 * have either been requeued or freed.
 */
static int udppp_queue_rcv_one_skb(struct sock *sk, struct sk_buff *skb) {

	udp_csum_pull_header(skb);

	return __udppp_queue_rcv_skb(sk, skb);

}

static int udppp_queue_rcv_skb(struct sock *sk, struct sk_buff *skb) {
	struct sk_buff *next, *segs;
	int ret;

	if (likely(!udp_unexpected_gso(sk, skb)))
		return udppp_queue_rcv_one_skb(sk, skb);

	BUILD_BUG_ON(sizeof(struct udp_skb_cb) > SKB_GSO_CB_OFFSET);
	__skb_push(skb, -skb_mac_offset(skb));
	segs = udp_rcv_segment(sk, skb, true);
	skb_list_walk_safe(segs, skb, next) {
		__skb_pull(skb, skb_transport_offset(skb));

		udp_post_segment_fix_csum(skb);
		ret = udppp_queue_rcv_one_skb(sk, skb);
		if (ret > 0)
			ippp_protocol_deliver_rcu(dev_net(skb->dev), skb, ret);
	}
	return 0;
}

static int __udppp_lib_mcast_deliver(struct net *net, struct sk_buff *skb,
		const __be32 saddr, const __be32 daddr,
		struct udp_table *udptable, int proto) {

			return 0;
}

static void udppp_sk_rx_dst_set(struct sock *sk, struct dst_entry *dst) {
	udp_sk_rx_dst_set(sk, dst);
}

static inline int udppp_csum_init(struct sk_buff *skb, struct udphdr *uh, int proto) {

	UDP_SKB_CB(skb)->partial_cov = 0;
	UDP_SKB_CB(skb)->cscov = skb->len;

	/* Note, we are only interested in != 0 or == 0, thus the
	* force to int.
	*/
	int err = (__force int)skb_checksum_init_zero_check(skb, proto, uh->check, inetpp_compute_pseudo);
	if (err)
		return err;

	if (skb->ip_summed == CHECKSUM_COMPLETE && !skb->csum_valid) {
		/* If SW calculated the value, we know it's bad */
		if (skb->csum_complete_sw)
			return 1;

		/* HW says the value is bad. Let's validate that.
		* skb->csum is no longer the full packet checksum,
		* so don't treat it as such.
		*/
		skb_checksum_complete_unset(skb);
	}

	return 0;
}

/* wrapper for udppp_queue_rcv_skb tacking care of csum conversion and
 * return code conversion for ip layer consumption
 */
static int udppp_unicast_rcv_skb(struct sock *sk, struct sk_buff *skb, struct udphdr *uh) {
	int ret;

	if (inet_get_convert_csum(sk) && uh->check)
		skb_checksum_try_convert(skb, IPPROTO_UDP, inetpp_compute_pseudo);

	ret = udppp_queue_rcv_skb(sk, skb);

	/* a return value > 0 means to resubmit the input, but
	 * it wants the return to be -protocol, or 0
	 */
	if (ret > 0)
		return -ret;
	return 0;
}

static int __udppp_lib_rcv(struct sk_buff *skb, struct udp_table *udptable, int proto) {
	struct udphdr *uh;
	unsigned short ulen;
	__be32 saddr, daddr;
	struct net *net = dev_net(skb->dev);
	bool refcounted;

	/*
	 *  Validate the packet.
	 */
	if (!pskb_may_pull(skb, sizeof(struct udphdr)))
		goto drop;		/* No space for header. */

	uh   = udp_hdr(skb);
	ulen = ntohs(uh->len);
	// saddr = ip_hdr(skb)->saddr;
	// daddr = ip_hdr(skb)->daddr;
	if (ulen > skb->len)
		goto short_packet;

	if (proto == IPPROTO_UDP) {
		/* UDP validates ulen. */
		if (ulen < sizeof(*uh) || pskb_trim_rcsum(skb, ulen))
			goto short_packet;
		uh = udp_hdr(skb);
	}

	if (udppp_csum_init(skb, uh, proto))
		goto csum_error;

	struct sock *sk /* = skb_steal_sock(skb, &refcounted) */;
	if (sk) {
		struct dst_entry *dst = skb_dst(skb);
		if (unlikely(sk->sk_rx_dst != dst))
			udppp_sk_rx_dst_set(sk, dst);

		int ret/*  = udp_unicast_rcv_skb(sk, skb, uh) */;
		if (refcounted)
			sock_put(sk);
		return ret;
	}

	struct rtable *rt = skb_rtable(skb);
	if (rt->rt_flags & (RTCF_BROADCAST|RTCF_MULTICAST))
		return __udppp_lib_mcast_deliver(net, skb, saddr, daddr, udptable, proto);

	sk = __udppp_lib_lookup_skb(skb, uh->source, uh->dest, udptable);
	if (sk){
		return udppp_unicast_rcv_skb(sk, skb, uh);
	}

	// if (!xfrm4_policy_check(NULL, XFRM_POLICY_IN, skb))
	// 	goto drop;
	// nf_reset_ct(skb);

	/* No socket. Drop packet silently, if checksum is wrong */
	if (udp_lib_checksum_complete(skb))
		goto csum_error;

	__UDP_INC_STATS(net, UDP_MIB_NOPORTS, false);
	// icmp_send(skb, ICMP_DEST_UNREACH, ICMP_PORT_UNREACH, 0);

	/*
	 * Hmm.  We got an UDP packet to a port to which we
	 * don't wanna listen.  Ignore it.
	 */
	kfree_skb(skb);
	return 0;

short_packet:
	net_dbg_ratelimited("UDP: short packet: From %pI4:%u %d/%d to %pI4:%u\n",
			    &saddr, ntohs(uh->source), ulen, skb->len, &daddr, ntohs(uh->dest));
	goto drop;

csum_error:
	/*
	 * RFC1122: OK.  Discards the bad packet silently (as far as
	 * the network is concerned, anyway) as per 4.1.3.4 (MUST).
	 */
	net_dbg_ratelimited("UDP: bad checksum. From %pI4:%u to %pI4:%u ulen %d\n",
			    &saddr, ntohs(uh->source), &daddr, ntohs(uh->dest), ulen);
	__UDP_INC_STATS(net, UDP_MIB_CSUMERRORS, false);
drop:
	__UDP_INC_STATS(net, UDP_MIB_INERRORS, false);
	kfree_skb(skb);
	return 0;
}

static struct sock *__udppp_lib_demux_lookup(struct net *net,
			__be16 loc_port, const struct ippp_addr *loc_addr,
			__be16 rmt_port, const struct ippp_addr *rmt_addr,
			int dif, int sdif) {

	return NULL;
}

void udppp_early_demux(struct sk_buff *skb) {
	struct net *net = dev_net(skb->dev);
	int dif = skb->dev->ifindex;
	int sdif = inet_sdif(skb);

	if (!pskb_may_pull(skb, skb_transport_offset(skb) +
	    sizeof(struct udphdr)))
		return;

	const struct udphdr *uh = udp_hdr(skb);

	struct sock *sk;
	if (skb->pkt_type == PACKET_HOST)
		sk = __udppp_lib_demux_lookup(net, uh->dest,
					     NULL,
					     uh->source,NULL,
					     dif, sdif);
	else
		return;

	if (!sk)
		return;

	skb->sk = sk;
	DEBUG_NET_WARN_ON_ONCE(sk_is_refcounted(sk));
	skb->destructor = sock_pfree;
	struct dst_entry *dst = rcu_dereference(sk->sk_rx_dst);

	if (dst)
		dst = dst_check(dst, sk->sk_rx_dst_cookie);
	if (dst) {
		/* set noref for now.
		 * any place which wants to hold dst has to call
		 * dst_hold_safe()
		 */
		skb_dst_set_noref(skb, dst);
	}
}

int udppp_rcv(struct sk_buff *skb) {
	return __udppp_lib_rcv(skb, dev_net(skb->dev)->ipv4.udp_table, IPPROTO_UDP);
}

/*
 * Throw away all pending data and cancel the corking. Socket is locked.
 */
static void udppp_flush_pending_frames(struct sock *sk) {
	struct udp_sock *up = udp_sk(sk);

	if (up->pending) {
		up->len = 0;
		WRITE_ONCE(up->pending, 0);
		ippp_flush_pending_frames(sk);
	}
}

static int udppp_pre_connect(struct sock *sk, struct sockaddr *uaddr,
			     int addr_len) {
	if (addr_len < realLen(uaddr))
		return -EINVAL;

	return 0;
}

/**
 *	udppp_hwcsum  -  handle HW checksumming
 *	@sk:	socket we are sending on
 *	@skb:	sk_buff containing the filled-in UDP header
 *		(checksum field must be zeroed out)
 *	@saddr: source address
 *	@daddr: destination address
 *	@len:	length of packet
 */
static void udppp_hwcsum(struct sock *sk, struct sk_buff *skb,
				 const __be32 saddr, const __be32 daddr, int len) {
	unsigned int offset;
	struct udphdr *uh = udp_hdr(skb);
	struct sk_buff *frags = skb_shinfo(skb)->frag_list;
	__wsum csum = 0;

	if (!frags) {
		/* Only one fragment on the socket.  */
		skb->csum_start = skb_transport_header(skb) - skb->head;
		skb->csum_offset = offsetof(struct udphdr, check);
		uh->check = ~csum_tcpudp_magic(saddr, daddr, len, IPPROTO_UDP, 0);
	} else {
		/*
		 * HW-checksum won't work as there are two or more
		 * fragments on the socket so that all csums of sk_buffs
		 * should be together
		 */
		offset = skb_transport_offset(skb);
		skb->csum = skb_checksum(skb, offset, skb->len - offset, 0);
		csum = skb->csum;

		skb->ip_summed = CHECKSUM_NONE;

		do {
			csum = csum_add(csum, frags->csum);
		} while ((frags = frags->next));

		uh->check = csum_tcpudp_magic(saddr, daddr, len, IPPROTO_UDP, csum);
		if (uh->check == 0)
			uh->check = CSUM_MANGLED_0;
	}
}

/*
 *	Sending
 */

static int udppp_send_skb(struct sk_buff *skb, struct flowipp *flpp,
			struct inet_cork *cork) {
	struct sock *sk = skb->sk;
	struct inet_sock *inet = inet_sk(sk);
	struct udphdr *uh;
	int err;
	int offset = skb_transport_offset(skb);
	int len = skb->len - offset;
	int datalen = len - sizeof(*uh);
	__wsum csum = 0;

	/*
	 * Create a UDP header
	 */
	uh = udp_hdr(skb);
	uh->source = inet->inet_sport;
	uh->dest = flpp->fl4.fl4_dport;
	uh->len = htons(len);
	uh->check = 0;

	if (cork->gso_size) {
		const int hlen = skb_network_header_len(skb) +
				 sizeof(struct udphdr);

		if (hlen + min(datalen, cork->gso_size) > cork->fragsize) {
			kfree_skb(skb);
			return -EMSGSIZE;
		}
		if (datalen > cork->gso_size * UDP_MAX_SEGMENTS) {
			kfree_skb(skb);
			return -EINVAL;
		}
		if (sk->sk_no_check_tx) {
			kfree_skb(skb);
			return -EINVAL;
		}
		if (dst_xfrm(skb_dst(skb))) {
			kfree_skb(skb);
			return -EIO;
		}

		if (datalen > cork->gso_size) {
			skb_shinfo(skb)->gso_size = cork->gso_size;
			skb_shinfo(skb)->gso_type = SKB_GSO_UDP_L4;
			skb_shinfo(skb)->gso_segs = DIV_ROUND_UP(datalen,
								 cork->gso_size);
			goto csum_partial;
		}
	}

	else if (sk->sk_no_check_tx) {			 /* UDP csum off */

		skb->ip_summed = CHECKSUM_NONE;
		goto send;

	} else if (skb->ip_summed == CHECKSUM_PARTIAL) { /* UDP hardware csum */
csum_partial:
		udppp_hwcsum(sk, skb, flpp->fl4.saddr, flpp->fl4.daddr, len);
		goto send;
	} else
		csum = udp_csum(skb);

	/* add protocol-dependent pseudo-header */
	uh->check = csum_tcpudp_magic(flpp->fl4.saddr, flpp->fl4.daddr, len,
				      sk->sk_protocol, csum);
	if (uh->check == 0)
		uh->check = CSUM_MANGLED_0;

send:
	err = ippp_send_skb(sock_net(sk), skb);
	if (err) {
		if (err == -ENOBUFS && !inet_test_bit(RECVERR, sk)) {
			UDP_INC_STATS(sock_net(sk),
				      UDP_MIB_SNDBUFERRORS, false);
			err = 0;
		}
	} else
		UDP_INC_STATS(sock_net(sk),
			      UDP_MIB_OUTDATAGRAMS, false);
	return err;
}

static int udppp_push_pending_frames(struct sock *sk) {
	struct sk_buff *skb;
	struct udp_sock  *up = udp_sk(sk);
	int err = 0;

	if (up->pending == AF_INET)
		return udp_push_pending_frames(sk);

	skb = ippp_finish_skb(sk);
	if (!skb)
		goto out;

	err = udppp_send_skb(skb, &(l4pp_sk(sk)->flpp),
			      &inet_sk(sk)->cork.base);
out:
	up->len = 0;
	WRITE_ONCE(up->pending, 0);
	return err;
}

int udppp_sendmsg(struct sock *sk, struct msghdr *msg, size_t len) {
	struct inet_sock *inet = inet_sk(sk);
	struct udp_sock *up = udp_sk(sk);
	struct flowipp flpp;
	struct flowi4 *fl4;
	int ulen = len;
	int free = 0;
	int connected = 0;
	__be32 faddr, saddr;
	int err = 0;

	if (len > 0xFFFF)
		return -EMSGSIZE;

	/*
	 *	Check the flags.
	 */

	 if (msg->msg_flags & MSG_OOB) /* Mirror BSD error message compatibility */
		return -EOPNOTSUPP;

	int (*getfrag)(void *, char *, int, int, int, struct sk_buff *);
	getfrag = ip_generic_getfrag;

	fl4 = &inet->cork.fl.u.ip4;
	if (READ_ONCE(up->pending)) {
		/*
		 * There are pending frames.
		 * The socket lock must be held while it's corked.
		 */
		lock_sock(sk);
		if (likely(up->pending)) {
			if (unlikely(up->pending != AF_INETPP)) {
				release_sock(sk);
				return -EINVAL;
			}
			goto do_append_data;
		}
		release_sock(sk);
	}
	ulen += sizeof(struct udphdr);

	/*
	 *	Get and verify the address.
	 */
	DECLARE_SOCKADDR(struct sockaddr_ippp *, usin, msg->msg_name);
	__be32 daddr;
	__be16 dport;
	if (usin) {
		if (msg->msg_namelen < 10)
			return -EINVAL;
		if (msg->msg_namelen < (6 + (usin->addr.len + 1) * 4))
			return -EINVAL;
		if (usin->family != AF_INETPP) {
			if (usin->family != AF_UNSPEC)
				return -EAFNOSUPPORT;
		}
		l4pp_sk(sk)->flpp.rmtaddr = usin->addr;
		daddr = leafAddr(&usin->addr);
		dport = usin->port;
		if (dport == 0)
			return -EINVAL;
	} else {
		if (sk->sk_state != TCP_ESTABLISHED)
			return -EDESTADDRREQ;
		daddr = inet->inet_daddr;
		dport = inet->inet_dport;
		/* Open fast path for connected socket.
		   Route will not be used, if at least one option is set.
		 */
		connected = 1;
	}

	struct ipcm_cookie ipc;
	ipcm_init_sk(&ipc, inet);
	ipc.gso_size = READ_ONCE(up->gso_size);

	if (msg->msg_controllen) {
		err = udp_cmsg_send(sk, msg, &ipc.gso_size);
		if (err > 0) {
			err = ippp_datagram_send_ctl(sock_net(sk), sk, msg, flpp, &ipc);
			connected = 0;
		}
		if (unlikely(err < 0)) {
			kfree(ipc.opt);
			return err;
		}
		if (ipc.opt)
			free = 1;
	}
	struct ip_options_data opt_copy;
	if (!ipc.opt) {
		rcu_read_lock();
		struct ip_options_rcu *inet_opt = rcu_dereference(inet->inet_opt);
		if (inet_opt) {
			memcpy(&opt_copy, inet_opt,
			       sizeof(*inet_opt) + inet_opt->opt.optlen);
			ipc.opt = &opt_copy.opt;
		}
		rcu_read_unlock();
	}

	saddr = ipc.addr;
	ipc.addr = faddr = daddr;

	u8 scope = ip_sendmsg_scope(inet, &ipc, msg);
	if (scope == RT_SCOPE_LINK)
		connected = 0;

	struct rtable *rt = NULL;
	if (connected)
		rt = (struct rtable *)sk_dst_check(sk, 0);

	if (!rt) {
		struct net *net = sock_net(sk);
		__u8 flow_flags = inet_sk_flowi_flags(sk);

		fl4 = &(flpp.fl4);
		flpp.rmtaddr = l4pp_sk(sk)->flpp.rmtaddr;
		flpp.locaddr = l4pp_sk(sk)->flpp.locaddr;
		fl4->saddr = leafAddr(&(flpp.locaddr));
		struct if_ *if__ = (struct if_*)findNode(if_global_list.head, __ip_dev_find(net, fl4->saddr, true)->name, 1);
		flpp.un = (if__)->un;
		flowi4_init_output(fl4, ipc.oif, ipc.sockc.mark, ipc.tos & INET_DSCP_MASK,
				   scope, sk->sk_protocol,
				   flow_flags, faddr, saddr, dport, inet->inet_sport, sk->sk_uid);

		security_sk_classify_flow(sk, flowi4_to_flowi_common(fl4));
		rt = ippp_route_output_flow(net, &flpp, sk, NULL, true);
		if (IS_ERR(rt)) {
			err = PTR_ERR(rt);
			rt = NULL;
			if (err == -ENETUNREACH)
				IP_INC_STATS(net, IPSTATS_MIB_OUTNOROUTES);
			goto out;
		}

		err = -EACCES;
		if (connected)
			sk_dst_set(sk, dst_clone(&rt->dst));
	}

	if (msg->msg_flags&MSG_CONFIRM) {
		if (msg->msg_flags & MSG_PROBE)
			dst_confirm_neigh(&rt->dst, &fl4->daddr);
		if ((msg->msg_flags&MSG_PROBE) && !len) {
			err = 0;
			goto out;
		}
	}

	/* Lockless fast path for the non-corking case. */
	int corkreq = udp_test_bit(CORK, sk) || msg->msg_flags&MSG_MORE;
	if (!corkreq) {
		struct inet_cork cork;

		struct sk_buff *skb = ippp_make_skb(sk, &flpp, getfrag, msg, ulen, sizeof(struct udphdr), &ipc, &rt, &cork, msg->msg_flags);
		err = PTR_ERR(skb);
		if (!IS_ERR_OR_NULL(skb))
			err = udppp_send_skb(skb, &flpp, &cork);
		goto out;
	}

	lock_sock(sk);
	if (unlikely(up->pending)) {
		/* The socket is already corked while preparing it. */
		/* ... which is an evident application bug. --ANK */
		release_sock(sk);

		net_dbg_ratelimited("socket already corked\n");
		err = -EINVAL;
		goto out;
	}
	/*
	 *	Now cork the socket to pend data.
	 */
	WRITE_ONCE(up->pending, AF_INETPP);

do_append_data:
	up->len += ulen;
	err = ippp_append_data(sk, &flpp, getfrag, msg, ulen,
			     sizeof(struct udphdr), &ipc, &rt,
			     corkreq ? msg->msg_flags|MSG_MORE : msg->msg_flags);
	if (err)
		udppp_flush_pending_frames(sk);
	else if (!corkreq)
		err = udp_push_pending_frames(sk);
	else if (unlikely(skb_queue_empty(&sk->sk_write_queue)))
		WRITE_ONCE(up->pending, 0);
	release_sock(sk);

out:
	ip_rt_put(rt);
	if (free)
		kfree(ipc.opt);
	if (!err)
		return len;
	/*
	 * ENOBUFS = no kernel mem, SOCK_NOSPACE = no sndbuf space.  Reporting
	 * ENOBUFS might not be good (it's not tunable per se), but otherwise
	 * we don't have a good statistic (IpOutDiscards but it can be too many
	 * things).  We could add another new stat but at least for now that
	 * seems like overkill.
	 */
	if (err == -ENOBUFS || test_bit(SOCK_NOSPACE, &sk->sk_socket->flags)) {
		UDP_INC_STATS(sock_net(sk), UDP_MIB_SNDBUFERRORS, false);
	}
	return err;
}
EXPORT_SYMBOL(udppp_sendmsg);

static void udppp_splice_eof(struct socket *sock) {
	struct sock *sk = sock->sk;
	struct udp_sock *up = udp_sk(sk);

	if (!READ_ONCE(up->pending) || udp_test_bit(CORK, sk))
		return;

	lock_sock(sk);
	if (up->pending && !udp_test_bit(CORK, sk))
		udppp_push_pending_frames(sk);
	release_sock(sk);
}

static void udppp_destroy_sock(struct sock *sk) {
	struct udp_sock *up = udp_sk(sk);
	lock_sock(sk);

	/* protects from races with udp_abort() */
	sock_set_flag(sk, SOCK_DEAD);
	udppp_flush_pending_frames(sk);
	release_sock(sk);

	if (static_branch_unlikely(&udppp_encap_needed_key)) {
		if (up->encap_type) {
			void (*encap_destroy)(struct sock *sk);
			encap_destroy = READ_ONCE(up->encap_destroy);
			if (encap_destroy)
				encap_destroy(sk);
		}
		if (udp_test_bit(ENCAP_ENABLED, sk)) {
			static_branch_dec(&udppp_encap_needed_key);
			udp_encap_disable();
			udp_tunnel_cleanup_gro(sk);
		}
	}
}

/*
 *	Socket option code for UDP
 */
static int udppp_setsockopt(struct sock *sk, int level, int optname, sockptr_t optval, unsigned int optlen) {
	if (level == SOL_UDP  || level == SOL_SOCKET)
		return udp_lib_setsockopt(sk, level, optname,
					  optval, optlen,
					  udp_push_pending_frames);
	return ippp_setsockopt(sk, level, optname, optval, optlen);
}

static int udppp_getsockopt(struct sock *sk, int level, int optname, char __user *optval, int __user *optlen) {
	if (level == SOL_UDP)
		return udp_lib_getsockopt(sk, level, optname, optval, optlen);
	return ippp_getsockopt(sk, level, optname, optval, optlen);
}

static struct net_protocol udppp_protocol = {
    .handler = udppp_rcv,
    .err_handler = udppp_err,
    .no_policy = 1,
};

//----------------------------------------------------------------
#ifdef CONFIG_PROC_FS
static int udppp_seq_show(struct seq_file *seq, void *v) {
	if (v == SEQ_START_TOKEN) {
		seq_puts(seq, 	"  sl  "						       \
			"local_address                         "		   \
			"remote_address                        "		   \
			"st tx_queue rx_queue tr tm->when retrnsmt"		   \
			"   uid  timeout inode ref pointer drops\n"
		);
	} else {
		int bucket = ((struct udp_iter_state *)seq->private)->bucket;
		struct inet_sock *inet = inet_sk(v);
		__u16 srcp = ntohs(inet->inet_sport);
		__u16 destp = ntohs(inet->inet_dport);
		struct sock *sp = (struct sock *)v;
		seq_printf(seq,
			"%5d: :%04X :%04X "
			"%02X %08X:%08X %02X:%08lX %08X %5u %8d %lu %d %pK %u\n",
			bucket,srcp, destp,
			sp->sk_state,
			sk_wmem_alloc_get(sp),
			udp_rqueue_get(v),
			0, 0L, 0,
			from_kuid_munged(seq_user_ns(seq), sk_uid(sp)),
			0,
			sock_i_ino(sp),
			refcount_read(&sp->sk_refcnt), sp,
			sk_drops_read(sp));
	}
	return 0;
}

const struct seq_operations udppp_seq_ops = {
	.start		= udp_seq_start,
	.next		= udp_seq_next,
	.stop		= udp_seq_stop,
	.show		= udppp_seq_show,
};

static struct udp_seq_afinfo udppp_seq_afinfo = {
	.family		= AF_INETPP,
	.udp_table	= NULL,
};

int __net_init udppp_proc_init(struct net *net) {
	if (!proc_create_net_data("udppp", 0444, net->proc_net, &udppp_seq_ops,
			sizeof(struct udp_iter_state), &udppp_seq_afinfo))
		return -ENOMEM;
	return 0;
}

void udppp_proc_exit(struct net *net) {
	remove_proc_entry("udppp", net->proc_net);
}
#endif /* CONFIG_PROC_FS */
//----------------------------------------------------------------
struct proto udppp_prot = {
	.name			= "UDPPP",
	.owner			= THIS_MODULE,
	.close			= udp_lib_close,
	.pre_connect	= udppp_pre_connect,
	.connect		= ippp_datagram_connect,
	.disconnect		= udp_disconnect,
	.ioctl			= udp_ioctl,
	.init			= udppp_init_sock,
	.destroy		= udppp_destroy_sock,
	.setsockopt		= udppp_setsockopt,
	.getsockopt		= udppp_getsockopt,
	.sendmsg		= udppp_sendmsg,
	.recvmsg		= udppp_recvmsg,
	.splice_eof		= udppp_splice_eof,
	.release_cb		= ippp_datagram_release_cb,
	.hash			= udp_lib_hash,
	.unhash			= udp_lib_unhash,
	.rehash			= udppp_rehash,
	.get_port		= udppp_get_port,
	.put_port		= udp_lib_unhash,
#ifdef CONFIG_BPF_SYSCALL
	.psock_update_sk_prot	= udp_bpf_update_proto,
#endif

	.memory_allocated	= &net_aligned_data.udp_memory_allocated,
	.per_cpu_fw_alloc	= &udp_memory_per_cpu_fw_alloc,

	.sysctl_mem		= sysctl_udp_mem,
	.sysctl_wmem_offset     = offsetof(struct net, ipv4.sysctl_udp_wmem_min),
	.sysctl_rmem_offset     = offsetof(struct net, ipv4.sysctl_udp_rmem_min),
	.obj_size		= sizeof(struct l4pp_sock),
	.h.udp_table		= NULL,
	.diag_destroy		= udp_abort,
};

static struct inet_protosw udppp_protosw = {
	.type =      SOCK_DGRAM,
	.protocol =  IPPROTO_UDP,
	.prot =      &udppp_prot,
	.ops =       &inetpp_dgram_ops,
	.flags =     INET_PROTOSW_PERMANENT,
};

int __init udppp_init(void) {
	int ret;

	ret = inetpp_add_protocol(&udppp_protocol, IPPROTO_UDP);
	if (ret)
		goto out;

	ret = inetpp_register_protosw(&udppp_protosw);
	if (ret)
		goto out_udppp_protocol;
out:
	return ret;

out_udppp_protocol:
	inetpp_del_protocol(&udppp_protocol, IPPROTO_UDP);
	goto out;
}

void udppp_exit(void) {
	inetpp_unregister_protosw(&udppp_protosw);
	inetpp_del_protocol(&udppp_protocol, IPPROTO_UDP);
}