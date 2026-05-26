#include <linux/module.h>
#include <linux/types.h>
#include <linux/kernel.h>
#include <linux/string.h>
#include <linux/errno.h>
#include <linux/slab.h>
#include <linux/net.h>
#include <linux/socket.h>
#include <linux/sockios.h>
#include <linux/in.h>
#include <linux/inet.h>
#include <linux/inetdevice.h>
#include <linux/netdevice.h>
#include <linux/etherdevice.h>
#include <net/snmp.h>
#include <linux/skbuff.h>
#include <net/arp.h>
#include <net/checksum.h>
#include <net/dst_metadata.h>
#include <linux/netfilter_ipv4.h>
#include <linux/netlink.h>
#include <linux/indirect_call_wrapper.h>
#include "ipppk.h"

void ippp_list_rcv(struct list_head *head, struct packet_type *pt, struct net_device *orig_dev) {
	struct sk_buff *skb, *next;

	list_for_each_entry_safe(skb, next, head, list) {
		skb_list_del_init(skb);
		pt->func(skb, skb->dev, pt, orig_dev);
	}
}

void ippp_protocol_deliver_rcu(struct net *net, struct sk_buff *skb, int protocol) {
	const struct net_protocol *ipprot;
	int raw = 0, ret;

resubmit:
	//raw = raw_local_deliver(skb, protocol);

	ipprot = rcu_dereference(inetpp_protos_c[protocol]);
	if (ipprot) {
		if (!ipprot->no_policy) {
			// if (!xfrm4_policy_check(NULL, XFRM_POLICY_IN, skb)) {
			// 	kfree_skb_reason(skb,
			// 			 SKB_DROP_REASON_XFRM_POLICY);
			// 	return;
			// }
			// nf_reset_ct(skb);
		}
		ret = INDIRECT_CALL_2(ipprot->handler, tcp_pp_rcv, udppp_rcv, skb);
		if (ret < 0) {
			protocol = -ret;
			goto resubmit;
		}
		__IP_INC_STATS(net, IPSTATS_MIB_INDELIVERS);
	} else {
		if (!raw) {
			// if (xfrm4_policy_check(NULL, XFRM_POLICY_IN, skb)) {
			// 	__IP_INC_STATS(net, IPSTATS_MIB_INUNKNOWNPROTOS);
			// 	icmp_send(skb, ICMP_DEST_UNREACH,
			// 		  ICMP_PROT_UNREACH, 0);
			// }
			// kfree_skb(skb);
		} else {
			// __IP_INC_STATS(net, IPSTATS_MIB_INDELIVERS);
			// consume_skb(skb);
		}
	}
}

int ippp_local_deliver_finish(struct net *net, struct sock *sk, struct sk_buff *skb)
{
	__skb_pull(skb, skb_network_header_len(skb));

	rcu_read_lock();
	ippp_protocol_deliver_rcu(net, skb, ippp_hdr(skb)->protocol);
	rcu_read_unlock();

	return 0;
}

/*
 * 	Deliver IP Packets to the higher protocol layers.
 */
int ippp_local_deliver(struct sk_buff *skb)
{
	/*
	 *	Reassemble IP fragments.
	 */
	struct net *net = dev_net(skb->dev);

	// if (ip_is_fragment(ip_hdr(skb))) {
	// 	if (ip_defrag(net, skb, IP_DEFRAG_LOCAL_DELIVER))
	// 		return 0;
	// }

	return NF_HOOK_PP(NF_INET_LOCAL_IN,
			net, NULL, skb, skb->dev, NULL,
			ippp_local_deliver_finish);
}

static void ippp_rcv_finish_core(struct net *net, struct sock *sk,
			      struct sk_buff *skb, struct net_device *dev,
			      const struct sk_buff *hint) {
	if (READ_ONCE(net->ipv4.sysctl_ip_early_demux) && !skb_dst(skb) && !skb->sk) {
		switch (ippp_hdr(skb)->protocol) {
		case IPPROTO_TCP:
			if (READ_ONCE(net->ipv4.sysctl_tcp_early_demux))
				tcppp_early_demux(skb);
			break;
		case IPPROTO_UDP:
			if (READ_ONCE(net->ipv4.sysctl_udp_early_demux))
				udppp_early_demux(skb);
			break;
		}
	}

	if (!skb_valid_dst(skb))
		ippp_route_input_noref(skb, dev);
}

int ippp_rcv_finish(struct net *net, struct sock *sk, struct sk_buff *skb)
{
	struct net_device *dev = skb->dev;

	/* if ingress device is enslaved to an L3 master device pass the
	 * skb to its handler for processing
	 */
	skb = l3mdev_ip_rcv(skb);
	if (!skb)
		return NET_RX_SUCCESS;

	ippp_rcv_finish_core(net, sk, skb, dev, NULL);

	return  dst_input(skb);
}

/*
 * 	Main IPPP Receive routine.
 */
static struct sk_buff *ippp_rcv_core(struct sk_buff *skb, struct net *net)
{
	const struct ippphdr *ippph;
	u32 len,hdrLen;

	/* When the interface is in promisc. mode, drop all the crap
	 * that it receives, do not try to analyse it.
	 */
	if (skb->pkt_type == PACKET_OTHERHOST)
		goto drop;

	__IP_UPD_PO_STATS(net, IPSTATS_MIB_IN, skb->len);

	skb = skb_share_check(skb, GFP_ATOMIC);
	if (!skb) {
		__IP_INC_STATS(net, IPSTATS_MIB_INDISCARDS);
		goto out;
	}

	if (!pskb_may_pull(skb, 20))
		goto inhdr_error;

	ippph = ippp_hdr(skb);
	hdrLen = hdr_len(ippph);

	/*
	 *	RFC1122: 3.2.1.2 MUST silently discard any IP frame that fails the checksum.
	 *
	 *	Is the datagram acceptable?
	 *
	 *	1.	Length at least the size of an ip header
	 *	2.	Version of 4
	 *	3.	Checksums correctly. [Speed optimisation for later, skip loopback checksums]
	 *	4.	Doesn't have a bogus length
	 */

	if (!pskb_may_pull(skb, hdrLen))
		goto inhdr_error;

	ippph = ippp_hdr(skb);
	hdrLen = hdr_len(ippph);

	len = ntohs(ippph->tot_len);
	if (skb->len < len) {
		__IP_INC_STATS(net, IPSTATS_MIB_INTRUNCATEDPKTS);
		goto drop;
	} else if (len < hdrLen)
		goto inhdr_error;

	/* Our transport medium may have padded the buffer out. Now we know it
	 * is IP we can trim to the true length of the frame.
	 * Note this now means skb->len holds ntohs(iph->tot_len).
	 */
	if (pskb_trim_rcsum(skb, len)) {
		__IP_INC_STATS(net, IPSTATS_MIB_INDISCARDS);
		goto drop;
	}

	ippph = ippp_hdr(skb);
	hdrLen = hdr_len(ippph);
	skb->transport_header = skb->network_header + hdrLen;

	/* Remove any debris in the socket control block */
	memset(IPCB(skb), 0, sizeof(struct inet_skb_parm));
	IPCB(skb)->iif = skb->skb_iif;

	/* Must drop socket now because of tproxy. */
	skb_orphan(skb);

	return skb;

inhdr_error:
	__IP_INC_STATS(net, IPSTATS_MIB_INHDRERRORS);
drop:
	kfree_skb(skb);
out:
	return NULL;
}

/*
 * IPPP receive entry point
 */
int ippp_rcv(struct sk_buff *skb, struct net_device *dev, struct packet_type *pt, struct net_device *orig_dev)
{
	struct net *net = dev_net(dev);
	skb = ippp_rcv_core(skb, net);
	if (skb == NULL)
		return NET_RX_DROP;

	return NF_HOOK_PP(NF_INET_PRE_ROUTING,net, NULL, skb, dev, NULL, ippp_rcv_finish);
}