#include <linux/uaccess.h>
#include <linux/module.h>
#include <linux/types.h>
#include <linux/kernel.h>
#include <linux/mm.h>
#include <linux/string.h>
#include <linux/errno.h>
#include <linux/highmem.h>
#include <linux/slab.h>

#include <linux/socket.h>
#include <linux/sockios.h>
#include <linux/in.h>
#include <linux/inet.h>
#include <linux/netdevice.h>
#include <linux/etherdevice.h>
#include <linux/proc_fs.h>
#include <linux/stat.h>
#include <linux/init.h>

#include <net/snmp.h>
#include <net/ip.h>
#include <net/protocol.h>
#include <net/route.h>
#include <net/xfrm.h>
#include <linux/skbuff.h>
#include <net/sock.h>
#include <net/arp.h>
#include <net/icmp.h>
#include <net/checksum.h>
#include <net/inetpeer.h>
#include <net/lwtunnel.h>
#include <linux/bpf-cgroup.h>
#include <linux/igmp.h>
#include <linux/netfilter_ipv4.h>
#include <linux/netfilter_bridge.h>
#include <linux/netlink.h>
#include <linux/tcp.h>
#include "ipppk.h"

static inline int neigh_hh_output2(const struct hh_cache *hh, struct sk_buff *skb) {
	unsigned int hh_alen = 0;
	unsigned int seq;
	unsigned int hh_len;

	do {
		seq = read_seqbegin(&hh->hh_lock);
		hh_len = READ_ONCE(hh->hh_len);
		if (likely(hh_len <= HH_DATA_MOD)) {
			hh_alen = HH_DATA_MOD;

			/* skb_push() would proceed silently if we have room for
			 * the unaligned size but not for the aligned size:
			 * check headroom explicitly.
			 */
			if (likely(skb_headroom(skb) >= HH_DATA_MOD)) {
				/* this is inlined by gcc */
				memcpy(skb->data - HH_DATA_MOD, hh->hh_data,
				       HH_DATA_MOD);
			}
			((struct ethhdr *)(skb->data - hh_len))->h_proto = htons(0x0810);
		} else {
			hh_alen = HH_DATA_ALIGN(hh_len);

			if (likely(skb_headroom(skb) >= hh_alen)) {
				memcpy(skb->data - hh_alen, hh->hh_data,
				       hh_alen);
			}
		}
	} while (read_seqretry(&hh->hh_lock, seq));

	if (WARN_ON_ONCE(skb_headroom(skb) < hh_alen)) {
		kfree_skb(skb);
		return NET_XMIT_DROP;
	}

	__skb_push(skb, hh_len);
	return dev_queue_xmit(skb);
}

static inline int neigh_output2(struct neighbour *n, struct sk_buff *skb) {
	const struct hh_cache *hh = &n->hh;

	/* n->nud_state and hh->hh_len could be changed under us.
	 * neigh_hh_output() is taking care of the race later.
	 */
	if ((READ_ONCE(n->nud_state) & NUD_CONNECTED) &&
	    READ_ONCE(hh->hh_len))
		return neigh_hh_output2(hh, skb);

	return n->output(n, skb);
}

static inline struct neighbour *ippp_neigh_for_gw(struct rtable *rt,
						struct sk_buff *skb) {
	struct net_device *dev = rt->dst.dev;
	struct neighbour *neigh;

	if (likely(rt->rt_gw_family == AF_INET)) {
		neigh = ip_neigh_gw4(dev, rt->rt_gw4);
	} else {
		neigh = ip_neigh_gw4(dev, rt->rt_gw4);
	}
	return neigh;
}

static int ippp_finish_output2(struct net *net, struct sock *sk, struct sk_buff *skb) {
	struct dst_entry *dst = skb_dst(skb);
	struct rtable *rt = (struct rtable *)dst;
	struct net_device *dev = dst->dev;
	unsigned int hh_len = LL_RESERVED_SPACE(dev);
	struct neighbour *neigh;

	if (rt->rt_type == RTN_MULTICAST) {
		IP_UPD_PO_STATS(net, IPSTATS_MIB_OUTMCAST, skb->len);
	} else if (rt->rt_type == RTN_BROADCAST)
		IP_UPD_PO_STATS(net, IPSTATS_MIB_OUTBCAST, skb->len);

	if (unlikely(skb_headroom(skb) < hh_len && dev->header_ops)) {
		skb = skb_expand_head(skb, hh_len);
		if (!skb)
			return -ENOMEM;
	}

	if (lwtunnel_xmit_redirect(dst->lwtstate)) {
		int res = lwtunnel_xmit(skb);

		if (res < 0 || res == LWTUNNEL_XMIT_DONE)
			return res;
	}

	rcu_read_lock_bh();
	neigh = ippp_neigh_for_gw(rt, skb);

	if (!IS_ERR(neigh)) {
		int res;

		sock_confirm_neigh(skb, neigh);
		/* if crossing protocols, can not use the cached header */
		res = neigh_output2(neigh, skb);
		rcu_read_unlock_bh();
		return res;
	}
	rcu_read_unlock_bh();

	net_dbg_ratelimited("%s: No header cache and no neighbour!\n",
			    __func__);
	kfree_skb_reason(skb, SKB_DROP_REASON_NEIGH_CREATEFAIL);
	return -EINVAL;
}

static int __ippp_finish_output(struct net *net, struct sock *sk, struct sk_buff *skb) {
	unsigned int mtu;

#if defined(CONFIG_NETFILTER) && defined(CONFIG_XFRM)
	/* Policy lookup after SNAT yielded a new policy */
	if (skb_dst(skb)->xfrm) {
		IPCB(skb)->flags |= IPSKB_REROUTED;
		return dst_output(net, sk, skb);
	}
#endif
	mtu = ip_skb_dst_mtu(sk, skb);
	// if (skb_is_gso(skb))
	// 	return ip_finish_output_gso(net, sk, skb, mtu);

	// if (skb->len > mtu || IPCB(skb)->frag_max_size)
	// 	return ip_fragment(net, sk, skb, mtu, ippp_finish_output2);

	return ippp_finish_output2(net, sk, skb);
}

int ippp_finish_output(struct net *net, struct sock *sk, struct sk_buff *skb) {
	int ret;

	ret = BPF_CGROUP_RUN_PROG_INET_EGRESS(sk, skb);
	switch (ret) {
	case NET_XMIT_SUCCESS:
		return __ippp_finish_output(net, sk, skb);
	case NET_XMIT_CN:
		return __ippp_finish_output(net, sk, skb) ? : ret;
	default:
		kfree_skb_reason(skb, SKB_DROP_REASON_BPF_CGROUP_EGRESS);
		return ret;
	}
}

int ippp_output(struct net *net, struct sock *sk, struct sk_buff *skb) {
	struct net_device *dev = skb_dst(skb)->dev/* , *indev = skb->dev */;

	IP_UPD_PO_STATS(net, IPSTATS_MIB_OUT, skb->len);

	skb->dev = dev;
	skb->protocol = htons(ETH_P_IPPP);

	return NF_HOOK_PP(NF_INET_POST_ROUTING, net, sk, skb, NULL, skb->dev, ippp_finish_output)/* ippp_finish_output(net, sk, skb) */;
}

static int __ippp_local_out(struct net *net, struct sock *sk, struct sk_buff *skb) {
	struct ippphdr *ippph = ippp_hdr(skb);

	ippph->tot_len = htons(skb->len);
	// ip_send_check(iph);

	/* if egress device is enslaved to an L3 master device pass the
	 * skb to its handler for processing
	 */
	// skb = l3mdev_ip_out(sk, skb);
	if (unlikely(!skb))
		return 0;

	skb->protocol = htons(ETH_P_IPPP);

	return NF_HOOK_PP(NF_INET_LOCAL_OUT,
		       net, sk, skb, NULL, skb_dst(skb)->dev,
		       ippp_output);
}

int ippp_local_out(struct net *net, struct sock *sk, struct sk_buff *skb) {
	int err;

	err = __ippp_local_out(net, sk, skb);
	// if (likely(err == 1))
	// 	err = dst_output(net, sk, skb);

	return err;
}

int ippp_send_skb(struct net *net, struct sk_buff *skb) {
	int err;

	err = ippp_local_out(net, skb->sk, skb);
	if (err) {
		if (err > 0)
			err = net_xmit_errno(err);
		if (err)
			IP_INC_STATS(net, IPSTATS_MIB_OUTDISCARDS);
	}

	return err;
}

static int __ippp_append_data(struct sock *sk,
			    struct flowipp *flpp,
			    struct sk_buff_head *queue,
			    struct inet_cork *cork,
			    struct page_frag *pfrag,
			    int getfrag(void *from, char *to, int offset,
					int len, int odd, struct sk_buff *skb),
			    void *from, int length, int transhdrlen,
			    unsigned int flags) {
	// struct inet_sock *inet = inet_sk(sk);
	struct ubuf_info *uarg = NULL;
	struct sk_buff *skb;

	// struct ip_options *opt = cork->opt;
	int hh_len;
	int exthdrlen;
	int mtu;
	int copy;
	int err;
	int offset = 0;
	unsigned int maxfraglen, fragheaderlen, maxnonfragsize;
	int csummode = CHECKSUM_NONE;
	struct rtable *rt = (struct rtable *)cork->dst;
	unsigned int wmem_alloc_delta = 0;
	bool paged, extra_uref = false;
	u32 tskey = 0;
	struct l4pp_sock *l4ppsk = l4pp_sk(sk);
	struct ippp_addr *daddrpp = &(l4ppsk->flpp.rmtaddr);
	struct ippp_addr *saddrpp = &(l4ppsk->flpp.locaddr);
	__u8 hdrlen = getHdrLen(daddrpp, saddrpp, flpp->un->level);
	
	skb = skb_peek_tail(queue);

	exthdrlen = !skb ? rt->dst.header_len : 0;
	mtu = cork->gso_size ? IP_MAX_MTU : cork->fragsize;
	paged = !!cork->gso_size;

	if (cork->tx_flags & SKBTX_ANY_SW_TSTAMP &&
	    sk->sk_tsflags & SOF_TIMESTAMPING_OPT_ID)
		tskey = atomic_inc_return(&sk->sk_tskey) - 1;

	hh_len = LL_RESERVED_SPACE(rt->dst.dev);

	fragheaderlen = 8 + (8 << hdrlen);	//sizeof(struct iphdr) + (opt ? opt->optlen : 0);
	maxfraglen = ((mtu - fragheaderlen) & ~7) + fragheaderlen;
	maxnonfragsize = ip_sk_ignore_df(sk) ? IP_MAX_MTU : mtu;

	// if (cork->length + length > maxnonfragsize - fragheaderlen) {
	// 	ip_local_error(sk, EMSGSIZE, fl4->daddr, inet->inet_dport,
	// 		       mtu - (opt ? opt->optlen : 0));
	// 	return -EMSGSIZE;
	// }

	/*
	 * transhdrlen > 0 means that this is the first fragment and we wish
	 * it won't be fragmented in the future.
	 */
	if (transhdrlen &&
	    length + fragheaderlen <= mtu &&
	    rt->dst.dev->features & (NETIF_F_HW_CSUM | NETIF_F_IP_CSUM) &&
	    (!(flags & MSG_MORE) || cork->gso_size) &&
	    (!exthdrlen || (rt->dst.dev->features & NETIF_F_HW_ESP_TX_CSUM)))
		csummode = CHECKSUM_PARTIAL;

	if (flags & MSG_ZEROCOPY && length && sock_flag(sk, SOCK_ZEROCOPY)) {
		uarg = msg_zerocopy_realloc(sk, length, skb_zcopy(skb), false);
		if (!uarg)
			return -ENOBUFS;
		extra_uref = !skb_zcopy(skb);	/* only ref on new uarg */
		if (rt->dst.dev->features & NETIF_F_SG &&
		    csummode == CHECKSUM_PARTIAL) {
			paged = true;
		} else {
			uarg_to_msgzc(uarg)->zerocopy = 0;
			skb_zcopy_set(skb, uarg, &extra_uref);
		}
	}

	cork->length += length;

	/* So, what's going on in the loop below?
	 *
	 * We use calculated fragment length to generate chained skb,
	 * each of segments is IP fragment ready for sending to network after
	 * adding appropriate IP header.
	 */

	if (!skb)
		goto alloc_new_skb;

	while (length > 0) {
		/* Check if the remaining data fits into current packet. */
		copy = mtu - skb->len;
		if (copy < length)
			copy = maxfraglen - skb->len;
		if (copy <= 0) {
			char *data;
			unsigned int datalen;
			unsigned int fraglen;
			unsigned int fraggap;
			unsigned int alloclen, alloc_extra;
			unsigned int pagedlen;
			struct sk_buff *skb_prev;
alloc_new_skb:
			skb_prev = skb;
			if (skb_prev)
				fraggap = skb_prev->len - maxfraglen;
			else
				fraggap = 0;

			/*
			 * If remaining data exceeds the mtu,
			 * we know we need more fragment(s).
			 */
			datalen = length + fraggap;
			if (datalen > mtu - fragheaderlen)
				datalen = maxfraglen - fragheaderlen;
			fraglen = datalen + fragheaderlen;
			pagedlen = 0;

			alloc_extra = hh_len + 15;
			alloc_extra += exthdrlen;

			/* The last fragment gets additional space at tail.
			 * Note, with MSG_MORE we overallocate on fragments,
			 * because we have no idea what fragment will be
			 * the last.
			 */
			if (datalen == length + fraggap)
				alloc_extra += rt->dst.trailer_len;

			if ((flags & MSG_MORE) &&
			    !(rt->dst.dev->features&NETIF_F_SG))
				alloclen = mtu;
			else if (!paged &&
				 (fraglen + alloc_extra < SKB_MAX_ALLOC ||
				  !(rt->dst.dev->features & NETIF_F_SG)))
				alloclen = fraglen;
			else {
				alloclen = min_t(int, fraglen, MAX_HEADER);
				pagedlen = fraglen - alloclen;
			}

			alloclen += alloc_extra;

			if (transhdrlen) {
				skb = sock_alloc_send_skb(sk, alloclen,
						(flags & MSG_DONTWAIT), &err);
			} else {
				skb = NULL;
				if (refcount_read(&sk->sk_wmem_alloc) + wmem_alloc_delta <=
				    2 * sk->sk_sndbuf)
					skb = alloc_skb(alloclen,
							sk->sk_allocation);
				if (unlikely(!skb))
					err = -ENOBUFS;
			}
			if (!skb)
				goto error;

			/*
			 *	Fill in the control structures
			 */
			skb->ip_summed = csummode;
			skb->csum = 0;
			skb_reserve(skb, hh_len);

			/*
			 *	Find where to start putting bytes.
			 */
			data = skb_put(skb, fraglen + exthdrlen - pagedlen);
			skb_set_network_header(skb, exthdrlen);
			skb->transport_header = (skb->network_header +
						 fragheaderlen);
			data += fragheaderlen + exthdrlen;

			if (fraggap) {
				skb->csum = skb_copy_and_csum_bits(
					skb_prev, maxfraglen,
					data + transhdrlen, fraggap);
				skb_prev->csum = csum_sub(skb_prev->csum,
							  skb->csum);
				data += fraggap;
				pskb_trim_unique(skb_prev, maxfraglen);
			}

			copy = datalen - transhdrlen - fraggap - pagedlen;
			if (copy > 0 && getfrag(from, data + transhdrlen, offset, copy, fraggap, skb) < 0) {
				err = -EFAULT;
				kfree_skb(skb);
				goto error;
			}

			offset += copy;
			length -= copy + transhdrlen;
			transhdrlen = 0;
			exthdrlen = 0;
			csummode = CHECKSUM_NONE;

			/* only the initial fragment is time stamped */
			skb_shinfo(skb)->tx_flags = cork->tx_flags;
			cork->tx_flags = 0;
			skb_shinfo(skb)->tskey = tskey;
			tskey = 0;
			skb_zcopy_set(skb, uarg, &extra_uref);

			if ((flags & MSG_CONFIRM) && !skb_prev)
				skb_set_dst_pending_confirm(skb, 1);

			/*
			 * Put the packet on the pending queue.
			 */
			if (!skb->destructor) {
				skb->destructor = sock_wfree;
				skb->sk = sk;
				wmem_alloc_delta += skb->truesize;
			}
			__skb_queue_tail(queue, skb);
			continue;
		}

		if (copy > length)
			copy = length;

		if (!(rt->dst.dev->features&NETIF_F_SG) &&
		    skb_tailroom(skb) >= copy) {
			unsigned int off;

			off = skb->len;
			if (getfrag(from, skb_put(skb, copy),
					offset, copy, off, skb) < 0) {
				__skb_trim(skb, off);
				err = -EFAULT;
				goto error;
			}
		} else if (!uarg) {
			int i = skb_shinfo(skb)->nr_frags;

			err = -ENOMEM;
			if (!sk_page_frag_refill(sk, pfrag))
				goto error;

			if (!skb_can_coalesce(skb, i, pfrag->page,
					      pfrag->offset)) {
				err = -EMSGSIZE;
				if (i == MAX_SKB_FRAGS)
					goto error;

				__skb_fill_page_desc(skb, i, pfrag->page,
						     pfrag->offset, 0);
				skb_shinfo(skb)->nr_frags = ++i;
				get_page(pfrag->page);
			}
			copy = min_t(int, copy, pfrag->size - pfrag->offset);
			if (getfrag(from,
				    page_address(pfrag->page) + pfrag->offset,
				    offset, copy, skb->len, skb) < 0)
				goto error_efault;

			pfrag->offset += copy;
			skb_frag_size_add(&skb_shinfo(skb)->frags[i - 1], copy);
			skb->len += copy;
			skb->data_len += copy;
			skb->truesize += copy;
			wmem_alloc_delta += copy;
		} else {
			err = skb_zerocopy_iter_dgram(skb, from, copy);
			if (err < 0)
				goto error;
		}
		offset += copy;
		length -= copy;
	}

	if (wmem_alloc_delta)
		refcount_add(wmem_alloc_delta, &sk->sk_wmem_alloc);
	return 0;

error_efault:
	err = -EFAULT;
error:
	net_zcopy_put_abort(uarg, extra_uref);
	cork->length -= length;
	IP_INC_STATS(sock_net(sk), IPSTATS_MIB_OUTDISCARDS);
	refcount_add(wmem_alloc_delta, &sk->sk_wmem_alloc);
	return err;
}

static int ippp_setup_cork(struct sock *sk, struct inet_cork *cork,
			 struct ipcm_cookie *ipc, struct rtable **rtp) {
	struct ip_options_rcu *opt;
	struct rtable *rt;

	rt = *rtp;
	if (unlikely(!rt))
		return -EFAULT;

	/*
	 * setup for corking.
	 */
	opt = ipc->opt;
	if (opt) {
		if (!cork->opt) {
			cork->opt = kmalloc(sizeof(struct ip_options) + 40,
					    sk->sk_allocation);
			if (unlikely(!cork->opt))
				return -ENOBUFS;
		}
		memcpy(cork->opt, &opt->opt, sizeof(struct ip_options) + opt->opt.optlen);
		cork->flags |= IPCORK_OPT;
		cork->addr = ipc->addr;
	}

	cork->fragsize = ip_sk_use_pmtu(sk) ?
			 dst_mtu(&rt->dst) : READ_ONCE(rt->dst.dev->mtu);

	if (!inetdev_valid_mtu(cork->fragsize))
		return -ENETUNREACH;

	cork->gso_size = ipc->gso_size;

	cork->dst = &rt->dst;
	/* We stole this route, caller should not release it. */
	*rtp = NULL;

	cork->length = 0;
	cork->ttl = ipc->ttl;
	cork->tos = ipc->tos;
	cork->mark = ipc->sockc.mark;
	cork->priority = ipc->sockc.priority;
	cork->transmit_time = ipc->sockc.transmit_time;
	cork->tx_flags = 0;
	sock_tx_timestamp(sk, &ipc->sockc, &cork->tx_flags);

	return 0;
}

static void ippp_cork_release(struct inet_cork *cork) {
	cork->flags &= ~IPCORK_OPT;
	kfree(cork->opt);
	cork->opt = NULL;
	dst_release(cork->dst);
	cork->dst = NULL;
}

static void __ippp_flush_pending_frames(struct sock *sk,
				      struct sk_buff_head *queue,
				      struct inet_cork *cork) {
	struct sk_buff *skb;

	while ((skb = __skb_dequeue_tail(queue)) != NULL)
		kfree_skb(skb);

	ippp_cork_release(cork);
}

struct sk_buff *__ippp_make_skb(struct sock *sk,
			      struct flowipp *flpp,
			      struct sk_buff_head *queue,
			      struct inet_cork *cork) {
	struct sk_buff *skb, *tmp_skb;
	struct sk_buff **tail_skb;
	struct inet_sock *inet = inet_sk(sk);
	// struct net *net = sock_net(sk);
	struct ip_options *opt = NULL;
	struct rtable *rt = (struct rtable *)cork->dst;
	struct ippphdr *iph;
	__be16 df = 0;
	__u8 ttl;
	struct l4pp_sock *l4ppsk = l4pp_sk(sk);
	struct ippp_addr *daddrpp = &(l4ppsk->flpp.rmtaddr);
	struct ippp_addr *saddrpp = &(l4ppsk->flpp.locaddr);
	__u8 hdrlen = getHdrLen(daddrpp, saddrpp, flpp->un->level);

	skb = __skb_dequeue(queue);
	if (!skb)
		goto out;
	tail_skb = &(skb_shinfo(skb)->frag_list);

	/* move skb->data to ip header from ext header */
	if (skb->data < skb_network_header(skb))
		__skb_pull(skb, skb_network_offset(skb));
	while ((tmp_skb = __skb_dequeue(queue)) != NULL) {
		__skb_pull(tmp_skb, skb_network_header_len(skb));
		*tail_skb = tmp_skb;
		tail_skb = &(tmp_skb->next);
		skb->len += tmp_skb->len;
		skb->data_len += tmp_skb->len;
		skb->truesize += tmp_skb->truesize;
		tmp_skb->destructor = NULL;
		tmp_skb->sk = NULL;
	}

	/* Unless user demanded real pmtu discovery (IP_PMTUDISC_DO), we allow
	 * to fragment the frame generated here. No matter, what transforms
	 * how transforms change size of the packet, it will come out.
	 */
	skb->ignore_df = ip_sk_ignore_df(sk);

	/* DF bit is set when we want to see DF on outgoing frames.
	 * If ignore_df is set too, we still allow to fragment this frame
	 * locally. */
	if (inet->pmtudisc == IP_PMTUDISC_DO ||
	    inet->pmtudisc == IP_PMTUDISC_PROBE ||
	    (skb->len <= dst_mtu(&rt->dst) &&
	     ip_dont_fragment(sk, &rt->dst)))
		df = htons(IP_DF);

	if (cork->flags & IPCORK_OPT)
		opt = cork->opt;

	if (cork->ttl != 0)
		ttl = cork->ttl;
	else if (rt->rt_type == RTN_MULTICAST)
		ttl = inet->mc_ttl;
	else
		ttl = 32;//ip_select_ttl(inet, &rt->dst);

	iph = ippp_hdr(skb);
	iph->ihl = hdrlen;
	iph->tos = (cork->tos != -1) ? cork->tos : inet->tos;
	iph->ttl = ttl;
	iph->protocol = sk->sk_protocol;
	/* copy addr */
	iph->dst_type = daddrpp->type;
	iph->dst_base = daddrpp->base;
	iph->dst_len  = daddrpp->len;
	for(__u8 i = 0; i <= iph->dst_len; i++) {
		iph->addr[i] = daddrpp->addr[i];
	}
	iph->src_type = saddrpp->type;
	iph->src_base = saddrpp->base;
	iph->src_len  = saddrpp->len;
	for(__u8 i = 0; i <= iph->src_len; i++) {
		iph->addr[iph->dst_len + 1 + i] = saddrpp->addr[i];
	}

	if (opt) {
		// iph->ihl += opt->optlen >> 2;
		// ip_options_build(skb, opt, cork->addr, rt);
	}

	skb->priority = (cork->tos != -1) ? cork->priority: sk->sk_priority;
	skb->mark = cork->mark;
	skb->tstamp = cork->transmit_time;
	/*
	 * Steal rt from cork.dst to avoid a pair of atomic_inc/atomic_dec
	 * on dst refcount
	 */
	cork->dst = NULL;
	skb_dst_set(skb, &rt->dst);

	// if (iph->protocol == IPPROTO_ICMP)
	// 	icmp_out_count(net, ((struct icmphdr *)
	// 		skb_transport_header(skb))->type);

	ippp_cork_release(cork);
out:
	return skb;
}

struct sk_buff *ippp_make_skb(struct sock *sk, struct flowipp *flpp,
			    int getfrag(void *from, char *to, int offset, int len, int odd, struct sk_buff *skb),
			    void *from, int length, int transhdrlen, struct ipcm_cookie *ipc, struct rtable **rtp,
			    struct inet_cork *cork, unsigned int flags) {
	struct sk_buff_head queue;
	int err = 0;

	if (flags & MSG_PROBE)
		return NULL;

	__skb_queue_head_init(&queue);

	cork->flags = 0;
	cork->addr = 0;
	cork->opt = NULL;
	err = ippp_setup_cork(sk, cork, ipc, rtp);
	if (err)
		return ERR_PTR(err);

	err = __ippp_append_data(sk, flpp, &queue, cork, &current->task_frag, getfrag, from, length, transhdrlen, flags);
	if (err) {
		__ippp_flush_pending_frames(sk, &queue, cork);
		return ERR_PTR(err);
	}

	return __ippp_make_skb(sk, flpp, &queue, cork);
}

void ippp_flush_pending_frames(struct sock *sk) {

}

int ippp_append_data(struct sock *sk, struct flowipp *flpp,
	int getfrag(void *from, char *to, int offset, int len,
			int odd, struct sk_buff *skb),
	void *from, int length, int transhdrlen,
	struct ipcm_cookie *ipc, struct rtable **rtp,
	unsigned int flags)
{
	struct inet_sock *inet = inet_sk(sk);
	int err;

	if (flags&MSG_PROBE)
	return 0;

	if (skb_queue_empty(&sk->sk_write_queue)) {
		err = ippp_setup_cork(sk, &inet->cork.base, ipc, rtp);
		if (err)
			return err;
	} else {
		transhdrlen = 0;
	}

	return __ippp_append_data(sk, flpp, &sk->sk_write_queue, &inet->cork.base,
			sk_page_frag(sk), getfrag,
			from, length, transhdrlen, flags);
}