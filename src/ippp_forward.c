#include <linux/types.h>
#include <linux/mm.h>
#include <linux/skbuff.h>
#include <linux/ip.h>
#include <linux/icmp.h>
#include <linux/netdevice.h>
#include <linux/slab.h>
#include <net/sock.h>
#include <net/ip.h>
#include <net/tcp.h>
#include <net/udp.h>
#include <net/icmp.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <linux/netfilter_ipv4.h>
#include <net/checksum.h>
#include <linux/route.h>
#include <net/route.h>
#include <net/xfrm.h>
#include <net/netns/generic.h>
#include "ipppk.h"

static int ippp_forward_finish(struct net *net, struct sock *sk, struct sk_buff *skb)
{
    struct ippphdr *ippph = ippp_hdr(skb);
	ippph->tot_len = htons(skb->len);
	return ippp_output(net, sk, skb);
}

int ippp_forward(struct sk_buff *skb) {
    if(!(((struct sysctl_net*)net_generic(dev_net(skb_dst(skb)->dev), sysctl_net_id))->forwarding))
        return 0;
    struct flowipp flpp;
	struct flowi4 *fl4;
    fl4 = &flpp.fl4;
    getAddrFromSkb(skb, &(flpp.rmtaddr), &(flpp.locaddr), 0);
    fl4->saddr = 0/* leafAddr(&(flpp.locaddr)) */;
    flpp.un = ((struct if_*)findNode(if_global_list.head, skb_dst(skb)->dev->name, 1))->un;
    // flowi4_init_output(fl4, 0/* ipc.oif */, 0/* ipc.sockc.mark */, 0/* tos */,
    //             RT_SCOPE_UNIVERSE, 0/* sk->sk_protocol */,
    //             0/* flow_flags */,
    //             0, 0, 0, 0,
    //             0/* sk->sk_uid */);
    struct net* net = dev_net(skb_dst(skb)->dev);
    struct dst_entry *dst = skb_dst(skb);
	struct rtable *rt = (struct rtable *)dst;
    struct rtable *nrt = ippp_route_output_flow(net, &flpp, NULL, skb, false);
    kfree(rt);
    skb_dst_set(skb, &nrt->dst);
    // ippp_forward_finish(net, skb->sk, skb);
    return NF_HOOK_PP(NF_INET_FORWARD,
            net, skb->sk, skb, skb->dev, rt->dst.dev,
            ippp_forward_finish);
}