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
#include <linux/netfilter_ipv4/ip_tables.h>
#include <linux/skbuff.h> 
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <net/tcp.h>
#include <linux/udp.h>
#include "../ipppk.h"

/* #define FILTER_VALID_HOOKS ((1 << NF_INET_LOCAL_IN) | \
			    (1 << NF_INET_FORWARD) | \
			    (1 << NF_INET_LOCAL_OUT)) */

// static const struct xt_table ippp_packet_filter = {
// 	.name		= "filter",
// 	.valid_hooks	= FILTER_VALID_HOOKS,
// 	.me		= THIS_MODULE,
// 	.af		= NFPROTO_IPV4,
// 	.priority	= NF_IP_PRI_FILTER,
// };

// static struct nf_hook_ops *ippp_filter_ops __read_mostly;

// /* Default to forward because I got too much mail already. */
// static bool forward = true;
// module_param(forward, bool, 0000);

// static int ippptable_filter_table_init(struct net *net)
// {
// 	struct ipt_replace *repl = ipppt_alloc_initial_table(&ippp_packet_filter);
// 	if (repl == NULL)
// 		return -ENOMEM;
// 	/* Entry 1 is the FORWARD hook */
// 	((struct ipt_standard *)repl->entries)[1].target.verdict =
// 		forward ? -NF_ACCEPT - 1 : NF_DROP - 1;

// 	int err = ipppt_register_table(net, &ippp_packet_filter, repl, ippp_filter_ops);
// 	kfree(repl);
// 	return err;
// }

// static int __net_init ippptable_filter_net_init(struct net *net)
// {
// 	if (!forward)
// 		return ippptable_filter_table_init(net);

// 	return 0;
// }

// static void __net_exit ippptable_filter_net_pre_exit(struct net *net)
// {
// 	ipt_unregister_table_pre_exit(net, "filter");
// }

// static void __net_exit ippptable_filter_net_exit(struct net *net)
// {
// 	ipt_unregister_table_exit(net, "filter");
// }

// static struct pernet_operations ippptable_filter_net_ops = {
// 	.init = ippptable_filter_net_init,
// 	.pre_exit = ippptable_filter_net_pre_exit,
// 	.exit = ippptable_filter_net_exit,
// };

// static int __init iptable_filter_init(void) {
// 	int ret = xt_register_template(&ippp_packet_filter,
// 				       ippptable_filter_table_init);

// 	if (ret < 0)
// 		return ret;

// 	ippp_filter_ops = xt_hook_ops_alloc(&ippp_packet_filter, ipppt_do_table);
// 	if (IS_ERR(ippp_filter_ops)) {
// 		xt_unregister_template(&ippp_packet_filter);
// 		return PTR_ERR(ippp_filter_ops);
// 	}

// 	ret = register_pernet_subsys(&ippptable_filter_net_ops);
// 	if (ret < 0) {
// 		xt_unregister_template(&ippp_packet_filter);
// 		kfree(ippp_filter_ops);
// 		return ret;
// 	}

// 	return 0;
// }

// static void iptable_filter_fini(void) {
// 	unregister_pernet_subsys(&ippptable_filter_net_ops);
// 	xt_unregister_template(&ippp_packet_filter);
// 	kfree(ippp_filter_ops);
// }