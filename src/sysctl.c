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
#include <net/tcp.h>
#include <linux/udp.h>
#include "ipppk.h"

unsigned int sysctl_net_id __read_mostly;

static int __net_init sysctl_init_net(struct net *net) {
	struct sysctl_net* sysctl_net = net_generic(net, sysctl_net_id);
	sysctl_net->ippp_table[0].procname	= "forwarding";
	sysctl_net->ippp_table[0].data		= &(sysctl_net->forwarding);
	sysctl_net->ippp_table[0].maxlen	= sizeof(sysctl_net->forwarding);
	sysctl_net->ippp_table[0].mode		= 0644;
	sysctl_net->ippp_table[0].proc_handler	= proc_dobool;
    sysctl_net->ippp_reg_table = register_net_sysctl(net, "net/ippp", sysctl_net->ippp_table);

	return 0;
}

static void __net_exit sysctl_exit_net(struct net *net) {
	struct sysctl_net* sysctl_net = net_generic(net, sysctl_net_id);
    unregister_net_sysctl_table(sysctl_net->ippp_reg_table);
}

static struct pernet_operations sysctl_net_ops = {
	.init = sysctl_init_net,
	.exit = sysctl_exit_net,
	.id   = &sysctl_net_id,
	.size = sizeof(struct sysctl_net),
};

int __init sysctl_init(void) {
	int err;

	err = register_pernet_device(&sysctl_net_ops);
	if (err < 0)
		return err;

	return err;
}

void sysctl_exit(void) {
	unregister_pernet_device(&sysctl_net_ops);
}