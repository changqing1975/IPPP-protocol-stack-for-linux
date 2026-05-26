#include <linux/module.h>
#include <linux/netdevice.h>
#include <linux/spinlock.h>
#include <net/protocol.h>
#include "ipppk.h"

struct net_protocol __rcu *inetpp_protos_c[MAX_INET_PROTOS] __read_mostly;
EXPORT_SYMBOL(inetpp_protos_c);

int inetpp_add_protocol(const struct net_protocol *prot, unsigned char protocol)
{
	return !cmpxchg((const struct net_protocol **)&inetpp_protos_c[protocol], NULL, prot) ? 0 : -1;
}
EXPORT_SYMBOL(inetpp_add_protocol);

int inetpp_del_protocol(const struct net_protocol *prot, unsigned char protocol)
{
	int ret;

	ret = (cmpxchg((const struct net_protocol **)&inetpp_protos_c[protocol], prot, NULL) == prot) ? 0 : -1;

	synchronize_net();

	return ret;
}
EXPORT_SYMBOL(inetpp_del_protocol);