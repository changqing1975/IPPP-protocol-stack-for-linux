#include <linux/module.h>
#include <linux/types.h>
#include <linux/mm.h>
#include <linux/skbuff.h>
#include <linux/ip.h>
#include <linux/icmp.h>
#include <linux/inetdevice.h>
#include <linux/netdevice.h>
#include <linux/slab.h>
#include <net/sock.h>
#include <net/ip.h>
#include <net/icmp.h>
#include <net/tcp_states.h>
#include <linux/udp.h>
#include <linux/igmp.h>
#include <linux/netfilter.h>
#include <linux/route.h>
#include <linux/mroute.h>
#include <net/inet_ecn.h>
#include <net/route.h>
#include <net/xfrm.h>
#include <net/compat.h>
#include <net/checksum.h>
#include <net/ip_fib.h>
#include <linux/errqueue.h>
#include <linux/uaccess.h>
#include "ipppk.h"

int ippp_setsockopt(struct sock *sk, int level, int optname, sockptr_t optval, unsigned int optlen) {
    int err = 0;

    return err;
}

int ippp_getsockopt(struct sock *sk, int level, int optname, char __user *optval, int __user *optlen) {
    int err = 0;

    return err;
}

int ippp_recv_error(struct sock *sk, struct msghdr *msg, int len, int *addr_len) {

	int err;

	err = -EAGAIN;

	return err;
}