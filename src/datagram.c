#include <linux/capability.h>
#include <linux/errno.h>
#include <linux/types.h>
#include <linux/kernel.h>
#include <linux/interrupt.h>
#include <linux/socket.h>
#include <linux/sockios.h>
#include <linux/route.h>
#include <linux/slab.h>
#include <linux/export.h>
#include <linux/icmp.h>
#include <net/ndisc.h>
#include <net/addrconf.h>
#include <net/tcp_states.h>
#include <net/dsfield.h>
#include <net/sock_reuseport.h>
#include <linux/errqueue.h>
#include <linux/uaccess.h>
#include "ipppk.h"

void ippp_datagram_release_cb(struct sock *sk)
{
	struct dst_entry *dst;

	if (ipv6_addr_v4mapped(&sk->sk_v6_daddr))
		return;

	rcu_read_lock();
	dst = __sk_dst_get(sk);
	if (!dst || !dst->obsolete ||
	    dst->ops->check(dst, inet6_sk(sk)->dst_cookie)) {
		rcu_read_unlock();
		return;
	}
	rcu_read_unlock();
}

static int __ippp_datagram_connect(struct sock *sk, struct sockaddr *uaddr,
			   int addr_len) {

	int err;
	err = -EINVAL;

	return err;
}

int ippp_datagram_connect(struct sock *sk, struct sockaddr *uaddr, int addr_len) {
	int res;

	lock_sock(sk);
	res = __ippp_datagram_connect(sk, uaddr, addr_len);
	release_sock(sk);
	return res;
}

int ippp_datagram_send_ctl(struct net *net, struct sock *sk,
	struct msghdr *msg, struct flowipp flpp,
	struct ipcm_cookie *ipc) {
	int err = 0;
	return err;
}