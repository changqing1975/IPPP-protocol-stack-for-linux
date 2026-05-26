/* IP plus plus protocol family
*	Linux INETPP implementation
*
*	Authors:
*	Changqing	<cq@ippp.xyz>
*/
#include <linux/module.h>
#include <linux/capability.h>
#include <linux/errno.h>
#include <linux/types.h>
#include <linux/socket.h>
#include <linux/in.h>
#include <linux/kernel.h>
#include <linux/timer.h>
#include <linux/string.h>
#include <linux/sockios.h>
#include <linux/net.h>
#include <linux/fcntl.h>
#include <linux/mm.h>
#include <linux/interrupt.h>
#include <linux/proc_fs.h>
#include <linux/stat.h>
#include <linux/init.h>
#include <linux/slab.h>
#include <linux/inet.h>
#include <linux/netdevice.h>
#include <net/ip.h>
#include <net/udp.h>
#include <net/tcp.h>
#include <net/ping.h>
#include <net/protocol.h>
#include <net/inet_common.h>
#include <net/route.h>
#include <net/addrconf.h>
#include <net/ndisc.h>
#include <net/rps.h>
#include <net/calipso.h>
#include <linux/uaccess.h>
#include "ipppk.h"

MODULE_AUTHOR("ChangQing");
MODULE_DESCRIPTION("IP plus plus protocol stack for Linux");
MODULE_LICENSE("GPL");

/* The inetswpp table contains everything that inetpp_create needs to
  * build a new socket.
  */
static struct list_head inetswpp[SOCK_MAX];
static DEFINE_SPINLOCK(inetswpp_lock);

void inetpp_sock_destruct(struct sock *sk) {
	inetpp_cleanup_sock(sk);
	inet_sock_destruct(sk);
}

static int inetpp_create(struct net *net, struct socket *sock, int protocol, int kern) {
	struct sock *sk;
	struct inet_protosw *answer;
	struct inet_sock *inet;
	struct proto *answer_prot;
	unsigned char answer_flags;
	int try_loading_module = 0;
	int err;

	if (protocol < 0 || protocol >= IPPROTO_MAX)
		return -EINVAL;

	sock->state = SS_UNCONNECTED;

	 /* Look for the requested type/protocol pair. */
lookup_protocol:
	err = -ESOCKTNOSUPPORT;
	rcu_read_lock();
	list_for_each_entry_rcu(answer, &inetswpp[sock->type], list) {

		err = 0;
		/* Check the non-wild match. */
		if (protocol == answer->protocol) {
			if (protocol != IPPROTO_IP)
				break;
		} else {
			/* Check for the two wild cases. */
			if (IPPROTO_IP == protocol) {
				protocol = answer->protocol;
				break;
			}
			if (IPPROTO_IP == answer->protocol)
				break;
		}
		err = -EPROTONOSUPPORT;
	}

	if (unlikely(err)) {
		if (try_loading_module < 2) {
			rcu_read_unlock();

			if (++try_loading_module == 1)
				request_module("net-pf-%d-proto-%d-type-%d", PF_INETPP, protocol, sock->type);
			else
				request_module("net-pf-%d-proto-%d", PF_INETPP, protocol);
			goto lookup_protocol;
		} else
			goto out_rcu_unlock;
	}

	err = -EPERM;
	if (sock->type == SOCK_RAW && !kern && !ns_capable(net->user_ns, CAP_NET_RAW))
		goto out_rcu_unlock;

	sock->ops = answer->ops;
	answer_prot = answer->prot;
	answer_flags = answer->flags;
	rcu_read_unlock();

	WARN_ON(!answer_prot->slab);

	err = -ENOMEM;
	sk = sk_alloc(net, PF_INETPP, GFP_KERNEL, answer_prot, kern);
	if (!sk)
		goto out;

	err = 0;
	if (INET_PROTOSW_REUSE & answer_flags)
		sk->sk_reuse = SK_CAN_REUSE;

	if (INET_PROTOSW_ICSK & answer_flags)
	inet_init_csk_locks(sk);

	inet = inet_sk(sk);
	inet_assign_bit(IS_ICSK, sk, INET_PROTOSW_ICSK & answer_flags);

	inet_clear_bit(NODEFRAG, sk);

	if (SOCK_RAW == sock->type) {
		inet->inet_num = protocol;
		if (IPPROTO_RAW == protocol)
			inet_set_bit(HDRINCL, sk);
	}

	if (READ_ONCE(net->ipv4.sysctl_ip_no_pmtu_disc))
	inet->pmtudisc = IP_PMTUDISC_DONT;
	else
	inet->pmtudisc = IP_PMTUDISC_WANT;
	
	atomic_set(&inet->inet_id, 0);

	sock_init_data(sock, sk);

	sk->sk_destruct		= inetpp_sock_destruct;
	sk->sk_family		= PF_INETPP;
	sk->sk_protocol		= protocol;
	sk->sk_backlog_rcv	= sk->sk_prot->backlog_rcv;
	sk->sk_txrehash		= READ_ONCE(net->core.sysctl_txrehash);

	inet->uc_ttl	= -1;
	inet_set_bit(MC_LOOP, sk);
	inet->mc_ttl	= 1;
	inet_set_bit(MC_ALL, sk);
	inet->mc_index	= 0;
	inet->mc_list	= NULL;
	inet->rcv_tos	= 0;

	if (inet->inet_num) {
		inet->inet_sport = htons(inet->inet_num);
		/* Add to protocol hash chains. */
		err = sk->sk_prot->hash(sk);
		if (err)
			goto out_sk_release;
	}

	if (sk->sk_prot->init) {
		err = sk->sk_prot->init(sk);
		if (err)
			goto out_sk_release;
	}

	if (!kern) {
		err = BPF_CGROUP_RUN_PROG_INET_SOCK(sk);
		if (err)
			goto out_sk_release;
	}
out:
	return err;
out_rcu_unlock:
	rcu_read_unlock();
	goto out;
out_sk_release:
	sk_common_release(sk);
	sock->sk = NULL;
	goto out;
}

static int __inetpp_bind(struct sock *sk, struct sockaddr *uaddr, int addr_len, u32 flags) {
	struct sockaddr_ippp *addr = (struct sockaddr_ippp *)uaddr;
	struct inet_sock *inet = inet_sk(sk);
	struct l4pp_sock *l4ppsk = l4pp_sk(sk);
	struct net *net = sock_net(sk);
	unsigned short snum;
	int err = 0;
	if (addr->family != AF_INETPP)
		err = -EAFNOSUPPORT;

	snum = ntohs(addr->port);
	if (snum && !ns_capable(net->user_ns, CAP_NET_BIND_SERVICE))
		goto out;

	if (flags & BIND_WITH_LOCK)
		lock_sock(sk);

	 /* Check these errors (active socket, double bind). */
	 if (sk->sk_state != TCP_CLOSE || inet->inet_num) {
		err = -EINVAL;
		goto out;
	}

	inet->inet_rcv_saddr = inet->inet_saddr = leafAddr(&(addr->addr));
	
	// Verify address validity
	if(addr->addr.type==1){			// relative address
		if(addr->addr.base!=0){

		}
	} else {						// absolute address

	}
	l4ppsk->flpp.locaddr = addr->addr;

	if (snum || !(inet_test_bit(BIND_ADDRESS_NO_PORT, sk) || (flags & BIND_FORCE_ADDRESS_NO_PORT))) {
		err = sk->sk_prot->get_port(sk, snum);
		if (err) {
			inet->inet_saddr = inet->inet_rcv_saddr = 0;
			goto out;
		}
	}
	if (inet->inet_rcv_saddr)
		sk->sk_userlocks |= SOCK_BINDADDR_LOCK;
	if (snum)
		sk->sk_userlocks |= SOCK_BINDPORT_LOCK;
	inet->inet_sport = htons(inet->inet_num);
	inet->inet_daddr = 0;
	inet->inet_dport = 0;
	sk_dst_reset(sk);
	err = 0;
out:
	if (flags & BIND_WITH_LOCK)
		release_sock(sk);
	return err;
}

static int inetpp_bind(struct socket *sock, struct sockaddr *uaddr, int addr_len) {
	struct sock *sk = sock->sk;
	u32 flags = BIND_WITH_LOCK;
	int err;

	if (sk->sk_prot->bind) {
		return sk->sk_prot->bind(sk, uaddr, addr_len);
	}
	if (addr_len < realLen(uaddr))
		return -EINVAL;

	err = BPF_CGROUP_RUN_PROG_INET_BIND_LOCK(sk, uaddr, &addr_len,
						 CGROUP_INET4_BIND, &flags);
	if (err)
		return err;

	return __inetpp_bind(sk, uaddr, addr_len, flags);
}

static int inetpp_release(struct socket *sock) {
	struct sock *sk = sock->sk;
	if (!sk)
		return -EINVAL;

	return inet_release(sock);
}

void inetpp_cleanup_sock(struct sock *sk) {

}

/*
*	This does both peername and sockname.
*/
static int inetpp_getname(struct socket *sock, struct sockaddr *uaddr, int peer)
{
	struct sockaddr_ippp *sin = (struct sockaddr_ippp *)uaddr;
	int sin_addr_len = sizeof(*sin);
	struct sock *sk = sock->sk;

	lock_sock(sk);
	if (peer) {

	} else {

	}
	release_sock(sk);
	return sin_addr_len;
}

static int ippp_ioctl(struct socket *sock, unsigned int cmd, unsigned long arg)
{
	struct sock *sk = sock->sk;
	int err = 0;
	void __user *p = (void __user *)arg;
	struct ifreq ifr;

	switch (cmd) {
	case SIOCADDRT:
	case SIOCDELRT:
		struct rtentry rt;
		if (copy_from_user(&rt, p, sizeof(struct rtentry)))
			return -EFAULT;
		break;
	case SIOCRTMSG:
		err = -EINVAL;
		break;
	case SIOCDARP:
	case SIOCGARP:
	case SIOCSARP:
		break;
	case SIOCGIFADDR:
	case SIOCGIFBRDADDR:
	case SIOCGIFNETMASK:
	case SIOCGIFDSTADDR:
	case SIOCGIFPFLAGS:
		if (get_user_ifreq(&ifr, NULL, p))
			return -EFAULT;
		break;

	case SIOCSIFADDR:
	case SIOCSIFBRDADDR:
	case SIOCSIFNETMASK:
	case SIOCSIFDSTADDR:
	case SIOCSIFPFLAGS:
	case SIOCSIFFLAGS:
		break;
	default:
		if (sk->sk_prot->ioctl)
			err = sk_ioctl(sk, cmd, (void __user *)arg);
		else
			err = -ENOIOCTLCMD;
		break;
	}
	return err;
}

#ifdef CONFIG_COMPAT
static int ippp_compat_ioctl(struct socket *sock, unsigned int cmd, unsigned long arg) {
	struct sock *sk = sock->sk;
	if (!sk->sk_prot->compat_ioctl)
		return -ENOIOCTLCMD;
	return sk->sk_prot->compat_ioctl(sk, cmd, arg);
}
#endif /* CONFIG_COMPAT */
 
 static int inetpp_sendmsg(struct socket *sock, struct msghdr *msg, size_t size) {
	DEBUG_LOG();
	struct sock *sk = sock->sk;
	if (unlikely(inet_send_prepare(sk)))
		return -EAGAIN;

	return INDIRECT_CALL_2(sk->sk_prot->sendmsg, tcp_sendmsg, udppp_sendmsg, sk, msg, size);
}

INDIRECT_CALLABLE_DECLARE(int udp_recvmsg(struct sock *, struct msghdr *, size_t, int, int, int *));

static int inetpp_recvmsg(struct socket *sock, struct msghdr *msg, size_t size, int flags) {
	struct sock *sk = sock->sk;

	if (likely(!(flags & MSG_ERRQUEUE)))
		sock_rps_record_flow(sk);

	int addr_len = 0;
	int err = INDIRECT_CALL_2(sk->sk_prot->recvmsg, udppp_recvmsg, tcp_recvmsg, sk, msg, size, flags, &addr_len);
	if (err >= 0)
		msg->msg_namelen = addr_len;
	return err;
}

const struct proto_ops inetpp_stream_ops = {
	.family			= PF_INETPP,
	.owner			= THIS_MODULE,
	.release		= inetpp_release,
	.bind			= inetpp_bind,
	.connect		= inet_stream_connect,
	.socketpair		= sock_no_socketpair,
	.accept			= inet_accept,
	.getname		= inetpp_getname,
	.poll			= tcp_poll,
	.ioctl			= ippp_ioctl,
	.gettstamp		= sock_gettstamp,
	.listen			= inet_listen,
	.shutdown		= inet_shutdown,
	.setsockopt		= sock_common_setsockopt,
	.getsockopt		= sock_common_getsockopt,
	.sendmsg		= inetpp_sendmsg,
	.recvmsg		= inetpp_recvmsg,
#ifdef CONFIG_MMU
	.mmap			= tcp_mmap,
#endif
	.sendmsg_locked	= tcp_sendmsg_locked,
	.splice_read	= tcp_splice_read,
	.read_sock		= tcp_read_sock,
	.peek_len		= tcp_peek_len,
#ifdef CONFIG_COMPAT
	.compat_ioctl	   = ippp_compat_ioctl,
#endif
	.set_rcvlowat	   = tcp_set_rcvlowat,
}; 

const struct proto_ops inetpp_dgram_ops = {
	.family			= PF_INETPP,
	.owner			= THIS_MODULE,
	.release		= inetpp_release,
	.bind			= inetpp_bind,
	.connect		= inet_dgram_connect,
	.socketpair		= sock_no_socketpair,
	.accept			= sock_no_accept,
	.getname		= inetpp_getname,
	.poll			= udp_poll,
	.ioctl			= ippp_ioctl,
	.gettstamp		= sock_gettstamp,
	.listen			= sock_no_listen,
 	.shutdown		= inet_shutdown,
	.setsockopt		= sock_common_setsockopt,
	.getsockopt		= sock_common_getsockopt,
	.sendmsg		= inetpp_sendmsg,
	.recvmsg		= inetpp_recvmsg,
	.mmap			= sock_no_mmap,
	.set_peek_off	= sk_set_peek_off,
#ifdef CONFIG_COMPAT
	.compat_ioctl	= ippp_compat_ioctl,
#endif
};

int inetpp_sk_rebuild_header(struct sock *sk) {
	return 0;
}

int inetpp_register_protosw(struct inet_protosw *p) {
	spin_lock_bh(&inetswpp_lock);

	int ret = -EINVAL;
	if (p->type >= SOCK_MAX)
		goto out_illegal;

	struct inet_protosw *answer = NULL;
	ret = -EPERM;
	struct list_head *last_perm = &inetswpp[p->type];
	struct list_head *lh;
	int protocol = p->protocol;
	list_for_each(lh, &inetswpp[p->type]) {
		answer = list_entry(lh, struct inet_protosw, list);

		/* Check only the non-wild match. */
		if (INET_PROTOSW_PERMANENT & answer->flags) {
			if (protocol == answer->protocol)
				break;
			last_perm = lh;
		}

		answer = NULL;
	}
	if (answer)
		goto out_permanent;

	list_add_rcu(&p->list, last_perm);
	ret = 0;
out:
	spin_unlock_bh(&inetswpp_lock);
	return ret;

out_permanent:
	pr_err("Attempt to override permanent protocol %d\n", protocol);
	goto out;

out_illegal:
	pr_err("Ignoring attempt to register invalid socket type %d\n",
	       p->type);
	goto out;
}
EXPORT_SYMBOL(inetpp_register_protosw);

void inetpp_unregister_protosw(struct inet_protosw *p) {
	if (INET_PROTOSW_PERMANENT & p->flags) {
		pr_err("Attempt to unregister permanent protocol %d\n",
		       p->protocol);
	} else {
		spin_lock_bh(&inetswpp_lock);
		list_del_rcu(&p->list);
		spin_unlock_bh(&inetswpp_lock);

		synchronize_net();
	}
}
EXPORT_SYMBOL(inetpp_unregister_protosw);

static const struct net_proto_family inetpp_family_ops = {
	.family = PF_INETPP,
	.create = inetpp_create,
	.owner = THIS_MODULE,
};

static struct packet_type ippp_packet_type __read_mostly = {
	.type = cpu_to_be16(ETH_P_IPPP),
	.func = ippp_rcv,
	.list_func = ippp_list_rcv,
};

static int __net_init inetpp_net_init(struct net *net)
{
	int err = 0;
	udppp_proc_init(net);
	tcppp_proc_init(net);
 	return err;

}

static void __net_exit inetpp_net_exit(struct net *net) {
	udppp_proc_exit(net);
	tcppp_proc_exit(net);
}

static struct pernet_operations inetpp_net_ops = {
	.init = inetpp_net_init,
	.exit = inetpp_net_exit,
};

static int __init inetpp_init(void) {
	int err = 0;

	for (struct list_head *r = &inetswpp[0]; r < &inetswpp[SOCK_MAX]; ++r)
		INIT_LIST_HEAD(r);

	err = proto_register(&tcppp_prot, 1);
	if (err)
		goto out_unregister_tcp_proto;

	err = proto_register(&udppp_prot, 1);
	if (err)
		goto out_unregister_udp_proto;

	err = sock_register(&inetpp_family_ops);
	if (err)
		goto out_sock_register_fail;

	err = register_pernet_subsys(&inetpp_net_ops);
	if (err)
		goto register_pernet_fail;

	err = tcppp_init();
	if (err)
		goto tcp_pp_fail;

	err = udppp_init();
	if (err)
		goto udppp_fail;

	dev_add_pack(&ippp_packet_type);
	if (err)
		goto ippp_packet_fail;

	config_init();
	if (err)
		goto config_fail;

	nf_init();
	if (err)
		goto nf_fail;

	nf_dstack_init();
	if (err)
		goto nf_dstack_fail;

	nf_encap_init();
	if (err)
		goto nf_encap_fail;

	nf_translate_init();
	if (err)
		goto nf_translate_fail;

	nf_nat_init();
	if (err)
		goto nf_nat_fail;

	sysctl_init();
	if (err)
		goto sysctl_fail;

#ifdef SEC
	sec_init();
	if (err)
		goto sec_fail;
#endif

	ah4_init();
	if (err)
		goto ah4_fail;

	esp4_init();
	if (err)
		goto esp4_fail;

	// err = map_load_from_file("/etc/alias.config");
	if (err)
		goto alias_fail;

	DEBUG_LOG("ippp inserted %d", module_refcount(THIS_MODULE));
out:
	return err;

alias_fail:
	esp4_fini();
esp4_fail:
	ah4_fini();
ah4_fail:
#ifdef SEC
	sec_exit();
sec_fail:
#endif
	sysctl_exit();
sysctl_fail:
	nf_nat_exit();
nf_nat_fail:
	nf_translate_exit();
nf_translate_fail:
	nf_encap_exit();
nf_encap_fail:
	nf_dstack_exit();
nf_dstack_fail:
	nf_exit();
nf_fail:
	config_exit();
config_fail:
	dev_remove_pack(&ippp_packet_type);
ippp_packet_fail:
	udppp_exit();
udppp_fail:
	tcppp_exit();
tcp_pp_fail:
	unregister_pernet_subsys(&inetpp_net_ops);
register_pernet_fail:
	sock_unregister(PF_INETPP);
out_sock_register_fail:
	proto_unregister(&udppp_prot);
out_unregister_udp_proto:
	proto_unregister(&tcppp_prot);
out_unregister_tcp_proto:
	goto out;
}

static void __exit inetpp_exit(void) {
	// map_destroy(&);
	esp4_fini();
	ah4_fini();
#ifdef SEC
	sec_exit();
#endif
	sysctl_exit();
	nf_nat_exit();
	nf_translate_exit();
	nf_encap_exit();
	nf_dstack_exit();
	nf_exit();
	config_exit();
	dev_remove_pack(&ippp_packet_type);
	udppp_exit();
	tcppp_exit();
	unregister_pernet_subsys(&inetpp_net_ops);
	sock_unregister(PF_INETPP);
	proto_unregister(&udppp_prot);
	proto_unregister(&tcppp_prot);
	DEBUG_LOG("ippp exit");
}

module_init(inetpp_init);
module_exit(inetpp_exit);