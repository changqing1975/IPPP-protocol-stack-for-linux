#include <linux/module.h>
#include <linux/random.h>
#include <linux/sched.h>
#include <linux/slab.h>
#include <linux/wait.h>
#include <linux/vmalloc.h>
#include <linux/memblock.h>
#include <net/addrconf.h>
#include <net/inet_connection_sock.h>
#include <net/inet_hashtables.h>
#include <net/secure_seq.h>
#include <net/ip.h>
#include <net/tcp.h>
#include <net/sock_reuseport.h>
#include "ipppk.h"

struct sock *__inetpp_lookup_established(const struct net *net,
    struct ippp_addr *saddr, __be16 sport,
    struct ippp_addr *daddr, u16 hnum,
    const int dif, const int sdif) {

    struct sock *sk = __inet_lookup_established(net, leafAddr(saddr), sport,
                                                     leafAddr(daddr), hnum, dif, sdif);

    return sk;
}

struct sock *inetpp_lookup_listener(const struct net *net,
    struct sk_buff *skb, int doff,
    struct ippp_addr *saddr, __be16 sport,
    struct ippp_addr *daddr, u16 hnum,
    const int dif, const int sdif) {

    struct sock *sk;
    sk = __inet_lookup_listener(net, NULL, 0,
            leafAddr(saddr), sport,
            leafAddr(daddr), hnum, dif, sdif);
    return sk;
}