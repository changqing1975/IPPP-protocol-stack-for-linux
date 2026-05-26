#ifndef _IPPP_H
#define _IPPP_H

#include <linux/hardirq.h>
#include <linux/jhash.h>
#include <linux/netfilter.h>
#include <linux/netfilter_ipv4.h>
#include <linux/netfilter_ipv4/ip_tables.h>
#include <linux/inetdevice.h>
#include <net/protocol.h>
#include <net/addrconf.h>
#include <net/inet_common.h>
#include <net/ndisc.h>
#include <net/flow.h>
#include <net/flow_dissector.h>
#include <net/snmp.h>
#include <net/netns/hash.h>
#include <net/inet_hashtables.h>
#include <net/net_namespace.h>
#include <net/netns/generic.h>
#include <net/xfrm.h>
#include <net/hotdata.h>
#include <asm/checksum.h>

/*
Since the Linux kernel source does not reserve a protocol number for the new protocol family, it would
theoretically require modifying the kernel source code, which is not very convenient. Therefore, we choose
to borrow the protocol family number of AF_IPX, which is basically unused.
*/
#define AF_INETPP 4
#define PF_INETPP AF_INETPP
#define ETH_P_IPPP 0x0810 /* Internet Protocol Plus Plus packet */
#define IPPROTO_IPPPIP 140
#define NFPROTO_IPPP 4

// -----------------------------------------------------------------------------------------------------------
// addr

#pragma pack(1)
struct ippp_addr {
	__u8    type;
	__u8	len:4,
			base:4;
	__be32  addr[16];
};

struct sockaddr_ippp {
	sa_family_t family;
  __be16 port;				// Port number
  struct ippp_addr addr;	// Internet address
};

struct ippphdr {
#if defined(__LITTLE_ENDIAN_BITFIELD)
	__u8	src_type:1,
			dst_type:1,
			has_ext_hdr:2,
				ihl:4;
#else
		__u8	ihl:4,
			has_ext_hdr:2,
			dst_type:1,
			src_type:1;
#endif
	__u8	tos;
	__be16  tot_len;
	__u8	ttl;
	__u8	protocol;
#if defined(__LITTLE_ENDIAN_BITFIELD)
	__u8	 dst_len:4,
			dst_base:4;
	__u8 	 src_len:4,
			src_base:4;
#else
	__u8	dst_base:4,
				dst_len:4;
	__u8	src_base:4,
				src_len:4;
#endif
	__be32 addr[32];
};
#pragma pack()

#define IPPPADDR_ANY (struct ippp_addr) { \
	.type = 1, \
	.base = 0, \
	.len = 0, \
	.addr = {0} \
}

static inline struct ippphdr *ippp_hdr(const struct sk_buff *skb);

static inline int realLen(struct sockaddr *uaddr) {
	struct sockaddr_ippp *addr = (struct sockaddr_ippp *)uaddr;
	return sizeof(struct sockaddr_ippp) - (15 - addr->addr.len) * 4;
}

static inline __be32 leafAddr(struct ippp_addr *addr) {
	return addr->addr[addr->len];
}

static inline void getAddrFromSkb(struct sk_buff *skb, struct ippp_addr* daddr, struct ippp_addr* saddr, unsigned int offset) {
	struct ippphdr *ippph = (struct ippphdr *)((unsigned char*)ippp_hdr(skb) + offset);
	if(daddr) {
		daddr->type = ippph->dst_type;
		daddr->base = ippph->dst_base;
		daddr->len = ippph->dst_len;
		for(int i = 0; i <= ippph->dst_len; i++) {
			daddr->addr[i] = ippph->addr[i];
		}
	}
	if(saddr) {
		saddr->type = ippph->src_type;
		saddr->base = ippph->src_base;
		saddr->len = ippph->src_len;
		for(int i = 0; i <= ippph->src_len; i++) {
			saddr->addr[i] = ippph->addr[ippph->dst_len + 1 + i];
		}
	}
}

static inline bool addr_equal(struct ippp_addr* addr1, struct ippp_addr* addr2) {
	if(addr1->type == addr2->type && addr1->base == addr2->base && addr1->len == addr2->len) {
		for(int i = 0; i <= addr1->len; i++) {
			if(addr1->addr[i] != addr2->addr[i])
				return false;
		}
		return true;
	}
	return false;
} 

static inline __be32 inet_addr(const char *str) {
    __be32 addr = 0;
    char *paddr = (char *)&addr;
    char *pstr = (char *)str;
    while (pstr)
    {
        *paddr++ = simple_strtol(pstr, NULL, 10);
        pstr = strchr(pstr, '.');
        if (pstr)
            pstr++;
    }
    return addr;
}

// static inline void u32tostr(__u32 dat, char *str) {
// 	char temp[20];
// 	unsigned char i=0,j=0;
// 	while(dat) {
// 		temp[j]=dat%10+0x30;
// 		j++;
// 		dat/=10;
// 	}
// 	for(i=0;i<j;i++) {
// 		str[i]=temp[j-i-1];
// 	}
// 	if(i==0)str[i++]='0';
// 	str[i]=0;
// }
// -----------------------------------------------------------------------------------------------------------
// Packet Header

#pragma pack(1)
struct ext_hdr_addr {
	__u16 addr[0];
};
#pragma pack()

static inline struct ippphdr *ippp_hdr(const struct sk_buff *skb) {
	return (struct ippphdr *)skb_network_header(skb);
}

static inline struct ext_hdr_addr *ext_hdr_addr(const struct ippphdr *ippph) {
	if(ippph->has_ext_hdr!=0)
		return (struct ext_hdr_addr *)&ippph->addr[2<<ippph->ihl];
	else
		return NULL;
}

static inline u32 hdr_len(const struct ippphdr *ippph) {
	if(ippph->has_ext_hdr==0)
		return 8 + (8<<ippph->ihl);
	else
	{
		struct ext_hdr_addr *exhrad = ext_hdr_addr(ippph);
		return ntohs(exhrad->addr[ippph->has_ext_hdr-2]);
	}
}

static inline __u8 getHdrLen(struct ippp_addr* daddrpp, struct ippp_addr* saddrpp, __u8 level) {
	__u8 hdrlen4B, hdrlen;
	if((daddrpp->type == 0) && (saddrpp->type == 0)) {
		hdrlen4B = daddrpp->len + saddrpp->len + 2;
	} else if((daddrpp->type == 1) && (saddrpp->type == 1)) {
		hdrlen4B = daddrpp->len + saddrpp->len + 2 +
		((daddrpp->base > saddrpp->base) ? daddrpp->base - saddrpp->base : saddrpp->base - daddrpp->base);
	} else if((daddrpp->type == 0) && (saddrpp->type == 1)) {
		hdrlen4B = daddrpp->len + saddrpp->len + 2 +
		(((level - saddrpp->len) > daddrpp->base) ? level - saddrpp->len - daddrpp->base : 0);
	} else if((daddrpp->type == 1) && (saddrpp->type == 0)) {
		hdrlen4B = daddrpp->len + saddrpp->len + 2 +
		(((level - daddrpp->len) > saddrpp->base) ? level - daddrpp->len - saddrpp->base : 0);
	}
	for(int i = 0; i < 5; i++){
		if(hdrlen4B <= 2<<i){
			hdrlen = i;
			break;
		}
	}
	return hdrlen;
}
// -----------------------------------------------------------------------------------------------------------
// config

int config_init(void);
void config_exit(void);

#pragma pack(1)
struct listNode {
    struct listNode* prev;
    struct listNode* next;
    char name[0];
};

struct List {
    struct listNode *head;
    __u32 len; 
    spinlock_t lock;
};
#pragma pack()

#define list_for_each_node(head, node)				\
	for(struct listNode* node = head; node != head; node = node->next)

struct listNode* findNode(struct listNode* head, const char* namestr, int offset);

static inline struct listNode* addNode(struct listNode* head, struct listNode* ln) {
    // if(findNode(head, ln->name, offset) != NULL) // duplicate check
    //     return head;
    if(!head) {
        ln->next = ln;
        ln->prev = ln;
    } else {
        ln->next = head;
        ln->prev = head->prev;
        head->prev->next = ln;
        head->prev = ln;
    }
    return ln;
}

static inline struct listNode* rmNode(struct listNode* head, struct listNode* ln) {
    if(head == ln) {
        if(ln->next != ln)
            head = ln->next;
        else
            head = NULL;
    }
    ln->prev->next = ln->next;
    ln->next->prev = ln->prev;
    return head;
}

static inline struct listNode* delNode(struct listNode* head, struct listNode* ln) {
	rmNode(head, ln);
    kfree(ln);
    return head;
}
// -----------------------------------------------------------------------------------------------------------
// unitnet

extern struct unitnet *rootUnitnet;
extern struct List if_global_list;
extern struct List unitnet_list;

#pragma pack(1)
struct gate;
struct unitnet;

struct ifAddr {
    struct listNode node;
    __be32 addr;
    __u8 type;		// 0:normal, 1:sup, 2:sub
    const struct in_ifaddr *ifa;
    struct if_* if_;
    struct gate* gate_;
    // struct unitnet* supsubnet;
};

struct if_ {
    struct listNode node;
    struct listNode unitnetnode;
    char name[16];
    const struct net_device *dev;
    struct unitnet* un;
    struct List ifaddr_list;
};

struct gate {
    struct listNode subnode;
    struct listNode supnode;
    __u8 type;			// 0:internal,1:external
	__be32 subgate;
    __be32 supgate;
    struct ifAddr* subaddr;
    struct ifAddr* supaddr;
    struct unitnet* subnet;
    struct unitnet* supnet;
    __u8 relative : 1,
        netprelen : 7;
    __u8 baselevel : 4,
          levellen : 4;
    __be32 addr[16];

	// virtual unitnet
	bool whole;		// whole unitnet or not
	struct {
		__be32 addrblock;
		__u8 prefixlen;
		struct ippp_addr subaddr;
	} addrmap[];
};

struct alias_map;

struct unitnet {
    struct listNode node;
    char name[16];
    __u8 type;			// 0:internal,1:external
    __u8 level;
    struct List if_list;
    struct List supgateway_list;
	struct alias_map *map;
};

struct external_gate {
    struct listNode subnode;
    struct listNode supnode;
    __u8 type;			// 0:internal,1:external
    __u8 uplevel;
    __be32 upaddr;
	__be32 downaddr;
    struct external_unitnet* up;
    struct external_unitnet* down;
};

struct external_unitnet {
    struct listNode node;
    char name[16];
    __u8 type;			// 0:internal,1:external
    __u8 level;
    struct List subgateway_list;
    struct List supgateway_list;
};

struct Class {
    struct listNode node;
    char name[16];
    struct List external_unitnet_list;
};

#pragma pack()

// -----------------------------------------------------------------------------------------------------------
// route

#pragma pack(1)
struct flowipp {
	struct flowi4    fl4;
    struct ippp_addr locaddr,
                     rmtaddr;
	struct unitnet* un;
} __attribute__((__aligned__(BITS_PER_LONG/8)));
#pragma pack()

struct rtable *ippp_route_output_ports(struct net *net, struct flowi4 *fl4,
	struct sock *sk,
	__be32 daddr, __be32 saddr,
	__be16 dport, __be16 sport,
	__u8 proto, __u8 tos, int oif);
struct rtable *ippp_route_connect(struct flowipp *flpp,
   struct ippp_addr dst, struct ippp_addr src,
   int oif, u8 protocol,
   __be16 sport, __be16 dport,
   struct sock *sk);
struct rtable *ippp_route_newports(struct flowipp *flpp, struct rtable *rt,
	__be16 orig_sport, __be16 orig_dport,
	__be16 sport, __be16 dport,
	struct sock *sk);
int ippp_route_input_noref(struct sk_buff *skb, struct net_device *dev);
struct rtable *__ippp_route_output_key(struct net *net, struct flowi4 *flp);
struct rtable *ippp_route_output_flow(struct net *net, struct flowipp *flpp, const struct sock *sk, struct sk_buff *skb, bool src);
// -----------------------------------------------------------------------------------------------------------
// socket

#pragma pack(1)
struct l4pp_sock {
	union{
		struct tcp_sock tcp;
		struct udp_sock udp;
	};
	struct flowipp flpp;
};
#pragma pack()

static inline struct l4pp_sock *l4pp_sk(const struct sock *sk) {
	return (struct l4pp_sock *)sk;
}
int ippp_setsockopt(struct sock *sk, int level, int optname, sockptr_t optval, unsigned int optlen);
int ippp_getsockopt(struct sock *sk, int level, int optname, char __user *optval, int __user *optlen);
void inetpp_cleanup_sock(struct sock *sk);
void inetpp_sock_destruct(struct sock *sk);
int inetpp_register_protosw(struct inet_protosw *p);
void inetpp_unregister_protosw(struct inet_protosw *p);
// -----------------------------------------------------------------------------------------------------------
// ippp

int ippp_rcv_finish(struct net *net, struct sock *sk, struct sk_buff *skb);
int ippp_local_out(struct net *net, struct sock *sk, struct sk_buff *skb);
void ippp_list_rcv(struct list_head *head, struct packet_type *pt,
		   struct net_device *orig_dev);
int ippp_local_deliver_finish(struct net *net, struct sock *sk, struct sk_buff *skb);
int ippp_local_deliver(struct sk_buff *skb);
void ippp_protocol_deliver_rcu(struct net *net, struct sk_buff *skb, int protocol);
int ippp_forward(struct sk_buff *skb);
int ippp_finish_output(struct net *net, struct sock *sk, struct sk_buff *skb);
int ippp_output(struct net *net, struct sock *sk, struct sk_buff *skb);
void ippp_flush_pending_frames(struct sock *sk);
int ippp_append_data(struct sock *sk, struct flowipp *flpp,
	int getfrag(void *from, char *to, int offset, int len,
			int odd, struct sk_buff *skb),
	void *from, int length, int transhdrlen,
	struct ipcm_cookie *ipc, struct rtable **rtp,
	unsigned int flags);
int ippp_rcv(struct sk_buff *skb, struct net_device *dev, struct packet_type *pt, struct net_device *orig_dev);
// -----------------------------------------------------------------------------------------------------------
// sysctl

#pragma pack(1)
struct sysctl_net {
    struct ctl_table_header *ippp_reg_table;
	bool forwarding;
	struct ctl_table ippp_table[1];
};
#pragma pack()

extern unsigned int sysctl_net_id __read_mostly;

int __init sysctl_init(void);
void sysctl_exit(void);
// -----------------------------------------------------------------------------------------------------------
// protocol

extern struct net_protocol __rcu *inetpp_protos_c[MAX_INET_PROTOS];

int inetpp_add_protocol(const struct net_protocol *prot, unsigned char protocol);
int inetpp_del_protocol(const struct net_protocol *prot, unsigned char protocol);
// -----------------------------------------------------------------------------------------------------------
// udp / tcp

static inline __wsum inetpp_compute_pseudo(struct sk_buff *skb, int proto) {
	return csum_tcpudp_nofold(
		ippp_hdr(skb)->addr[ippp_hdr(skb)->dst_len + ippp_hdr(skb)->src_len + 1],
		ippp_hdr(skb)->addr[ippp_hdr(skb)->dst_len],
		skb->len, proto, 0);
}

// -----------------------------------------------------------------------------------------------------------
// udp

#include <net/udp.h>

extern struct proto udppp_prot;
extern const struct proto_ops inetpp_dgram_ops;

int udppp_sendmsg(struct sock *sk, struct msghdr *msg, size_t len);
int udppp_recvmsg(struct sock *sk, struct msghdr *msg, size_t len,int flags, int *addr_len);
int udppp_rcv(struct sk_buff *skb);
void udppp_early_demux(struct sk_buff *skb);
void ippp_datagram_release_cb(struct sock *sk);
int ippp_datagram_connect(struct sock *sk, struct sockaddr *uaddr, int addr_len);
int ippp_datagram_send_ctl(struct net *net, struct sock *sk, struct msghdr *msg, struct flowipp flpp, struct ipcm_cookie *ipc);
int udppp_proc_init(struct net *net);
void udppp_proc_exit(struct net *net);
int udppp_init(void);
void udppp_exit(void);
struct sk_buff *__ippp_make_skb(struct sock *sk, struct flowipp *flpp, struct sk_buff_head *queue, struct inet_cork *cork);

static inline struct sk_buff *ippp_finish_skb(struct sock *sk) {
	return __ippp_make_skb(sk, &(((struct l4pp_sock*)sk)->flpp) , &sk->sk_write_queue, &inet_sk(sk)->cork.base);
}
int ippp_send_skb(struct net *net, struct sk_buff *skb);
struct sk_buff *ippp_make_skb(struct sock *sk, struct flowipp *flpp,
			    int getfrag(void *from, char *to, int offset, int len, int odd, struct sk_buff *skb),
			    void *from, int length, int transhdrlen, struct ipcm_cookie *ipc, struct rtable **rtp,
			    struct inet_cork *cork, unsigned int flags);
int ippp_recv_error(struct sock *sk, struct msghdr *msg, int len, int *addr_len);
// -----------------------------------------------------------------------------------------------------------
// tcp

#include <net/tcp.h>

extern struct proto tcppp_prot;
extern const struct proto_ops inetpp_stream_ops;
extern struct request_sock_ops tcppp_request_sock_ops;
extern const struct tcp_request_sock_ops tcp_request_sock_ippp_ops;

#pragma pack(1)
struct tcp_pp_request_sock {
	struct tcp_request_sock treq;
	struct flowipp flpp;
};

struct tcp_pp_timewait_sock {
	struct tcp_timewait_sock tcp_twsk;
	struct flowipp flpp;
};
#pragma pack()

int tcp_pp_rcv(struct sk_buff *skb);
int tcppp_init(void);
void tcppp_exit(void);
void tcppp_early_demux(struct sk_buff *skb);
int tcppp_proc_init(struct net *net);
void tcppp_proc_exit(struct net *net);
int ippp_queue_xmit(struct sock *sk, struct sk_buff *skb, struct flowi *fl);
int ippp_xmit(struct sock *sk, struct sk_buff *skb, struct rtable *rt, int tos,
					struct ippp_addr *daddrpp, struct ippp_addr *saddrpp, bool sock_type);

static inline void __tcp_pp_send_check(struct sk_buff *skb, __be32 saddr, __be32 daddr) {
	struct tcphdr *th = tcp_hdr(skb);

	th->check = ~tcp_v4_check(skb->len, saddr, daddr, 0);
	skb->csum_start = skb_transport_header(skb) - skb->head;
	skb->csum_offset = offsetof(struct tcphdr, check);
}

struct dst_entry *inetpp_csk_route_child_sock(const struct sock *sk,
	struct sock *newsk,
	const struct request_sock *req);
struct dst_entry *inetpp_csk_route_req(const struct sock *sk, struct flowipp *flpp, const struct tcp_pp_request_sock *treqpp);
__u32 cookie_pp_init_sequence(const struct sk_buff *skb, __u16 *mssp);
struct sock *cookie_pp_check(struct sock *sk, struct sk_buff *skb);

static siphash_aligned_key_t ts_secret;

static __always_inline void ts_secret_init(void) {
	net_get_random_once(&ts_secret, sizeof(ts_secret));
}

static inline u32 _secure_tcp_ts_off(const struct net *net, __be32 saddr, __be32 daddr) {
	if (READ_ONCE(net->ipv4.sysctl_tcp_timestamps) != 1)
		return 0;

	ts_secret_init();
	return siphash_2u32((__force u32)saddr, (__force u32)daddr,
			    &ts_secret);
}

int tcp_pp_ao_calc_key_sk(struct tcp_ao_key *mkt, u8 *key,
	const struct sock *sk, __be32 sisn,
	__be32 disn, bool send);
int tcp_pp_ao_calc_key_rsk(struct tcp_ao_key *mkt, u8 *key, struct request_sock *req);
struct tcp_ao_key *tcp_pp_ao_lookup(const struct sock *sk,
	struct sock *addr_sk,
	int sndid, int rcvid);
struct tcp_ao_key *tcp_pp_ao_lookup_rsk(const struct sock *sk,
	struct request_sock *req,
	int sndid, int rcvid);
int tcp_pp_ao_hash_skb(char *ao_hash, struct tcp_ao_key *key,
	const struct sock *sk, const struct sk_buff *skb,
	const u8 *tkey, int hash_offset, u32 sne);
int tcp_pp_parse_ao(struct sock *sk, int cmd, sockptr_t optval, int optlen);
int tcp_pp_ao_synack_hash(char *ao_hash, struct tcp_ao_key *ao_key,
	struct request_sock *req, const struct sk_buff *skb,
	int hash_offset, u32 sne);
struct sock *__inetpp_lookup_established(const struct net *net,
	struct ippp_addr *saddr, __be16 sport,
	struct ippp_addr *daddr, u16 hnum,
	const int dif, const int sdif);
struct sock *inetpp_lookup_listener(const struct net *net,
	struct sk_buff *skb, int doff,
	struct ippp_addr *saddr, __be16 sport,
	struct ippp_addr *daddr, u16 hnum,
	const int dif, const int sdif);
static inline struct sock *__inetpp_lookup_skb(
		struct sk_buff *skb, int doff,
		const __be16 sport,
		const __be16 dport,
		int iif, int sdif,
		bool *refcounted) {
	bool prefetched;
	struct sock *sk = skb_steal_sock(skb, refcounted, &prefetched);
	const struct ippphdr *ippph = ippp_hdr(skb);
	
	if (sk)
		return sk;
	// skb_dst is uninitialized because input_noref was not executed, which will cause system crash.
	return __inet_lookup(dev_net(skb->dev), skb,
				doff, ippph->addr[ippph->dst_len + ippph->src_len + 1], sport,
				ippph->addr[ippph->dst_len], dport, iif, sdif,
				refcounted);
}

static int __ippp_options_echo(struct net *net, struct ip_options *dopt,
	struct sk_buff *skb, const struct ip_options *sopt) {
	unsigned char *sptr, *dptr;
	int soffset, doffset;
	int	optlen;

	memset(dopt, 0, sizeof(struct ip_options));

	if (sopt->optlen == 0)
	return 0;

	sptr = skb_network_header(skb);
	dptr = dopt->__data;

	if (sopt->rr) {
	optlen  = sptr[sopt->rr+1];
	soffset = sptr[sopt->rr+2];
	dopt->rr = dopt->optlen + sizeof(struct iphdr);
	memcpy(dptr, sptr+sopt->rr, optlen);
	if (sopt->rr_needaddr && soffset <= optlen) {
	if (soffset + 3 > optlen)
		return -EINVAL;
	dptr[2] = soffset + 4;
	dopt->rr_needaddr = 1;
	}
	dptr += optlen;
	dopt->optlen += optlen;
	}
	if (sopt->ts) {
	optlen = sptr[sopt->ts+1];
	soffset = sptr[sopt->ts+2];
	dopt->ts = dopt->optlen + sizeof(struct iphdr);
	memcpy(dptr, sptr+sopt->ts, optlen);
	if (soffset <= optlen) {
	if (sopt->ts_needaddr) {
		if (soffset + 3 > optlen)
			return -EINVAL;
		dopt->ts_needaddr = 1;
		soffset += 4;
	}
	if (sopt->ts_needtime) {
		if (soffset + 3 > optlen)
			return -EINVAL;
		if ((dptr[3]&0xF) != IPOPT_TS_PRESPEC) {
			dopt->ts_needtime = 1;
			soffset += 4;
		} else {
			dopt->ts_needtime = 0;

			if (soffset + 7 <= optlen) {
				__be32 addr;

				memcpy(&addr, dptr+soffset-1, 4);
				if (inet_addr_type(net, addr) != RTN_UNICAST) {
					dopt->ts_needtime = 1;
					soffset += 8;
				}
			}
		}
	}
	dptr[2] = soffset;
	}
	dptr += optlen;
	dopt->optlen += optlen;
	}
	if (sopt->srr) {
	unsigned char *start = sptr+sopt->srr;
	__be32 faddr;

	optlen  = start[1];
	soffset = start[2];
	doffset = 0;
	if (soffset > optlen)
	soffset = optlen + 1;
	soffset -= 4;
	if (soffset > 3) {
	memcpy(&faddr, &start[soffset-1], 4);
	for (soffset -= 4, doffset = 4; soffset > 3; soffset -= 4, doffset += 4)
		memcpy(&dptr[doffset-1], &start[soffset-1], 4);
	/*
	* RFC1812 requires to fix illegal source routes.
	*/
	if (memcmp(&ip_hdr(skb)->saddr,
			&start[soffset + 3], 4) == 0)
		doffset -= 4;
	}
	if (doffset > 3) {
	dopt->faddr = faddr;
	dptr[0] = start[0];
	dptr[1] = doffset+3;
	dptr[2] = 4;
	dptr += doffset+3;
	dopt->srr = dopt->optlen + sizeof(struct iphdr);
	dopt->optlen += doffset+3;
	dopt->is_strictroute = sopt->is_strictroute;
	}
	}
	if (sopt->cipso) {
	optlen  = sptr[sopt->cipso+1];
	dopt->cipso = dopt->optlen+sizeof(struct iphdr);
	memcpy(dptr, sptr+sopt->cipso, optlen);
	dptr += optlen;
	dopt->optlen += optlen;
	}
	while (dopt->optlen & 3) {
	*dptr++ = IPOPT_END;
	dopt->optlen++;
	}
	return 0;
}

static inline struct ip_options_rcu *tcp_pp_save_options(struct net *net,
							 struct sk_buff *skb)
{
	const struct ip_options *opt = &TCP_SKB_CB(skb)->header.h4.opt;
	struct ip_options_rcu *dopt = NULL;

	if (opt->optlen) {
		int opt_size = sizeof(*dopt) + opt->optlen;

		dopt = kmalloc(opt_size, GFP_ATOMIC);
		if (dopt && __ippp_options_echo(net, &dopt->opt, skb, opt)) {
			kfree(dopt);
			dopt = NULL;
		}
	}
	return dopt;
}
int inetpp_sk_rebuild_header(struct sock *sk);
// -----------------------------------------------------------------------------------------------------------
// sec

extern unsigned int sec_net_id __read_mostly;

#pragma pack(1)
struct xfrmpp_state {
	struct xfrm_state x;
	struct listNode node;
	struct ippp_addr daddr, saddr;
	__u8 daddr_prefix_len, saddr_prefix_len, direction, daddr_level;
};

struct sec_net {
	struct xfrmpp_state* xfrmpp_states;
};
#pragma pack()

#ifdef SEC
int __init sec_init(void);
void sec_exit(void);
int xfrmpp_register_type(const struct xfrm_type *type, unsigned short family);
void xfrmpp_unregister_type(const struct xfrm_type *type, unsigned short family);
#endif
int __init ah4_init(void);
void ah4_fini(void);
int __init esp4_init(void);
void esp4_fini(void);
const struct xfrm_type *xfrmpp_get_type(u8 proto, unsigned short family);
struct xfrmpp_state *xfrmpp_state_alloc(struct net *net);
// struct xfrm_algo_desc *xfrm_calg_get_byname(const char *name, int probe);
// -----------------------------------------------------------------------------------------------------------
// netfilter

extern unsigned int nf_net_id __read_mostly;

#pragma pack(1)
struct nf_net {
	struct nf_hook_entries __rcu *hooks_ippp[NF_INET_NUMHOOKS];
};

struct translate_node {
	struct listNode node;
	struct net_device *base_dev;
	struct net_device *dev;
};
#pragma pack()

int nf_dstack_init(void);
void nf_dstack_exit(void);
int nf_encap_init(void);
void nf_encap_exit(void);
int encap_newlink(struct net *net, struct net_device *dev, char* name);
int encap_dellink(struct net *net, struct net_device *dev);
bool is_translate_dev(struct net* net, struct net_device *dev);
int nf_translate_init(void);
void nf_translate_exit(void);
int translate_newlink(struct net *net, struct net_device *base_dev, char* name);
int translate_dellink(struct net *net, struct net_device *dev);
int nf_nat_init(void);
void nf_nat_exit(void);
int nat_newlink(struct net *net, struct ifAddr* ifa, __be32 prefix, __u8 prefix_len);
int nat_dellink(struct net *net, struct ifAddr* ifa, __be32 prefix, __u8 prefix_len);
int __init nf_init(void);
void nf_exit(void);
int nf_register_net_hooks_pp(struct net *net, const struct nf_hook_ops *reg, unsigned int n);
void nf_unregister_net_hooks_pp(struct net *net, const struct nf_hook_ops *reg, unsigned int hookcount);
static inline int nf_hook_pp(unsigned int hooknum, struct net *net,
	struct sock *sk, struct sk_buff *skb,
	struct net_device *in, struct net_device *out,
	int (*okfn)(struct net *, struct sock *, struct sk_buff *))
{
	int ret = 1;
	rcu_read_lock();
	struct nf_hook_entries* hook_head = rcu_dereference(((struct nf_net*)net_generic(net, nf_net_id))->hooks_ippp[hooknum]);
	if (hook_head) {
		struct nf_hook_state state;
		nf_hook_state_init(&state, hooknum, NFPROTO_IPPP, in, out, sk, net, okfn);
		ret = nf_hook_slow(skb, &state, hook_head, 0);
	}
	rcu_read_unlock();
	return ret;
}

static inline int NF_HOOK_PP(unsigned int hooknum, struct net *net, struct sock *sk, struct sk_buff *skb,
	struct net_device *in, struct net_device *out,
	int (*okfn)(struct net *, struct sock *, struct sk_buff *))
{
	int ret = nf_hook_pp(hooknum, net, sk, skb, in, out, okfn);
	if (ret == 1)
		ret = okfn(net, sk, skb);
	return ret;
}
// -----------------------------------------------------------------------------------------------------------
// ippptables

void netlink_rcv_msg_tables(struct sk_buff *skb);
unsigned int ipppt_do_table(void *priv, struct sk_buff *skb, const struct nf_hook_state *state);
void *ipppt_alloc_initial_table(const struct xt_table *info);
int ipppt_register_table(struct net *net, const struct xt_table *table, const struct ipt_replace *repl,
	const struct nf_hook_ops *template_ops);
// -----------------------------------------------------------------------------------------------------------
// alias

#include <linux/hashtable.h>
#include <linux/jhash.h>
#include <linux/slab.h>

#define MAP_BITS 6  // 2^6 = 64buckets Hash table size, adjustable as needed

#pragma pack(1)
struct map_entry {
    struct hlist_node node;
    uint32_t key_len;       // not including '\0'
    char *key;
    __be32 value;
};

struct alias_map {
    struct hlist_head table[1 << MAP_BITS];
    spinlock_t lock;
    int count;
	struct unitnet* un;
	__be32 master;
};
#pragma pack()

static inline uint32_t map_hash(const char *key, uint32_t len) {
    return jhash(key, len, 0);
}

void map_init(struct alias_map *m);
int map_add(struct alias_map *m, char *key, uint32_t len, __be32 value);
int map_get_by_key(struct alias_map *m, const char *key, uint32_t len, struct map_entry **entry);
int map_get_by_value(struct alias_map *m, __be32 value, struct map_entry **entry);
int __attribute__((unused)) map_del_by_key(struct alias_map *m, const char *key);
int map_del_by_value(struct alias_map *m, __be32 value);
int __attribute__((unused)) map_mod_by_key(struct alias_map *m, const char *key, __be32 value);
int map_mod_by_value(struct alias_map *m, __be32 value, char *key);
void map_destroy(struct alias_map *m);
int map_serialize(struct alias_map *m, char *buf, size_t *buf_len);
int __attribute__((unused)) map_save_to_file(struct alias_map *m, const char *path);
int map_load_from_file(struct alias_map *m, const char *path);
// -----------------------------------------------------------------------------------------------------------
// debug

#define DEBUG_LOG(fmt, ...) printk(KERN_NOTICE"DEBUG_LOG %s %s %d --"fmt" \n", \
	__FILE__, __func__, __LINE__, ##__VA_ARGS__)

// print string in hex format
static inline void printkHex(const unsigned char *buf, const int num) {
	char buf2[1000];
	char* ptr = buf2;
	for(int i = 0; i < num; i++)
	{
		sprintf(ptr,"%02X ", buf[i]);
		ptr += 3;
		if ((i+1)%16 == 0) {
			sprintf(ptr,"%c", '\n');
			ptr++;
		}
	}
	printk("%s\n",buf2);
}
// -----------------------------------------------------------------------------------------------------------

#endif	/* _IPPP_H */