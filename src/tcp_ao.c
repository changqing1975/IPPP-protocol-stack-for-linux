/*
 * INET		An implementation of the TCP Authentication Option (TCP-AO).
 *		See RFC5925.
 *
 */
 #include <crypto/hash.h>
 #include <linux/tcp.h>
 
 #include <net/tcp.h>
 #include <net/ipv6.h>
 #include "ipppk.h"
 
static int tcp_pp_ao_calc_key(struct tcp_ao_key *mkt, u8 *key,
                __be32 saddr,
                __be32 daddr,
                __be16 sport, __be16 dport,
                __be32 sisn, __be32 disn)
{

//  int err;

    return 0/* err */;
}
 
//  int tcp_pp_ao_calc_key_skb(struct tcp_ao_key *mkt, u8 *key,
//                 const struct sk_buff *skb,
//                 __be32 sisn, __be32 disn)
//  {

//  }
 
int tcp_pp_ao_calc_key_sk(struct tcp_ao_key *mkt, u8 *key,
            const struct sock *sk, __be32 sisn,
            __be32 disn, bool send)
{
    if (send)
        return tcp_pp_ao_calc_key(mkt, key, sk->sk_rcv_saddr,
                    sk->sk_daddr, htons(sk->sk_num),
                    sk->sk_dport, sisn, disn);
    else
        return tcp_pp_ao_calc_key(mkt, key, sk->sk_daddr,
                    sk->sk_rcv_saddr, sk->sk_dport,
                    htons(sk->sk_num), disn, sisn);
}
 
int tcp_pp_ao_calc_key_rsk(struct tcp_ao_key *mkt, u8 *key, struct request_sock *req) {
//  struct inet_request_sock *ireq = inet_rsk(req);

    return 0/* tcp_pp_ao_calc_key(mkt, key,
            &ireq->ir_pp_loc_addr, &ireq->ir_pp_rmt_addr,
            htons(ireq->ir_num), ireq->ir_rmt_port,
            htonl(tcp_rsk(req)->snt_isn),
            htonl(tcp_rsk(req)->rcv_isn)) */;
}
 
struct tcp_ao_key *tcp_pp_ao_lookup(const struct sock *sk,
                    struct sock *addr_sk,
                    int sndid, int rcvid)
{
    int l3index = l3mdev_master_ifindex_by_index(sock_net(sk), addr_sk->sk_bound_dev_if);
    union tcp_ao_addr *addr = (union tcp_ao_addr *)&addr_sk->sk_daddr;

    return tcp_ao_do_lookup(sk, l3index, addr, AF_INET, sndid, rcvid);
}
 
struct tcp_ao_key *tcp_pp_ao_lookup_rsk(const struct sock *sk,
                    struct request_sock *req,
                    int sndid, int rcvid)
{
	struct inet_request_sock *ireq = inet_rsk(req);
	union tcp_ao_addr *addr = (union tcp_ao_addr *)&ireq->ir_rmt_addr;
	int l3index;

	l3index = l3mdev_master_ifindex_by_index(sock_net(sk), ireq->ir_iif);
	return tcp_ao_do_lookup(sk, l3index, addr, AF_INET, sndid, rcvid);
}
 
int tcp_pp_ao_hash_skb(char *ao_hash, struct tcp_ao_key *key,
            const struct sock *sk, const struct sk_buff *skb,
            const u8 *tkey, int hash_offset, u32 sne)
{
    return 0/* tcp_ao_hash_skb(AF_INET, ao_hash, key, sk, skb, tkey,
            hash_offset, sne) */;
}
 
int tcp_pp_parse_ao(struct sock *sk, int cmd, sockptr_t optval, int optlen) {
    return 0/* tcp_parse_ao(sk, cmd, AF_INET, optval, optlen) */;
}
 
int tcp_pp_ao_synack_hash(char *ao_hash, struct tcp_ao_key *ao_key,
            struct request_sock *req, const struct sk_buff *skb,
            int hash_offset, u32 sne) {

//     int err;

    return 0/* err */;
}