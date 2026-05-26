#include <crypto/hash.h>
#include <crypto/utils.h>
#include <linux/err.h>
#include <linux/module.h>
#include <linux/slab.h>
#include <net/ip.h>
#include <net/xfrm.h>
#include <net/ah.h>
#include <linux/crypto.h>
#include <linux/pfkeyv2.h>
#include <linux/scatterlist.h>
#include <net/icmp.h>
#include <net/protocol.h>
#include "../ipppk.h"

struct ah_skb_cb {
	struct xfrm_skb_cb xfrm;
	void *tmp;
};

#define AH_SKB_CB(__skb) ((struct ah_skb_cb *)&((__skb)->cb[0]))

static void *ah_alloc_tmp(unsigned int size, struct crypto_ahash *ahash, int nfrags) {
	unsigned int len = size + crypto_ahash_digestsize(ahash);
	len = ALIGN(len, crypto_tfm_ctx_alignment());
	len += sizeof(struct ahash_request) + crypto_ahash_reqsize(ahash);
	len = ALIGN(len, __alignof__(struct scatterlist));
	len += sizeof(struct scatterlist) * nfrags;
	return kmalloc(len, GFP_ATOMIC);
}

static inline struct ahash_request *ah_tmp_req(struct crypto_ahash *ahash, u8 *icv) {
	struct ahash_request *req;

	req = (void *)PTR_ALIGN(icv + crypto_ahash_digestsize(ahash),
				crypto_tfm_ctx_alignment());

	ahash_request_set_tfm(req, ahash);

	return req;
}

static inline struct scatterlist *ah_req_sg(struct crypto_ahash *ahash, struct ahash_request *req) {
	return (void *)ALIGN((unsigned long)(req + 1) +
			     crypto_ahash_reqsize(ahash),
			     __alignof__(struct scatterlist));
}

static void ah_output_done(void *data, int err) {
	struct sk_buff *skb = data;
	struct ip_auth_hdr *ah = ip_auth_hdr(skb);
	struct ippphdr *tmp_ippph = AH_SKB_CB(skb)->tmp;
	unsigned int ippphdr_len = 8 + (8 << tmp_ippph->ihl);
	struct xfrm_state *x = skb_dst(skb)->xfrm;
	u8 *icv = (u8*)tmp_ippph + ippphdr_len;
	if (x->props.flags & XFRM_STATE_ESN)
		icv += sizeof(__be32);
	struct ah_data *ahp = x->data;
	memcpy(ah->auth_data, icv, ahp->icv_trunc_len);
	memcpy(skb_network_header(skb), tmp_ippph, ippphdr_len);

	kfree(AH_SKB_CB(skb)->tmp);
	xfrm_output_resume(skb->sk, skb, err);
}

static int ah_output(struct xfrm_state *x, struct sk_buff *skb) {
	int err;
	struct sk_buff *trailer;
	if ((err = skb_cow_data(skb, 0, &trailer)) < 0)
		goto out;
	int nfrags = err;

	struct ippphdr *ippph = ippp_hdr(skb);
	unsigned int ippphdr_len = 8 + (8 << ippph->ihl);

	__u8 ah_hdrlen = x->props.header_len;
	int nhead = ippphdr_len + ah_hdrlen + LL_RESERVED_SPACE(skb->dev) - skb_headroom(skb);
	if (nhead <= 0) {
		nhead = 0;
	}
	pskb_expand_head(skb, nhead, 0, GFP_ATOMIC);
	skb_push(skb, ah_hdrlen);
	skb_reset_network_header(skb);

	int sglists = 0;
	int seqhi_len = 0;
	if (x->props.flags & XFRM_STATE_ESN) {
		sglists = 1;
		seqhi_len = sizeof(__be32);
	}
	err = -ENOMEM;
	//------------------------------------------------------------
	/* 申请一块内存，给各个量用
	    |------------------|
	    |      ippph       |
	    |------------------|
	    |      seqhi       |
	    |------------------|
	    |       icv        |
	    |------------------|
	    |       req        |
	    |------------------|
	    |       sg         |
	    |------------------|
	    |    seqhisg       |
	    |------------------|
	*/
	struct ah_data *ahp			= x->data;
	struct crypto_ahash *ahash	= ahp->ahash;
	struct ippphdr *tmp_ippph		= ah_alloc_tmp(ippphdr_len + seqhi_len, ahash, nfrags + sglists);
	if (!tmp_ippph)
		goto out;
	__be32 *seqhi				= (__be32 *)((char *)tmp_ippph + ippphdr_len);
	u8 *icv						= (u8 *)seqhi + seqhi_len;
	struct ahash_request *req	= ah_tmp_req(ahash, icv);
	struct scatterlist *sg		= ah_req_sg(ahash, req);
	struct scatterlist *seqhisg	= sg + nfrags;
	//------------------------------------------------------------
	// 将可变字段暂存至tmp_iph暂时保存
	ippph = ippp_hdr(skb);
	memcpy(tmp_ippph, skb_network_header(skb) + ah_hdrlen, ippphdr_len);
	memset(ippph, 0, ippphdr_len);
	ippph->ihl = tmp_ippph->ihl;
	ippph->has_ext_hdr = tmp_ippph->has_ext_hdr;
	ippph->dst_type = tmp_ippph->dst_type;
	ippph->src_type = tmp_ippph->src_type;
	ippph->tot_len = tmp_ippph->tot_len = htons(skb->len);
	/* 处理扩展头? */
	//------------------------------------------------------------
	// 设置头部各字段，包括将可变字段置0
	struct ip_auth_hdr *ah = (struct ip_auth_hdr*)(skb_network_header(skb) + ippphdr_len);
	ah->nexthdr = tmp_ippph->protocol;
	ippph->protocol = tmp_ippph->protocol = IPPROTO_AH;
	ah->reserved = 0;
	ah->hdrlen  = (ah_hdrlen >> 2) - 2;
	ah->spi = x->id.spi;
	ah->seq_no = htonl(++x->replay.oseq);
	memset(ah->auth_data, 0, ahp->icv_trunc_len);
	//------------------------------------------------------------
	// 计算认证数据
	sg_init_table(sg, nfrags + sglists);
	err = skb_to_sgvec_nomark(skb, sg, 0, skb->len);
	if (unlikely(err < 0))
		goto out_free;

	if (x->props.flags & XFRM_STATE_ESN) {
		/* Attach seqhi sg right after packet payload */
		*seqhi = htonl(XFRM_SKB_CB(skb)->seq.output.hi);
		sg_set_buf(seqhisg, seqhi, seqhi_len);
	}
	ahash_request_set_crypt(req, sg, icv, skb->len + seqhi_len);
	ahash_request_set_callback(req, 0, ah_output_done, skb);

	AH_SKB_CB(skb)->tmp = tmp_ippph;

	err = crypto_ahash_digest(req);
	if (err) {
		if (err == -EINPROGRESS)
			goto out;

		if (err == -ENOSPC)
			err = NET_XMIT_DROP;
		goto out_free;
	}

	memcpy(ah->auth_data, icv, ahp->icv_trunc_len);
	//------------------------------------------------------------
	// 回填可变字段
	memcpy(skb_network_header(skb), tmp_ippph, ippphdr_len);

out_free:
	kfree(tmp_ippph);
out:
	return err;
}

static void ah_input_done(void *data, int err) {
	struct sk_buff *skb = data;

	if (err)
		goto out;

	struct xfrm_state *x = xfrm_input_state(skb);
	struct ah_data *ahp = x->data;
	struct ippphdr *tmp_ippph = AH_SKB_CB(skb)->tmp;
	unsigned int ippphdr_len = 8 + (8 << tmp_ippph->ihl);
	u8 *auth_data = (u8 *)tmp_ippph + ippphdr_len;
	u8 *icv = (u8 *)auth_data + ahp->icv_trunc_len;

	err = crypto_memneq(icv, auth_data, ahp->icv_trunc_len) ? -EBADMSG : 0;
	if (err)
		goto out;

	struct ip_auth_hdr *ah = (struct ip_auth_hdr*)(skb_network_header(skb) + ippphdr_len);
	err = ah->nexthdr;

	int ah_hdrlen = (ah->hdrlen + 2) << 2;
	skb->network_header += ah_hdrlen;
	memcpy(skb_network_header(skb), tmp_ippph, ippphdr_len);
	__skb_pull(skb, ah_hdrlen + ippphdr_len);
	skb_reset_transport_header(skb);

out:
	kfree(AH_SKB_CB(skb)->tmp);
	xfrm_input_resume(skb, err);
}

static int ah_input(struct xfrm_state *x, struct sk_buff *skb) {
	int err = -ENOMEM;

	struct ippphdr *ippph = ippp_hdr(skb);
	unsigned int ippphdr_len = 8 + (8 << ippph->ihl);
	skb_pull(skb, ippphdr_len);
	if (!pskb_may_pull(skb, sizeof(struct ip_auth_hdr)))
		goto out;

	struct ip_auth_hdr *ah = (struct ip_auth_hdr *)skb->data;
	int ah_hdrlen = (ah->hdrlen + 2) << 2;
	struct ah_data *ahp = x->data;
	if (x->props.flags & XFRM_STATE_ALIGN4) {
		if (ah_hdrlen != XFRM_ALIGN4(sizeof(struct ip_auth_hdr) + ahp->icv_full_len) && ah_hdrlen != XFRM_ALIGN4(sizeof(struct ip_auth_hdr) + ahp->icv_trunc_len))
			goto out;
	} else {
		if (ah_hdrlen != XFRM_ALIGN8(sizeof(struct ip_auth_hdr) + ahp->icv_full_len) && ah_hdrlen != XFRM_ALIGN8(sizeof(struct ip_auth_hdr) + ahp->icv_trunc_len))
			goto out;
	}

	if (!pskb_may_pull(skb, ah_hdrlen))
		goto out;

	/* We are going to _remove_ AH header to keep sockets happy, so... Later this can change. */
	if (skb_unclone(skb, GFP_ATOMIC))
		goto out;

	skb->ip_summed = CHECKSUM_NONE;
	int nfrags;
	struct sk_buff *trailer;
	if ((nfrags = skb_cow_data(skb, 0, &trailer)) < 0) {
		err = nfrags;
		goto out;
	}

	int sglists = 0;
	int seqhi_len = 0;
	if (x->props.flags & XFRM_STATE_ESN) {
		sglists = 1;
		seqhi_len = sizeof(__be32);
	}
	//------------------------------------------------------------
	/* 申请一块内存，给各个量用
	    |------------------|
	    |      ippph       |
	    |------------------|
	    |      seqhi       |
	    |------------------|
	    |       icv        |
	    |------------------|
	    |       req        |
	    |------------------|
	    |       sg         |
	    |------------------|
	    |    seqhisg       |
	    |------------------|
	*/
	struct crypto_ahash *ahash	= ahp->ahash;
	struct ippphdr *tmp_ippph	= ah_alloc_tmp(ippphdr_len + ahp->icv_trunc_len + seqhi_len, ahash, nfrags + sglists);
	if (!tmp_ippph) {
		err = -ENOMEM;
		goto out;
	}
	__be32 *seqhi				= (__be32 *)((char *)tmp_ippph + ippphdr_len);
	u8 *auth_data				= (u8 *)seqhi + seqhi_len;
	u8 *icv						= (u8 *)auth_data + ahp->icv_trunc_len;
	struct ahash_request *req	= ah_tmp_req(ahash, icv);
	struct scatterlist *sg		= ah_req_sg(ahash, req);
	struct scatterlist *seqhisg	= sg + nfrags;

	memcpy(tmp_ippph, ippph, ippphdr_len);
	tmp_ippph->protocol = ah->nexthdr;
	memcpy(auth_data, ah->auth_data, ahp->icv_trunc_len);

	memset(ippph, 0, ippphdr_len);
	ippph->ihl = tmp_ippph->ihl;
	ippph->has_ext_hdr = tmp_ippph->has_ext_hdr;
	ippph->dst_type = tmp_ippph->dst_type;
	ippph->src_type = tmp_ippph->src_type;
	ippph->tot_len = tmp_ippph->tot_len;
	ippph->protocol = IPPROTO_AH;
	memset(ah->auth_data, 0, ahp->icv_trunc_len);
	// 处理扩展头?
	skb_push(skb, ippphdr_len);
	//------------------------------------------------------------
	// 计算认证数据
	sg_init_table(sg, nfrags + sglists);
	err = skb_to_sgvec_nomark(skb, sg, 0, skb->len);
	if (unlikely(err < 0))
		goto out_free;

	if (x->props.flags & XFRM_STATE_ESN) {
		/* Attach seqhi sg right after packet payload */
		*seqhi = XFRM_SKB_CB(skb)->seq.input.hi;
		sg_set_buf(seqhisg, seqhi, seqhi_len);
	}
	ahash_request_set_crypt(req, sg, icv, skb->len + seqhi_len);
	ahash_request_set_callback(req, 0, ah_input_done, skb);

	AH_SKB_CB(skb)->tmp = tmp_ippph;

	err = crypto_ahash_digest(req);
	if (err) {
		if (err == -EINPROGRESS)
			goto out;

		goto out_free;
	}
	//------------------------------------------------------------
	err = crypto_memneq(icv, auth_data, ahp->icv_trunc_len) ? -EBADMSG : 0;
	if (err)
		goto out_free;
	//------------------------------------------------------------
	__skb_pull(skb, ah_hdrlen);
	skb_reset_network_header(skb);
	memcpy(skb_network_header(skb), tmp_ippph, ippphdr_len);

out_free:
	kfree (tmp_ippph);
out:
	return err;
}

static int ah_init_state(struct xfrm_state *x, struct netlink_ext_ack *extack) {
	x->props.flags |= XFRM_STATE_ALIGN4;
	if (!x->aalg) {
		goto error;
	}
	if (x->encap) {
		goto error;
	}

	struct ah_data *ahp = kzalloc(sizeof(*ahp), GFP_KERNEL);
	if (!ahp)
		return -ENOMEM;

	struct crypto_ahash *ahash = crypto_alloc_ahash(x->aalg->alg_name, 0, 0);
	if (IS_ERR(ahash)) {
		goto error;
	}

	ahp->ahash = ahash;
	if (crypto_ahash_setkey(ahash, x->aalg->alg_key, (x->aalg->alg_key_len + 7) / 8)) {
		goto error;
	}

	struct xfrm_algo_desc *aalg_desc = xfrm_aalg_get_byname(x->aalg->alg_name, 1);
	BUG_ON(!aalg_desc);

	if (aalg_desc->uinfo.auth.icv_fullbits/8 != crypto_ahash_digestsize(ahash)) {
		goto error;
	}

	ahp->icv_full_len = aalg_desc->uinfo.auth.icv_fullbits/8;
    x->aalg->alg_trunc_len = aalg_desc->uinfo.auth.icv_truncbits;
	ahp->icv_trunc_len = x->aalg->alg_trunc_len/8;
	if (x->props.flags & XFRM_STATE_ALIGN4)
		x->props.header_len = XFRM_ALIGN4(sizeof(struct ip_auth_hdr) + ahp->icv_trunc_len);
	else
		x->props.header_len = XFRM_ALIGN8(sizeof(struct ip_auth_hdr) + ahp->icv_trunc_len);
	x->data = ahp;
	return 0;

error:
	if (ahp) {
		crypto_free_ahash(ahp->ahash);
		kfree(ahp);
	}
	return -EINVAL;
}

static void ah_destroy(struct xfrm_state *x) {
	struct ah_data *ahp = x->data;

	if (!ahp)
		return;

	crypto_free_ahash(ahp->ahash);
	kfree(ahp);
}

static const struct xfrm_type ah_type = {
	.owner		= THIS_MODULE,
	.proto	    = IPPROTO_AH,
	.flags		= XFRM_TYPE_REPLAY_PROT,
	.init_state	= ah_init_state,
	.destructor	= ah_destroy,
	.input		= ah_input,
	.output		= ah_output
};

int __init ah4_init(void) {
	#ifdef SEC
	if (xfrmpp_register_type(&ah_type, AF_INETPP) < 0) {
		pr_info("%s: can't add xfrm type\n", __func__);
		return -EAGAIN;
	}
	#endif

	return 0;
}

void ah4_fini(void) {
	#ifdef SEC
	xfrmpp_unregister_type(&ah_type, AF_INETPP);
	#endif
}