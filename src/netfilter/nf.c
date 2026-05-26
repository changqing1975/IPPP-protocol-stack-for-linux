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
#include "../ipppk.h"

unsigned int nf_net_id __read_mostly;
static DEFINE_MUTEX(nf_hook_mutex);

static struct nf_hook_entries *allocate_hook_entries_size(u16 num)
{
	struct nf_hook_entries *e;
	size_t alloc = sizeof(*e) +
		       sizeof(struct nf_hook_entry) * num +
		       sizeof(struct nf_hook_ops *) * num +
		       sizeof(struct nf_hook_entries_rcu_head);

	if (num == 0)
		return NULL;

	e = kvzalloc(alloc, GFP_KERNEL_ACCOUNT);
	if (e)
		e->num_hook_entries = num;
	return e;
}

static struct nf_hook_entries *
nf_hook_entries_grow(const struct nf_hook_entries *old,
		     const struct nf_hook_ops *reg)
{
	unsigned int alloc_entries = 1;
	unsigned int old_entries = old ? old->num_hook_entries : 0;
	struct nf_hook_ops **orig_ops = NULL;

	if (old) {
		orig_ops = nf_hook_entries_get_hook_ops(old);
		alloc_entries += old_entries;
	}

	if (alloc_entries > 1024)
		return ERR_PTR(-E2BIG);

	struct nf_hook_entries *new = allocate_hook_entries_size(alloc_entries);
	if (!new)
		return ERR_PTR(-ENOMEM);

	struct nf_hook_ops **new_ops = nf_hook_entries_get_hook_ops(new);

	unsigned int i = 0;
	unsigned int nhooks = 0;
	bool inserted = false;
	while (i < old_entries) {
		if (inserted || reg->priority > orig_ops[i]->priority) {
			new_ops[nhooks] = (void *)orig_ops[i];
			new->hooks[nhooks] = old->hooks[i];
			i++;
		} else {
			new_ops[nhooks] = (void *)reg;
			new->hooks[nhooks].hook = reg->hook;
			new->hooks[nhooks].priv = reg->priv;
			inserted = true;
		}
		nhooks++;
	}

	if (!inserted) {
		new_ops[nhooks] = (void *)reg;
		new->hooks[nhooks].hook = reg->hook;
		new->hooks[nhooks].priv = reg->priv;
	}

	return new;
}

static void __nf_hook_entries_free(struct rcu_head *h)
{
	struct nf_hook_entries_rcu_head *head;

	head = container_of(h, struct nf_hook_entries_rcu_head, head);
	kvfree(head->allocation);
}

static void nf_hook_entries_free(struct nf_hook_entries *e)
{
	struct nf_hook_entries_rcu_head *head;
	struct nf_hook_ops **ops;
	unsigned int num;

	if (!e)
		return;

	num = e->num_hook_entries;
	ops = nf_hook_entries_get_hook_ops(e);
	head = (void *)&ops[num];
	head->allocation = e;
	call_rcu(&head->head, __nf_hook_entries_free);
}

static int _nf_register_net_hook_pp(struct net *net, const struct nf_hook_ops *reg) {
	struct nf_net* nf_net = net_generic(net, nf_net_id);
	struct nf_hook_entries __rcu **pp = nf_net->hooks_ippp + reg->hooknum;

	mutex_lock(&nf_hook_mutex);

	struct nf_hook_entries* p = rcu_dereference_protected(*pp, lockdep_is_held(&nf_hook_mutex));
	struct nf_hook_entries* new_hooks = nf_hook_entries_grow(p, reg);

	if (!IS_ERR(new_hooks)) {
		rcu_assign_pointer(*pp, new_hooks);
	}

	mutex_unlock(&nf_hook_mutex);
	if (IS_ERR(new_hooks))
		return PTR_ERR(new_hooks);

	nf_hook_entries_free(p);
	return 0;
}

static int nf_register_net_hook_pp(struct net *net, const struct nf_hook_ops *reg) {
	if (reg->pf == NFPROTO_IPPP)
        return _nf_register_net_hook_pp(net, reg);
	else
		return nf_register_net_hook(net, reg);
}

static void _nf_unregister_net_hook_pp(struct net *net, const struct nf_hook_ops *reg) {

}

static void nf_unregister_net_hook_pp(struct net *net, const struct nf_hook_ops *reg) {
	if (reg->pf == NFPROTO_IPPP) {
		_nf_unregister_net_hook_pp(net, reg);
	} else {
		nf_unregister_net_hook(net, reg);
	}
}

int nf_register_net_hooks_pp(struct net *net, const struct nf_hook_ops *reg, unsigned int n) {
	unsigned int i;
	int err = 0;

	for (i = 0; i < n; i++) {
		err = nf_register_net_hook_pp(net, &reg[i]);
		if (err)
			goto err;
	}
	return err;

err:
	if (i > 0)
		nf_unregister_net_hooks_pp(net, reg, i);
	return err;
}

void nf_unregister_net_hooks_pp(struct net *net, const struct nf_hook_ops *reg, unsigned int hookcount) {
	unsigned int i;

	for (i = 0; i < hookcount; i++)
		nf_unregister_net_hook_pp(net, &reg[i]);
}

static int __net_init nf_init_net(struct net *net) {
	// struct nf_net* nf_net = net_generic(net, nf_net_id);

	return 0;
}

static void __net_exit nf_exit_net(struct net *net) {
	// struct nf_net* nf_net = net_generic(net, nf_net_id);

}

static struct pernet_operations nf_net_ops = {
	.init = nf_init_net,
	.exit = nf_exit_net,
	.id   = &nf_net_id,
	.size = sizeof(struct nf_net),
};

int __init nf_init(void) {
	int err;

	err = register_pernet_device(&nf_net_ops);
	if (err < 0)
		return err;

	return err;
}

void nf_exit(void) {
	unregister_pernet_device(&nf_net_ops);
}