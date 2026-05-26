/*
 * 		IP++ Address Management Tool——Kernel Part
 *
 * Authors:	
 *		ChangQing, <cq@ippp.xyz>
 *
 */
// ip link add link enp0s3 name enp0s3.10 type vlan id 10
// ip link add veth0 type veth peer name veth1

#include <linux/init.h>
#include <linux/module.h>
#include <linux/types.h>
#include <net/sock.h>
#include <linux/netlink.h>
#include <linux/spinlock.h>
#include <linux/inetdevice.h>
#include <linux/init.h>
#include <linux/fs.h>
#include <linux/uaccess.h>
#ifdef SEC
    #include <../net/xfrm/xfrm_hash.h>
#endif
#include "json.h"
#include "ipppk.h"

#define NETLINK_IPPP     30
#define USER_PORT        100
#define PORT_IPPP       1001
#define PORT_TABLES     1002

__u8 interlevelgateway = false;
struct List if_global_list;
struct List unitnet_list;       // internal
struct List Class_list;         // external
struct unitnet *rootUnitnet = NULL;
struct sock *nlsk = NULL;
extern struct net init_net;

inline __u8 readByte(char** from) {
    __u8 res = **from;
    (*from)++;
    return res;
}

inline __u8 minium(__u8 a, __u8 b) {
    return a < b ? a : b;
}

inline void readStr(char* to, char** from, __u8 len) {
    memset(to, 0, len);
    strncpy(to, (*from) + 1, minium(**from, len));
    *from += (1 + **from);
}

inline __be32 readIpAddr(char** from) {
    __be32 res = *((__be32*)(*from));
    (*from) += 4;
    return res;
}

inline int matches(const char *prefix, const char *string) {
	if (!*prefix)
		return 1;
	while (*string && *prefix == *string) {
		prefix++;
		string++;
	}

	return !!*prefix;
}

struct msg {
    __u8 type;
    __u8 code;
    __be16 len;
    char data[0];
};

inline int nodesNum(struct listNode* head) {
    if(head == NULL)
        return 0;
    int len = 0;
    struct listNode* ln = head;
    while(ln) {
        ln = ln->next;
        len++;
        if(ln == head)
            return len;
    }
    return -1;
}

struct listNode* findNode(struct listNode* head, const char* namestr, int offset) {
    struct listNode* ln = head;
    while(ln) {
        if(matches(ln->name + sizeof(struct listNode)*offset, namestr) == 0)
            return ln;
        ln = ln->next;
        if(ln == head)
            return NULL;
    }
    return NULL;
}

inline struct listNode* findNode2(struct listNode* head, __be32 addr) {
    struct listNode* ln = head;
    while(ln) {
        if(((struct gate*)ln)->supgate == addr)
            return ln;
        ln = ln->next;
        if(ln == head)
            return NULL;
    }
    return NULL;
}

inline struct ifAddr* findAddrFromUnitnet(struct unitnet* un, __be32 addr) {
    struct if_* cif_ = (struct if_*)(un->if_list.head);
    do {
        struct ifAddr* cifaddr = (struct ifAddr*)(cif_->ifaddr_list.head);
        do {
            if(cifaddr->addr == addr) {
                return cifaddr;
            }
            cifaddr = (struct ifAddr*)(((struct listNode*)cifaddr)->next);
        }while(cifaddr != (struct ifAddr*)(cif_->ifaddr_list.head));
        cif_ = (struct if_*)(((struct listNode*)cif_ + 1)->next - 1);
    }while(cif_ != (struct if_*)(un->if_list.head));
    return NULL;
}

inline struct external_gate* findGateFromUnitnet(struct external_unitnet* un, __be32 addr) {
    struct external_gate* gate_ = (struct external_gate*)(un->subgateway_list.head);
    do {
        if(gate_->upaddr == addr) {
            return gate_;
        }
        gate_ = (struct external_gate*)(((struct listNode*)gate_)->next);
    }while(gate_ != (struct external_gate*)(un->subgateway_list.head));
    return NULL;
}

inline struct net_device* findNet_device(const char* namestr) {
    struct net* net;
    for_each_net(net) {
        struct net_device *dev;
        for_each_netdev(net, dev) {
            if(matches(dev->name, namestr) == 0)
                return dev;
        }
    }
    return NULL;
}

inline void addrConf(const struct net_device *dev, struct if_* if_p) {
	struct in_device *in_dev = rtnl_dereference(dev->ip_ptr);
	if (!in_dev)
		return;
    struct ifAddr* ifaddr_;
	struct in_ifaddr* ifa;

	in_dev_for_each_ifa_rtnl(ifa, in_dev) {
        ifaddr_  = (struct ifAddr *)kmalloc(sizeof(struct ifAddr), GFP_KERNEL);
        ifaddr_->type = 0;
        ifaddr_->addr = ifa->ifa_local;
        ifaddr_->ifa = ifa;
        ifaddr_->if_ = if_p;
        if_p->ifaddr_list.head = addNode(if_p->ifaddr_list.head, (struct listNode*)ifaddr_);
	}
	return;
}

inline void ifConf(void) {
	const struct net_device* dev;
    struct if_* if_p;

	rtnl_lock();
    if_global_list.head = NULL;
	for_each_netdev(&init_net, dev) {
        if_p = (struct if_ *)kmalloc(sizeof(struct if_), GFP_KERNEL);
        if_p->ifaddr_list.head = NULL;
        memset(if_p->name, 0, 16);
        strcpy(if_p->name, dev->name);
        if_p->dev = dev;
        if_global_list.head = addNode(if_global_list.head, (struct listNode*)if_p);
        // addrConf(dev, if_p);                                                 // ??
	}
	rtnl_unlock();
}

inline int send_usrmsg(char *pbuf, uint16_t len) {
    // allocate memory for sk_buff
    struct sk_buff *nl_skb = nlmsg_new(len, GFP_ATOMIC);
    if(!nl_skb) {
        printk("netlink alloc failure\n");
        return -1;
    }

    /* 设置netlink消息头部 */
    struct nlmsghdr *nlh = nlmsg_put(nl_skb, 0, 0, NETLINK_IPPP, len, 0);
    if(nlh == NULL) {
        printk("nlmsg_put failaure \n");
        nlmsg_free(nl_skb);
        return -1;
    }

    // copy data and send
    memcpy(nlmsg_data(nlh), pbuf, len);
    int ret = netlink_unicast(nlsk, nl_skb, USER_PORT, MSG_DONTWAIT);

    return ret;
}

static void netlink_rcv_msg(struct sk_buff *skb) {
    if(skb->len >= nlmsg_total_size(0)) {
        if(nlmsg_hdr(skb)->nlmsg_pid == PORT_IPPP) {
            char *umsg = NLMSG_DATA(nlmsg_hdr(skb));
            struct msg* m_msg = (struct msg*)umsg;
            char tbuf[128] = {0};
            struct msg* t_msg = (struct msg*)tbuf;
            if(umsg) {
                printk("kernel recv from user: ");
                printkHex(umsg, ntohs(m_msg->len));
                if((m_msg->type) == 0) {
                    if(m_msg->code == 0) {
                        t_msg->type = 0;
                        t_msg->code = 0;
                        t_msg->len = htons(5);
                        t_msg->data[0] = interlevelgateway;
                        send_usrmsg(tbuf, 5);
                    } else if(m_msg->code == 1) {
                        interlevelgateway = m_msg->data[0];
                    }
                } else if((m_msg->type) == 1) {
                    if(m_msg->code == 0) {
                        if(m_msg->len == htons(4)) {
                            struct unitnet* un = (struct unitnet*)(unitnet_list.head);
                            char* ptr = t_msg->data;
                            t_msg->type = 1;
                            t_msg->code = 0;
                            int unitnetnum = nodesNum(unitnet_list.head);
                            int all_len = 5 + unitnetnum;
                            *ptr = unitnetnum;
                            ptr++;
                            char* ptr_unitnet_len = ptr;
                            ptr += unitnetnum;
                            for(int i = 0; i < unitnetnum; i++) {
                                struct if_* if_node = (struct if_*)(un->if_list.head);
                                int unitnet_len = 0;
                                int unitnetnamelen = strlen(un->name);
                                *ptr = unitnetnamelen;
                                ptr++;
                                strncpy(ptr, un->name, unitnetnamelen);
                                ptr += unitnetnamelen;
                                *ptr = un->level;
                                ptr++;
                                int if_num = nodesNum((struct listNode*)if_node + 1);
                                *ptr = if_num;
                                ptr++;
                                char* ptr_if_len = ptr;
                                ptr += if_num;
                                for(int j = 0; j < if_num; j++) {
                                    int if_namelen = strlen(if_node->name);
                                    *ptr = if_namelen;
                                    ptr++;
                                    strncpy(ptr, if_node->name, if_namelen);
                                    ptr += if_namelen;
                                    *(ptr_if_len + j) = if_namelen + 1;
                                    unitnet_len += (if_namelen + 1);
                                    if_node = (struct if_*)(((struct listNode*)if_node + 1)->next - 1);
                                }
                                *(ptr_unitnet_len + i) = unitnet_len + unitnetnamelen + if_num +3;
                                all_len += *(ptr_unitnet_len + i);
                                un = (struct unitnet*)(((struct listNode*)un)->next);
                            }
                            t_msg->len = htons(all_len);
                            send_usrmsg(tbuf, all_len);
                        } else {

                        }
                    } else if(m_msg->code == 1) {
                        char ifname[16];
                        struct unitnet* un = (struct unitnet *)kmalloc(sizeof(struct unitnet), GFP_KERNEL);
                        un->type = 0;
                        un->if_list.head = NULL;
                        un->supgateway_list.head = NULL;
                        char* ptr = m_msg->data;
                        readStr(un->name, &ptr, 15);
                        __u8 n = readByte(&ptr);
                        char* ptr_base = ptr;
                        ptr += n;
                        for(__u8 i = 0; i < n; i++) {
                            char* ptr_ = ptr;
                            readStr(ifname, &ptr_, 15);
                            ptr += *(ptr_base+i);
                            struct if_* if_p = (struct if_*)findNode(if_global_list.head, ifname, 1);
                            if_p->un = un;
                            un->if_list.head = (addNode(un->if_list.head?(un->if_list.head)+1:NULL, (struct listNode*)if_p + 1) - 1);
                        }
                        unitnet_list.head = addNode(unitnet_list.head, (struct listNode*)un);
                    } else if(m_msg->code == 2) {
                        char unitnetname[16];
                        char* ptr = m_msg->data;
                        readStr(unitnetname, &ptr, 15);
                        unitnet_list.head = delNode(unitnet_list.head, findNode(unitnet_list.head, unitnetname, 0));
                    } else if(m_msg->code == 3) {
                        char unitnetname[16];
                        char* ptr = m_msg->data;
                        readStr(unitnetname, &ptr, 15);
                        int level = readByte(&ptr);
                        struct unitnet *un = (struct unitnet *)findNode(unitnet_list.head, unitnetname, 0);
                        un->level = level;
                        if(level == 0) {
                            rootUnitnet = un;
                        }
                    }
                } else if((m_msg->type) == 2) {
                    if(m_msg->code == 0)
                    {
                        t_msg->type = 2;
                        t_msg->code = 0;
                        if(m_msg->len == htons(4)) {
                            struct unitnet* un = (struct unitnet*)(unitnet_list.head);
                            char* ptr_unitnet_len;
                            char* ptr = t_msg->data;
                            __u8 unitnetnum = nodesNum(unitnet_list.head);
                            __u8 all_len = 5 + unitnetnum;
                            *ptr = unitnetnum;
                            ptr++;
                            ptr_unitnet_len = ptr;
                            ptr += unitnetnum;
                            for(int i = 0; i < unitnetnum; i++) {
                                char* ptr_unitnetnum = ptr;
                                __u8 unitnetnamelen, sup_num;
                                struct gate* supgateway_l = (struct gate*)(un->supgateway_list.head);
                                char* ptr_sup_len;
                                unitnetnamelen = strlen(un->name);
                                *ptr = unitnetnamelen;
                                ptr++;
                                strncpy(ptr, un->name, unitnetnamelen);
                                ptr += unitnetnamelen;
                                sup_num = nodesNum((struct listNode*)supgateway_l + 1);
                                *ptr = sup_num;
                                ptr++;
                                ptr_sup_len = ptr;
                                ptr += sup_num;
                                for(int j = 0; j < sup_num; j++) {
                                    char* ptr_supgateway = ptr;
                                    *ptr = supgateway_l->relative << 7;
                                    *ptr |= supgateway_l->netprelen;
                                    ptr++;
                                    *ptr = supgateway_l->baselevel << 4;
                                    *ptr |= supgateway_l->levellen;
                                    ptr++;
                                    for(int k = 0; k <= supgateway_l->levellen; k++) {
                                        *((__be32*)ptr + k) = supgateway_l->addr[k];
                                    }
                                    ptr += (supgateway_l->levellen + 1)*4;
                                    *((__be32*)ptr) = supgateway_l->supgate;
                                    ptr += 4;
                                    *ptr = supgateway_l->type;
                                    ptr++;
                                    if(supgateway_l->type == 0) {
                                        struct unitnet* un = supgateway_l->supaddr->if_->un;
                                        __u8 supunitnetnamelen = strlen(un->name);
                                        *ptr = supunitnetnamelen;
                                        ptr++;
                                        strncpy(ptr, un->name, supunitnetnamelen);
                                        ptr += supunitnetnamelen;
                                        *((__be32*)ptr) = supgateway_l->supaddr->addr;
                                        ptr += 4;
                                    }
                                    *(ptr_sup_len + j) = ptr - ptr_supgateway;
                                    supgateway_l = (struct gate*)(((struct listNode*)supgateway_l + 1)->next - 1);
                                }
                                *(ptr_unitnet_len + i) = ptr - ptr_unitnetnum;
                                all_len += *(ptr_unitnet_len + i);
                                un = (struct unitnet*)(((struct listNode*)un)->next);
                            }
                            t_msg->len = htons(all_len);
                            send_usrmsg(tbuf, all_len);
                        } else {

                        }
                    } else if((m_msg->code == 1) ) {
                        char unitnetname[16];
                        char* ptr = m_msg->data;
                    readStr(unitnetname, &ptr, 15);
                        char unitnetname2[16];
                        readStr(unitnetname2, &ptr, 15);
                        struct gate* sg = (struct gate *)kmalloc(sizeof(struct gate), GFP_KERNEL);
                        sg->type = 0;
                        sg->relative = 0;
                        sg->netprelen = 0;
                        sg->baselevel = 0;
                        sg->levellen = 0;
                        sg->addr[0] = 0;
                        sg->supgate = *((__be32*)ptr);
                        struct gate* sg_head = (struct gate*)(((struct unitnet *)findNode(unitnet_list.head, unitnetname, 0))->supgateway_list.head);
                        sg_head = (struct gate*)addNode((struct listNode*)sg_head, (struct listNode*)sg);
                    } else if(m_msg->code == 2) {
                        /*
                        内部与外部单元网对接(向下的外部单元网可以不管)
                        找到find supgate
                        gate->downunitnet指向本单元网
                        gate加入本单元网supgateway_list
                        */
                        char unitnetname[16];
                        char* ptr = m_msg->data;
                        readStr(unitnetname, &ptr, 15);
                        //找到gate
                        struct external_gate* gate_;
                        ptr++;
                        int level_sum = (*ptr) & 0x0F;
                        ptr++;
                        struct external_unitnet* eun = (struct external_unitnet *)findNode(((struct Class *)findNode(Class_list.head, "0", 0))->external_unitnet_list.head, "0", 0);;
                        for(int i=0; i<level_sum + 1; i++) {
                            gate_ = findGateFromUnitnet(eun, *((__be32*)ptr));
                            if(i < level_sum) {
                                eun = gate_->down;
                                ptr += 4;
                            }
                        }
                        struct unitnet *un = (struct unitnet *)findNode(unitnet_list.head, unitnetname, 0);
                        gate_->down = (struct external_unitnet*)un;
                        un->supgateway_list.head = addNode(un->supgateway_list.head?(un->supgateway_list.head)+1:NULL, (struct listNode*)gate_ + 1) - 1;
                    } else if(m_msg->code == 3) {
                        char unitnetname[16];
                        char* ptr = m_msg->data;
                        readStr(unitnetname, &ptr, 15);
                        struct gate* sg_head = (struct gate*)(((struct unitnet *)findNode(unitnet_list.head, unitnetname, 0))->supgateway_list.head);
                        sg_head = (struct gate*)delNode((struct listNode*)sg_head, findNode2((struct listNode*)sg_head,*((__be32*)ptr)));
                    }
                } else if((m_msg->type) == 3) {
                    if(m_msg->code == 0) {
                        t_msg->type = 3;
                        t_msg->code = 0;
                        if(m_msg->len == htons(4)) {
                            __u8 unitnetnum, all_len;
                            struct unitnet* un = (struct unitnet*)(unitnet_list.head);
                            char* ptr_unitnet_len;
                            char* ptr = t_msg->data;
                            unitnetnum = nodesNum(unitnet_list.head);
                            all_len = 5 + unitnetnum;
                            *ptr = unitnetnum;
                            ptr++;
                            ptr_unitnet_len = ptr;
                            ptr += unitnetnum;
                            for(int i = 0; i < unitnetnum; i++) {
                                char* ptr_unitnet = ptr;
                                int unitnetnamelen, if_num;
                                struct if_* if_node = (struct if_*)(un->if_list.head);
                                char* ptr_if_len;
                                unitnetnamelen = strlen(un->name);
                                *ptr = unitnetnamelen;
                                ptr++;
                                strncpy(ptr, un->name, unitnetnamelen);
                                ptr += unitnetnamelen;
                                if_num = nodesNum((struct listNode*)if_node + 1);
                                *ptr = if_num;
                                ptr++;
                                ptr_if_len = ptr;
                                ptr += if_num;
                                for(int j = 0; j < if_num; j++) {
                                    char* ptr_if = ptr;
                                    int if_namelen = strlen(if_node->name);
                                    __u8 addr_num;
                                    char* ptr_addr_len;
                                    struct ifAddr* ifAddr = (struct ifAddr*)(if_node->ifaddr_list.head);
                                    *ptr = if_namelen;
                                    ptr++;
                                    strncpy(ptr, if_node->name, if_namelen);
                                    ptr += if_namelen;
                                    addr_num = nodesNum((struct listNode*)ifAddr);
                                    *ptr = addr_num;
                                    ptr++;
                                    ptr_addr_len = ptr;
                                    ptr += addr_num;
                                    for(int k = 0; k < addr_num; k++) {
                                        char* ptr_addr = ptr;
                                        *((__be32*)ptr) = ifAddr->addr;
                                        ptr += 4;
                                        if(ifAddr->type == 2) {
                                            __u8 subunitnetnamelen = strlen(ifAddr->gate_->subnet->name);
                                            *ptr = subunitnetnamelen;
                                            ptr++;
                                            strncpy(ptr, ifAddr->gate_->subnet->name, subunitnetnamelen);
                                            ptr += subunitnetnamelen;
                                            *ptr = ifAddr->gate_->relative << 7;
                                            *ptr |= ifAddr->gate_->netprelen;
                                            ptr++;
                                            *ptr = ifAddr->gate_->baselevel << 4;
                                            *ptr |= ifAddr->gate_->levellen;
                                            ptr++;
                                            for(int l = 0; l <= ifAddr->gate_->levellen; l++) {
                                                *((__be32*)ptr + l) = ifAddr->gate_->addr[l];
                                            }
                                            ptr += (ifAddr->gate_->levellen + 1)*4;
                                            *((__be32*)ptr) = ifAddr->gate_->supgate;
                                            ptr += 4;
                                        } else {
                                            *ptr = 0;
                                            ptr++;
                                        }
                                        *(ptr_addr_len + k) = ptr - ptr_addr;
                                        ifAddr = (struct ifAddr*)(((struct listNode*)ifAddr)->next);
                                    }
                                    *(ptr_if_len + j) = ptr - ptr_if;
                                    if_node = (struct if_*)(((struct listNode*)if_node + 1)->next - 1);
                                }
                                *(ptr_unitnet_len + i) = ptr - ptr_unitnet;
                                all_len += *(ptr_unitnet_len + i);
                                un = (struct unitnet*)(((struct listNode*)un)->next);
                            }
                            t_msg->len = htons(all_len);
                            send_usrmsg(tbuf, all_len);
                        } else {

                        }
                    } else if((m_msg->code == 1) || (m_msg->code == 2)) {
                        char unitnetname[16];
                        char* ptr = m_msg->data;
                        readStr(unitnetname, &ptr, 15);
                        struct unitnet* un = (struct unitnet *)findNode(unitnet_list.head, unitnetname, 0);
                        __be32 addr = *((__be32*)ptr);
                        ptr += 4;
                        struct ifAddr* ifaddrp = findAddrFromUnitnet(un, addr);
                        if(ifaddrp){
                            ifaddrp->type = 2;
                        }
                        struct gate* sg = (struct gate *)kmalloc(sizeof(struct gate), GFP_KERNEL);
                        sg->type = 0;
                        sg->subgate = addr;
                        sg->subaddr = ifaddrp;
                        sg->subnet = un;
                        ifaddrp->gate_ = sg;
                        char subunitnetname[16];
                        readStr(subunitnetname, &ptr, 15);
                        struct unitnet* sun = (struct unitnet *)findNode(unitnet_list.head, subunitnetname, 0);
                        __be32 supaddr = *((__be32*)ptr);
                        struct ifAddr* supifaddrp = findAddrFromUnitnet(sun, supaddr);
                        if(supifaddrp){
                            supifaddrp->type = 1;
                        }
                        sg->supgate = supaddr;
                        sg->supaddr = supifaddrp;
                        sg->supnet = sun;
                        supifaddrp->gate_ = sg;
                        if(m_msg->code == 1) {
                            sg->relative = 0;
                            sg->netprelen = 0;
                            sg->baselevel = 0;
                            sg->levellen = 0;
                            sg->addr[0] = 0;
                        } else if(m_msg->code == 2) {
                            // sg->relative = (*ptr) >> 7;
                            // sg->netprelen = (*ptr) & 0x7F;
                            // ptr++;
                            // sg->baselevel = (*ptr) >> 4;
                            // sg->levellen = (*ptr) & 0x0F;
                            // ptr++;
                            // __be32* ptr_addr = (__be32*)ptr;
                            // for(int i = 0; i <= sg->levellen; i++) {
                            //     sg->addr[i] = *(ptr_addr + i);
                            // }
                            // sg->supgate = *(ptr_addr + sg->levellen + 1);
                        }
                        sun->supgateway_list.head = addNode(sun->supgateway_list.head?(sun->supgateway_list.head)+1:NULL, (struct listNode*)sg + 1) - 1;
                    } else if(m_msg->code == 3) {
                        char unitnetname[16];
                        char* ptr = m_msg->data;
                        readStr(unitnetname, &ptr, 15);
                        struct unitnet* un = (struct unitnet *)findNode(unitnet_list.head, unitnetname, 0);
                        __be32 addr = *((__be32*)ptr);
                        struct ifAddr* ifaddrp = findAddrFromUnitnet(un, addr);
                        ifaddrp->gate_->subnet->supgateway_list.head = delNode(ifaddrp->gate_->subnet->supgateway_list.head, (struct listNode*)(ifaddrp->gate_) + 1) - 1;
                        ifaddrp->type = 0;
                        ifaddrp->gate_->subnet = NULL;
                        ifaddrp->gate_ = NULL;
                    }
                } else if(m_msg->type == 4) {
                    if(m_msg->code == 0) {

                    } else if(m_msg->code == 1) {
                        char* ptr = m_msg->data;
                        char filepath[256] = {0};
                        readStr(filepath, &ptr, 255);
                        struct file *fp = filp_open(filepath, O_RDONLY | O_CREAT, 0644);
                        if (IS_ERR(fp)){
                            printk("create file error\n");
                            return;
                        }
                        char* str_json = (char*)kmalloc(16384, GFP_KERNEL);
                        memset(str_json, 0, 16384);
                        loff_t pos =0;
                        kernel_read(fp, str_json, 16380, &pos);         //printk有字数限制？
                        filp_close(fp,NULL);

                        json *root, *classes, *class_unets, *unet_json, *subgates, *subgate, *supgates, *supgate;
                        root = JSON__Parse(str_json);
                        classes = JSON__GetObjectItem(root, "classes");
                        int class_sum = JSON__GetArraySize(classes);
                        for(int i=0; i<class_sum; i++) {
                            struct Class *Class_ = (struct Class *)kmalloc(sizeof(struct Class), GFP_KERNEL);
                            Class_list.head = addNode(Class_list.head, (struct listNode*)Class_);
                            char class_name[2];
                            snprintf(class_name, sizeof(class_name), "%d", i);
                            strcpy(Class_->name, class_name);
                            class_unets = JSON__GetObjectItem(JSON__GetArrayItem(classes, i), "unets");
                            int class_unets_sum = JSON__GetArraySize(class_unets);
                            for(int j=0; j<class_unets_sum; j++) {
                                struct external_unitnet *unet = (struct external_unitnet *)kmalloc(sizeof(struct external_unitnet), GFP_KERNEL);
                                unet->type = 1;
                                if(i == 0) {
                                    rootUnitnet = (struct unitnet*)unet;
                                }
                                Class_->external_unitnet_list.head = addNode(Class_->external_unitnet_list.head,  (struct listNode*)unet);
                                unet_json = JSON__GetArrayItem(class_unets, j);
                                strcpy(unet->name, JSON__GetObjectItem(unet_json, "name")->valuestring);
                                subgates = JSON__GetObjectItem(unet_json, "subgates");
                                if(subgates != NULL) {
                                    int subgates_sum = JSON__GetArraySize(subgates);
                                    for(int k=0; k<subgates_sum; k++) {
                                        struct external_gate *gate_ = (struct external_gate *)kmalloc(sizeof(struct external_gate), GFP_KERNEL);
                                        unet->subgateway_list.head = addNode(unet->subgateway_list.head,  (struct listNode*)gate_);
                                        subgate = JSON__GetArrayItem(subgates, k);
                                        gate_->up = unet;
                                        gate_->upaddr = inet_addr(JSON__GetObjectItem(subgate, "wip")->valuestring);
                                        gate_->downaddr = inet_addr(JSON__GetObjectItem(subgate, "lip")->valuestring);
                                    }
                            }
                            }
                        }
                        for(int i=1; i<class_sum; i++) {
                            char class_name[2];
                            snprintf(class_name, sizeof(class_name), "%d", i-1);
                            struct Class *upClass = (struct Class *)findNode(Class_list.head, class_name, 0);
                            snprintf(class_name, sizeof(class_name), "%d", i);
                            struct Class *Class_ = (struct Class *)findNode(Class_list.head, class_name, 0);
                            class_unets = JSON__GetObjectItem(JSON__GetArrayItem(classes, i), "unets");
                            int class_unets_sum = JSON__GetArraySize(class_unets);
                            for(int j=0; j<class_unets_sum; j++) {
                                unet_json = JSON__GetArrayItem(class_unets, j);
                                struct external_unitnet *unet = (struct external_unitnet *)findNode(Class_->external_unitnet_list.head, JSON__GetObjectItem(unet_json, "name")->valuestring, 0);
                                supgates = JSON__GetObjectItem(unet_json, "supgates");
                                if(supgates != NULL) {
                                    int supgates_sum = JSON__GetArraySize(supgates);
                                    for(int k=0; k<supgates_sum; k++) {
                                        supgate = JSON__GetArrayItem(supgates, k);
                                        struct external_unitnet *upUnet = (struct external_unitnet *)findNode(upClass->external_unitnet_list.head, JSON__GetObjectItem(supgate, "supunet")->valuestring, 0);
                                        struct external_gate *gate_ = findGateFromUnitnet(upUnet, inet_addr(JSON__GetObjectItem(supgate, "wip")->valuestring));
                                        unet->supgateway_list.head = addNode(unet->supgateway_list.head?(unet->supgateway_list.head)+1:NULL, (struct listNode*)gate_ + 1) - 1;
                                        gate_->down = unet;
                                    }
                                }
                            }
                        }
                        // 释放空间
                        if(root != NULL) {
                            JSON__Delete(root);
                            root = NULL;
                            classes = NULL;
                            class_unets = NULL;
                            unet_json = NULL;
                            subgates = NULL;
                            subgate = NULL;
                            supgates = NULL;
                            supgate = NULL;
                        }
                        if(str_json != NULL)
                            kfree(str_json);
                    }
                } else if(m_msg->type == 5) {
                    if(m_msg->code == 0) {

                    } else if(m_msg->code == 1) {
                        char* ptr = m_msg->data;
                        for(int i = 0; i < 2; i++) {
                            struct if_* if_p = (struct if_ *)kmalloc(sizeof(struct if_), GFP_KERNEL);
                            if_p->ifaddr_list.head = NULL;
                            memset(if_p->name, 0, 16);
                            readStr(if_p->name, &ptr, 15);
                            if_p->dev = findNet_device(if_p->name);
                            if_global_list.head = addNode(if_global_list.head, (struct listNode*)if_p);
                        }
                    }
                } else if(m_msg->type == 6) {
                    if(m_msg->code == 0) {

                    } else if(m_msg->code == 1) {
                        char* ptr = m_msg->data;
                        struct ifAddr* ifaddr_ = (struct ifAddr *)kmalloc(sizeof(struct ifAddr), GFP_KERNEL);
                        ifaddr_->type = 0;
                        ifaddr_->addr = *((__be32*)ptr);
                        ptr += 4;
                        ptr++;
                        char ifname[16];
                        readStr(ifname, &ptr, 15);
                        struct if_* if_p = (struct if_*)findNode(if_global_list.head, ifname, 1);
                        ifaddr_->if_ = if_p;
                        ifaddr_->ifa = findNet_device(if_p->name)->ip_ptr->ifa_list;
                        if_p->ifaddr_list.head = addNode(if_p->ifaddr_list.head, (struct listNode*)ifaddr_);
                    }
                } else if(m_msg->type == 7) {
                    if(m_msg->code == 0) {

                    } else if(m_msg->code == 1) {

                    } else if(m_msg->code == 3) {
                        // char* ptr = m_msg->data;
                        // u32 fd = ntohl(*((__be32*)ptr));
                        // struct net* net = get_net_ns_by_fd(fd);
                        // struct dstack_net* dstack_net = create_net_ext(net);
                        // ptr += 4;
                        // readStr(dstack_net->name, &ptr, 15);
                    }
                } else if(m_msg->type == 8) {
                    if(m_msg->code == 0) {
                        
                    } else if(m_msg->code == 1) {
                        char* ptr = m_msg->data;
                        __u8 netns_type = *ptr;
                        ptr++;
                        struct net* net;
                        if(netns_type == 0) {
                            net = NULL;
                        } else if(netns_type == 1) {
                            u32 fd = ntohl(*((__be32*)ptr));
                            net = get_net_ns_by_fd(fd);
                        }
                        ptr += 4;
                        char encap_name[16];
                        readStr(encap_name, &ptr, 15);
                        char if_name[16];
                        readStr(if_name, &ptr, 15);
                        encap_newlink(net, findNet_device(if_name), encap_name);
                    } else if(m_msg->code == 2) {
                        char* ptr = m_msg->data;
                        ptr++;
                        ptr += 4;
                        char if_name[16];
                        readStr(if_name, &ptr, 15);
                        encap_dellink(NULL, findNet_device(if_name));
                    }
                } else if(m_msg->type == 9) {
                    if(m_msg->code == 0) {
                        
                    } else if(m_msg->code == 1) {
                        char* ptr = m_msg->data;
                        __u8 netns_type = *ptr;
                        ptr++;
                        struct net* net;
                        if(netns_type == 0) {
                            net = NULL;
                        } else if(netns_type == 1) {
                            u32 fd = ntohl(*((__be32*)ptr));
                            net = get_net_ns_by_fd(fd);
                        }
                        ptr += 4;
                        char translate_name[16];
                        readStr(translate_name, &ptr, 15);
                        ptr++;
                        char if_name[16];
                        readStr(if_name, &ptr, 15);
                        translate_newlink(net, findNet_device(if_name), translate_name);
                    } else if(m_msg->code == 2) {
                        char* ptr = m_msg->data;
                        __u8 netns_type = *ptr;
                        ptr++;
                        struct net* net;
                        if(netns_type == 0) {
                            net = NULL;
                        } else if(netns_type == 1) {
                            u32 fd = ntohl(*((__be32*)ptr));
                            net = get_net_ns_by_fd(fd);
                        }
                        ptr += 4;
                        char translate_name[16];
                        readStr(translate_name, &ptr, 15);
                        translate_dellink(net, findNet_device(translate_name));
                    }
                } else if(m_msg->type == 10) {
                    if(m_msg->code == 0) {
                        
                    } else if(m_msg->code == 1) {
                        char* ptr = m_msg->data;
                        __u8 netns_type = *ptr;
                        ptr++;
                        struct net* net;
                        if(netns_type == 0) {
                            net = NULL;
                        } else if(netns_type == 1) {
                            u32 fd = ntohl(*((__be32*)ptr));
                            net = get_net_ns_by_fd(fd);
                        }
                        ptr += 4;
                        char un_name[16];
                        readStr(un_name, &ptr, 15);
                        __be32 addr = *((__be32*)ptr);
                        struct ifAddr* ifa =  findAddrFromUnitnet((struct unitnet*)findNode(unitnet_list.head, un_name, 0), addr);
                        ptr += 4;
                        __be32 prefix = ntohl(*((__be32*)ptr));
                        ptr += 4;
                        __u8 prefix_len = *ptr;
                        nat_newlink(net, ifa, prefix, prefix_len);
                    } else if(m_msg->code == 2) {
                        char* ptr = m_msg->data;
                        __u8 netns_type = *ptr;
                        ptr++;
                        struct net* net;
                        if(netns_type == 0) {
                            net = NULL;
                        } else if(netns_type == 1) {
                            u32 fd = ntohl(*((__be32*)ptr));
                            net = get_net_ns_by_fd(fd);
                        }
                        ptr += 4;
                        char un_name[16];
                        readStr(un_name, &ptr, 15);
                        __be32 addr = *((__be32*)ptr);
                        struct ifAddr* ifa =  findAddrFromUnitnet((struct unitnet*)findNode(unitnet_list.head, un_name, 0), addr);
                        ptr += 4;
                        __be32 prefix = ntohl(*((__be32*)ptr));
                        ptr += 4;
                        __u8 prefix_len = *ptr;
                        nat_dellink(net, ifa, prefix, prefix_len);
                    }
                } else if(m_msg->type == 11) {
                    if(m_msg->code == 0) {
                        
                    } else if(m_msg->code == 1) {

                    } else if(m_msg->code == 2) {

                    }
                } else if(m_msg->type == 12) {
                #ifdef SEC
                    if(m_msg->code == 0) {
                        
                    } else if(m_msg->code == 1) {
                        char* ptr = m_msg->data;
                        __u8 netns_type = *ptr;
                        ptr++;
                        struct net* net;
                        if(netns_type == 0) {
                            net = NULL;
                        } else if(netns_type == 1) {
                            u32 fd = ntohl(*((__be32*)ptr));
                            net = get_net_ns_by_fd(fd);
                        }
                        ptr += 4;
                        struct xfrmpp_state *x = xfrmpp_state_alloc(net);
                        struct xfrm_state *_x = (struct xfrm_state *)x;
                        _x->props.flags = XFRM_STATE_ALIGN4;
                        while((ptr - m_msg->data) < (ntohs(m_msg->len) - 4)) {
                            if(*ptr == 0) {
                                ptr++;
                                x->saddr.type = (*ptr);
                                ptr++;
                                x->saddr.base = (*ptr) >> 4;
                                x->saddr.len = (*ptr) & 0x0F;
                                ptr++;
                                for(int i = 0; i < x->saddr.len + 1; i++) {
                                    x->saddr.addr[i] = *((__be32*)ptr);
                                    ptr += 4;
                                }
                                x->saddr_prefix_len = *ptr;
                                ptr++;
                            } else if(*ptr == 1) {
                                ptr++;
                                x->daddr.type = (*ptr);
                                ptr++;
                                x->daddr.base = (*ptr) >> 4;
                                x->daddr.len = (*ptr) & 0x0F;
                                ptr++;
                                for(int i = 0; i < x->daddr.len + 1; i++) {
                                    x->daddr.addr[i] = *((__be32*)ptr);
                                    ptr += 4;
                                }
                                x->daddr_prefix_len = *ptr;
                                ptr++;
                                x->daddr_level = *ptr;
                                ptr++;
                            } else if(*ptr == 2) {
                                ptr++;
                                _x->id.proto = *ptr;
                                _x->type = xfrmpp_get_type(_x->id.proto, AF_INETPP);
                                ptr++;
                            } else if(*ptr == 3) {
                                ptr++;
                                x->direction = *ptr;
                                ptr++;
                            } else if(*ptr == 4) {
                                ptr++;
                                _x->id.spi = *((__be32*)ptr);
                                ptr += 4;
                            } else if(*ptr == 5) {
                                ptr++;
                                char alg_name[16] = {0};
                                readStr(alg_name, &ptr, 15);
                                int keysize = *ptr;
                                ptr++;
                                _x->aalg = kmalloc(sizeof(*_x->aalg) + keysize, GFP_KERNEL);
                                strcpy(_x->aalg->alg_name, xfrm_aalg_get_byname(alg_name, 1)->name);
                                _x->aalg->alg_key_len = keysize/*  * 8 */;
                                memcpy(_x->aalg->alg_key, ptr, keysize);
                                ptr += keysize;
                                // _x->props.aalgo = sa->sadb_sa_auth;
                            } else if(*ptr == 6) {
                                ptr++;
                                char alg_name[16] = {0};
                                readStr(alg_name, &ptr, 15);
                                int keysize = *ptr;
                                ptr++;
                                _x->ealg = kmalloc(sizeof(*_x->ealg) + keysize, GFP_KERNEL);
                                strcpy(_x->ealg->alg_name, xfrm_ealg_get_byname(alg_name, 1)->name);
                                _x->ealg->alg_key_len = keysize/*  * 8 */;
                                memcpy(_x->ealg->alg_key, ptr, keysize);
                                ptr += keysize;
                            } else if(*ptr == 7) {
                                ptr++;
                                if(*ptr == 1) {
                                    _x->props.flags |= XFRM_STATE_ESN;
                                } else {
                                    _x->props.flags &= ~XFRM_STATE_ESN;
                                }
                                ptr += 4;
                            } else {

                            }
                        }
                        _x->type->init_state(_x, NULL);
                        struct sec_net* sec_net = net_generic(net, sec_net_id);
                        sec_net->xfrmpp_states = container_of(addNode(sec_net->xfrmpp_states?&(sec_net->xfrmpp_states->node):NULL, &(x->node)), struct xfrmpp_state, node);
                    } else if(m_msg->code == 2) {

                    }
                #endif
                } else if((m_msg->type) == 13) {
                    if(m_msg->code == 0) {
                        if(m_msg->len == htons(4)) {
                        //     struct unitnet* un = (struct unitnet*)(unitnet_list.head);
                        //     char* ptr = t_msg->data;
                        //     t_msg->type = 1;
                        //     t_msg->code = 0;
                        //     int unitnetnum = nodesNum(unitnet_list.head);
                        //     int all_len = 5 + unitnetnum;
                        //     *ptr = unitnetnum;
                        //     ptr++;
                        //     char* ptr_unitnet_len = ptr;
                        //     ptr += unitnetnum;
                        //     for(int i = 0; i < unitnetnum; i++) {
                        //         struct if_* if_node = (struct if_*)(un->if_list.head);
                        //         int unitnet_len = 0;
                        //         int unitnetnamelen = strlen(un->name);
                        //         *ptr = unitnetnamelen;
                        //         ptr++;
                        //         strncpy(ptr, un->name, unitnetnamelen);
                        //         ptr += unitnetnamelen;
                        //         *ptr = un->level;
                        //         ptr++;
                        //         int if_num = nodesNum((struct listNode*)if_node + 1);
                        //         *ptr = if_num;
                        //         ptr++;
                        //         char* ptr_if_len = ptr;
                        //         ptr += if_num;
                        //         for(int j = 0; j < if_num; j++) {
                        //             int if_namelen = strlen(if_node->name);
                        //             *ptr = if_namelen;
                        //             ptr++;
                        //             strncpy(ptr, if_node->name, if_namelen);
                        //             ptr += if_namelen;
                        //             *(ptr_if_len + j) = if_namelen + 1;
                        //             unitnet_len += (if_namelen + 1);
                        //             if_node = (struct if_*)(((struct listNode*)if_node + 1)->next - 1);
                        //         }
                        //         *(ptr_unitnet_len + i) = unitnet_len + unitnetnamelen + if_num +3;
                        //         all_len += *(ptr_unitnet_len + i);
                        //         un = (struct unitnet*)(((struct listNode*)un)->next);
                        //     }
                        //     t_msg->len = htons(all_len);
                        //     send_usrmsg(tbuf, all_len);
                        } else {

                        }
                    } else if(m_msg->code == 1) {
                        char unitnetname[16];
                        char* ptr = m_msg->data;
                        readStr(unitnetname, &ptr, 15);
                        struct unitnet *un = (struct unitnet *)findNode(unitnet_list.head, unitnetname, 0);
                        un->map = (struct alias_map *)kmalloc(sizeof(struct alias_map), GFP_KERNEL);
                        map_init(un->map);
                        un->map->count = 0;
                        un->map->un = un;
                        un->map->master =*((__be32*)ptr);
                    } else if(m_msg->code == 2) {
                        char unitnetname[16];
                        char* ptr = m_msg->data;
                        readStr(unitnetname, &ptr, 15);
                        struct unitnet *un = (struct unitnet *)findNode(unitnet_list.head, unitnetname, 0);
                        map_destroy(un->map);
                        kfree(un->map);
                        un->map = NULL;
                    } else if(m_msg->code == 3) {
                        char unitnetname[16];
                        char* ptr = m_msg->data;
                        readStr(unitnetname, &ptr, 15);
                        struct unitnet *un = (struct unitnet *)findNode(unitnet_list.head, unitnetname, 0);
                        un->map->master =*((__be32*)ptr);
                    } else if(m_msg->code == 4) {
                        char unitnetname[16];
                        char* ptr = m_msg->data;
                        readStr(unitnetname, &ptr, 15);
                        struct unitnet *un = (struct unitnet *)findNode(unitnet_list.head, unitnetname, 0);
                        __be32 value =*((__be32*)ptr);
                        ptr += 4;
                        char key[16];
                        readStr(key, &ptr, 15);
                        map_add(un->map, key, strlen(key), value);
                    } else if(m_msg->code == 5) {
                        char unitnetname[16];
                        char* ptr = m_msg->data;
                        readStr(unitnetname, &ptr, 15);
                        struct unitnet *un = (struct unitnet *)findNode(unitnet_list.head, unitnetname, 0);
                        __be32 value =*((__be32*)ptr);
                        map_del_by_value(un->map, value);
                    } else if(m_msg->code == 6) {
                        char unitnetname[16];
                        char* ptr = m_msg->data;
                        readStr(unitnetname, &ptr, 15);
                        struct unitnet *un = (struct unitnet *)findNode(unitnet_list.head, unitnetname, 0);
                        __be32 value =*((__be32*)ptr);
                        ptr += 4;
                        char key[16];
                        readStr(key, &ptr, 15);
                        map_mod_by_value(un->map, value, key);
                    }
                }
            }
        } else if(nlmsg_hdr(skb)->nlmsg_pid == PORT_TABLES) {
            netlink_rcv_msg_tables(skb);
        }
    }
}

static int netdevice_notifier_event(struct notifier_block *self, unsigned long event, void *arg) {
	struct netdev_notifier_info *info = (struct netdev_notifier_info *)arg;
 
	switch(event) {
		case NETDEV_REGISTER:
			printk("device:%s REGISTER\n", info->dev->name);
			break;
		case NETDEV_UNREGISTER:
			printk("device:%s UNREGISTER\n", info->dev->name);
			break;
		case NETDEV_UP:
			printk("device name = %s , event is UP\n", info->dev->name);
			break;
		case NETDEV_DOWN:
			printk("device name = %s , event is down\n", info->dev->name);
			break;
		default:
			break;
	}
 
	return 0;
}

static struct notifier_block netdevice_notifier = {
	.notifier_call = netdevice_notifier_event,
};

struct netlink_kernel_cfg cfg = {
    .input  = netlink_rcv_msg, /* set recv callback */
};  

int config_init(void) {
    /* create netlink socket */
    nlsk = (struct sock *)netlink_kernel_create(&init_net, NETLINK_IPPP, &cfg);
    if(nlsk == NULL) {   
        printk("netlink_kernel_create error !\n");
        return -1; 
    }
    printk("config_init\n");
    ifConf();
    register_netdevice_notifier(&netdevice_notifier);
    return 0;
}

void config_exit(void) {
    unregister_netdevice_notifier(&netdevice_notifier);
    if (nlsk) {
        netlink_kernel_release(nlsk);
        nlsk = NULL;
    }
    printk("config_exit!\n");
}