// SPDX-License-Identifier: GPL-2.0-or-later
/*
    IP++地址管理工具

Authors:	
	ChangQing, <cq@ippp.xyz>

Fixes:
	ChangQing	: 	XXX
To Fix:
  加锁？
  图形界面
  参数检验（是否存在、格式...）
  代码完善优化（内存泄漏、复用...）
  完善注解
  某些长度由1字节改为2字节？
  显示无接口unitnet时出错？

近期工作：
    命名空间
    net_device刷新

在文件/etc/profile中最后一行添加
export PATH="$PATH:/home/ippp/ippp/ippp_stack_linux/tool"

若要让其立即生效，可执行：
source /etc/profile

若要让其永久生效，在文件/root/.bashrc中最后一行添加
source /etc/profile

g++ -static -DDEBUG -o ippp ippp.cpp
*/

#include <stdio.h>
#include <stdlib.h>
#include <string>
#include <sys/socket.h>
#include <string.h>
#include <linux/netlink.h>
#include <stdint.h>
#include <unistd.h>
#include <errno.h>
#include <arpa/inet.h>
#include<fcntl.h>

#define NETLINK_IPPP    30
#define PORT_IPPP       1001
#define MSG_LEN         253
#define MAX_PLOAD       253

typedef struct _user_msg {
    struct nlmsghdr hdr;
    unsigned char msg[MSG_LEN];
} user_msg;

#pragma pack(1)
struct msg {
    __u8 type;
    __u8 code;
    __be16 len;
    char data[0];
};
#pragma pack()

#ifdef DEBUG
    #define print(...) printf(__VA_ARGS__)
    /*十六进制形式打印字符串*/
    void printHex( const unsigned char *buf, const int num) {
        char buf2[1024];
        char* ptr = buf2;
        for(int i = 0; i < num; i++) {
            sprintf(ptr,"%02X ", buf[i]);
            ptr += 3;
            if ((i+1)%16 == 0) {
                sprintf(ptr,"%c", '\n');
                ptr++;
            }
        }
        printf("%s\n",buf2);
    }
#else
    #define print(...)
    #define printHex(...)
#endif

inline __u8 charton(char c) {
    if(c > 96)
        return c - 87;
    else if(c > 64)
        return c - 55;
    else
        return c - 48;
}

int matches(const char *prefix, const char *string, int prelen) {
	if (!*prefix)
		return 1;
	while (*prefix && *prefix == *string) {
		prefix++;
		string++;
        prelen--;
	}

	return (!!*prefix) | (prelen > 0);
}

int nl_socket_create(int port) {
    /* 创建NETLINK socket */
    int skfd = socket(AF_NETLINK, SOCK_RAW, NETLINK_IPPP);
    if(skfd == -1) {
        perror("create socket error\n");
        return -1;
    }

    struct sockaddr_nl saddr;
    memset(&saddr, 0, sizeof(saddr));
    saddr.nl_family = AF_NETLINK; //AF_NETLINK
    saddr.nl_pid = port;  //端口号(port ID) 
    saddr.nl_groups = 0;
    if(bind(skfd, (struct sockaddr *)&saddr, sizeof(saddr)) != 0) {
        perror("bind() error\n");
        close(skfd);
        return -1;
    }
    return skfd;
}

void sendMsg(int skfd, struct nlmsghdr *nlh, int port, struct msg* m_msg, struct sockaddr_nl daddr) {
    memset(&daddr, 0, sizeof(daddr));
    daddr.nl_family = AF_NETLINK;
    daddr.nl_pid = 0; // to kernel 
    daddr.nl_groups = 0;

    nlh = (struct nlmsghdr *)malloc(NLMSG_SPACE(MAX_PLOAD));
    memset(nlh, 0, sizeof(struct nlmsghdr));
    nlh->nlmsg_len = NLMSG_SPACE(MAX_PLOAD);
    nlh->nlmsg_flags = 0;
    nlh->nlmsg_type = 0;
    nlh->nlmsg_seq = 0;
    nlh->nlmsg_pid = port; //self port

    memcpy(NLMSG_DATA(nlh), m_msg, ntohs(m_msg->len));

    if(!(sendto(skfd, nlh, nlh->nlmsg_len, 0, (struct sockaddr *)&daddr, sizeof(struct sockaddr_nl)))) {
        perror("sendto error\n");
        close(skfd);
        exit(-1);
    }
    print("send to kernel:\n");
    printHex((const unsigned char *)m_msg, ntohs(m_msg->len));
}

void recvMsg(int skfd, struct sockaddr_nl daddr, user_msg* u_msg) {
    memset(u_msg, 0, sizeof(user_msg));
    socklen_t len = sizeof(struct sockaddr_nl);

    if(!(recvfrom(skfd, u_msg, sizeof(user_msg), 0, (struct sockaddr *)&daddr, &len))) {
        perror("recv form kernel error\n");
        close(skfd);
        exit(-1);
    }
    print("recv from kernel:\n");
    printHex(u_msg->msg, ntohs(((struct msg*)(u_msg->msg))->len));
}

void makeMsg(struct msg*& m_msg, __u8 type, __u8 code, __u16 len) {
    m_msg = (struct msg*)malloc(len);
    m_msg->type = type;
    m_msg->code = code;
    m_msg->len = htons(len);
}

static int _do_cmd(int argc, char **argv, int skfd, int port, __u8 netns_type, __be32 fd) {
    struct msg* m_msg;
    struct msg* r_msg;
    struct nlmsghdr *nlh = NULL;
    struct sockaddr_nl daddr;
    int res = 0;
	if(matches(*argv, "interclassgateway", 1) == 0) {
        if(matches(*(argv + 1), "show", 2) == 0) {
            makeMsg(m_msg, 0, 0, 4);
        } else if(matches(*(argv + 1), "set", 2) == 0) {
            if((matches(*(argv + 2), "yes", 1) == 0) || (matches(*(argv + 2), "no", 1) == 0)) {
                makeMsg(m_msg, 0, 1, 4 + 1);
                m_msg->data[0] = (matches(*(argv + 2), "yes", 1) == 0) ? 1 : 0;
            }
        } else {
            printf("parameter error!\n");
            goto out;
        }
        sendMsg(skfd, nlh, port, m_msg, daddr);
        if(m_msg->code == 0) {
            user_msg u_msg;
            recvMsg(skfd, daddr, &u_msg);
            r_msg = (struct msg*)(u_msg.msg);
            if((r_msg->type == 0) && (r_msg->code == 0) && (ntohs(r_msg->len) == 5))
                printf("%s\n", (r_msg->data[0] == 1)?"yes":"no");
        }
	} else if(matches(*argv, "unitnet", 1) == 0) {
        if(matches(*(argv + 1), "show", 2) == 0) {
            if(argc == 2) {
                makeMsg(m_msg, 1, 0, 4);
            } else {
                int ifnum = argc - 2;
                int iflen = 0;
                for(int i = 0; i<ifnum; i++) {
                    iflen += (strlen(*(argv+2+i))+1);
                }
                makeMsg(m_msg, 1, 0, 4 + 1 + ifnum + iflen);
                char* curptr = m_msg->data;
                *curptr = ifnum;
                curptr++;
                for(int i = 0; i<ifnum; i++) {
                    *curptr = strlen(*(argv+2+i))+1;
                    curptr++;
                }
                for(int i = 0; i<ifnum; i++) {
                    *curptr = strlen(*(argv+2+i));
                    memcpy(curptr+1, *(argv+2+i), strlen(*(argv+2+i)));
                    curptr += (strlen(*(argv+2+i))+1);
                }
            }
        } else if(matches(*(argv + 1), "add", 1) == 0) {
            std::string cmd = "ip netns add " + std::string(*(argv+2));
            system(cmd.c_str());
            int ifnum = argc - 3;
            int iflen = 0;
            for(int i = 0; i<ifnum; i++) {
                iflen += (strlen(*(argv+3+i))+1);
            }
            makeMsg(m_msg, 1, 1, 4 + 1 + strlen(*(argv+2)) + 1 + ifnum + iflen);
            char* curptr = m_msg->data;
            *curptr = strlen(*(argv+2));
            curptr++;
            memcpy(curptr, *(argv+2), strlen(*(argv+2)));
            curptr += strlen(*(argv+2));
            *curptr = ifnum;
            curptr++;
            for(int i = 0; i<ifnum; i++) {
                *curptr = strlen(*(argv+3+i))+1;
                curptr++;
                cmd = "ip link set " + std::string(*(argv+3+i)) + " netns " + std::string(*(argv+2));
                system(cmd.c_str());
            }
            for(int i = 0; i<ifnum; i++) {
                *curptr = strlen(*(argv+3+i));
                memcpy(curptr+1, *(argv+3+i), strlen(*(argv+3+i)));
                curptr += (strlen(*(argv+3+i))+1);
            }
        } else if(matches(*(argv + 1), "del", 1) == 0) {
            makeMsg(m_msg, 1, 2, 4 + 1 + strlen(*(argv+2)));
            *(m_msg->data) = strlen(*(argv+2));
            memcpy(m_msg->data + 1, *(argv+2), strlen(*(argv+2)));
            // std::string cmd = "ip netns delete " + std::string(*(argv+2));
            // system(cmd.c_str());
        } else if(matches(*(argv + 1), "setclass", 2) == 0) {
            makeMsg(m_msg, 1, 3, 4 + 1 + strlen(*(argv+2)) + 1);
            *(m_msg->data) = strlen(*(argv+2));
            memcpy(m_msg->data + 1, *(argv+2), strlen(*(argv+2)));
            *(m_msg->data + 1 + strlen(*(argv+2))) = atoi(*(argv+3));
        } else {
            printf("parameter error!\n");
            goto out;
        }
        sendMsg(skfd, nlh, port, m_msg, daddr);
        if(m_msg->code == 0) {
            user_msg u_msg;
            recvMsg(skfd, daddr, &u_msg);
            r_msg = (struct msg*)(u_msg.msg);
            if((r_msg->type == 1) && (r_msg->code == 0)) {
                char unitnetname[16], ifname[16];
                char* ptr = r_msg->data;
                int unitnetnum = *ptr;
                ptr += (unitnetnum + 1);
                for(int i = 0; i < unitnetnum; i++) {
                    memset(unitnetname, 0, 16);
                    memcpy(unitnetname, ptr + 1, *ptr);
                    printf("%s  ", unitnetname);
                    ptr += (1 + *ptr);
                    printf("class:%d,\n    interfaces: ", *ptr);
                    ptr++;
                    int if_num = *ptr;
                    ptr += (1 + *ptr);
                    for(int j = 0; j < if_num; j++) {
                        memset(ifname, 0, 16);
                        memcpy(ifname, ptr + 1, *ptr);
                        printf("%s", ifname);
                        if(j != (if_num - 1))
                            printf(", ");
                        else
                            printf("\n");
                        ptr += (1 + *ptr);
                    }
                }
            }
        }
    } else if(matches(*argv, "supgateway", 3) == 0) {
        if(matches(*(argv + 1), "show", 1) == 0) {
            if(argc == 2) {
                makeMsg(m_msg, 2, 0, 4);
            } else {
                int ifnum = argc - 2;
                int iflen = 0;
                for(int i = 0; i<ifnum; i++) {
                    iflen += (strlen(*(argv+2+i))+1);
                }
                makeMsg(m_msg, 2, 0, 4 + 1 + ifnum + iflen);
                char* curptr = m_msg->data;
                *curptr = ifnum;
                curptr++;
                for(int i = 0; i<ifnum; i++) {
                    *curptr = strlen(*(argv+2+i))+1;
                    curptr++;
                }
                for(int i = 0; i<ifnum; i++) {
                    *curptr = strlen(*(argv+2+i));
                    memcpy(curptr+1, *(argv+2+i), strlen(*(argv+2+i)));
                    curptr += (strlen(*(argv+2+i))+1);
                }
            }
        } else if(matches(*(argv + 1), "add", 1) == 0) {
            if(argc == 7) {
                if(matches(*(argv + 5), "via", 3) != 0) {
                    printf("parameter error!\n");
                    goto out;
                }
                makeMsg(m_msg, 2, 1, 4 + 1 + strlen(*(argv+2)) + 1 + strlen(*(argv+3)) + 8);
                char* curptr = m_msg->data;
                *curptr = strlen(*(argv+2));
                curptr++;
                memcpy(curptr, *(argv+2), strlen(*(argv+2)));
                curptr += strlen(*(argv+2));
                *curptr = strlen(*(argv+3));
                curptr++;
                memcpy(curptr, *(argv+3), strlen(*(argv+3)));
                curptr += strlen(*(argv+3));
                *((__be32 *)curptr) = inet_addr(*(argv+4));
                curptr += 4;
                *((__be32 *)curptr) = inet_addr(*(argv+6));
            } else {
                if(matches(*(argv + 4), "via", 3) != 0) {
                    printf("parameter error!\n");
                    goto out;
                }
                __u8 relative = (**(argv+3) == '/') ? 0 : 1;
                __u8 classlen = 0;
                char baseclassstr[10] = {0};
                strncpy(baseclassstr, *(argv+3)+1, strchr(*(argv+3), '#')-*(argv+3)-1);
                __u8 baseclass = atoi(baseclassstr);
                __u8 netprelen = atoi(strrchr(*(argv+3), '/')+1);
                char* ptr = *(argv+3);
                while(ptr = strchr(ptr, '-')) {
                    classlen++;
                    ptr++;
                }
                makeMsg(m_msg, 2, 2, 4 + 1 + strlen(*(argv+2)) + 2 + (classlen+1)*4 + 4);
                char* curptr = m_msg->data;
                *curptr = strlen(*(argv+2));
                curptr++;
                memcpy(curptr, *(argv+2), strlen(*(argv+2)));
                curptr += strlen(*(argv+2));
                *curptr = (relative<<7)|netprelen;
                curptr++;
                *curptr = (baseclass<<4)|classlen;
                curptr++;
                ptr = strchr(*(argv+3), '#') + 1;
                char inet_addrstr[32];
                for(int i = 0; i <= classlen; i++) {
                    memset(inet_addrstr, 0,32);
                    strncpy(inet_addrstr, ptr, strchr(ptr, '-')?(strchr(ptr, '-')-ptr):(strchr(ptr, '/')-ptr));
                    *((__be32 *)curptr) = inet_addr(inet_addrstr);
                    curptr += 4;
                    if(strchr(ptr, '-'))
                        ptr = strchr(ptr, '-') + 1;
                }
                *((__be32 *)curptr) = inet_addr(*(argv+5));
            }
        } else if(matches(*(argv + 1), "del", 1) == 0) {
            makeMsg(m_msg, 2, 3, 4 + 1 + strlen(*(argv+2)) + 4);
            *(m_msg->data) = strlen(*(argv+2));
            memcpy(m_msg->data+1, *(argv+2), strlen(*(argv+2)));
            *((__be32 *)(m_msg->data+1+strlen(*(argv+2)))) = inet_addr(*(argv+3));
        } else {
            printf("parameter error!\n");
            goto out;
        }
        sendMsg(skfd, nlh, port, m_msg, daddr);
        if(m_msg->code == 0) {
            user_msg u_msg;
            recvMsg(skfd, daddr, &u_msg);
            r_msg = (struct msg*)(u_msg.msg);
            if((r_msg->type == 2) && (r_msg->code == 0)) {
                char unitnetname[16];
                char* ptr = r_msg->data;
                int unitnetnum = *ptr;
                ptr++;
                char* ptr_unitnet_len = ptr;
                ptr += unitnetnum;
                __u8 offset_un = 0;
                for(int i = 0; i < unitnetnum; i++) {
                    ptr = ptr_unitnet_len + unitnetnum + offset_un;
                    offset_un += *(ptr_unitnet_len + i);
                    struct in_addr addr1; 
                    memset(unitnetname, 0, 16);
                    memcpy(unitnetname, ptr + 1, *ptr);
                    printf("%s\n", unitnetname);
                    ptr += (1 + *ptr);
                    __u8 sup_num = *ptr;
                    ptr++;
                    char* ptr_suplen = ptr;
                    ptr += sup_num;
                    __u8 offset_sup = 0;
                    for(int j = 0; j < sup_num; j++) {
                        ptr = ptr_suplen + sup_num + offset_sup;
                        offset_sup += *(ptr_suplen + j);
                        printf("    ");
                        __u8 relative = (*ptr) >> 7;
                        __u8 netprelen = (*ptr) & 0x7F;
                        ptr++;
                        __u8 baseclass = (*ptr) >> 4;
                        __u8 classlen = (*ptr) & 0x0F;
                        ptr++;
                        char baseclassstr[10] = {0};
                        if(relative == 0)
                            printf("/");
                        else
                            printf(".");
                        if(relative == 1)
                            printf("%d", -baseclass);
                        else
                            printf("%d", baseclass);
                        printf("#");
                        for(int k = 0; k <= (classlen + 1); k++) {
                            addr1.s_addr = *((__be32*)ptr);
                            printf("%s", inet_ntoa(addr1));
                            if(k < classlen)
                                printf("-");
                            else if(k == classlen)
                                printf("/%d via ", netprelen);
                            ptr += 4;
                        }
                        if(*ptr == 0)
                            printf(" external\n");
                        else {
                            char supunitnetname[16];
                            printf(" internal ");
                            ptr++;
                            memset(supunitnetname, 0, 16);
                            memcpy(supunitnetname, ptr + 1, *ptr);
                            printf("%s ", supunitnetname);
                            ptr += (1 + *ptr);
                            addr1.s_addr = *((__be32*)ptr);
                            printf("%s\n", inet_ntoa(addr1));
                        }
                    }
                }
            }
        }
    } else if(matches(*argv, "subgateway", 3) == 0) {
        if(matches(*(argv + 1), "show", 1) == 0) {
            if(argc == 2) {
                makeMsg(m_msg, 3, 0, 4);
            } else {
                makeMsg(m_msg, 3, 0, 4 + 1 + strlen(*(argv+2)) + 4);
                *(m_msg->data) = strlen(*(argv+2));
                memcpy(m_msg->data+1, *(argv+2), strlen(*(argv+2)));
                *((__be32 *)(m_msg->data+1+strlen(*(argv+2)))) = inet_addr(*(argv+3));
            }
        } else if(matches(*(argv + 1), "add", 1) == 0) {
            if(argc == 7) {
                if(matches(*(argv + 5), "via", 3) != 0) {
                    printf("parameter error!\n");
                    goto out;
                }
                makeMsg(m_msg, 3, 1, 4 + 1 + strlen(*(argv+2)) + 4 + 1 + strlen(*(argv+4)) + 4);
                *(m_msg->data) = strlen(*(argv+2));
                memcpy(m_msg->data+1, *(argv+2), strlen(*(argv+2)));
                *((__be32 *)(m_msg->data+1+strlen(*(argv+2)))) = inet_addr(*(argv+3));
                *(m_msg->data+1+strlen(*(argv+2))+4) = strlen(*(argv+4));
                memcpy(m_msg->data+1+strlen(*(argv+2))+4+1, *(argv+4), strlen(*(argv+4)));
                *((__be32 *)(m_msg->data+1+strlen(*(argv+2))+4+1+strlen(*(argv+4)))) = inet_addr(*(argv+6));
            } else {
                if(matches(*(argv + 6), "via", 3) != 0) {
                    printf("parameter error!\n");
                    goto out;
                }
                __u8 relative = (**(argv+5) == '/') ? 0 : 1;
                __u8 netprelen;
                char baseclassstr[10] = {0};
                strncpy(baseclassstr, *(argv+5)+1, strchr(*(argv+5), '#')-*(argv+5)-1);
                __u8 baseclass = atoi(baseclassstr);
                netprelen = atoi(strrchr(*(argv+5), '/')+1);
                char* ptr = *(argv+5);
                __u8 classlen = 0;
                while(ptr = strchr(ptr, '-')) {
                    classlen++;
                    ptr++;
                }
                makeMsg(m_msg, 3, 2, 4 + 1 + strlen(*(argv+2)) + 4 + 1 + strlen(*(argv+4)) + 2 + (classlen+1)*4 + 4);
                char* curptr = m_msg->data;
                *curptr = strlen(*(argv+2));
                curptr++;
                memcpy(curptr, *(argv+2), strlen(*(argv+2)));
                curptr += strlen(*(argv+2));
                *((__be32 *)curptr) = inet_addr(*(argv+3));
                curptr += 4;
                *curptr = strlen(*(argv+4));
                curptr++;
                memcpy(curptr, *(argv+4), strlen(*(argv+4)));
                curptr += strlen(*(argv+4));
                *curptr = (relative<<7)|netprelen;
                curptr++;
                *curptr = (baseclass<<4)|classlen;
                curptr++;
                ptr = strchr(*(argv+5), '#') + 1;
                char inet_addrstr[32];
                for(int i = 0; i <= classlen; i++) {
                    memset(inet_addrstr, 0,32);
                    strncpy(inet_addrstr, ptr, strchr(ptr, '-')?(strchr(ptr, '-')-ptr):(strchr(ptr, '/')-ptr));
                    *((__be32 *)curptr) = inet_addr(inet_addrstr);
                    curptr += 4;
                    if(strchr(ptr, '-'))
                        ptr = strchr(ptr, '-') + 1;
                }
                *((__be32 *)curptr) = inet_addr(*(argv+7));
            }
        } else if(matches(*(argv + 1), "del", 1) == 0) {
            makeMsg(m_msg, 3, 3, 4 + 1 + strlen(*(argv+2)) + 4);
            *(m_msg->data) = strlen(*(argv+2));
            memcpy(m_msg->data+1, *(argv+2), strlen(*(argv+2)));
            *((__be32 *)(m_msg->data+1+strlen(*(argv+2)))) = inet_addr(*(argv+3));
        } else {
            printf("parameter error!\n");
            goto out;
        }
        sendMsg(skfd, nlh, port, m_msg, daddr);
        if(m_msg->code == 0) {
            user_msg u_msg;
            recvMsg(skfd, daddr, &u_msg);
            r_msg = (struct msg*)(u_msg.msg);
            if((r_msg->type == 3) && (r_msg->code == 0)) {
                char* ptr = r_msg->data;
                int unitnetnum = *ptr;
                ptr++;
                char* ptr_unitnet_len = ptr;
                ptr += unitnetnum;
                __u8 offset_un = 0;
                for(int i = 0; i < unitnetnum; i++) {
                    ptr = ptr_unitnet_len + unitnetnum + offset_un;
                    offset_un += *(ptr_unitnet_len + i);
                    char unitnetname[16] = {0};
                    memcpy(unitnetname, ptr + 1, *ptr);
                    printf("%s\n", unitnetname);
                    ptr += (1 + *ptr);
                    __u8 if_num = *ptr;
                    ptr++;
                    char* ptr_iflen = ptr;
                    ptr += if_num;
                    __u8 offset_if = 0;
                    for(int j = 0; j < if_num; j++) {
                        ptr = ptr_iflen + if_num + offset_if;
                        offset_if += *(ptr_iflen + j);
                        printf("    ");
                        char ifname[16] = {0};
                        memcpy(ifname, ptr + 1, *ptr);
                        printf("%s\n", ifname);
                        ptr += (1 + *ptr);
                        __u8 addr_num = *ptr;
                        ptr++;
                        char* ptr_addrlen = ptr;
                        ptr += addr_num;
                        __u8 offset_addr = 0;
                        for(int k = 0; k < addr_num; k++) {
                            ptr = ptr_addrlen + addr_num + offset_addr;
                            offset_addr += *(ptr_addrlen + j);
                            printf("        ");
                            struct in_addr addr1;
                            addr1.s_addr = *((__be32*)ptr);
                            printf("%s subgateway ", inet_ntoa(addr1));
                            ptr += 4;
                            if(*ptr == 0) {
                                printf("null\n");
                            } else {
                                char subunitnetname[16] = {0};
                                memcpy(subunitnetname, ptr + 1, *ptr);
                                printf("%s ", subunitnetname);
                                ptr += (1 + *ptr);
                                __u8 relative = (*ptr) >> 7;
                                __u8 netprelen = (*ptr) & 0x7F;
                                ptr++;
                                __u8 baseclass = (*ptr) >> 4;
                                __u8 classlen = (*ptr) & 0x0F;
                                ptr++;
                                char baseclassstr[10] = {0};
                                if(relative == 0)
                                    printf("/");
                                else
                                    printf(".");
                                if(relative == 1)
                                    printf("%d", -baseclass);
                                else
                                    printf("%d", baseclass);
                                printf("#");
                                for(int l = 0; l <= (classlen + 1); l++) {
                                    addr1.s_addr = *((__be32*)ptr);
                                    printf("%s", inet_ntoa(addr1));
                                    if(l < classlen)
                                        printf("-");
                                    else if(l == classlen)
                                        printf("/%d via ", netprelen);
                                    else
                                        printf("\n");
                                    ptr += 4;
                                }
                            }
                        }
                    }
                }
            }
        }
    } else if(matches(*argv, "parents", 1) == 0) {
        if(matches(*(argv + 1), "show", 2) == 0) {
            if(argc == 2) {
                makeMsg(m_msg, 4, 0, 4);
            } else {

            }
        } else if(matches(*(argv + 1), "set", 2) == 0) {
            char cwd[256];
            if (getcwd(cwd, sizeof(cwd)) != nullptr) {
                makeMsg(m_msg, 4, 1, 4 + 1 + strlen(cwd) + 1 + strlen(*(argv+2)));
                cwd[strlen(cwd)] = '/';
                memcpy(cwd + strlen(cwd), *(argv+2), strlen(*(argv+2)));
                *(m_msg->data) = strlen(cwd);
                memcpy(m_msg->data + 1, cwd, strlen(cwd));
            }
        } else if(matches(*(argv + 1), "solicitate", 2) == 0) {
            makeMsg(m_msg, 4, 2, 4);
        } else if(matches(*(argv + 1), "clear", 1) == 0) {
            makeMsg(m_msg, 4, 3, 4);
        } else {
            printf("parameter error!\n");
            goto out;
        }
        sendMsg(skfd, nlh, port, m_msg, daddr);
        if(m_msg->code == 0) {

        }
    } else if(matches(*argv, "link", 1) == 0) {
        if(matches(*(argv + 1), "show", 2) == 0) {
            if(argc == 2) {
                makeMsg(m_msg, 5, 0, 4);
            }
        } else if(matches(*(argv + 1), "add", 1) == 0) {
            if(argc == 8) {
                if((matches(*(argv + 3), "type", 4) == 0) && (matches(*(argv + 4), "veth", 4) == 0)
                && (matches(*(argv + 5), "peer", 4) == 0) && (matches(*(argv + 6), "name", 4) == 0)) {
                    makeMsg(m_msg, 5, 1, 4 + 1 + strlen(*(argv+2)) + 1 + strlen(*(argv+7)));
                    char* ptr = m_msg->data;
                    *ptr = strlen(*(argv+2));
                    ptr++;
                    memcpy(ptr, *(argv+2), strlen(*(argv+2)));
                    ptr += strlen(*(argv+2));
                    *ptr = strlen(*(argv+7));
                    ptr++;
                    memcpy(ptr, *(argv+7), strlen(*(argv+7)));
                    std::string cmd = "ip";
                    for(int i=0; i<argc; i++) {
                        cmd += (" " + std::string(*(argv+i)));
                    }
                    system(cmd.c_str());
                }
            }
        } else if(matches(*(argv + 1), "set", 2) == 0) {

        }else {
            printf("parameter error!\n");
            goto out;
        }
        sendMsg(skfd, nlh, port, m_msg, daddr);
        if(m_msg->code == 0) {

        }
    } else if(matches(*argv, "addr", 1) == 0) {
        if(matches(*(argv + 1), "show", 1) == 0) {
            if(argc == 2) {
                makeMsg(m_msg, 6, 0, 4);
            } else {

            }
        } else if(matches(*(argv + 1), "add", 1) == 0) {
            makeMsg(m_msg, 6, 1, 4 + 4 + 1 + 1 + strlen(*(argv+4)));
            char* ptr = m_msg->data;
            char inet_addrstr[32] = {0};
            strncpy(inet_addrstr, *(argv+2), strchr(*(argv+2), '/')-*(argv+2));
            *((__be32 *)ptr) = inet_addr(inet_addrstr);
            ptr += 4;
            *ptr = atoi(strrchr(*(argv+2), '/')+1);
            ptr++;
            *ptr = strlen(*(argv+4));
            ptr++;
            memcpy(ptr, *(argv+4), strlen(*(argv+4)));
            res = 1;
            std::string cmd = "ip";
            for(int i=(res == 1)?-4:0; i<argc; i++) {
                cmd += (" " + ((std::string(*(argv+i)) == "ippp")?"ip":std::string(*(argv+i))));
            }
            system(cmd.c_str());
        } else if(matches(*(argv + 1), "del", 1) == 0) {
            makeMsg(m_msg, 6, 2, 4);
        } else {
            printf("parameter error!\n");
            goto out;
        }
        sendMsg(skfd, nlh, port, m_msg, daddr);
        if(m_msg->code == 0) {

        }
    } else if(matches(*argv, "netns", 1) == 0) {
        if(matches(*(argv + 1), "exec", 1) == 0) {

        } else if(matches(*(argv + 1), "add", 1) == 0) {
            makeMsg(m_msg, 7, 3, 4 + 4 + 1 + strlen(*(argv+2)));
            char* ptr = m_msg->data;
            __be32 fd = htonl(open(("/var/run/netns/" +  std::string(*(argv+2))).c_str(), O_RDONLY));
            *((__be32 *)ptr) = fd;
            ptr += 4;
            *ptr = strlen(*(argv+2));
            ptr++;
            memcpy(ptr, *(argv+2), strlen(*(argv+2)));
            std::string cmd = "ip netns add " + std::string(*(argv+2));
            system(cmd.c_str());
        } else {
            printf("parameter error!\n");
            goto out;
        }
        sendMsg(skfd, nlh, port, m_msg, daddr);
        if(m_msg->code == 0) {

        }
    } else if(matches(*argv, "encap", 1) == 0) {
        if(matches(*(argv + 1), "add", 1) == 0) {
            makeMsg(m_msg, 8, 1, 4 + 4 + 1 + 1 + strlen(*(argv+2)) + 1 + strlen(*(argv+4)));
            char* curptr = m_msg->data;
            *curptr = netns_type;
            curptr++;
            *((__be32 *)curptr) = fd;
            curptr += 4;
            *curptr = strlen(*(argv+2));
            curptr++;
            memcpy(curptr, *(argv+2), strlen(*(argv+2)));
            curptr += strlen(*(argv+2));
            *curptr = strlen(*(argv+4));
            curptr++;
            memcpy(curptr, *(argv+4), strlen(*(argv+4)));
        } else if(matches(*(argv + 1), "del", 1) == 0) {
            makeMsg(m_msg, 8, 2, 4 + 1 + strlen(*(argv+2)));
            char* curptr = m_msg->data;
            *curptr = strlen(*(argv+2));
            curptr++;
            memcpy(curptr, *(argv+2), strlen(*(argv+2)));
        } else {
            printf("parameter error!\n");
            goto out;
        }
        sendMsg(skfd, nlh, port, m_msg, daddr);
        if(m_msg->code == 0) {

        }
    } else if(matches(*argv, "translate", 1) == 0) {
        if(matches(*(argv + 1), "add", 1) == 0) {
            makeMsg(m_msg, 9, 1, 4 + 4 + 1 + 1 + 1 + strlen(*(argv+2)) + 1 + strlen(*(argv+5)));
            char* curptr = m_msg->data;
            *curptr = netns_type;
            curptr++;
            *((__be32 *)curptr) = fd;
            curptr += 4;
            *curptr = strlen(*(argv+2));
            curptr++;
            memcpy(curptr, *(argv+2), strlen(*(argv+2)));
            curptr += strlen(*(argv+2));
            if(matches(*(argv + 3), "ipv4", 4) == 0) {
                *curptr = 0;
            } else {
                *curptr = 0xFF;
            }
            curptr++;
            *curptr = strlen(*(argv+5));
            curptr++;
            memcpy(curptr, *(argv+5), strlen(*(argv+5)));
        } else if(matches(*(argv + 1), "del", 1) == 0) {
            makeMsg(m_msg, 9, 2, 4 + 1 + 4 + 1 + strlen(*(argv+2)));
            char* curptr = m_msg->data;
            *curptr = netns_type;
            curptr++;
            *((__be32 *)curptr) = fd;
            curptr += 4;
            *curptr = strlen(*(argv+2));
            curptr++;
            memcpy(curptr, *(argv+2), strlen(*(argv+2)));
        } else {
            printf("parameter error!\n");
            goto out;
        }
        sendMsg(skfd, nlh, port, m_msg, daddr);
        if(m_msg->code == 0) {

        }
    } else if(matches(*argv, "nat", 1) == 0) {
        if(matches(*(argv + 1), "add", 1) == 0) {
            makeMsg(m_msg, 10, 1, 4 + 1 + 4 + 1 + strlen(*(argv+2)) + 4 + 4 + 1);
            char* curptr = m_msg->data;
            *curptr = netns_type;
            curptr++;
            *((__be32 *)curptr) = fd;
            curptr += 4;
            *curptr = strlen(*(argv+2));
            curptr++;
            memcpy(curptr, *(argv+2), strlen(*(argv+2)));
            curptr += strlen(*(argv+2));
            char inet_addrstr[16] = {0};
            strncpy(inet_addrstr, *(argv+3), strlen(*(argv+3)));
            *((__be32 *)curptr) = inet_addr(inet_addrstr);
            curptr += 4;
            char inet_addrstr2[16] = {0};
            strncpy(inet_addrstr2, *(argv+4), strchr(*(argv+4), '/')-*(argv+4));
            *((__be32 *)curptr) = inet_addr(inet_addrstr2);
            curptr += 4;
            *curptr = atoi(strrchr(*(argv+4), '/')+1);
        } else if(matches(*(argv + 1), "del", 1) == 0) {
            makeMsg(m_msg, 10, 2, 4 + 1 + 4 + 1 + strlen(*(argv+2)) + 4 + 4 + 1);
            char* curptr = m_msg->data;
            *curptr = netns_type;
            curptr++;
            *((__be32 *)curptr) = fd;
            curptr += 4;
            *curptr = strlen(*(argv+2));
            curptr++;
            memcpy(curptr, *(argv+2), strlen(*(argv+2)));
            curptr += strlen(*(argv+2));
            char inet_addrstr[16] = {0};
            strncpy(inet_addrstr, *(argv+3), strlen(*(argv+3)));
            *((__be32 *)curptr) = inet_addr(inet_addrstr);
            curptr += 4;
            char inet_addrstr2[16] = {0};
            strncpy(inet_addrstr2, *(argv+4), strchr(*(argv+4), '/')-*(argv+4));
            *((__be32 *)curptr) = inet_addr(inet_addrstr2);
            curptr += 4;
            *curptr = atoi(strrchr(*(argv+4), '/')+1);
        } else {
            printf("parameter error!\n");
            goto out;
        }
        sendMsg(skfd, nlh, port, m_msg, daddr);
        if(m_msg->code == 0) {

        }
    } else if(matches(*argv, "route", 1) == 0) {
        if(matches(*(argv + 1), "add", 1) == 0) {
            makeMsg(m_msg, 11, 1, 4);
            res = 1;
            std::string cmd = "ip";
            for(int i=(res == 1)?-4:0; i<argc; i++) {
                cmd += (" " + ((std::string(*(argv+i)) == "ippp")?"ip":std::string(*(argv+i))));
            }
            system(cmd.c_str());
        } else if(matches(*(argv + 1), "del", 1) == 0) {
            makeMsg(m_msg, 11, 1, 4);
            res = 1;
            std::string cmd = "ip";
            for(int i=(res == 1)?-4:0; i<argc; i++) {
                cmd += (" " + ((std::string(*(argv+i)) == "ippp")?"ip":std::string(*(argv+i))));
            }
            system(cmd.c_str());
        } else {
            printf("parameter error!\n");
            goto out;
        }
        sendMsg(skfd, nlh, port, m_msg, daddr);
        if(m_msg->code == 0) {

        }
    } else if(matches(*argv, "xfrm", 2) == 0) {
        if(matches(*(argv + 1), "state", 1) == 0) {
            if(matches(*(argv + 2), "add", 1) == 0) {
                char msg[1024];
                char* curptr = msg;
                *curptr = netns_type;
                curptr++;
                *((__be32 *)curptr) = fd;
                curptr += 4;
                int argn = 3;
                while(argn < argc) {
                    if((matches(*(argv + argn), "src", 3) == 0) || (matches(*(argv + argn), "dst", 3) == 0)) {
                        *curptr = (matches(*(argv + argn), "src", 3) == 0) ? 0 : 1;
                        curptr++;
                       *curptr = (**(argv + argn + 1) == '.') ? 1 : 0;
                        curptr++;
                        char baseclassstr[4] = {0};
                        strncpy(baseclassstr, *(argv + argn + 1) + 1, strchr(*(argv + argn + 1), '#') - *(argv + argn + 1) - 1);
                        __u8 baseclass = atoi(baseclassstr);
                        char* ptr = *(argv + argn + 1);
                        __u8 classlen = 0;
                        while(ptr = strchr(ptr, '-')) {
                            classlen++;
                            ptr++;
                        }
                        *curptr = (baseclass << 4) | classlen;
                        curptr++;
                        ptr = strchr(*(argv + argn + 1), '#') + 1;
                        char inet_addrstr[32];
                        for(int i = 0; i <= classlen; i++) {
                            memset(inet_addrstr, 0,32);
                            strncpy(inet_addrstr, ptr, strchr(ptr, '-')?(strchr(ptr, '-')-ptr):(strchr(ptr, '/')-ptr));
                            *((__be32 *)curptr) = inet_addr(inet_addrstr);
                            curptr += 4;
                            if(strchr(ptr, '-'))
                                ptr = strchr(ptr, '-') + 1;
                        }
                        if(matches(*(argv + argn), "src", 3) == 0) {
                            *curptr = atoi(strchr(*(argv + argn + 1), '/') + 1);
                            curptr++;
                        } else {
                            char* x1 = strchr(*(argv + argn + 1), '/');
                            char* x2 = strrchr(*(argv + argn + 1), '/');
                            std::string s1(x1);
                            *curptr = atoi(s1.substr(1, x2 - x1 -1).c_str());
                            curptr++;
                            *curptr = atoi(x2 + 1);
                            curptr++;
                        }
                        argn += 2;
                    } else if(matches(*(argv + argn), "proto", 5) == 0) {
                        *curptr = 2;
                        curptr++;
                        if(matches(*(argv + argn + 1), "ah", 2) == 0) {
                            *curptr = 51;
                        } else if(matches(*(argv + argn + 1), "esp", 3) == 0) {
                           *curptr = 50;
                        }
                        curptr++;
                        argn += 2;
                    } else if(matches(*(argv + argn), "direct", 3) == 0) {
                        *curptr = 3;
                        curptr++;
                        if(matches(*(argv + argn + 1), "inout", 5) == 0) {
                           *curptr = 2;
                        } else if(matches(*(argv + argn + 1), "out", 3) == 0) {
                            *curptr = 0;
                        } else if(matches(*(argv + argn + 1), "in", 2) == 0) {
                           *curptr = 1;
                        } else {
                            *curptr = 3;
                        }
                        curptr++;
                        argn += 2;
                    } else if(matches(*(argv + argn), "spi", 3) == 0) {
                        *curptr = 4;
                        curptr++;
                        for(int i = 0; i < 4; i++) {
                            *curptr = charton(*(*(argv + argn + 1) + 2 + i * 2)) * 16 + charton(*(*(argv + argn + 1) + 2 + i * 2 + 1));
                            curptr++;
                        }
                        argn += 2;
                    } else if((matches(*(argv + argn), "auth", 4) == 0) || (matches(*(argv + argn), "enc", 3) == 0)) {
                        *curptr = (matches(*(argv + argn), "auth", 4) == 0) ? 5 : 6;
                        curptr++;
                        *curptr = strlen(*(argv + argn + 1));
                        curptr++;
                        memcpy(curptr, *(argv + argn + 1), strlen(*(argv + argn + 1)));
                        curptr += strlen(*(argv + argn + 1));
                        __u8 _strlen = strlen(*(argv + argn + 2))/2 -1;
                        *curptr = _strlen;
                        curptr++;
                        for(int i = 0; i < _strlen; i++) {
                            *curptr = charton(*(*(argv + argn + 2) + 2 + i * 2)) * 16 + charton(*(*(argv + argn + 2) + 2 + i * 2 + 1));
                            curptr++;
                        }
                        argn += 3;
                    } else if(matches(*(argv + argn), "proto", 5) == 0) {
                        *curptr = 7;
                        curptr++;
                        if(matches(*(argv + argn + 1), "true", 4) == 0) {
                            *curptr = 1;
                        } else if(matches(*(argv + argn + 1), "false", 5) == 0) {
                           *curptr = 0;
                        }
                        curptr++;
                        argn += 2;
                    } else {
                        argn++;
                    }
                }
                makeMsg(m_msg, 12, 1, 4 + curptr - msg);
                memcpy(m_msg->data, msg, curptr - msg);
            } else if(matches(*(argv + 2), "del", 1) == 0) {

            } else if(matches(*(argv + 2), "set", 1) == 0) {
                char cwd[256];
                if (getcwd(cwd, sizeof(cwd)) != nullptr) {
                    makeMsg(m_msg, 12, 1, 4 + 1 + strlen(cwd) + 1 + strlen(*(argv+2)));
                    cwd[strlen(cwd)] = '/';
                    memcpy(cwd + strlen(cwd), *(argv+2), strlen(*(argv+2)));
                    *(m_msg->data) = strlen(cwd);
                    memcpy(m_msg->data + 1, cwd, strlen(cwd));
                }
            }
        } else {
            printf("parameter error!\n");
            goto out;
        }
        sendMsg(skfd, nlh, port, m_msg, daddr);
        if(m_msg->code == 0) {

        }
    } else if(matches(*argv, "alias", 2) == 0) {
        if(matches(*(argv + 1), "show", 1) == 0) {
            makeMsg(m_msg, 13, 0, 4);
        } else if(matches(*(argv + 1), "addmaster", 4) == 0) {
            makeMsg(m_msg, 13, 1, 4 + 1 + strlen(*(argv+2)) + 4);
            char* curptr = m_msg->data;
            *curptr = strlen(*(argv+2));
            curptr++;
            memcpy(curptr, *(argv+2), strlen(*(argv+2)));
            curptr += strlen(*(argv+2));
            *((__be32 *)curptr) = inet_addr(*(argv+3));
        } else if(matches(*(argv + 1), "delmaster", 4) == 0) {
            makeMsg(m_msg, 13, 2, 4 + 1 + strlen(*(argv+2)));
            char* curptr = m_msg->data;
            *curptr = strlen(*(argv+2));
            curptr++;
            memcpy(curptr, *(argv+2), strlen(*(argv+2)));
        } else if(matches(*(argv + 1), "modmaster", 4) == 0) {
            makeMsg(m_msg, 13, 3, 4 + 1 + strlen(*(argv+2)) + 4);
            char* curptr = m_msg->data;
            *curptr = strlen(*(argv+2));
            curptr++;
            memcpy(curptr, *(argv+2), strlen(*(argv+2)));
            curptr += strlen(*(argv+2));
            *((__be32 *)curptr) = inet_addr(*(argv+3));
        } else if(matches(*(argv + 1), "addalias", 4) == 0) {
            makeMsg(m_msg, 13, 4, 4 + 1 + strlen(*(argv+2)) + 4 + 4 + 1 + strlen(*(argv+5)));
            char* curptr = m_msg->data;
            *curptr = strlen(*(argv+2));
            curptr++;
            memcpy(curptr, *(argv+2), strlen(*(argv+2)));
            curptr += strlen(*(argv+2));
            *((__be32 *)curptr) = inet_addr(*(argv+3));
            curptr += 4;
           *curptr = strlen(*(argv+4));
            curptr++;
            memcpy(curptr, *(argv+4), strlen(*(argv+4)));
        } else if(matches(*(argv + 1), "delalias", 4) == 0) {
            makeMsg(m_msg, 13, 5, 4 + 1 + strlen(*(argv+2)) + 4 + 4);
            char* curptr = m_msg->data;
            *curptr = strlen(*(argv+2));
            curptr++;
            memcpy(curptr, *(argv+2), strlen(*(argv+2)));
            curptr += strlen(*(argv+2));
            *((__be32 *)curptr) = inet_addr(*(argv+3));
        } else if(matches(*(argv + 1), "modalias", 4) == 0) {
            makeMsg(m_msg, 13, 6, 4 + 1 + strlen(*(argv+2)) + 4 + 4 + 1 + strlen(*(argv+5)));
            char* curptr = m_msg->data;
            *curptr = strlen(*(argv+2));
            curptr++;
            memcpy(curptr, *(argv+2), strlen(*(argv+2)));
            curptr += strlen(*(argv+2));
            *((__be32 *)curptr) = inet_addr(*(argv+3));
            curptr += 4;
           *curptr = strlen(*(argv+4));
            curptr++;
            memcpy(curptr, *(argv+4), strlen(*(argv+4)));
        } else {
            printf("parameter error!\n");
            goto out;
        }
        sendMsg(skfd, nlh, port, m_msg, daddr);
        if(m_msg->code == 0) {
            user_msg u_msg;
            recvMsg(skfd, daddr, &u_msg);
            r_msg = (struct msg*)(u_msg.msg);
            if((r_msg->type == 1) && (r_msg->code == 0)) {
                // char unitnetname[16], ifname[16];
                // char* ptr = r_msg->data;
                // int unitnetnum = *ptr;
                // ptr += (unitnetnum + 1);
                // for(int i = 0; i < unitnetnum; i++) {
                //     memset(unitnetname, 0, 16);
                //     memcpy(unitnetname, ptr + 1, *ptr);
                //     printf("%s  ", unitnetname);
                //     ptr += (1 + *ptr);
                //     printf("class:%d,\n    interfaces: ", *ptr);
                //     ptr++;
                //     int if_num = *ptr;
                //     ptr += (1 + *ptr);
                //     for(int j = 0; j < if_num; j++) {
                //         memset(ifname, 0, 16);
                //         memcpy(ifname, ptr + 1, *ptr);
                //         printf("%s", ifname);
                //         if(j != (if_num - 1))
                //             printf(", ");
                //         else
                //             printf("\n");
                //         ptr += (1 + *ptr);
                //     }
                // }
            }
        }
    }
out:
    free(m_msg);
    free((void *)nlh);
	return res;
}

static int do_cmd(int argc, char **argv, int skfd, int port) {
    if(matches(*argv, "netns", 1) == 0 && matches(*(argv + 1), "exec", 1) == 0) {
        __be32 fd = htonl(open(("/var/run/netns/" + std::string(*(argv+2))).c_str(), O_RDONLY));
        return _do_cmd(argc - 4, argv + 4, skfd, port, 1, fd);
    } else {
        return _do_cmd(argc, argv, skfd, port, 0, 0);
    }
}

int main(int argc, char **argv) {
    if (argc < 2)
        return 0;

    int port = PORT_IPPP;

    int skfd = nl_socket_create(port);

    do_cmd(argc - 1, argv + 1, skfd, port);

    close(skfd);
    return 0;
}