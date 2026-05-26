// g++ -DDEBUG -o c tcp_client.cpp

#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <stdlib.h>
#include <net/if.h>
#include <sys/ioctl.h>
#include "../../print.h"

int main()
{
     int fd = socket(AF_INET6, SOCK_STREAM, 0);
     if(fd == -1) {
          perror("socket create error");
          exit(1);
     }
     //----------------------------------------------------------------
     struct sockaddr_in6 server_addr = {
          .sin6_family = AF_INET6,
          .sin6_port = htons(8881),
     };
     inet_pton(AF_INET6, "fe80::a00:27ff:fe9b:fd6d", &server_addr.sin6_addr);
     struct ifreq req;
	strcpy(req.ifr_name, "enp0s3");
	ioctl(fd, SIOCGIFINDEX, &req);
     server_addr.sin6_scope_id = req.ifr_ifindex;
     int err = connect(fd, (struct sockaddr*)&server_addr, sizeof(server_addr));
     if(err == -1) {
          perror("connect error");
          exit(1);
     } else {
          printf("connected\n");
     }
     //----------------------------------------------------------------
     do {
          const char sndBuff[40] = "hello world!";
          send(fd, sndBuff, 40, 0);
          //------------------------------------------------------------
          unsigned char rcvBuff[40];
          int n = recv(fd, rcvBuff, 40, 0);
          printf("received:%s\n", rcvBuff);
          printfHex(rcvBuff, n);
     } while(getchar()=='c');
     //----------------------------------------------------------------
     if(close(fd) == 0)
          printf("close fd success\n");
     else
          printf("close fd error\n");
     //----------------------------------------------------------------
     return 0;
}