// g++ -DDEBUG -o c udp_client.cpp

#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <stdlib.h>
#include "../../print.h"

int main()
{
     int fd = socket(AF_INET6, SOCK_DGRAM, 0);
     if(fd == -1) {
          perror("socket create error");
          exit(1);
     }
     //----------------------------------------------------------------
     struct sockaddr_in6 local_addr = {
          .sin6_family = AF_INET6,
          .sin6_port = htons(8880),
     };
     local_addr.sin6_addr = in6addr_any;
     if(bind(fd, (struct sockaddr*)&local_addr, sizeof(local_addr)) == -1)
     {
          perror("bind");
          exit(1);
     } else {
          printf("bind success\n");
     }
     //----------------------------------------------------------------
     unsigned char rcvBuff[40];
     unsigned char sndBuff[40] = "HELL WORLD!";
     socklen_t remoteAddrLen = sizeof(struct sockaddr_in6);
     struct sockaddr_in6 remote_addr = {
          .sin6_family = AF_INET6,
          .sin6_port = htons(8888),
     };
     inet_pton(AF_INET6, "fe80::a00:27ff:fe9b:fd6d", &remote_addr.sin6_addr);
     do {
          sendto(fd, sndBuff, 40, 0, (struct sockaddr*)&remote_addr, remoteAddrLen);
          recvfrom(fd, rcvBuff, 40, 0, (struct sockaddr*)&remote_addr, &remoteAddrLen);
          printfHex(rcvBuff, 40);
          printf("received:%s\n", rcvBuff);
     } while(getchar()=='c');
     //----------------------------------------------------------------
     if(close(fd) == 0)
          printf("close fd success\n");
     else
          printf("close fd error\n");
     //----------------------------------------------------------------
     return 0;
}