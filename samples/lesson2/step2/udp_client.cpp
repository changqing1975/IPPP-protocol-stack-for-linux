// g++ -static -DDEBUG -o c udp_client.cpp

#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include "../../print.h"
#include "../../ippp.h"

int main()
{
     int fd = socket(PF_INETPP, SOCK_DGRAM, 0);
     if(fd == -1) {
          perror("socket create error");
          exit(1);
     }
     //----------------------------------------------------------------
     struct sockaddr_ippp local_addr = {
          .family = PF_INETPP,
          .port = htons(8880),
     };
     inetpp_aton("/0#1.1.1.1-1.1.1.2-1.1.1.2-1.1.1.2", &local_addr.addr);
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
     socklen_t remoteAddrLen = sizeof(struct sockaddr_ippp);
     struct sockaddr_ippp remote_addr = {
          .family = PF_INETPP,
          .port = htons(8888),
     };
     inetpp_aton("/0#1.1.1.1-1.1.1.3-1.1.1.2-1.1.1.2-1.1.1.2", &remote_addr.addr);
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