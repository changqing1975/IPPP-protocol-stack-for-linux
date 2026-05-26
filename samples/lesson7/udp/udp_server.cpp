// g++ -DDEBUG -o s udp_server.cpp

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
     if(fd == -1)
     {
          perror("socket create error");
          exit(1);
     }
     printf("fd:%d\n", fd);
     //----------------------------------------------------------------
     struct sockaddr_ippp local_addr = {
          .family = PF_INETPP,
          .port = htons(8888),
     };
     inetpp_aton(".0#1.1.1.2", &local_addr.addr);
     if(bind(fd, (struct sockaddr*)&local_addr, sizeof(local_addr)) == -1)
     {
          perror("bind");
          exit(1);
     }
     //----------------------------------------------------------------
     unsigned char sndBuff[40] = "HELLO WORLD!";
     unsigned char rcvBuff[40];
     struct sockaddr_ippp remote_addr;
     socklen_t remoteAddrLen = sizeof(remote_addr);
     do {
          int rc = recvfrom(fd, rcvBuff, 40, 0, (struct sockaddr*)&remote_addr, &remoteAddrLen);
          printf("received %d: %s\n", rc, rcvBuff);
          printfHex(rcvBuff, rc);
          printf("remoteAddr Len:%d\n", remoteAddrLen);
          printfHex((unsigned char*)&remote_addr, remoteAddrLen);
          sendto(fd, sndBuff, 20, 0, (struct sockaddr*)&remote_addr, remoteAddrLen);
     } while(getchar()=='c');
     //----------------------------------------------------------------
     if (close(fd) == 0)
          printf("close fd success\n");
     else
          printf("close fd error\n");
     //----------------------------------------------------------------
     return 0;
}