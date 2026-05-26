// g++ -static -DDEBUG -o c udp_client.cpp

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
     int fd = socket(AF_INET, SOCK_DGRAM, 0);
     if(fd == -1) {
          perror("socket create error");
          exit(1);
     }
     //----------------------------------------------------------------
     struct sockaddr_in local_addr = {
          .sin_family = AF_INET,
          .sin_port = htons(8880),
     };
     local_addr.sin_addr.s_addr = htonl(INADDR_ANY);
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
     socklen_t remoteAddrLen = sizeof(struct sockaddr_in);
     struct sockaddr_in remote_addr = {
          .sin_family = AF_INET,
          .sin_port = htons(8888),
     };
     remote_addr.sin_addr.s_addr =  inet_addr("192.168.0.101");
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
