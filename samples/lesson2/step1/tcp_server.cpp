// g++ -static -DDEBUG -o ts tcp_server.cpp

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
     int lfd = socket(PF_INETPP, SOCK_STREAM, 0);
     if(lfd == -1) {
          perror("socket create error");
          exit(1);
     }
     printf("lfd:%d\n",lfd);
     //----------------------------------------------------------------
     struct sockaddr_ippp server_addr = {
          .family = PF_INETPP,
          .port = htons(8888),
     };
     inetpp_aton(".0#1.1.1.2", &server_addr.addr);
     if(bind(lfd, (struct sockaddr*)&server_addr, sizeof(server_addr)) == -1) {
          perror("bind error");
          close(lfd);
          return 0;
     }
     //----------------------------------------------------------------
     int err = listen(lfd, 10);
     //----------------------------------------------------------------
     socklen_t addr_length;
     struct sockaddr_ippp client_addr;
     int cfd = accept(lfd, (struct sockaddr*)&client_addr, &addr_length);
     //----------------------------------------------------------------
     unsigned char sndBuff[40] = "HELLO WORLD!";
     unsigned char rcvBuff[40];
     do {
          send(cfd, sndBuff, 40, 0);
          recv(cfd, rcvBuff, 40, 0);
          printfHex(rcvBuff, 40);
          printf("received:%s\n", rcvBuff);
     } while(getchar() == 'c');
     //----------------------------------------------------------------
     if (close(cfd) == 0)
          printf("close cfd success\n");
     else
          printf("close cfd error\n");
     if (close(lfd) == 0)
          printf("close lfd success\n");
     else
          printf("close lfd error\n");
     //----------------------------------------------------------------
     return 0;
}