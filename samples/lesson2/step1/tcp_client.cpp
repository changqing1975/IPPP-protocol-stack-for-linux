// g++ -static -DDEBUG -o tc tcp_client.cpp

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
     int fd = socket(PF_INETPP, SOCK_STREAM, 0);
     if(fd == -1) {
          perror("socket create error");
          exit(1);
     }
     //----------------------------------------------------------------
     /* 可以主动指定绑定地址。也可以不指定，此时使用该网络命名空间的默认地址；此默认地址为
     从本命名空间默认地址回溯至根单元网（公网）的全链路绝对地址；若无法完整回溯，则使用相
     对地址.#x.x.x.x，x.x.x.x为本单元网默认地址。 */
     struct sockaddr_ippp local_addr = {
          .family = PF_INETPP,
          .port = htons(8880),
     };
     inetpp_aton("/0#1.1.1.1-1.1.1.2", &local_addr.addr);
     if(bind(fd, (struct sockaddr*)&local_addr, sizeof(local_addr)) == -1)
     {
          perror("bind");
          exit(1);
     } else {
          printf("bind success\n");
     }
     //----------------------------------------------------------------
     struct sockaddr_ippp server_addr = {
          .family = PF_INETPP,
          .port = htons(8888),
     };
     inetpp_aton("/0#1.1.1.2-1.1.1.2", &server_addr.addr);
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