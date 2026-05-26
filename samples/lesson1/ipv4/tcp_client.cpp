// g++ -DDEBUG -o c tcp_client.cpp

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
     int fd = socket(AF_INET, SOCK_STREAM, 0);
     if(fd == -1) {
          perror("socket create error");
          exit(1);
     }
     //----------------------------------------------------------------
     struct sockaddr_in server_addr = {
          .sin_family = AF_INET,
          .sin_port = htons(8881),
     };
     server_addr.sin_addr.s_addr = inet_addr("192.168.0.101");
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