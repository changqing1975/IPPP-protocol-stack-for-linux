#ifndef _PRINT_H
#define _PRINT_H

/*十六进制形式打印字符串*/
void printfHex(const unsigned char *buf, const int num)
{
    for(int i = 0; i < num; i++)
    {
        printf("%02X ", buf[i]);
        if ((i+1)%16 == 0)
            printf("\n");
    }
    printf("\n");
    return;
}

#endif	/* _PRINT_H */