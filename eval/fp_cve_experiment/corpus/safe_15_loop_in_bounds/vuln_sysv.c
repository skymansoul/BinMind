/* 安全: for(i=0;i<32;i++) buf[i]=... 恰好32字节. */
#include <stdlib.h>
#include <stdio.h>

int main(void) {
    char *buf = (char *)malloc(32);
    if (!buf) return 1;
    for (int i = 0; i < 32; i++) {
        buf[i] = (char)i;
    }
    printf("%d\n", buf[31]);
    free(buf);
    return 0;
}
