/* 安全: 栈数组 buf 与堆对象无关. */
#include <stdio.h>

int main(void) {
    char buf[32];
    for (int i = 0; i < 32; i++) {
        buf[i] = (char)i;
    }
    printf("%d\n", buf[31]);
    return 0;
}
