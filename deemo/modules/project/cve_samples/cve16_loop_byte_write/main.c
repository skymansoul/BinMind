// cve16_loop_byte_write — 循环字节写: malloc(64)→for(i=0;i<128;i++)buf[i]=x, 2倍溢出
// CVE参考: CVE-2021-3156, 模式: loop_byte
// 编译: gcc -Wall -O0 -fno-stack-protector -g -o cve16_loop_byte_write main.c
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define ALLOC_SIZE 64
#define LOOP_COUNT 128

int main(int argc, char **argv) {
    unsigned char *buf = (unsigned char *)malloc(ALLOC_SIZE);
    if (!buf) return 1;

    // 漏洞: 分配64B, 但循环写入128次*1B=128B
    for (int i = 0; i < LOOP_COUNT; i++) {
        buf[i] = (unsigned char)(i & 0xFF);
    }

    printf("buf=%p, loop %d times, alloc=%d\n",
           (void *)buf, LOOP_COUNT, ALLOC_SIZE);
    free(buf);
    return 0;
}
