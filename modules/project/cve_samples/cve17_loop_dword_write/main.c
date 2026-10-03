// cve17_loop_dword_write — 循环DWORD写: malloc(256)→for(i=0;i<128;i++)buf[i]=val, 4B/iter溢出
// CVE参考: CVE-2019-13140, 模式: loop_dword
// 编译: gcc -Wall -O0 -fno-stack-protector -g -o cve17_loop_dword_write main.c
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define ALLOC_SIZE 256
#define LOOP_COUNT 512

int main(int argc, char **argv) {
    unsigned char *buf = (unsigned char *)malloc(ALLOC_SIZE);
    if (!buf) return 1;

    // 漏洞: 分配256B, 但循环写入512次*4B=2048B
    for (int i = 0; i < LOOP_COUNT; i++) {
        buf[i] = (unsigned char)(i & 0xFF);
    }

    printf("buf=%p, loop %d times, alloc=%d\n",
           (void *)buf, LOOP_COUNT, ALLOC_SIZE);
    free(buf);
    return 0;
}
