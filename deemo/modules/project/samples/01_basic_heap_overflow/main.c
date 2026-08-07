/* 样本01: 基础堆溢出 — malloc(0x80) + memcpy(0x100)
 * 模式: 分配固定大小, 写入量大于分配大小
 * CVE参考: CVE-2012-2136 (Linux kernel sock_alloc_send_pskb)
 * 触发条件: memcpy写入量超过malloc分配量
 * 为何有效: 最基础的堆溢出模式, 用于验证检测器的基本功能
 * 编译: gcc -g -o demo main.c
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define ALLOC_SIZE 0x80
#define WRITE_SIZE 0x100

int main(int argc, char **argv) {
    char *buf = (char *)malloc(ALLOC_SIZE);
    if (!buf) return 1;
    /* 漏洞: 分配0x80字节但写入0x100字节 */
    memset(buf, 'A', WRITE_SIZE);
    printf("buf=%p, wrote %d bytes into %d-byte buffer\n",
           (void *)buf, WRITE_SIZE, ALLOC_SIZE);
    free(buf);
    return 0;
}
