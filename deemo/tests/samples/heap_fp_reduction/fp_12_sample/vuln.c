/*
 * FP-12: strcpy 溢出 —— 经典堆溢出模式
 *
 * malloc(8) + strcpy(长字符串) → 明确的堆溢出。
 * 检测器应高置信度检出。
 */
#include <stdlib.h>
#include <string.h>
#include <stdio.h>

int main(void) {
    char *buf = malloc(8);
    if (!buf) return 1;
    // 拷贝 32 字节到只有 8 字节的缓冲区
    strcpy(buf, "AAAAAAAABBBBBBBBCCCCCCCCDDDDDDDD");
    printf("strcpy overflow: %s\n", buf);
    free(buf);
    return 0;
}
