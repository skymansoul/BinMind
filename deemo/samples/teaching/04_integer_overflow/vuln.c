/*
 * 教学样本 #4: 整数溢出导致缓冲区溢出
 *
 * 漏洞: size 为 unsigned short，若输入 size=65535 且 len>size，
 *       则 malloc(65535+1)=malloc(0) 分配极小缓冲区，memcpy 写入大量数据。
 * 编译: gcc -o vuln vuln.c
 *
 * 利用思路: 整数溢出 → malloc(0) → heap overflow → 覆盖堆元数据
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

void process(unsigned short size, const char *input, unsigned int input_len) {
    /* size 最大 65535，size+1 可能回绕到 0 */
    char *buf = malloc(size + 1);
    if (!buf) return;

    if (input_len > size) {
        printf("input too long (len=%u > size=%u), truncating\n", input_len, size);
        input_len = size;
    }

    memcpy(buf, input, input_len);
    buf[input_len] = '\0';
    printf("processed: %s\n", buf);
    free(buf);
}

int main(int argc, char **argv) {
    if (argc < 2) {
        printf("usage: %s <input_string>\n", argv[0]);
        return 1;
    }
    unsigned short size = 65535;
    process(size, argv[1], strlen(argv[1]));
    return 0;
}
