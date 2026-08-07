/* 整数溢出 → 堆溢出: CWE-190 → CWE-122 的连锁 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

void process_items(unsigned int count, unsigned int item_size, char *data) {
    /* 漏洞: count * item_size 可能溢出为小值 */
    unsigned int total = count * item_size;
    char *buf = (char *)malloc(total);
    if (!buf) return;
    /* 实际写入 count * item_size 原始乘积 → 溢出 total */
    memcpy(buf, data, (size_t)count * item_size);
    printf("processed %u items\n", count);
    free(buf);
}

int main(void) {
    char data[4096];
    memset(data, 'X', sizeof(data));
    /* 0x10000 * 0x10000 = 0x100000000 (溢出为 0 on 32-bit) */
    process_items(0x10001, 0x10001, data);
    return 0;
}
