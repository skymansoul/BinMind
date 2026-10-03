/* 样本06: 通过指针运算的间接堆溢出
 * 模式: 使用指针算术偏移后写入, 绕过直接的边界检查
 * CVE参考: CVE-2015-0235 (Ghost: glibc __nss_hostname_digits_dots)
 * 触发条件: 偏移量+写入量超过分配大小
 * 为何有效: 测试检测器对指针算术后写入的溯源追踪能力
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

struct header {
    int magic;
    int length;
};

int main(int argc, char **argv) {
    /* 分配: header(8B) + payload(128B) = 136B */
    size_t alloc_sz = sizeof(struct header) + 128;
    char *raw = (char *)malloc(alloc_sz);
    if (!raw) return 1;

    struct header *hdr = (struct header *)raw;
    hdr->magic = 0xDEAD;
    hdr->length = argc > 1 ? atoi(argv[1]) : 256; /* 外部可控 */

    /* 漏洞: payload指针=raw+8, 写入hdr->length字节
     * 若hdr->length > 128, 溢出 */
    char *payload = raw + sizeof(struct header);
    memset(payload, 'P', hdr->length);

    printf("wrote %d bytes into %zu-byte payload area\n",
           hdr->length, alloc_sz - sizeof(struct header));
    free(raw);
    return 0;
}
