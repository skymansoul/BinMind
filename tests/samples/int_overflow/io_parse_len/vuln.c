#include <stdio.h>
#include <stdlib.h>
#include <string.h>
/* IO-14: 解析器中的长度字段 — ntohl/反序列化后的宽度问题 */
int main(int argc, char **argv) {
    /* 模拟 ntohl(*(uint32_t*)pkt) */
    unsigned long pkt_len = (unsigned long)(argc > 1 ? atol(argv[1]) : 0xFFFFFFFF);
    /* 检查不充分: 只检查上界 */
    if (pkt_len > 65536) { printf("too large\n"); return 1; }
    /* pkt_len=0 → malloc(1) 但后续按60处理 */
    size_t alloc = pkt_len ? (size_t)pkt_len : 1;
    char *buf = (char *)malloc(alloc);
    if (!buf) return 1;
    memset(buf, 0, 60);  /* VULNERABLE if alloc < 60 */
    free(buf); return 0;
}
