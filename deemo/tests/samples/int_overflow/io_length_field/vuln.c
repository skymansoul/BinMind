#include <stdio.h>
#include <stdlib.h>
#include <string.h>
/* IO-12: 协议长度字段溢出 — 从网络/文件读取的长度字段可能恶意构造 */
int main(int argc, char **argv) {
    unsigned short net_len = (unsigned short)(argc > 1 ? atoi(argv[1]) : 0xFFFF);
    size_t actual = (size_t)net_len + 16;  /* net_len=0xFFFF → 0x1000F → 无溢出 */
    /* 但如果net_len来自网络字节序 htons(0xFFFF)=0xFFFF, 计算可能安全 */
    char *buf = (char *)malloc(actual);
    if (!buf) return 1;
    memset(buf, 0, actual);
    size_t copy = (size_t)net_len * 2;  /* VULNERABLE: 0xFFFF*2=0x1FFFE, 但product已溢出ushort */
    memcpy(buf, "data", copy < actual ? copy : actual);
    free(buf); return 0;
}
