// int05_sext_trunc: movsxd 符号扩展截断 → 负值扩展为极大值
// 模式: 32位负值通过movsxd扩展到64位, 若用于长度计算误解
// 预期检测: Mode 5 (SEXT_TRUNC) — 符号扩展截断
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int main(int argc, char **argv) {
    // 模拟: 32位API返回 -1 (错误码), 被当作长度
    int result = -1;
    if (argc > 1) result = atoi(argv[1]);

    // 漏洞: 若result为负, 存储到int变量后转为size_t
    // 在二进制的movsxd会将-1扩展为0xFFFFFFFFFFFFFFFF
    ssize_t len = (ssize_t)result;

    if (len > 0) {
        // 此路径在result=-1时不应进入 (len=-1, len>0为false)
        char *buf = (char *)malloc((size_t)len);
        if (!buf) return 1;
        memset(buf, 0, (size_t)len);
        free(buf);
        return 0;
    }

    printf("len=%zd (negative, skipped)\n", len);
    return 0;
}
