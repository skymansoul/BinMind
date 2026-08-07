// LSP-12: 无路径约束 — malloc(128)+memcpy(buf,n), n无约束
// LSP: 无谓词可提取 → INCONCLUSIVE (保守保留)
// 预期: 保留告警 (正确行为: 缺乏信息无法证明安全)
#include <stdlib.h>
#include <string.h>

void vuln_func(char* src, int n) {
    char* buf = malloc(128);
    if (buf) {
        memcpy(buf, src, n);
        free(buf);
    }
}
