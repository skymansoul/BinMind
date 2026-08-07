// uaf07_safe_xor_clear — 安全指针清除
// CVE参考: SAFE-PTR-CLEAR, 模式: safe_ptr_clear
// 检测目标: free→xor reg,reg后不应报告UAF (指针被正确清除)
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int main(int argc, char **argv) {
    char *buf = (char *)malloc(128);
    if (!buf) return 1;
    memset(buf, 'A', 64);
    printf("before free: %p\n", (void *)buf);
    free(buf);
    buf = NULL;  // 安全: 清除悬挂指针
    // 此后无UAF
    printf("cleared: %p\n", (void *)buf);
    return 0;
}
