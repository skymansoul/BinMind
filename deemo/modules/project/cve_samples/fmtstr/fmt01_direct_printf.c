// fmt01_direct_printf: 用户输入直接作为printf格式参数
// 模式: printf(argv[1]) — 最经典的格式化字符串漏洞
// 预期检测: DIRECT_USER_FMT — CRITICAL
#include <stdio.h>
#include <stdlib.h>

int main(int argc, char **argv) {
    if (argc < 2) {
        printf("Usage: %s <input>\n", argv[0]);
        return 1;
    }
    // 漏洞: argv[1] 直接作为格式字符串
    printf(argv[1]);
    printf("\n");
    return 0;
}
