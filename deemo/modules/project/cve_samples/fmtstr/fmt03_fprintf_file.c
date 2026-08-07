// fmt03_fprintf_file: fprintf格式参数来自栈变量
// 模式: fprintf(f, fmt_from_input) — 文件写入场景
// 预期检测: STACK_FMT / HEAP_FMT — HIGH
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int main(int argc, char **argv) {
    const char *fmt = "default %d\n";
    if (argc > 1) fmt = argv[1];

    // 漏洞: fmt来自argv[1], 攻击者可控制格式字符串
    fprintf(stdout, fmt, 42);
    return 0;
}
