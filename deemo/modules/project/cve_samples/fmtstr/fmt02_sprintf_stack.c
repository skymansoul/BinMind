// fmt02_sprintf_stack: sprintf到栈缓冲区, 格式参数来自用户输入
// 模式: sprintf(buf, user_input)
// 预期检测: STACK_FMT / DIRECT_USER_FMT — HIGH/CRITICAL
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int main(int argc, char **argv) {
    char buf[256];
    if (argc < 2) {
        strcpy(buf, "hello %s");
    } else {
        strcpy(buf, argv[1]);
    }
    // 漏洞: buf内容来自argv[1], 作为格式字符串
    char output[512];
    sprintf(output, buf, "world");
    printf("%s\n", output);
    return 0;
}
