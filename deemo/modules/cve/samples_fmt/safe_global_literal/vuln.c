/* N/A 安全对照: 全局只读字面量格式串. */
#include <stdio.h>

static const char g_fmt[] = "%d\n";

int main(int argc, char **argv) {
    printf(g_fmt, argc);
    return 0;
}
