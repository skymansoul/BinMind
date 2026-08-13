#include <stdio.h>
#include <string.h>
int main(int argc, char **argv) {
    char fmt[128];
    if (argc < 2) return 1;
    strncpy(fmt, argv[1], sizeof(fmt) - 1);   /* 模拟 recv 输入 */
    fmt[sizeof(fmt) - 1] = '\0';
    printf(fmt);
    return 0;
}
