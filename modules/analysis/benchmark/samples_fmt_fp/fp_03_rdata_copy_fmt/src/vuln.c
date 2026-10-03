#include <stdio.h>
#include <string.h>
int main(int argc, char **argv) {
    char fmt[64];
    strcpy(fmt, "count=%d\n");    /* 复制自常量字符串 */
    printf(fmt, argc);
    return 0;
}
