/* 安全: snprintf 显式限长, 常量格式串. */
#include <stdio.h>

int main(void) {
    char buf[32];
    snprintf(buf, sizeof(buf), "v=%d", 7);
    printf("%s\n", buf);
    return 0;
}
