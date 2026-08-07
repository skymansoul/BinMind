/* 安全: fprintf 到 stderr 的常量格式串. */
#include <stdio.h>

int main(void) {
    fprintf(stderr, "error %d occurred\n", 5);
    return 0;
}
