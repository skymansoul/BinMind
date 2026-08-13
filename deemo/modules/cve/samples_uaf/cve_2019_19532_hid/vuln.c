/* CVE-2019-19532 HID debug 事件: 释放后打印缓冲内容. */
#include <stdio.h>
#include <stdlib.h>

int main(int argc, char **argv) {
    char *p = (char *)malloc(64);
    if (!p) return 1;
    free(p);
    printf("%s\n", p);
    return 0;
}
