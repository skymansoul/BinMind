/* 安全: 包装函数 printf(fmt) 但 fmt 恒为常量. */
#include <stdio.h>

void show(const char *fmt) {
    printf(fmt);
}

int main(void) {
    show("value=%d\n");
    return 0;
}
