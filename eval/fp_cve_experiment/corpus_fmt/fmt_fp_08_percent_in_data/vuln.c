/* 安全: 数据经 %s 传入, 数据内百分号无格式语义. */
#include <stdio.h>

int main(void) {
    printf("rate: %s\n", "50%");
    return 0;
}
