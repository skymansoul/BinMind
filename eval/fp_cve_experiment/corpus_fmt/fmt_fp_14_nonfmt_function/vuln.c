/* 安全: puts/strlen 不是格式化函数. */
#include <stdio.h>
#include <string.h>

int main(void) {
    char buf[64];
    strcpy(buf, "plain %s");
    puts(buf);
    printf("%zu\n", strlen(buf));
    return 0;
}
