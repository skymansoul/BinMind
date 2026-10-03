#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/*
 * CVE-55: 返回子指针后溢出
 *
 * 模式:
 *   char *get_field_buf() { return (char*)malloc(16); }
 *   main: char *p = get_field_buf(); memcpy(p, src, 128);
 *   alloc=16 usable=24, write=128 > 24 → OVERFLOW
 * 检测器需要: 识别get_field_buf是工厂函数, 返回malloc结果
 */
char *get_field_buf() {
    return (char *)malloc(16);
}

int main() {
    char *p = get_field_buf();
    if (!p) return 1;

    char src[128];
    memset(src, 'Z', 128);
    memcpy(p, src, 128);

    printf("returned_ptr_overflow\n");
    free(p);
    return 0;
}
