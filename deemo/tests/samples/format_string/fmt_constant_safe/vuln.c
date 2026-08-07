#include <stdio.h>
/* FMT-02: 常量格式串 — 安全, 不应报告 */
int main(void) {
    printf("hello %s %d\n", "world", 42);  /* SAFE: 编译时常量 */
    return 0;
}
