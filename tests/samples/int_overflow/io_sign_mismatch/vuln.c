#include <stdio.h>
#include <stdlib.h>
#include <string.h>
/* IO-03: 有符号/无符号比较错误 — 负数被隐式转换为大正数 */
int main(int argc, char **argv) {
    int user_len = argc > 1 ? atoi(argv[1]) : -1;
    /* user_len是int, 但sizeof返回size_t(无符号), 负数被提升为大正数 */
    if ((unsigned)user_len > 1024) { printf("too large\n"); return 1; }
    /* user_len=-1 → (unsigned)-1=0xFFFFFFFF > 1024, 但检查的是"too large" */
    char *buf = (char *)malloc(1024);
    if (!buf) return 1;
    if (user_len > 0) memcpy(buf, "data", (size_t)user_len);  /* VULNERABLE */
    free(buf); return 0;
}
