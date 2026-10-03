#include <stdio.h>
#include <stdlib.h>
#include <string.h>
/* FMT-13: 堆上的格式字符串 — fmt字符串本身在堆上
 * 检测点: 格式字符串来源追踪需要跟踪堆内存 */
int main(int argc, char **argv) {
    char *fmt = (char *)malloc(256);
    if (!fmt) return 1;
    if (argc < 2) {
        strcpy(fmt, "hello %s\n");
    } else {
        strcpy(fmt, argv[1]);  /* 用户输入复制到堆上 */
    }
    printf(fmt, "world");      /* VULNERABLE if argc>=2 */
    free(fmt);
    return 0;
}
