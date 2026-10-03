/* 安全: snprintf 显式限制长度, 写入不超过分配区. */
#include <stdlib.h>
#include <stdio.h>

int main(void) {
    char *buf = (char *)malloc(64);
    if (!buf) return 1;
    snprintf(buf, 64, "value=%s", "short");
    printf("%s\n", buf);
    free(buf);
    return 0;
}
