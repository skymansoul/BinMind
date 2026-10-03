/* 安全: 动态分配大小被路径守卫钳制到256, 复制固定9字节. */
#include <stdlib.h>
#include <string.h>
#include <stdio.h>

int process(int user_len) {
    int size = user_len;
    if (size > 256) size = 256;
    if (size < 0) size = 0;
    char *buf = (char *)malloc((size_t)size);
    if (!buf) return -1;
    memcpy(buf, "safe_data", 9);
    printf("%s\n", buf);
    free(buf);
    return 0;
}

int main(void) {
    process(512);
    process(128);
    return 0;
}
