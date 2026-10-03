/* 安全: MIN(size,128) 钳制分配大小, 复制22字节. */
#include <stdlib.h>
#include <string.h>
#include <stdio.h>

#define MIN(a, b) ((a) < (b) ? (a) : (b))

int main(void) {
    int input_size = 1024 * 1024;
    int safe_size = MIN(input_size, 128);
    char *buf = (char *)malloc((size_t)safe_size);
    if (!buf) return 1;
    memcpy(buf, "safe within 128 bytes", 22);
    printf("%s\n", buf);
    free(buf);
    return 0;
}
