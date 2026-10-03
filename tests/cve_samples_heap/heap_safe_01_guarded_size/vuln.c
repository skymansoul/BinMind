/* 安全: 守卫条件约束了size, alloc >= write
 * 预期: 堆检测器应过滤 (有守卫且写入≤约束)
 */
#include <stdlib.h>
#include <string.h>

#define MAX_SIZE 256

void safe_copy(int n, const char *src) {
    if (n > MAX_SIZE) n = MAX_SIZE;  /* 守卫 */
    char *buf = (char*)malloc(n);
    memcpy(buf, src, n);  /* 安全: n已被钳制 */
    free(buf);
}

int main() {
    char src[1024];
    memset(src, 'S', 1024);
    safe_copy(512, src);  /* n被钳制为256 */
    return 0;
}
