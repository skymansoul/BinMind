// HEAP-FP-004: 循环内累积溢出
// 每次循环memcpy(dst+offset, src, chunk) → 累积超出分配
// 测试目的: 验证循环上下文的检测增强
// 期望: 检出堆溢出(循环加权)

#include <string.h>
#include <stdlib.h>

void loop_concat_vuln(const char *in, int total_len, int chunk_size) {
    char *buf = malloc(total_len);
    if (!buf) return;
    int offset = 0;
    while (offset < total_len + 64) {  // VULN: 循环条件超出分配
        int copy_now = chunk_size;
        if (offset + copy_now > total_len + 64)
            copy_now = (total_len + 64) - offset;
        if (copy_now <= 0) break;
        memcpy(buf + offset, in, copy_now);
        offset += copy_now;
    }
    free(buf);
}

int main() {
    char data[512];
    memset(data, 'L', 512);
    loop_concat_vuln(data, 256, 64);
    return 0;
}
