/* sample16: 安全守卫 — 有正确边界检查的堆访问 (应该不报警)
 *
 * 漏洞类型: 无 — 这是安全的代码
 * 触发条件: 所有堆访问都有正确的边界检查
 * 测试价值: 验证误报过滤器能否正确识别安全代码,
 *          不会将有边界检查的访问误报为溢出
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

void safe_copy(const char *src, size_t max_len) {
    size_t actual_len = strlen(src);
    // 边界检查: 限制复制长度
    if (actual_len > max_len) {
        actual_len = max_len;
    }

    char *buf = (char *)malloc(max_len + 1);
    if (!buf) return;

    // SAFE: actual_len ≤ max_len, buf 大小 = max_len+1
    memcpy(buf, src, actual_len);
    buf[actual_len] = '\0';
    printf("safe: %s\n", buf);
    free(buf);
}

void safe_loop(char *buf, size_t buf_size, size_t n) {
    // 循环有边界检查
    size_t limit = n < buf_size ? n : buf_size;
    for (size_t i = 0; i < limit; i++) {
        buf[i] = (char)(i & 0xFF);  // SAFE: i < buf_size
    }
}

int main(int argc, char **argv) {
    if (argc < 2) { fprintf(stderr, "usage: %s <input>\n", argv[0]); return 1; }
    safe_copy(argv[1], 256);

    char *buf2 = (char *)malloc(128);
    safe_loop(buf2, 128, 256);  // n=256, buf=128 → limit=128, 安全
    free(buf2);
    return 0;
}
