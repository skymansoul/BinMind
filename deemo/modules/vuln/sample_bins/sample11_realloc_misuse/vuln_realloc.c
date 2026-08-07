/* sample11: realloc 误用 — 不检查返回值 + 大小计算错
 *
 * 漏洞类型: Heap overflow via realloc misuse
 * 触发条件: realloc可能返回新指针, 旧指针变为悬垂; 且新大小计算错
 * 测试价值: realloc场景的特殊性 — 指针可能变, 大小可能错
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

void append_data(char **buf, size_t *cap, const char *data, size_t data_len) {
    size_t old_cap = *cap;
    // [VULN-1] 未检查 realloc 返回值
    // [VULN-2] 新容量计算逻辑有误: 应该是 old_cap + data_len, 却写 old_cap + data_len/2
    size_t new_cap = old_cap + data_len / 2;  // BUG: 应该是 + data_len
    char *new_buf = (char *)realloc(*buf, new_cap);
    *buf = new_buf;
    *cap = new_cap;
    // [VULN] data_len可能 > 新增容量, memcpy溢出
    memcpy(*buf + old_cap, data, data_len);
}

int main(void) {
    char *buf = (char *)malloc(64);
    size_t cap = 64;
    memset(buf, 0, 64);
    // 触发: 加入64字节数据, 但容量只扩展32 → 溢出32字节
    append_data(&buf, &cap, "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA", 64);
    printf("buf: %s\n", buf);
    free(buf);
    return 0;
}
