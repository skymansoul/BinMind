/* CVE-2020-9490 — 堆溢出, calloc乘积溢出
 * 漏洞类型: 堆溢出 (calloc整数溢出导致分配过小)
 * 触发条件: calloc(n, elem_size), n*elem_size溢出后分配小块
 * 根因: 整数溢出→分配大小不等于需要的缓冲区大小
 * 有效原因: 测试calloc分配乘法语义的检测
 */
#include <stdlib.h>
#include <string.h>

void *alloc_array(size_t count, size_t elem_size) {
    size_t total = count * elem_size;
    void *buf = calloc(count, elem_size);
    if (!buf) return NULL;
    /* buf实际分配total字节, 但total可能溢出 */
    memset(buf, 0, total);
    return buf;
}

int main() {
    /* 正常情况: 10*8=80字节 */
    void *p = alloc_array(10, 8);
    free(p);
    return 0;
}
