/* sample27: 安全重用 — free后立即同大小malloc复用 (FP测试)

 * 漏洞类型: N/A (安全代码 — 应被过滤)
 * 模式: free(p, size=N); q = malloc(N); use(q) — 合法重用
 * 测试价值: DT-HSA 应识别同大小 malloc 复用并标记为 safe (非 UAF)
 *           这是 UAF 检测的关键假阳性测试 — 验证保守策略有效性
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

void safe_reuse_pattern(void) {
    /* 分配并初始化 */
    char *buf = (char *)malloc(128);
    if (!buf) return;
    strcpy(buf, "temporary_data");
    printf("Buffer: %s\n", buf);

    /* 释放 */
    free(buf);

    /* 立即分配同大小缓冲区 — ptmalloc2 大概率返回同一块 */
    char *new_buf = (char *)malloc(128);
    if (!new_buf) return;
    strcpy(new_buf, "new_data_reused_chunk");
    printf("New buffer: %s\n", new_buf);

    /* 安全: new_buf 是对新分配的使用, 不是 UAF */
    free(new_buf);
}

int main(void) {
    safe_reuse_pattern();
    return 0;
}
