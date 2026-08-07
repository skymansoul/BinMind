/* sample22: realloc UAF — realloc可能移动块, 旧指针变为悬垂

 * 漏洞类型: UAF via realloc
 * CVE映射: CVE-2023-6597 (realloc UAF in PHP xml parser)
 * 触发条件: p = malloc(N); q = realloc(p, M); free(q); use(p)
 *   当 realloc 移动块时, p 指向已释放的旧块, use(p) 触发 UAF
 * 测试价值: realloc 场景的 malloc 地址追踪 — 验证 record_realloc 处理
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int main(void) {
    char *p = (char *)malloc(64);
    if (!p) return 1;
    strcpy(p, "original_data");

    /* realloc 到不同大小 — 可能移动块 */
    char *q = (char *)realloc(p, 256);
    if (!q) { free(p); return 1; }
    strcat(q, "_extended");

    /* 释放新块 */
    free(q);

    /* [VULN] realloc UAF: 若 realloc 移动了块, p 指向旧块(已释放) */
    printf("Old pointer: %s\n", p);

    return 0;
}
