/* sample21: 全局指针UAF — 通过全局变量访问已释放内存

 * 漏洞类型: UAF via Global Pointer
 * CVE映射: CVE-2023-40168 (Jetty global session UAF)
 * 触发条件: 全局指针被多个函数共享, 一处 free 后另一处仍通过全局变量访问
 * 测试价值: 验证全局变量逃逸追踪 — uaf_cross_fn_scorer 的 escaped_to 维度
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* 全局指针 — 多函数共享 */
static char *g_shared_buffer = NULL;

void init_buffer(void) {
    g_shared_buffer = (char *)malloc(256);
    if (g_shared_buffer) {
        strcpy(g_shared_buffer, "global_shared_data");
        printf("Buffer inited: %s\n", g_shared_buffer);
    }
}

void cleanup_buffer(void) {
    if (g_shared_buffer) {
        free(g_shared_buffer);
        printf("Buffer freed\n");
    }
}

void use_buffer(void) {
    /* [VULN] 全局指针UAF: cleanup_buffer 已 free, 此处通过全局变量仍使用 */
    if (g_shared_buffer) {
        printf("Using buffer: %s\n", g_shared_buffer);
    }
}

int main(void) {
    init_buffer();
    cleanup_buffer();
    use_buffer();  /* UAF via global */
    return 0;
}
