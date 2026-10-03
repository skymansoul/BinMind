/* sample20: 跨函数UAF — 指针在调用链中逃逸

 * 漏洞类型: Cross-Function Use-After-Free
 * CVE映射: CVE-2023-39976 (libqb UAF via nested function calls)
 * 触发条件: fn_A 分配并传递指针给 fn_B, fn_B 释放, fn_A 继续使用
 * 测试价值: 跨函数指针追踪 — 验证 CrossFnAnalyzer + DT-HSA 联合检出
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* 被调用方: 接收并释放指针 */
void release_buffer(char *buf) {
    if (buf) {
        printf("Releasing buffer at %p\n", (void *)buf);
        free(buf);
    }
}

/* 调用方: 分配并传递, 但在 callee free 后继续使用 */
void use_after_release(void) {
    char *data = (char *)malloc(128);
    if (!data) return;
    strcpy(data, "cross_fn_uaf_test");

    release_buffer(data);

    /* [VULN] 跨函数UAF: release_buffer 已 free, 此处继续使用 */
    printf("Data after release: %s\n", data);
}

int main(void) {
    use_after_release();
    return 0;
}
