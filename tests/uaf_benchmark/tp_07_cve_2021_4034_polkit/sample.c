/* UAF-07: CVE-2021-4034 (polkit pkexec) 简化复刻
 * CVE: CVE-2021-4034, 本地提权, pkexec 中对 argv[1] 的 UAF.
 * 触发: 全局指针 g_path 经 malloc 分配; free(g_path) 后未置 NULL;
 *       另一函数在 g_path 非空时解引用 → UAF.
 * 为何有效: 跨函数全局指针的 free→use, 释放后未置空;
 *       需在 free 与 use 间建立全局变量生命周期关联.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static char *g_path = NULL;

void init(void) {
    g_path = (char *)malloc(8);
    if (g_path) {
        strcpy(g_path, "/bin/sh");
    }
}

void cleanup(void) {
    free(g_path);          /* 释放但不置 NULL */
}

void use_after_cleanup(void) {
    if (g_path) {
        printf("%s\n", g_path);   /* UAF: g_path 悬垂 */
    }
}

int main(void) {
    init();
    cleanup();
    use_after_cleanup();
    return 0;
}
