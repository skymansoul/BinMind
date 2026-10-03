/*
 * sample_uaf_08 — Function parameter UAF (跨函数).
 *
 * 指针作为参数传入函数, 在函数外free后函数内继续使用.
 * 跨函数UAF需要调用上下文追踪.
 *
 * TARPS预期: DEF_TP — 跨函数UAF, 需要调用点分析
 * 编译: gcc -o sample_uaf_08 sample_uaf_08.c
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static void write_data(char *dest) {
    /* dest可能已在上层被free */
    strcpy(dest, "cross_function_uaf");
}

static void cleanup_and_callback(char *p) {
    free(p);
    /* BUG: free后立即回调, 回调中使用悬垂指针 */
    write_data(p);
}

int main(void) {
    char *buf = (char *)malloc(256);
    if (!buf) return 1;
    strcpy(buf, "initial_data");

    cleanup_and_callback(buf);

    /* buf已在cleanup_and_callback中free */
    /* 后续不应用访问buf */

    printf("done\n");
    return 0;
}
