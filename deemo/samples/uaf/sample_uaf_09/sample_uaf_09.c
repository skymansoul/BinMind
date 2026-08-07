/*
 * sample_uaf_09 — Global pointer UAF.
 *
 * 全局指针在某个函数中分配, 在另一个函数中释放,
 * 然后在第三个函数中使用.
 * 全局变量的生命周期跨越函数边界, 更难追踪.
 *
 * TARPS预期: DEF_TP — 全局指针UAF
 * 编译: gcc -o sample_uaf_09 sample_uaf_09.c
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static char *g_shared_buf = NULL;

static void init_buffer(void) {
    g_shared_buf = (char *)malloc(512);
    if (g_shared_buf) {
        strcpy(g_shared_buf, "global_shared_data");
    }
}

static void release_buffer(void) {
    if (g_shared_buf) {
        free(g_shared_buf);
        /* BUG: 未将g_shared_buf置NULL */
    }
}

static void use_buffer(void) {
    /* UAF: g_shared_buf可能已被release_buffer释放 */
    if (g_shared_buf) {
        /* 非NULL检查通过, 但指向已释放的内存 */
        printf("content: %s\n", g_shared_buf);
        g_shared_buf[0] = 'X';
    }
}

int main(void) {
    init_buffer();
    release_buffer();
    use_buffer();  /* UAF here */
    return 0;
}
