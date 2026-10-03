/**
 * CVE-2022-23222 — 全局指针: 两个路径分别free同一全局
 * 模式: global_ptr_df
 *
 * 对静态分析的挑战:
 *   1. malloc/free调用的参数追踪
 *   2. 指针别名传播 (q=p → free(p); free(q))
 *   3. 栈槽存储/重载 (save=p → free(p) → p=save → free(p))
 *   4. O2/Os优化后的代码模式保持
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

static volatile void *volatile_vuln_sink;  /* 阻止O2/Os编译期消除 */

__attribute__((noinline))
void v_2022_23222_kernel_vuln(int count) {
    __asm__ __volatile__("" : "+r"(count));
    void *p = malloc(64);
    if (!p) return;
    volatile_vuln_sink = p;
    __asm__ __volatile__("" : "+r"(count));
    static void *gp = NULL;
    gp = p;
    if (count > 100) {{ free(gp); }}
    free(gp);  /* 二者之中必有一个double free */
    printf("v_2022_23222_kernel: done\n");
}
__attribute__((noinline))
void v_2022_23222_kernel_safe(int count) {
    __asm__ __volatile__("" : "+r"(count));
    void *p = malloc(64);
    if (!p) return;
    volatile_vuln_sink = p;
    __asm__ __volatile__("" : "+r"(count));
    static void *gp = NULL;
    gp = p;
    free(gp); gp = NULL;
    if (gp) free(gp);  /* null check prevents DF */
    printf("v_2022_23222_kernel: ok\n");
}
int main(int argc, char **argv) {
    int count = 65536;
    if (argc > 1) count = atoi(argv[1]);
    printf("double free test\n");
    v_2022_23222_kernel_vuln(count);
    v_2022_23222_kernel_safe(count);
    return 0;
}
