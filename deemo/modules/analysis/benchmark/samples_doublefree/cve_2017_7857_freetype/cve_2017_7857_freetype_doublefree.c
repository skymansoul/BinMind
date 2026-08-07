/**
 * CVE-2017-7857 — realloc失败→double free
 * 模式: realloc_path_df
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
void v_2017_7857_freetype_vuln(int count) {
    __asm__ __volatile__("" : "+r"(count));
    void *p = malloc(64);
    if (!p) return;
    volatile_vuln_sink = p;
    __asm__ __volatile__("" : "+r"(count));
    void *q = realloc(p, 128);  /* realloc可能移动或释放旧块 */
    if (q) p = q;
    free(p);
    free(p);  /* double free */
    printf("v_2017_7857_freetype: done\n");
}
__attribute__((noinline))
void v_2017_7857_freetype_safe(int count) {
    __asm__ __volatile__("" : "+r"(count));
    void *p = malloc(64);
    if (!p) return;
    volatile_vuln_sink = p;
    __asm__ __volatile__("" : "+r"(count));
    void *q = realloc(p, 128);
    if (q) {{ free(p); p = NULL; }}  /* old ptr recorded */
    printf("v_2017_7857_freetype: ok\n");
}
int main(int argc, char **argv) {
    int count = 65536;
    if (argc > 1) count = atoi(argv[1]);
    printf("double free test\n");
    v_2017_7857_freetype_vuln(count);
    v_2017_7857_freetype_safe(count);
    return 0;
}
