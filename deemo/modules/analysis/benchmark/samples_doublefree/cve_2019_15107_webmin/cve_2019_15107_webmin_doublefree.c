/**
 * CVE-2019-15107 — 栈重载: 存栈→free→再加载→free
 * 模式: stack_reload_df
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
void v_2019_15107_webmin_vuln(int count) {
    __asm__ __volatile__("" : "+r"(count));
    void *p = malloc(64);
    if (!p) return;
    volatile_vuln_sink = p;
    __asm__ __volatile__("" : "+r"(count));
    void *save = p;  /* 栈槽保存指针 */
    free(p);
    p = save;  /* 从栈重载 */
    free(p);  /* double free via stack reload */
    printf("v_2019_15107_webmin: done\n");
}
__attribute__((noinline))
void v_2019_15107_webmin_safe(int count) {
    __asm__ __volatile__("" : "+r"(count));
    void *p = malloc(64);
    if (!p) return;
    volatile_vuln_sink = p;
    __asm__ __volatile__("" : "+r"(count));
    void *save = p;
    free(p);
    if (save) save = NULL;  /* 清除栈副本 */
    printf("v_2019_15107_webmin: ok\n");
}
int main(int argc, char **argv) {
    int count = 65536;
    if (argc > 1) count = atoi(argv[1]);
    printf("double free test\n");
    v_2019_15107_webmin_vuln(count);
    v_2019_15107_webmin_safe(count);
    return 0;
}
