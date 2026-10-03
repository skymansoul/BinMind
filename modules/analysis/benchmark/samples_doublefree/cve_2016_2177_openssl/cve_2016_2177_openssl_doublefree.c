/**
 * CVE-2016-2177 — 多级错误路径: err1:free(p);err2:free(p)
 * 模式: multi_error_df
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
void v_2016_2177_openssl_vuln(int count) {
    __asm__ __volatile__("" : "+r"(count));
    void *p = malloc(64);
    if (!p) return;
    volatile_vuln_sink = p;
    __asm__ __volatile__("" : "+r"(count));
    if (count < 0) goto err1;
    if (count > 1000) goto err2;
    goto done;
    err1:
        free(p);
    err2:
        free(p);  /* err1落入err2 → double free */
    done:
        printf("ok\n");
    printf("v_2016_2177_openssl: done\n");
}
__attribute__((noinline))
void v_2016_2177_openssl_safe(int count) {
    __asm__ __volatile__("" : "+r"(count));
    void *p = malloc(64);
    if (!p) return;
    volatile_vuln_sink = p;
    __asm__ __volatile__("" : "+r"(count));
    int freed = 0;
    if (count < 0) {{ free(p); freed = 1; }}
    if (!freed) {{ free(p); freed = 1; }}
    printf("v_2016_2177_openssl: ok\n");
}
int main(int argc, char **argv) {
    int count = 65536;
    if (argc > 1) count = atoi(argv[1]);
    printf("double free test\n");
    v_2016_2177_openssl_vuln(count);
    v_2016_2177_openssl_safe(count);
    return 0;
}
