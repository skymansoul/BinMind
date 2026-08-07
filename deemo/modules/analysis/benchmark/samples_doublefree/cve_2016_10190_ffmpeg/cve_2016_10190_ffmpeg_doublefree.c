/**
 * CVE-2016-10190 — 错误路径: if(err)free(p); free(p)
 * 模式: error_path_df
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
void v_2016_10190_ffmpeg_vuln(int count) {
    __asm__ __volatile__("" : "+r"(count));
    void *p = malloc(64);
    if (!p) return;
    volatile_vuln_sink = p;
    __asm__ __volatile__("" : "+r"(count));
    if (count > 0) free(p);  /* 错误路径 */
    free(p);  /* 总是执行 → 若count>0则double free */
    printf("v_2016_10190_ffmpeg: done\n");
}
__attribute__((noinline))
void v_2016_10190_ffmpeg_safe(int count) {
    __asm__ __volatile__("" : "+r"(count));
    void *p = malloc(64);
    if (!p) return;
    volatile_vuln_sink = p;
    __asm__ __volatile__("" : "+r"(count));
    if (count > 0) {{ free(p); p = NULL; }}
    if (p) free(p);  /* null check */
    printf("v_2016_10190_ffmpeg: ok\n");
}
int main(int argc, char **argv) {
    int count = 65536;
    if (argc > 1) count = atoi(argv[1]);
    printf("double free test\n");
    v_2016_10190_ffmpeg_vuln(count);
    v_2016_10190_ffmpeg_safe(count);
    return 0;
}
