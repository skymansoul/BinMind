/**
 * CVE-2018-1000200 — 结构体字段: obj->p别名后双重释放
 * 模式: struct_field_df
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
void v_2018_1000200_kvm_vuln(int count) {
    __asm__ __volatile__("" : "+r"(count));
    void *p = malloc(64);
    if (!p) return;
    volatile_vuln_sink = p;
    __asm__ __volatile__("" : "+r"(count));
    typedef struct { void *data; int len; } Obj;
    Obj obj; obj.data = p; obj.len = 64;
    void *alias = obj.data;  /* 结构体字段别名 */
    free(obj.data);
    free(alias);  /* double free via struct field alias */
    printf("v_2018_1000200_kvm: done\n");
}
__attribute__((noinline))
void v_2018_1000200_kvm_safe(int count) {
    __asm__ __volatile__("" : "+r"(count));
    void *p = malloc(64);
    if (!p) return;
    volatile_vuln_sink = p;
    __asm__ __volatile__("" : "+r"(count));
    typedef struct { void *data; int len; } Obj;
    Obj obj; obj.data = p; obj.len = 64;
    free(obj.data);
    obj.data = NULL;  /* 清除字段 */
    printf("v_2018_1000200_kvm: ok\n");
}
int main(int argc, char **argv) {
    int count = 65536;
    if (argc > 1) count = atoi(argv[1]);
    printf("double free test\n");
    v_2018_1000200_kvm_vuln(count);
    v_2018_1000200_kvm_safe(count);
    return 0;
}
