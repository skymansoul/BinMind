/* UAF-003: free后立即返回——清理代码中的free，后续use不可达
 * 场景: free(ptr); return; — use(ptr)在自由点之后但路径上不可达
 * uaf_state_machine缺陷: 枚举free后的所有指令use，不检查返回语句
 * 路径分析器能力: 识别free后紧跟return→UNREACHABLE_AFTER→大幅降级
 * 预期: 原有状态机报告UAF(FP)，增强过滤器识别为清理代码
 */

#include <stdlib.h>
#include <stdio.h>

typedef struct {
    int *values;
    int count;
} IntArray;

void cleanup_and_log(IntArray *arr) {
    if (!arr) return;

    /* 清理代码: free → return */
    free(arr->values);
    arr->values = NULL;  /* 防御性置空——不是UAF */
    free(arr);

    /* ret指令在此——后续任何代码都不可达 */
    return;  /* 编译器可能在此放ret */

    /* 以下代码不可达——编译器可能优化掉，但-O0会保留 */
    /* printf("cleanup done\n"); —— 若存在，检查器不应报告UAF */
}

IntArray *create_array(int count) {
    IntArray *arr = (IntArray *)malloc(sizeof(IntArray));
    if (!arr) return NULL;

    arr->values = (int *)calloc(count, sizeof(int));
    if (!arr->values) {
        free(arr);
        return NULL;
    }
    arr->count = count;
    return arr;
}

int main(void) {
    IntArray *a = create_array(10);
    if (a) {
        for (int i = 0; i < a->count; i++)
            a->values[i] = i * 2;
        printf("a[5]=%d\n", a->values[5]);
    }
    cleanup_and_log(a);
    return 0;
}
