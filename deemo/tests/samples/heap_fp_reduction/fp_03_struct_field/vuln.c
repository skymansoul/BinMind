/*
 * FP-03: 结构体字段访问模式
 *
 * 对 malloc 的缓冲区做多个间隔为 4 的 store, 这是典型的结构体字段赋值模式。
 * 单一检测器看到最后一个 store 的偏移可能接近或超出分配大小,
 * 但结合所有 store 的分布模式, 这是安全的字段初始化。
 *
 * 预期: 基准检测器 → 可能误报
 *       增强管线 → 模式分析降置信度
 */
#include <stdlib.h>
#include <stdio.h>

typedef struct {
    int field0;
    int field1;
    int field2;
    int field3;
    int field4;
    int field5;
    int field6;
    int field7;
} my_struct;

int main(void) {
    my_struct *s = malloc(sizeof(my_struct));
    if (!s) return 1;
    // 连续字段访问 —— 结构体初始化模式
    s->field0 = 0;
    s->field1 = 1;
    s->field2 = 2;
    s->field3 = 3;
    s->field4 = 4;
    s->field5 = 5;
    s->field6 = 6;
    s->field7 = 7;
    printf("struct fields: %d %d %d %d\n",
           s->field0, s->field3, s->field5, s->field7);
    free(s);
    return 0;
}
