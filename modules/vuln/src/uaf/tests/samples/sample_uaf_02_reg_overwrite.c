/* sample_uaf_02_reg_overwrite.c — 寄存器覆盖FP: free后xor清零再use */
#include <stdlib.h>
void process(int flag) {
    int *p = (int*)malloc(64);
    *p = 42;
    free(p);
    p = NULL;   /* 显式清零 — 非UAF, 但若检测器只看free+use则误报 */
    if (p) *p = 99;  /* 不可达 (p==NULL) — 若报告UAF则为FP */
    (void)flag;
}
int main() {
    process(0);
    return 0;
}
