#include <stdio.h>
#include <stdlib.h>
/* IO-11: 数组索引由溢出的整数计算 — 负索引访问 */
int main(int argc, char **argv) {
    int idx = argc > 1 ? atoi(argv[1]) : -1;
    int buf[256];
    for (int i = 0; i < 256; i++) buf[i] = i;
    /* idx=-1 → buf[-1]=0 可能破坏栈 */
    unsigned int uidx = (unsigned int)idx;
    if (uidx < 256) buf[idx] = 0;  /* VULNERABLE: idx是负的但uidx检查通过 */
    printf("buf[0]=%d\n", buf[0]);
    return 0;
}
