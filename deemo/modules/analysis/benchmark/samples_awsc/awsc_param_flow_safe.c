/** awsc_param_flow_safe: SAFE: write s2 == alloc s2 (param flow) */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static char payload[8192];

void f(int n) {
    /* n 经局部变量传播后同时用于分配与写入 */
    int s1 = n * 4;
    int s2 = s1;
    char *buf = (char *)malloc(s2);
    if (!buf) return;
    memcpy(buf, payload, s2);
    free(buf);
    printf("done\n");
}
int main(void) { memset(payload,'A',sizeof(payload)); f(64); return 0; }
