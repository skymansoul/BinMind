#include <stdio.h>
#include <stdlib.h>
#include <string.h>
/* INTOF-SAFE-05: 分配尺寸经下界与上限双重校验后才进入 malloc */
int main(int argc, char **argv) {
    int len = argc > 1 ? atoi(argv[1]) : 16;
    if (len <= 0) return 1;                    /* 非法尺寸拒绝 */
    if (len > 1024) {                          /* 上限约束 */
        fprintf(stderr, "too big\n");
        return 1;
    }
    char *buf = (char *)malloc((size_t)len + 1);  /* len 已限定在 (0,1024] */
    if (buf) {
        snprintf(buf, (size_t)len + 1, "len=%d", len);
        printf("%s\n", buf);
        free(buf);
    }
    return 0;
}
