#include <stdio.h>
#include <stdlib.h>
#include <string.h>
/* FMT-13: 循环中构造格式串并通过%n写入 */
int main(int argc, char **argv) {
    int vals[10] = {0};
    char fmt[256] = {0};
    if (argc > 1) {
        for (int i = 0; i < 10; i++)
            sprintf(fmt + strlen(fmt), "%%%d$n", i+1);
        printf(fmt, &vals[0],&vals[1],&vals[2],&vals[3],&vals[4],
               &vals[5],&vals[6],&vals[7],&vals[8],&vals[9]);
    }
    printf("vals[0]=%d\n", vals[0]);
    return 0;
}
