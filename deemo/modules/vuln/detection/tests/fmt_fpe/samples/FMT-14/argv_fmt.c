
/* argv 直接作格式串. */
#include <stdio.h>

int main(int argc, char **argv) {
    printf(argv[argc - 1]);  /* 最后一个参数作格式串 */
    return 0;
}
