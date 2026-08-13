/* scanf 输入后直接 printf. */
#include <stdio.h>
int main(void) {
    char buf[64];
    scanf("%63s", buf);
    printf(buf);
    return 0;
}
