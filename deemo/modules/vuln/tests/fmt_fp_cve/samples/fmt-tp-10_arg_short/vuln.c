/* 说明符多于实参, 越界读. */
#include <stdio.h>
int main(void) {
    int a = 1;
    printf("%d %d %d", a);
    return 0;
}
