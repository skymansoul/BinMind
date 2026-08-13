#include <stdio.h>
int main(void) {
    char fmt[64];
    gets(fmt);                    /* 用户输入 */
    printf(fmt);
    return 0;
}
