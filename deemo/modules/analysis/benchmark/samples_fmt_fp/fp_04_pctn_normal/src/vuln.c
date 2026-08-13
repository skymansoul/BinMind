#include <stdio.h>
int main(void) {
    int written = 0;
    printf("prefix%n-suffix\n", &written);  /* %n 目标为本地地址 */
    return written == 0;
}
