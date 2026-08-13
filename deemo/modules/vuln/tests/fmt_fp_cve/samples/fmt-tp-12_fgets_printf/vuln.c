/* fgets 读入后 printf. */
#include <stdio.h>
int main(void) {
    char buf[128];
    if (!fgets(buf, 128, stdin)) return 0;
    printf(buf);
    return 0;
}
