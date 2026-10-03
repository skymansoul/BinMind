/* gets 读入的输入直接作为格式串. */
#include <stdio.h>
int main(void) {
    char buf[256];
    gets(buf);
    printf(buf);
    return 0;
}
