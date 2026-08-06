/* CWE-121: gets() — classic unconditional stack overflow, C11 removed */
#include <stdio.h>
int main(void) {
    char buf[16];
    gets(buf); /* unconditional overflow */
    puts(buf);
    return 0;
}
