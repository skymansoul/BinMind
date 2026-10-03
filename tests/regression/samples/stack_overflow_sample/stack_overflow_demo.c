/* 栈溢出: 固定大小buffer + unchecked strcpy */
#include <stdio.h>
#include <string.h>
void vulnerable(char *input) {
    char buf[64];
    strcpy(buf, input); /* STACK BUFFER OVERFLOW — no bounds check */
    printf("%s\n", buf);
}
int main(int argc, char **argv) {
    if (argc > 1) vulnerable(argv[1]);
    return 0;
}
