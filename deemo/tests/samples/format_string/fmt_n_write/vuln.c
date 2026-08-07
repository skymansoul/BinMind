#include <stdio.h>
#include <string.h>
/* FMT-04: 用户输入含%n — 任意地址写原语 */
int main(int argc, char **argv) {
    int written = 0;
    char fmt[128];
    if (argc > 1) {
        strncpy(fmt, argv[1], sizeof(fmt)-1);
        fmt[127] = '\0';
    } else {
        strcpy(fmt, "hello %n");
    }
    printf(fmt, &written);  /* VULNERABLE: fmt可能含%n */
    printf("written=%d\n", written);
    return 0;
}
