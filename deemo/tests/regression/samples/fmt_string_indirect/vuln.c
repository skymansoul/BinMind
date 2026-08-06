#include <stdio.h>
#include <string.h>
/* 间接传参格式化字符串——syslog模式 */
void indirect_log(char *input) {
    char buffer[256];
    snprintf(buffer, sizeof(buffer), "%%s", input);
    /* BUG: buffer仍来自用户输入, 间接传给printf */
    char *ptr = buffer;
    printf(ptr);
}
int main(int argc, char **argv) {
    if (argc < 2) return 1;
    indirect_log(argv[1]);
    return 0;
}
