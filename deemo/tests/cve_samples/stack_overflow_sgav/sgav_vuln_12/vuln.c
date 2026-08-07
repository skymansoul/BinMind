/* VULN: memcpy(buf, src, n) 其中 n 来自用户输入, 无守卫约束 */
#include <string.h>
#include <stdlib.h>
void vuln(int n, const char *src) {
    char buf[32];
    memcpy(buf, src, n);
}
int main(int argc, char **argv) {
    int n = argc > 1 ? atoi(argv[1]) : 64;
    vuln(n, "AAAAAAAAAAAA");
    return 0;
}
