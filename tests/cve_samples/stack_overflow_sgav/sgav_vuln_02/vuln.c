/* VULN: 通过指针别名 strcpy, 简单正则可能漏检 */
#include <string.h>
void vuln(const char *input) {
    char buf[32];
    char *p = buf;
    strcpy(p, input);
}
int main(int argc, char **argv) {
    if (argc > 1) vuln(argv[1]);
    return 0;
}
