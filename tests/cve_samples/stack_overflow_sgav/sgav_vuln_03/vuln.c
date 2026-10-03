/* VULN: sprintf 拼接多个参数超出缓冲区 */
#include <stdio.h>
void vuln(const char *a, const char *b) {
    char buf[64];
    sprintf(buf, "%s%s", a, b);
}
int main(int argc, char **argv) {
    vuln(argc>1?argv[1]:"AAAA", argc>2?argv[2]:"BBBB");
    return 0;
}
