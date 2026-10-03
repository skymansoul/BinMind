/* stack_overflow_03 — sprintf 无长度限制写入栈缓冲区
 * CWE-121: sprintf(buf, "%s%s", a, b) 无长度检查
 * gcc -o vuln vuln.c -fno-stack-protector
 */
#include <stdio.h>
#include <string.h>
void combine(const char *a, const char *b) {
    char local[64];
    sprintf(local, "%s%s", a, b); /* a+b 可能 >64 */
    puts(local);
}
int main(int argc, char **argv) {
    combine(argc>1?argv[1]:"AAAA", argc>2?argv[2]:"BBBB");
    return 0;
}
