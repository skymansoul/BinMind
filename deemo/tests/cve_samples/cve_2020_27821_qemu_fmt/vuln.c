/* CVE-2020-27821 — QEMU 格式化字符串 / CWE-134 */
#include <stdio.h>
void qemu_error(const char *msg) { fprintf(stderr, msg); } /* BUG */
int main(int argc, char **argv) {
    if (argc>1) qemu_error(argv[1]); return 0;
}
