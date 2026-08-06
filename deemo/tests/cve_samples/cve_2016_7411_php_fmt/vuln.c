/* CVE-2016-7411 — PHP 格式化字符串 / CWE-134 */
#include <stdio.h>
void php_error(const char *msg) { printf(msg); } /* BUG: user msg as fmt */
int main(int argc, char **argv) {
    if (argc>1) php_error(argv[1]); return 0;
}
