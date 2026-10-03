/* CVE-2019-15947 — Bitcoin Core 格式化字符串 / CWE-134 */
#include <stdio.h>
void wallet_log(const char *tx) { printf(tx); } /* BUG: tx hex as fmt */
int main(int argc, char **argv) {
    if (argc>1) wallet_log(argv[1]); return 0;
}
