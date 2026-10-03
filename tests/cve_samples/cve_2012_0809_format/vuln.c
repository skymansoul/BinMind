/* CVE-2012-0809 — sudo 格式化字符串 (debug path) / CWE-134 */
#include <stdio.h>
void debug_log(const char *user) { printf(user); } /* BUG: user as format */
int main(int argc, char **argv) {
    if (argc>1) debug_log(argv[1]); return 0;
}
