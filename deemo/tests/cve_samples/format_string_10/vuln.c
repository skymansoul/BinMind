/* format_string_10 — __attribute__((format)) 缺失导致的误用
 * 声明为printf-like但实际未检查格式化
 * gcc -o vuln vuln.c -Wno-format-security
 */
#include <stdio.h>
void my_log(const char *s) { printf(s); }
int main(int argc, char **argv) { my_log(argc>1?argv[1]:"ok"); return 0; }
