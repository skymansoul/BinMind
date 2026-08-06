/* format_string_05 — fprintf通过包装函数间接使用用户输入
 * CWE-134: 日志函数直接传递用户控制的格式字符串
 * gcc -o vuln vuln.c
 */
#include <stdio.h>
void log_error(const char *msg) { fprintf(stderr, msg); }
int main(int argc, char **argv) { log_error(argc>1?argv[1]:"test"); return 0; }
