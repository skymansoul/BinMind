/* format_string_09 — setproctitle 注入
 * CWE-134: 进程标题设置时未过滤格式字符
 * 简化: 用printf模拟setproctitle场景
 * gcc -o vuln vuln.c
 */
#include <stdio.h>
#include <string.h>
void set_title(const char *t) { printf(t); }
int main(int argc, char **argv) { set_title(argc>1?argv[1]:"proc"); return 0; }
