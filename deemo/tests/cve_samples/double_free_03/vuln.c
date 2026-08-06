/* double_free_03 — 通过别名双重释放
 * CWE-415: 全局变量别名导致同一指针两次free
 * gcc -o vuln vuln.c
 */
#include <stdio.h>
#include <stdlib.h>
char *g_alias = NULL;
void setup() { char *p = malloc(256); g_alias = p; free(p); }
void teardown() { free(g_alias); } /* g_alias指向已释放内存 */
int main() { setup(); teardown(); return 0; }
