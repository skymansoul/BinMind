/* heap_overflow_11 — scanf无限读取导致堆溢出
 * CWE-122: scanf("%s", heap_buf)无长度限制
 * gcc -o vuln vuln.c
 */
#include <stdio.h>
#include <stdlib.h>
int main() { char *p = malloc(32); scanf("%s", p); free(p); return 0; }
