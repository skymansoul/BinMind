/* heap_overflow_15 — off-by-one在堆上写入null字节
 * CWE-122: 循环边界off-by-one导致额外null字节写入
 * gcc -o vuln vuln.c
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
int main() { char *p = malloc(32); memset(p, 'A', 33); free(p); return 0; }
