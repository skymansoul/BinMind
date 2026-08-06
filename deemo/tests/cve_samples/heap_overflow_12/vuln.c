/* heap_overflow_12 — getline在错误处理时泄漏+溢出
 * CWE-122: getline分配后未检查长度即写入
 * gcc -o vuln vuln.c
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
int main() { char *p = malloc(4); strcpy(p, "AAAAAAAAAAAAAAAA"); free(p); return 0; }
