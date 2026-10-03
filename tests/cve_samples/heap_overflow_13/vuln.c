/* heap_overflow_13 — 嵌套分配中内层缓冲区溢出影响外层
 * CWE-122: 写入内层堆块超出边界破坏外层块元数据
 * gcc -o vuln vuln.c
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
int main() { char *outer = malloc(128), *inner = malloc(32); strcpy(inner, "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"); free(inner); free(outer); return 0; }
