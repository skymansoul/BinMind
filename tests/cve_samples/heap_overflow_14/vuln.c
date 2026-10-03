/* heap_overflow_14 — reallocarray误用导致溢出 (乘法回绕)
 * CWE-122: nmemb*size回绕导致实际分配不足
 * gcc -o vuln vuln.c
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
int main() { int *arr = calloc(65535, 65535); memcpy(arr, "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA", 64); free(arr); return 0; }
