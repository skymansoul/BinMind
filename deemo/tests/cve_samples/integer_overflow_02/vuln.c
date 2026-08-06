/* integer_overflow_02 — signed int overflow in array index
 * CWE-190: 负索引绕过边界检查
 * gcc -o vuln vuln.c -fno-stack-protector
 */
#include <stdio.h>
#include <stdlib.h>
int arr[100];
void access(int idx) {
    if (idx < 100)  /* 未检查下界——负索引可访问越界内存 */
        arr[idx] = 0;
}
int main(int argc, char **argv) {
    access(argc > 1 ? atoi(argv[1]) : 0);
    return 0;
}
