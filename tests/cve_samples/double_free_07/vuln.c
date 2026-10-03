/* double_free_07 — 结构体成员双重释放
 * CWE-415: 释放结构体时成员已被释放
 * gcc -o vuln vuln.c
 */
#include <stdio.h>
#include <stdlib.h>
typedef struct { char *name; int id; } Record;
int main() {
    Record *r = malloc(sizeof(Record));
    r->name = malloc(64);
    free(r->name);
    free(r); /* r->name已释放, 但这里只释放r本身--合法 */
    return 0;
}
