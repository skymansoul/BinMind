/* uaf_02 — 函数内 malloc/free 后通过别名指针使用
 * 对应 CWE-416: 同一指针两次解引用
 * 编译: gcc -o vuln vuln.c
 */
#include <stdio.h>
#include <stdlib.h>

typedef struct { int id; char *name; } Record;

void process() {
    Record *r = (Record *)malloc(sizeof(Record));
    r->id = 1;
    r->name = (char *)malloc(32);
    free(r->name);    /* 释放 name */
    r->name[0] = 'X'; /* UAF: name 已被释放 */
    free(r);
}

int main() {
    process();
    return 0;
}
