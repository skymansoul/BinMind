/* uaf_07 — 引用计数错误导致过早释放 (简化: 手动计数)
 * CWE-416: 引用计数未同步, 最后一次使用前释放
 * gcc -o vuln vuln.c
 */
#include <stdio.h>
#include <stdlib.h>
typedef struct { int refs; char *data; } Buf;
Buf *create() { Buf *b = malloc(sizeof(Buf)); b->refs = 1; b->data = malloc(256); return b; }
void release(Buf *b) { if (--b->refs <= 0) { free(b->data); free(b); } }
int main() { Buf *b = create(); release(b); puts(b->data); }
