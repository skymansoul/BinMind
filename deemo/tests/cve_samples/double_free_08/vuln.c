/* double_free_08 — 链表遍历中错误释放
 * CWE-415: 释放当前节点后继续使用next并再次释放
 * gcc -o vuln vuln.c
 */
#include <stdio.h>
#include <stdlib.h>
typedef struct Node { int data; struct Node *next; } Node;
int main() {
    Node *a = malloc(sizeof(Node)), *b = malloc(sizeof(Node));
    a->next = b; b->next = NULL;
    free(a);
    free(a->next); /* a已释放, a->next是悬垂指针 */
    return 0;
}
