/* uaf_10 — 迭代器失效 (容器修改后迭代器未更新)
 * CWE-416: 链表元素被移除后迭代器仍指向已释放节点
 * gcc -o vuln vuln.c
 */
#include <stdio.h>
#include <stdlib.h>
typedef struct Node { int val; struct Node *next; } Node;
int main() {
    Node *n1 = malloc(sizeof(Node)), *n2 = malloc(sizeof(Node));
    n1->val = 1; n1->next = n2; n2->val = 2; n2->next = NULL;
    Node *it = n1;
    free(n1);
    printf("%d\n", it->val); /* UAF: it指向已释放的n1 */
    return 0;
}
