#include <stdio.h>
#include <stdlib.h>
#include <string.h>
/* UAF-10: 队列pop后的UAF — 出队元素被释放但外部仍持有引用 */
typedef struct QNode { char *msg; struct QNode *next; } QNode;
static QNode *queue = NULL;
void push(const char *m) {
    QNode *n = (QNode *)malloc(sizeof(QNode));
    n->msg = strdup(m); n->next = queue; queue = n;
}
QNode *pop(void) {
    if (!queue) return NULL;
    QNode *n = queue; queue = queue->next; return n;
}

int main(void) {
    push("msg_one"); push("msg_two");
    QNode *item = pop();
    printf("popped: %s\n", item->msg);
    free(item->msg); free(item);
    printf("use after pop: %s\n", item->msg);  /* VULNERABLE */
    QNode *item2 = pop();
    if (item2) { free(item2->msg); free(item2); }
    return 0;
}
