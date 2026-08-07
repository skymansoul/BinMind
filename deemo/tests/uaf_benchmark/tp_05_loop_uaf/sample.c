/* TP-05: Loop UAF (CWE-416) */
#include <stdlib.h>
#include <stdio.h>
typedef struct item { int id; struct item *next; } item_t;
void loop_uaf(item_t *head) {
    item_t *cur = head;
    while (cur) {
        item_t *next = cur->next;
        free(cur);
        cur = next;
    }
    printf("head id: %d\n", head->id);  /* UAF */
}
int main(void) {
    item_t *a = (item_t *)malloc(sizeof(item_t));
    item_t *b = (item_t *)malloc(sizeof(item_t));
    a->id = 1; a->next = b; b->id = 2; b->next = NULL;
    loop_uaf(a); return 0;
}