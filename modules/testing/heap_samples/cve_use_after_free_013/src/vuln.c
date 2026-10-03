/* Use-after-free: free then use dangling pointer */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
typedef struct node { int id; char data[64]; struct node *next; } node_t;
int main(void) {
    node_t *n1 = (node_t *)malloc(sizeof(node_t));
    if (!n1) return 1;
    n1->id = 1; strcpy(n1->data, "original");
    free(n1);
    char *str = (char *)malloc(32);
    if (!str) return 1;
    strcpy(str, "OVERWRITTEN!");
    node_t *d = n1;  /* BUG: dangling pointer */
    printf("[*] id=%d data=%s\n", d->id, d->data);
    free(str);
    return 0;
}
