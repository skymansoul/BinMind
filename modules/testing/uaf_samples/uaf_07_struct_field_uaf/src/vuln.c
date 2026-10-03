#include <stdio.h>
#include <stdlib.h>
#include <string.h>
struct node { int id; char *name; };
int main(void) {
    struct node *n = (struct node *)malloc(sizeof(*n));
    if (!n) return 1;
    n->id = 1;
    n->name = (char *)malloc(32);
    if (!n->name) return 1;
    strcpy(n->name, "alice");
    free(n->name);
    printf("[*] %s\n", n->name);   /* UAF: 字段解引用 */
    free(n);
    return 0;
}
