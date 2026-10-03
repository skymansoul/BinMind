#include <stdio.h>
#include <stdlib.h>
#include <string.h>
/* UAF-06: 结构体字段指针 — free后通过struct->field访问 */
typedef struct { int size; char *name; char *desc; } Item;
int main(void) {
    Item *it = (Item *)malloc(sizeof(Item));
    if (!it) return 1;
    it->name = (char *)malloc(32);
    strcpy(it->name, "item_name");
    free(it->name);  /* 释放子对象 */
    free(it);        /* 释放父对象 */
    printf("name: %s\n", it->name);  /* VULNERABLE: it和it->name都已释放 */
    return 0;
}
