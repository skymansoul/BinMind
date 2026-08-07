#include <stdio.h>
#include <stdlib.h>
/* UAF-07: 数组中的对象指针 — 释放后通过数组索引访问 */
#define COUNT 8
typedef struct { int val; char *label; } Elem;
int main(void) {
    Elem *arr[COUNT];
    for (int i = 0; i < COUNT; i++) {
        arr[i] = (Elem *)malloc(sizeof(Elem));
        arr[i]->val = i * 10;
    }
    for (int i = 0; i < COUNT; i++) free(arr[i]);
    printf("val=%d\n", arr[3]->val);  /* VULNERABLE: arr[3]已释放 */
    return 0;
}
