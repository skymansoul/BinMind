#include <stdlib.h>
#include <stdio.h>

typedef struct { int len; char *data; } obj_t;

__attribute__((noinline)) void trigger_struct_vuln(void) {
    obj_t *obj = (obj_t *)malloc(sizeof(obj_t));
    if (!obj) return;
    obj->len = 64;
    obj->data = (char *)malloc(obj->len);
    free(obj->data);
    free(obj);
    /* obj和obj->data均已释放，volatile防止编译器DCE */
    *(volatile char *)obj->data = 'X';
}

int main(void) {
    trigger_struct_vuln();
    return 0;
}
