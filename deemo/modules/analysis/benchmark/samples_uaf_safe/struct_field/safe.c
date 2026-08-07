#include <stdlib.h>
#include <stdio.h>

typedef struct { int len; char *data; } obj_t;

static volatile char g_check1;
static volatile char g_check2;

__attribute__((noinline)) void trigger_struct_safe(void) {
    obj_t *obj = (obj_t *)malloc(sizeof(obj_t));
    if (!obj) return;
    obj->len = 64;
    obj->data = (char *)malloc(obj->len);
    if (!obj->data) { free(obj); return; }
    char *data_ptr = obj->data;
    /* volatile读写阻止编译器消除两条malloc路径 */
    g_check1 = obj->len;
    g_check2 = data_ptr[0];
    free(obj);
    free(data_ptr);
}

int main(void) {
    trigger_struct_safe();
    return 0;
}
