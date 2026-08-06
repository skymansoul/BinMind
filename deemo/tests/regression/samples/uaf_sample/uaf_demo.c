/* 经典Use-After-Free: free后继续使用指针 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
typedef struct { char data[32]; void (*callback)(void); } obj_t;
void safe_callback() { printf("safe\n"); }
void exploit_callback() { printf("EXPLOITED\n"); }
int main() {
    obj_t *obj = (obj_t *)malloc(sizeof(obj_t));
    obj->callback = safe_callback;
    free(obj);                    /* FREE */
    obj_t *obj2 = (obj_t *)malloc(sizeof(obj_t)); /* REALLOC — 可能复用obj地址 */
    obj2->callback = exploit_callback;
    obj->callback();              /* UAF — 调用obj->callback但obj已被释放且可能被obj2复用 */
    return 0;
}
