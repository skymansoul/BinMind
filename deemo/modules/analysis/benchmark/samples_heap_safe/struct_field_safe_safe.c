/** struct_field_safe: SAFE: field access within bounds */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static volatile void *volatile_sink;
#define MK_BARRIER(x) __asm__ __volatile__("" : : "r"(x) : "memory")


int main() {
    void *p = malloc(96);
    if (!p) return 1;
    volatile_sink = p;
    MK_BARRIER(0);
    typedef struct { char hdr[32]; char data[64]; } Obj; Obj *obj = (Obj*)p; char *src = malloc(64); memset(src,88,64); memcpy(obj->data, src, 64); free(src);
    printf("struct_field: safe\n");
    return 0;
}
