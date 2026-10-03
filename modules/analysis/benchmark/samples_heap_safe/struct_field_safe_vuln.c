/** struct_field_vuln: OVERFLOW: 128 > data[64] */
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
    typedef struct { char hdr[32]; char data[64]; } Obj; Obj *obj = (Obj*)p; char *src = malloc(128); memset(src,65,128); memcpy(obj->data, src, 128); free(src);
    printf("struct_field: vuln\n");
    return 0;
}
