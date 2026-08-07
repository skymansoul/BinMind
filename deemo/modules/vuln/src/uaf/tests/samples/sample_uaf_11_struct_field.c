/* sample_uaf_11_struct_field.c — 结构体字段中的指针UAF */
#include <stdlib.h>
typedef struct {
    int *data;
    int size;
} Buffer;
void test() {
    Buffer b;
    b.data = (int*)malloc(64);
    b.size = 64;
    b.data[0] = 42;
    free(b.data);
    b.data[0] = 99;  /* UAF via struct field */
}
int main() {
    test();
    return 0;
}
