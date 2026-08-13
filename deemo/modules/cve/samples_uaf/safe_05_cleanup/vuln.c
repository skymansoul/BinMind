/* N/A 安全对照: 释放结构体后读取字段指针用于二次 free, cleanup 语义. */
#include <stdlib.h>

struct S {
    char *data;
};

int main(int argc, char **argv) {
    struct S *s = (struct S *)malloc(sizeof(struct S));
    if (!s) return 1;
    s->data = (char *)malloc(16);
    free(s);
    free(s->data);
    return 0;
}
