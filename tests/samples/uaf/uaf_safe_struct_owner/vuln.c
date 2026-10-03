#include <stdio.h>
#include <stdlib.h>
#include <string.h>
/* UAF-SAFE-05: 结构体持有指针, free 后仅更新标量字段, 不再触碰指针字段 */
struct holder {
    char *data;
    int len;
};

int main(int argc, char **argv) {
    struct holder h;
    h.data = (char *)malloc(32);
    if (!h.data) return 1;
    h.len = 32;
    memcpy(h.data, "hello", 6);
    printf("len=%d data=%s\n", h.len, h.data);
    free(h.data);
    h.len = 0;                   /* 仅更新标量, 不解引用 h.data */
    printf("after free len=%d\n", h.len);
    return 0;
}
