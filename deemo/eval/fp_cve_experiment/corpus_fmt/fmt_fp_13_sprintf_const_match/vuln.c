/* 安全: sprintf 常量格式串, 缓冲足够. */
#include <stdio.h>

int main(void) {
    char out[64];
    sprintf(out, "user=%s id=%d", "alice", 1);
    printf("%s\n", out);
    return 0;
}
