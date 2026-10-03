/*
 * UAF-REALLOC-PATH — realloc 移动后旧指针失效
 * realloc 扩容强制移动 → 旧块被归还; 保留的 old 指针随后被 strcpy 使用.
 * 触发: grow() 把 buf 扩容到 4096, 触发搬运; old 指针指向已归还旧块.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

void grow(char *buf) {
    char *old = buf;
    char *nb = (char *)realloc(buf, 4096);
    if (!nb) return;
    /* 漏洞: realloc 移动后 old 指向已归还旧块, 仍被写入 */
    strcpy(old, "use-after-realloc");
    printf("%s\n", nb);
}

int main(void) {
    char *buf = (char *)malloc(64);
    if (!buf) return 1;
    strcpy(buf, "seed");
    grow(buf);
    return 0;
}
