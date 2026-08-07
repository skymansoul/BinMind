// uaf10_realloc_uaf — realloc后的UAF
// CVE参考: CVE-UAF-REALLOC, 模式: uaf_realloc
// 检测目标: realloc可能返回新地址, 旧指针变为悬挂
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int main(int argc, char **argv) {
    char *buf = (char *)malloc(64);
    if (!buf) return 1;
    memset(buf, 'A', 32);
    char *new_buf = (char *)realloc(buf, 256);
    if (!new_buf) { free(buf); return 1; }
    // UAF: realloc后使用旧指针buf (可能已释放)
    memset(buf, 'B', 16);
    printf("realloc UAF: old=%p new=%p\n", (void *)buf, (void *)new_buf);
    free(new_buf);
    return 0;
}
