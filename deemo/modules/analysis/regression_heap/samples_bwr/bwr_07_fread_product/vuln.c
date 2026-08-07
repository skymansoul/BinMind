/*
 * BWR-07: fread 乘积参数 (PCST)
 *
 * fread(ptr, size, nmemb, stream) 实际写入 size*nmemb = 1024*4 = 4096 字节.
 * 旧逻辑只取第3实参 nmemb 低估写入量 → 漏报. PCST 取 (size,nmemb) 乘积,
 * 4096 > malloc(256) 可用区 → 确认溢出.
 */
#include <stdio.h>
#include <stdlib.h>

int main(void) {
    char *p = (char *)malloc(256);
    FILE *fp;
    if (!p) return 1;
    fp = fopen("dummy.bin", "rb");
    if (!fp) {
        free(p);
        return 0;
    }
    fread(p, 1024, 4, fp);
    fclose(fp);
    free(p);
    return 0;
}
