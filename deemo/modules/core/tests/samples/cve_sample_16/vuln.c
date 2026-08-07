/* 复杂场景: strcat 链导致的堆溢出 — 逐步拼接时总长度超出分配 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

void build_path(char *dir, char *file, char *ext) {
    size_t alloc = strlen(dir) + 32; /* 分配时以为够用 */
    char *path = (char *)malloc(alloc);
    if (!path) return;
    strcpy(path, dir);
    strcat(path, "/");
    strcat(path, file);
    strcat(path, ".");
    strcat(path, ext);
    /* 实际总长度 = dir + "/" + file + "." + ext → 可能 > alloc */
    printf("path=%s\n", path);
    free(path);
}

int main(void) {
    build_path("/very/long/base/directory/path/here",
               "a_very_long_filename_that_exceeds_buffer",
               "tar.gz");
    return 0;
}
