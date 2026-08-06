#include <stdio.h>
#include <string.h>

void build_path(char *dir, char *file) {
    char path[64] = {0};
    strcat(path, "/home/user/");
    strcat(path, dir);
    strcat(path, "/");
    strcat(path, file);  // 累积追加可能溢出
    printf("path: %s\n", path);
}

int main(int argc, char **argv) {
    if (argc < 3) return 1;
    build_path(argv[1], argv[2]);
    return 0;
}
