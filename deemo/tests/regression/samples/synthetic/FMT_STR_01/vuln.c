#include <stdio.h>

void log_message(char *msg) {
    printf(msg);  // 用户输入直接作为 fmt 参数
    printf("\n");
}

int main(int argc, char **argv) {
    if (argc < 2) return 1;
    log_message(argv[1]);
    return 0;
}
