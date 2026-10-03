#include <stdio.h>
#include <stdlib.h>
#include <string.h>
/* CVE-2021-3156 模式: 堆缓冲区溢出——未检查用户输入长度 */
void process_input(char *user_data, int len) {
    char *buf = malloc(64);
    if (!buf) return;
    /* BUG: len未验证, 可能>64导致堆溢出 */
    memcpy(buf, user_data, len);
    printf("processed: %s
", buf);
    free(buf);
}
int main(int argc, char **argv) {
    if (argc < 2) return 1;
    process_input(argv[1], strlen(argv[1]));
    return 0;
}
