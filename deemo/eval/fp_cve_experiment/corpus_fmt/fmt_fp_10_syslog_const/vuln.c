/* 安全: syslog 使用常量格式串. */
#include <stdio.h>

void my_log(const char *msg) {
    printf("LOG: %s\n", msg);
}

int main(void) {
    my_log("started");
    return 0;
}
