/* uaf_01 — free 后通过全局指针继续使用
 * 对应 CWE-416: Use After Free
 * 编译: gcc -o vuln vuln.c
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

char *global_ptr = NULL;

void setup() {
    global_ptr = (char *)malloc(128);
    strcpy(global_ptr, "sensitive_data");
}

void cleanup() {
    free(global_ptr);
    /* 漏置 NULL — global_ptr 成为悬垂指针 */
}

void use_after() {
    printf("data: %s\n", global_ptr);  /* UAF: 使用已释放的内存 */
}

int main() {
    setup();
    cleanup();
    use_after();
    return 0;
}
