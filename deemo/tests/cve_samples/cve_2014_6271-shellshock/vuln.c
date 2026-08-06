/* CVE-2014-6271: Shellshock — 简化: 环境变量长度未校验导致的堆溢出 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
void parse_env_value(char *value, size_t vlen) {
    char *buf = malloc(256);
    /* BUG: vlen 来自环境变量, 可能远超 256 字节 */
    memcpy(buf, value, vlen);
    printf("ENV: %s\n", buf);
    free(buf);
}
int main() { parse_env_value("() { :;}; /bin/sh", 65535); return 0; }
