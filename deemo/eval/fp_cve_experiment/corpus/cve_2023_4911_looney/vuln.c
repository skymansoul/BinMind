/* CVE-2023-4911 Looney Tunables: ld.so 解析
 * GLIBC_TUNABLES 时把环境变量 strcpy 进定长堆缓冲区.
 */
#include <stdlib.h>
#include <stdio.h>
#include <string.h>

char *parse_tunables(const char *env) {
    size_t n = 1024;
    char *buf = (char *)malloc(n);
    if (!buf) return 0;
    strcpy(buf, env);
    return buf;
}

int main(int argc, char **argv) {
    (void)argc;
    char env[2048];
    memset(env, 'T', 2047);
    env[2047] = 0;
    char *r = parse_tunables(env);
    printf("%d\n", r[0]);
    free(r);
    return 0;
}
