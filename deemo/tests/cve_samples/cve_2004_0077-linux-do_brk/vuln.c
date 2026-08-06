/* CVE-2004-0077: Linux do_brk() heap overflow — 简化: 堆边界绕过 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
void vulnerable_brk(char *user_data, size_t user_len) {
    char *buf = malloc(64);
    /* BUG: 未校验 user_len <= 64 —— 攻击者可传入超大数据触发堆溢出 */
    memcpy(buf, user_data, user_len);
    printf("%s\n", buf);
    free(buf);
}
int main(int argc, char *argv[]) { if(argc>1) vulnerable_brk(argv[1], strlen(argv[1])); return 0; }
