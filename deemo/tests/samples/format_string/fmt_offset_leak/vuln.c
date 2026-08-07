#include <stdio.h>
#include <stdlib.h>
/* FMT-02: 格式字符串偏移泄露 — 通过%p/%x泄露栈内容
 * 攻击者通过可控格式字符串读取栈上的敏感数据 */
int main(int argc, char **argv) {
    char secret[32] = "s3cr3t_k3y_h3r3";
    char buf[64];
    if (argc < 2) return 1;
    snprintf(buf, sizeof(buf), argv[1]);  /* VULNERABLE: 可控格式字符串 */
    printf("result: %s\n", buf);
    return 0;
}
