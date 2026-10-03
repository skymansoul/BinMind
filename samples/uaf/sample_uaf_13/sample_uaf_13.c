/*
 * sample_uaf_13 — Safe pattern: NULL-zero after free (FP验证).
 *
 * 使用后置NULL的标准安全模式.
 * free(p) 后 p=NULL, 且对NULL进行守卫检查.
 * 这是正确的防护, 不是UAF.
 *
 * TARPS预期: DEF_FP — NULL置零+守卫=安全
 * 编译: gcc -o sample_uaf_13 sample_uaf_13.c
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static void safe_free_pattern(char **pp) {
    if (pp && *pp) {
        free(*pp);
        *pp = NULL;  /* 安全: 双重指针置零 */
    }
}

int main(void) {
    char *buf = (char *)malloc(128);
    if (!buf) return 1;
    strcpy(buf, "safe_pattern");

    safe_free_pattern(&buf);

    /* buf现在是NULL — 守卫检查生效 */
    if (buf != NULL) {
        buf[0] = 'S';  /* 死代码, 不执行 */
    }

    printf("safe: buf is NULL-guarded\n");
    return 0;
}
