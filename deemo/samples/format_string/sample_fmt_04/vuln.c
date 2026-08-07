/*
 * sample_fmt_04 — fprintf(stderr, user_input)
 * 模式: fgets → fprintf(stderr, user_input)
 * 期望: CONFIRMED
 */
#include <stdio.h>

int main(void) {
    char buf[256];
    if (fgets(buf, sizeof(buf), stdin) == NULL)
        return 1;
    fprintf(stderr, buf);  /* [VULN] */
    return 0;
}
