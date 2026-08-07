#include <stdio.h>
#include <stdlib.h>
/* FMT-09: snprintf 带固定格式串 — 安全, 不应报告 */
int main(int argc, char **argv) {
    char buf[256];
    if (argc > 1)
        snprintf(buf, sizeof(buf), "user_input: %s", argv[1]);  /* SAFE */
    else
        snprintf(buf, sizeof(buf), "no input");
    printf("%s\n", buf);
    return 0;
}
