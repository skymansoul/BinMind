#include <stdio.h>
#include <stdlib.h>
#include <string.h>
/* FMT-15: 外部输入直接传给sprintf作为格式串 */
int main(int argc, char **argv) {
    char buf[512];
    if (argc > 1)
        sprintf(buf, argv[1], 42);  /* VULNERABLE: argv[1]作为格式串 */
    else
        sprintf(buf, "answer=%d", 42);
    printf("%s\n", buf);
    return 0;
}
