#include <stdio.h>
#include <stdlib.h>
/* FMT-03: 通过%x/%p泄露栈数据 */
int main(int argc, char **argv) {
    char buf[64];
    if (argc > 1) snprintf(buf, sizeof(buf), argv[1]);  /* VULNERABLE */
    else snprintf(buf, sizeof(buf), "safe: %%s");
    printf("%s\n", buf);
    return 0;
}
